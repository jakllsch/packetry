//! USB capture backend for usb-sniffer.

use std::collections::VecDeque;
use std::num::NonZeroU32;
use std::time::Duration;
use std::sync::mpsc;

use anyhow::{Context as ErrorContext, Error, bail};
use num_enum::{IntoPrimitive};
use nusb::{
    self,
    transfer::{
        Control,
        ControlType,
        Recipient,
    },
    DeviceInfo,
    Interface
};

use super::{
    BackendDevice,
    BackendHandle,
    Speed,
    PacketIterator,
    PacketResult,
    TimestampedPacket,
    TransferQueue,
};

use crate::capture::CaptureMetadata;

pub const VID_PID: (u16, u16) = (0x6666, 0x6620);
const ENDPOINT: u8 = 0x82;
const READ_LEN: usize = 0x4000;
const NUM_TRANSFERS: usize = 4;

#[derive(Debug, Clone, Copy, IntoPrimitive)]
#[repr(u8)]
enum Command {
    Ctrl = 0xd0,
}

#[derive(Debug, Clone, Copy, IntoPrimitive)]
#[repr(u8)]
enum CaptureCtrl {
    Reset = 0,
    Enable = 1,
    Speed0 = 2,
    Speed1 = 3,
    Test = 4,
}

/// A UsbSniffer device attached to the system.
pub struct UsbSnifferDevice {
    device_info: DeviceInfo,
    interface_number: u8,
    alt_setting_number: u8,
    speeds: Vec<Speed>,
    metadata: CaptureMetadata,
}

/// A handle to an open UsbSniffer device.
#[derive(Clone)]
pub struct UsbSnifferHandle {
    interface: Interface,
    metadata: CaptureMetadata,
}

/// Converts from received data bytes to timestamped packets.
pub struct UsbSnifferStream {
    receiver: mpsc::Receiver<Vec<u8>>,
    buffer: VecDeque<u8>,
    capture_header: bool,
    capture_status: bool,
    capture_size: usize,
    total_clk_cycles: u64,
    ts: u64,
}

/// Convert 60MHz clock cycles to nanoseconds, rounding down.
fn clk_to_ns(clk_cycles: u64) -> u64 {
    const TABLE: [u64; 3] = [0, 16, 33];
    let quotient = clk_cycles / 3;
    let remainder = clk_cycles % 3;
    quotient * 50 + TABLE[remainder as usize]
}

/// Probe a UsbSniffer device.
pub fn probe(device_info: DeviceInfo) -> Result<Box<dyn BackendDevice>, Error> {
    Ok(Box::new(UsbSnifferDevice::new(device_info)?))
}

impl UsbSnifferDevice {
    /// Check whether a UsbSniffer device has an accessible analyzer interface.
    pub fn new(device_info: DeviceInfo) -> Result<UsbSnifferDevice, Error> {

        // Check we can open the device.
        let device = device_info
            .open()
            .context("Failed to open device")?;

        // Read the active configuration.
        let config = device
            .active_configuration()
            .context("Failed to retrieve active configuration")?;

        // Iterate over the interfaces...
        for interface in config.interfaces() {
            let interface_number = interface.interface_number();

            // ...and alternate settings...
            for alt_setting in interface.alt_settings() {
                let alt_setting_number = alt_setting.alternate_setting();

                // Try to claim the interface.
                let interface = device
                    .claim_interface(interface_number)
                    .context("Failed to claim interface")?;

                // Select the required alternate, if not the default.
                if alt_setting_number != 0 {
                    interface
                        .set_alt_setting(alt_setting_number)
                        .context("Failed to select alternate setting")?;
                }

                let metadata = CaptureMetadata {
                    iface_desc: Some("UsbSniffer USB Analyzer".to_string()),
                    iface_hardware: Some({
                        let bcd = device_info.device_version();
                        let major = bcd >> 8;
                        let minor = bcd as u8;
                        format!("UsbSniffer r{major}.{minor}")
                    }),
                    iface_os: Some(
                        format!("usb-sniffer")),
                    iface_snaplen: Some(NonZeroU32::new(0xFFFF).unwrap()),
                    .. Default::default()
                };

                // Fetch the available speeds.
                let handle = UsbSnifferHandle { interface, metadata };
                let speeds = handle
                    .speeds()
                    .context("Failed to fetch available speeds")?;

                // Now we have a usable device.
                return Ok(
                    UsbSnifferDevice {
                        device_info,
                        interface_number,
                        alt_setting_number,
                        speeds,
                        metadata: handle.metadata,
                    }
                )
            }
        }

        bail!("No supported analyzer interface found");
    }

    /// Open this device.
    pub fn open(&self) -> Result<UsbSnifferHandle, Error> {
        let device = self.device_info.open()?;
        let interface = device.claim_interface(self.interface_number)?;
        if self.alt_setting_number != 0 {
            interface.set_alt_setting(self.alt_setting_number)?;
        }
        Ok(UsbSnifferHandle {
            interface,
            metadata: self.metadata.clone()
        })
    }
}

impl BackendDevice for UsbSnifferDevice {
    fn open_as_generic(&self) -> Result<Box<dyn BackendHandle>, Error> {
        Ok(Box::new(self.open()?))
    }

    fn supported_speeds(&self) -> &[Speed] {
        &self.speeds
    }
}

impl BackendHandle for UsbSnifferHandle {
    fn metadata(&self) -> &CaptureMetadata {
        &self.metadata
    }

    fn begin_capture(
        &mut self,
        speed: Speed,
        data_tx: mpsc::Sender<Vec<u8>>
    ) -> Result<TransferQueue, Error>
    {
        self.start_capture(speed)?;

        Ok(TransferQueue::new(&self.interface, data_tx,
            ENDPOINT, NUM_TRANSFERS, READ_LEN))
    }

    fn end_capture(&mut self) -> Result<(), Error> {
        self.stop_capture()
    }

    fn post_capture(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn timestamped_packets(&self, data_rx: mpsc::Receiver<Vec<u8>>)
        -> Box<dyn PacketIterator>
    {
        Box::new(
            UsbSnifferStream {
                receiver: data_rx,
                buffer: VecDeque::new(),
                capture_header: true,
                capture_status: false,
                capture_size: 0,
                ts: 0,
                total_clk_cycles: 0,
            }
        )
    }

    fn duplicate(&self) -> Box<dyn BackendHandle> {
        Box::new(self.clone())
    }
}

impl UsbSnifferHandle {

    fn speeds(&self) -> Result<Vec<Speed>, Error> {
        use Speed::*;
        let mut speeds = Vec::new();
        for speed in [Auto, High, Full, Low] {
            if true {
                speeds.push(speed);
            }
        }
        Ok(speeds)
    }

    fn start_capture (&mut self, speed: Speed) -> Result<(), Error> {
        let _ = self.ctrl_init();
        let _ = self.cmd_ctrl(CaptureCtrl::Enable, 0);
        let _ = self.cmd_ctrl(CaptureCtrl::Reset, 1);
        // flush_data???
        
        if speed == Speed::High {
            let _ = self.cmd_ctrl(CaptureCtrl::Speed0, 0);
            let _ = self.cmd_ctrl(CaptureCtrl::Speed1, 1);
        } else if speed == Speed::Full {
            let _ = self.cmd_ctrl(CaptureCtrl::Speed0, 1);
            let _ = self.cmd_ctrl(CaptureCtrl::Speed1, 0);
        } else if speed == Speed::Low {
            let _ = self.cmd_ctrl(CaptureCtrl::Speed0, 0);
            let _ = self.cmd_ctrl(CaptureCtrl::Speed1, 0);
        } else {
            let _ = self.cmd_ctrl(CaptureCtrl::Speed0, 1);
            let _ = self.cmd_ctrl(CaptureCtrl::Speed1, 1);
        }
        let _ = self.cmd_ctrl(CaptureCtrl::Reset, 0);
        let _ = self.cmd_ctrl(CaptureCtrl::Enable, 1);
        Ok(())
    }

    fn stop_capture(&mut self) -> Result<(), Error> {
        let _ = self.cmd_ctrl(CaptureCtrl::Enable, 0);
        self.cmd_ctrl(CaptureCtrl::Reset, 1)
    }

    fn ctrl_init(&mut self) -> Result<(), Error> {
        let _ = self.cmd_ctrl(CaptureCtrl::Reset, 1);
        let _ = self.cmd_ctrl(CaptureCtrl::Enable, 0);
        let _ = self.cmd_ctrl(CaptureCtrl::Test, 0);
        let _ = self.cmd_ctrl(CaptureCtrl::Speed0, 1);
        let _ = self.cmd_ctrl(CaptureCtrl::Speed0, 0);
        let _ = self.cmd_ctrl(CaptureCtrl::Speed1, 1);
        let _ = self.cmd_ctrl(CaptureCtrl::Speed1, 0);
        Ok(())
    }

    fn cmd_ctrl(&mut self, index: CaptureCtrl, value: u8) -> Result<(), Error> {
        let mut wvalue = index as u16;
        if value > 0 {
            wvalue |= 0x0010;
        }
        let control = Control {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: Command::Ctrl.into(),
            value: wvalue,
            index: 0 as u16,
        };
        let data = &[];
        let timeout = Duration::from_secs(1);
        self.interface
            .control_out_blocking(control, data, timeout)
            .context("Write request failed")?;
        Ok(())
    }

}

impl PacketIterator for UsbSnifferStream {}

impl Iterator for UsbSnifferStream {
    type Item = PacketResult;
    fn next(&mut self) -> Option<PacketResult> {
        loop {
            // Do we have another packet already in the buffer?
            match self.next_buffered_packet() {
                // Yes; return the packet.
                Some(packet) => return Some(Ok(packet)),
                // No; wait for more data from the capture thread.
                None => match self.receiver.recv().ok() {
                    // Received more data; add it to the buffer and retry.
                    Some(bytes) => self.buffer.extend(bytes.iter()),
                    // Capture has ended, there are no more packets.
                    None => return None
                }
            }
        }
    }
}

impl UsbSnifferStream {
    fn next_buffered_packet(&mut self) -> Option<TimestampedPacket> {

        // Loop over any non-packet events, until we get to a packet.
        loop {
            if self.buffer.len() < 1 {
                return None
            }
            //println!("{} {} {} {} {}", self.capture_header, self.buffer.len(), self.capture_status, self.buffer[0], self.capture_size);
            if self.capture_header {
                self.capture_status = 0 == self.buffer[0] & 0x80;
                if self.capture_status {
                    self.capture_size = 4;
                } else {
                    self.capture_size = 7;
                }
            }
    
            if self.buffer.len() < self.capture_size {
                return None;
            }

            if self.capture_header {
                let ts = u32::from_be_bytes([0 as u8, self.buffer[0] & 0xf as u8, self.buffer[1] as u8, self.buffer[2] as u8]) as u64;
                if self.buffer[0] & 0x10 != 0 {
                    self.total_clk_cycles += 0x100000;
                }
                self.ts = self.total_clk_cycles + ts;
                if self.capture_status {
                    self.buffer.drain(0..self.capture_size);
                } else {
                    let packet_len = u16::from_be_bytes(
                        [self.buffer[3] & 0x7, self.buffer[4]]) as usize;
                    //println!("be {}", packet_len);
                    self.buffer.drain(0..7);
                    self.capture_size = packet_len - 7;
                    //println!("capture size {}", self.capture_size);
                    self.capture_header = 0 == self.capture_size;
                }
            } else {
                self.capture_header = true;
                break;
            }
        }

        Some(TimestampedPacket {
            timestamp_ns: clk_to_ns(self.ts),
            bytes: self.buffer.drain(0..self.capture_size).collect()
        })
    }
}
