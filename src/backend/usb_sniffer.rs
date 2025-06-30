//! USB capture backend for usb-sniffer.

use std::collections::VecDeque;
use std::time::Duration;
use std::sync::mpsc;

use anyhow::{Context as ErrorContext, Error};
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
const INTERFACE: u8 = 0;
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

bitfield! {
    pub struct StatusHeader(MSB0 [u8]);
    impl Debug;
    u32;
    pub status, _: 0;        // byte 0 bit 7
    pub toggle, _: 1;        // byte 0 bit 6
    pub zero, _: 2;          // byte 0 bit 5
    pub ts_overflow, _: 3;   // byte 0 bit 4
    pub ts, _: 23, 4;        // byte 0 bit 3-0, byte 1, byte 2
    pub speed, _: 25, 24;    // byte 3 bit 1-0
    pub trigger, _: 26;      // byte 3 bit 2
    pub vbus, _: 27;         // byte 3 bit 3
    pub ls, _: 31, 28;       // byte 3 bits 7-4
}

bitfield! {
    pub struct DataHeader(MSB0 [u8]);
    impl Debug;
    u32;
    pub status, _: 0;        // byte 0 bit 7
    pub toggle, _: 1;        // byte 0 bit 6
    pub zero, _: 2;          // byte 0 bit 5
    pub ts_overflow, _: 3;   // byte 0 bit 4
    pub ts, _: 23, 4;        // byte 0 bit 3-0, byte 1, byte 2
    //pub unused3, _: 25, 24;  // byte 3 bit 7-6
    pub data_error, _: 26;   // byte 3 bit 5
    pub crc_error, _: 27;    // byte 3 bit 4
    pub overflow, _: 28;     // byte 3 bit 3
    pub size, _: 39, 29;     // byte 3 bits 2-0, byte 4
    pub duration, _: 55, 40; // byte 5, byte 6
}

/// A usb-sniffer device attached to the system.
pub struct UsbSnifferDevice {
    device_info: DeviceInfo,
}

/// A handle to an open usb-sniffer device.
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

/// Probe a usb-sniffer device.
pub fn probe(device_info: DeviceInfo) -> Result<Box<dyn BackendDevice>, Error> {
    Ok(Box::new(UsbSnifferDevice::new(device_info)?))
}

impl UsbSnifferDevice {
    /// Check whether a usb-sniffer device has an accessible analyzer interface.
    pub fn new(device_info: DeviceInfo) -> Result<UsbSnifferDevice, Error> {

        // Check we can open the device.
        let _device = device_info
            .open()
            .context("Failed to open device")?;

        // Now we have a usable device.
        Ok(UsbSnifferDevice {device_info} )
    }

    /// Open this device.
    pub fn open(&self) -> Result<UsbSnifferHandle, Error> {
        let device = self.device_info.open()?;
        let interface = device.claim_interface(INTERFACE)?;
        let metadata = CaptureMetadata {
            iface_desc: Some("usb-sniffer USB Analyzer".to_string()),
            .. Default::default()
        };
        Ok(UsbSnifferHandle {
            interface,
            metadata,
        })
    }
}

impl BackendDevice for UsbSnifferDevice {
    fn open_as_generic(&self) -> Result<Box<dyn BackendHandle>, Error> {
        Ok(Box::new(self.open()?))
    }

    fn supported_speeds(&self) -> &[Speed] {
        use Speed::*;
        &[Auto, High, Full, Low]
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

    fn start_capture (&mut self, speed: Speed) -> Result<(), Error> {
        self.ctrl_init()?;
        self.cmd_ctrl(CaptureCtrl::Enable, 0)?;
        self.cmd_ctrl(CaptureCtrl::Reset, 1)?;
        // flush_data???
        if speed == Speed::High {
            self.cmd_ctrl(CaptureCtrl::Speed0, 0)?;
            self.cmd_ctrl(CaptureCtrl::Speed1, 1)?;
        } else if speed == Speed::Full {
            self.cmd_ctrl(CaptureCtrl::Speed0, 1)?;
            self.cmd_ctrl(CaptureCtrl::Speed1, 0)?;
        } else if speed == Speed::Low {
            self.cmd_ctrl(CaptureCtrl::Speed0, 0)?;
            self.cmd_ctrl(CaptureCtrl::Speed1, 0)?;
        } else {
            self.cmd_ctrl(CaptureCtrl::Speed0, 1)?;
            self.cmd_ctrl(CaptureCtrl::Speed1, 1)?;
        }
        self.cmd_ctrl(CaptureCtrl::Reset, 0)?;
        self.cmd_ctrl(CaptureCtrl::Enable, 1)
    }

    fn stop_capture(&mut self) -> Result<(), Error> {
        self.cmd_ctrl(CaptureCtrl::Enable, 0)?;
        self.cmd_ctrl(CaptureCtrl::Reset, 1)
    }

    fn ctrl_init(&mut self) -> Result<(), Error> {
        self.cmd_ctrl(CaptureCtrl::Reset, 1)?;
        self.cmd_ctrl(CaptureCtrl::Enable, 0)?;
        self.cmd_ctrl(CaptureCtrl::Test, 0)?;
        self.cmd_ctrl(CaptureCtrl::Speed0, 1)?;
        self.cmd_ctrl(CaptureCtrl::Speed0, 0)?;
        self.cmd_ctrl(CaptureCtrl::Speed1, 1)?;
        self.cmd_ctrl(CaptureCtrl::Speed1, 0)?;
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
            index: 0,
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
            if self.buffer.is_empty() {
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
                let statusheader = StatusHeader(self.buffer.range(0..4).copied().collect::<Vec<u8>>());
                let ts = u32::from_be_bytes([0, self.buffer[0] & 0xf, self.buffer[1], self.buffer[2]]) as u64;
                if statusheader.ts_overflow() {
                    assert!(self.buffer[0] & 0x10 != 0);
                    self.total_clk_cycles += 0x100000;
                }
                self.ts = self.total_clk_cycles + statusheader.ts() as u64;
                if self.capture_status {
                    assert!(!statusheader.status());
                    //println!("{:?}", statusheader);
                    assert_eq!(statusheader.ts() as u64, ts);
                    self.buffer.drain(0..self.capture_size);
                } else {
                    let dataheader = DataHeader(self.buffer.range(0..7).copied().collect::<Vec<u8>>());
                    assert_eq!(dataheader.ts() as u64, ts);
                    //println!("{:?}", dataheader);
                    let packet_len = u16::from_be_bytes(
                        [self.buffer[3] & 0x7, self.buffer[4]]) as usize;
                    //println!("be {}", packet_len);
                    assert_eq!(dataheader.size() as usize, packet_len);
                    self.buffer.drain(0..self.capture_size);
                    self.capture_size = dataheader.size() as usize - 7;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statusheader() {
        let data: [u8; 4] = [0x98, 0x76, 0x54, 0x32];
        let statusheader = StatusHeader(&data);

        println!("statusheader {:?}", statusheader);
        assert_eq!(statusheader.ts(), 0x87654);
    }
    #[test]
    fn test_dataheader() {
        let data: [u8; 7] = [0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc];
        let dataheader = DataHeader(&data);

        println!("dataheader {:?}", dataheader);
        assert_eq!(dataheader.ts(), 0x87654);
        assert_eq!(dataheader.size(), 0x210);
        assert_eq!(dataheader.duration(), 0xfedc);
    }
}
