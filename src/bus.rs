#![allow(clippy::unreadable_literal)]

use crate::duart::Duart;
use crate::err::BusError;
use crate::mem::Mem;
use crate::mouse::Mouse;
use std::io::Write;
use std::{fmt::Debug, fs::OpenOptions};
use std::{fs::File, ops::Range};

const NVRAM_SIZE: usize = 8192;

/// Access Status Code
pub enum AccessCode {
    MoveTranslated,
    CoprDataWrite,
    AutoVectorIrqAck,
    CoprDataFetch,
    StopAck,
    CoprBroadcast,
    CoprStatusFetch,
    ReadInterlocked,
    AddressFetch,
    OperandFetch,
    Write,
    IrqAck,
    IfAfterPcDisc,
    InstrPrefetch,
    InstrFetch,
    NoOp,
}

/// A virtual device on the bus.
pub trait Device: Send + Sync + Debug {
    fn address_range(&self) -> &Range<usize>;
    fn name(&self) -> &str;
    fn is_read_only(&self) -> bool;
    fn read_byte(&mut self, address: usize, access: AccessCode) -> Result<u8, BusError>;
    fn read_half(&mut self, address: usize, access: AccessCode) -> Result<u16, BusError>;
    fn read_word(&mut self, address: usize, access: AccessCode) -> Result<u32, BusError>;
    fn write_byte(&mut self, address: usize, val: u8, access: AccessCode) -> Result<(), BusError>;
    fn write_half(&mut self, address: usize, val: u16, access: AccessCode) -> Result<(), BusError>;
    fn write_word(&mut self, address: usize, val: u32, access: AccessCode) -> Result<(), BusError>;
    fn load(&mut self, address: usize, data: &[u8]) -> Result<(), BusError>;
}

//
// Bus Memory Map
//
//  0x000000..0x01ffff     ROM
//  0x200000..0x20003f     DUART (Port A: host, Port B: keyboard/printer)
//  0x300000..0x3000ff     8530 SCC on optional I/O board
//  0x400000..0x400003     Mouse X/Y data
//  0x500000..0x500001     Display starting addr
//  0x600000..0x601fff     BBRAM (Non-volatile RAM)
//  0x700000..0x7fffff     RAM (256K or 1M)
//

pub struct Bus {
    rom: Mem,
    duart: Duart,
    mouse: Mouse,
    vid: Mem,   // TODO: Figure out what device this really is
    bbram: Mem, // TODO: change to BBRAM when implemented
    ram: Mem,
    trace_log: Option<File>,
}

impl Bus {
    pub fn new(mem_size: usize) -> Bus {
        Bus {
            rom: Mem::new(0, 0x20000, true),
            duart: Duart::new(),
            mouse: Mouse::new(),
            vid: Mem::new(0x500000, 0x2, false),
            bbram: Mem::new(0x600000, 0x2000, false),
            ram: Mem::new(0x700000, mem_size, false),
            trace_log: None,
        }
    }

    fn get_device(&mut self, address: usize) -> Result<&mut dyn Device, BusError> {
        if address < 0x20000 {
            return Ok(&mut self.rom);
        }

        if (0x200000..0x200040).contains(&address) {
            return Ok(&mut self.duart);
        }

        if (0x400000..0x400004).contains(&address) {
            return Ok(&mut self.mouse);
        }

        if (0x500000..0x500002).contains(&address) {
            return Ok(&mut self.vid);
        }

        if (0x600000..0x602000).contains(&address) {
            return Ok(&mut self.bbram);
        }

        if (0x700000..0x800000).contains(&address) {
            return Ok(&mut self.ram);
        }

        Err(BusError::NoDevice(address))
    }

    pub fn trace_on(&mut self, name: &str) -> std::io::Result<()> {
        let mut out = OpenOptions::new().create(true).write(true).open(name)?;
        writeln!(out, "TRACE START")?;
        self.trace_log = Some(out);
        Ok(())
    }

    pub fn trace_enabled(&self) -> bool {
        self.trace_log.is_some()
    }

    pub fn trace_off(&mut self) {
        self.trace_log = None;
    }

    pub fn trace(&mut self, step: u64, line: &str) {
        if let Some(trace_log) = &mut self.trace_log {
            let _ = writeln!(trace_log, "{:08}: {}", step, line);
        }
    }

    pub fn read_byte(&mut self, address: usize, access: AccessCode) -> Result<u8, BusError> {
        self.get_device(address)?.read_byte(address, access)
    }

    pub fn read_half(&mut self, address: usize, access: AccessCode) -> Result<u16, BusError> {
        if address & 1 != 0 {
            return Err(BusError::Alignment(address));
        }
        self.get_device(address)?.read_half(address, access)
    }

    pub fn read_word(&mut self, address: usize, access: AccessCode) -> Result<u32, BusError> {
        if address & 3 != 0 {
            return Err(BusError::Alignment(address));
        }
        self.get_device(address)?.read_word(address, access)
    }

    pub fn read_op_half(&mut self, address: usize) -> Result<u16, BusError> {
        let m = self.get_device(address)?;

        Ok(u16::from(m.read_byte(address, AccessCode::OperandFetch)?)
            | u16::from(m.read_byte(address + 1, AccessCode::OperandFetch)?).wrapping_shl(8))
    }

    pub fn read_op_word(&mut self, address: usize) -> Result<u32, BusError> {
        let m = self.get_device(address)?;

        Ok(u32::from(m.read_byte(address, AccessCode::OperandFetch)?)
            | u32::from(m.read_byte(address + 1, AccessCode::OperandFetch)?).wrapping_shl(8)
            | u32::from(m.read_byte(address + 2, AccessCode::OperandFetch)?).wrapping_shl(16)
            | u32::from(m.read_byte(address + 3, AccessCode::OperandFetch)?).wrapping_shl(24))
    }

    pub fn write_byte(&mut self, address: usize, val: u8) -> Result<(), BusError> {
        self.get_device(address)?.write_byte(address, val, AccessCode::Write)
    }

    pub fn write_half(&mut self, address: usize, val: u16) -> Result<(), BusError> {
        if address & 1 != 0 {
            return Err(BusError::Alignment(address));
        }
        self.get_device(address)?.write_half(address, val, AccessCode::Write)
    }

    pub fn write_word(&mut self, address: usize, val: u32) -> Result<(), BusError> {
        if address & 3 != 0 {
            return Err(BusError::Alignment(address));
        }
        self.get_device(address)?.write_word(address, val, AccessCode::Write)
    }

    pub fn load(&mut self, address: usize, data: &[u8]) -> Result<(), BusError> {
        self.get_device(address)?.load(address, data)
    }

    pub fn video_ram(&self) -> &[u8] {
        let vid_register = (u16::from(self.vid[0]) << 8 | u16::from(self.vid[1])) as usize;
        let start = vid_register * 4;
        let end = start + 0x19000;
        self.ram.as_slice(start..end)
    }

    pub fn service(&mut self) {
        self.duart.service();
    }

    pub fn get_interrupts(&mut self) -> Option<u8> {
        self.duart.get_interrupt()
    }

    pub fn mouse_move(&mut self, x: u16, y: u16) {
        self.mouse.x = x;
        self.mouse.y = y;
    }

    pub fn mouse_down(&mut self, button: u8) {
        self.duart.mouse_down(button);
    }

    pub fn mouse_up(&mut self, button: u8) {
        self.duart.mouse_up(button);
    }

    pub fn rs232_tx_poll(&mut self) -> Option<u8> {
        self.duart.rs232_tx_poll()
    }

    pub fn kb_tx_poll(&mut self) -> Option<u8> {
        self.duart.kb_tx_poll()
    }

    pub fn rx_char(&mut self, char: u8) {
        self.duart.rx_char(char);
    }

    pub fn rx_keyboard(&mut self, keycode: u8) {
        self.duart.rx_keyboard(keycode);
    }

    pub fn duart_output(&self) -> u8 {
        self.duart.output_port()
    }

    pub fn get_nvram(&self) -> &[u8] {
        self.bbram.as_slice(0..NVRAM_SIZE)
    }

    pub fn set_nvram(&mut self, nvram: &[u8]) {
        for (i, b) in nvram.iter().enumerate() {
            self.bbram[i] = *b;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_fail_on_alignment_errors() {
        let mut bus: Bus = Bus::new(0x10000);

        assert!(bus.write_byte(0x700000, 0x1f).is_ok());
        assert!(bus.write_half(0x700000, 0x1f1f).is_ok());
        assert!(bus.write_word(0x700000, 0x1f1f1f1f).is_ok());
        assert!(bus.write_half(0x700001, 0x1f1f).is_err());
        assert!(bus.write_half(0x700002, 0x1f1f).is_ok());
        assert!(bus.write_word(0x700001, 0x1f1f1f1f).is_err());
        assert!(bus.write_word(0x700002, 0x1f1f1f1f).is_err());
        assert!(bus.write_word(0x700003, 0x1f1f1f1f).is_err());
        assert!(bus.write_word(0x700004, 0x1f1f1f1f).is_ok());
    }
}
