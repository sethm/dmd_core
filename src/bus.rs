use crate::err::BusError;
use crate::mem::Mem;
use crate::duart::Duart;
use crate::mouse::Mouse;
use crate::err::DuartError;
use std::fmt::Debug;
use std::ops::Range;

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
    IFAfterPCDisc,
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
    scc: Mem,      // TODO: Remove
    mouse: Mouse,
    vid: Mem,      // TODO: Figure out what device this really is
    bbram: Mem,    // TODO: change to BBRAM when implemented
    ram: Mem,
}

impl Bus {
    pub fn new(mem_size: usize) -> Bus {
        Bus {
            rom: Mem::new(0, 0x20000, true),
            duart: Duart::new(),
            scc: Mem::new(0x300000, 0x100, false),
            mouse: Mouse::new(),
            vid: Mem::new(0x500000, 0x2, false),
            bbram: Mem::new(0x600000, 0x2000, false),
            ram: Mem::new(0x700000, mem_size, false),
        }
    }

    fn get_device(&mut self, address: usize) -> Result<&mut Device, BusError> {
        if address < 0x20000 {
            return Ok(&mut self.rom);
        }

        if address >= 0x200000 && address < 0x200040 {
            return Ok(&mut self.duart);
        }

        if address >= 0x300000 && address < 0x300100 {
            return Ok(&mut self.scc);
        }

        if address >= 0x400000 && address < 0x400004 {
            return Ok(&mut self.mouse);
        }

        if address >= 0x500000 && address < 0x500002 {
            return Ok(&mut self.vid);
        }

        if address >= 0x600000 && address < 0x602000 {
            return Ok(&mut self.bbram);
        }

        if address >= 0x700000 && address < 0x800000 {
            return Ok(&mut self.ram);
        }

        Err(BusError::NoDevice(address as u32))
    }

    pub fn read_byte(&mut self, address: usize, access: AccessCode) -> Result<u8, BusError> {
        self.get_device(address)?.read_byte(address, access)
    }

    pub fn read_half(&mut self, address: usize, access: AccessCode) -> Result<u16, BusError> {
        if address & 1 != 0 {
            return Err(BusError::Alignment);
        }
        self.get_device(address)?.read_half(address, access)
    }

    pub fn read_word(&mut self, address: usize, access: AccessCode) -> Result<u32, BusError> {
        if address & 3 != 0 {
            return Err(BusError::Alignment);
        }
        self.get_device(address)?.read_word(address, access)
    }

    pub fn read_op_half(&mut self, address: usize) -> Result<u16, BusError> {
        let m = self.get_device(address)?;

        Ok((m.read_byte(address, AccessCode::OperandFetch)? as u16)
            | (m.read_byte(address + 1, AccessCode::OperandFetch)? as u16).wrapping_shl(8))
    }

    pub fn read_op_word(&mut self, address: usize) -> Result<u32, BusError> {
        let m = self.get_device(address)?;

        Ok((m.read_byte(address, AccessCode::OperandFetch)? as u32)
            | (m.read_byte(address + 1, AccessCode::OperandFetch)? as u32).wrapping_shl(8)
            | (m.read_byte(address + 2, AccessCode::OperandFetch)? as u32).wrapping_shl(16)
            | (m.read_byte(address + 3, AccessCode::OperandFetch)? as u32).wrapping_shl(24))
    }

    pub fn write_byte(&mut self, address: usize, val: u8) -> Result<(), BusError> {
        self.get_device(address)?.write_byte(address, val, AccessCode::Write)
    }

    pub fn write_half(&mut self, address: usize, val: u16) -> Result<(), BusError> {
        if address & 1 != 0 {
            return Err(BusError::Alignment);
        }
        self.get_device(address)?.write_half(address, val, AccessCode::Write)
    }

    pub fn write_word(&mut self, address: usize, val: u32) -> Result<(), BusError> {
        if address & 3 != 0 {
            return Err(BusError::Alignment);
        }
        self.get_device(address)?.write_word(address, val, AccessCode::Write)
    }

    pub fn load(&mut self, address: usize, data: &[u8]) -> Result<(), BusError> {
        self.get_device(address)?.load(address, data)
    }

    pub fn video_ram(&self) -> Result<&[u8], BusError> {
        self.ram.as_slice(0x0..0x19000)
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

    pub fn tx_poll(&mut self) -> Option<u8> {
        self.duart.tx_poll()
    }

    pub fn rx_char(&mut self, char: u8) -> Result<(), DuartError> {
        self.duart.rx_char(char)
    }

    pub fn rx_keyboard(&mut self, keycode: u8) -> Result<(), DuartError> {
        self.duart.rx_keyboard(keycode)
    }

    pub fn rx_ready(&self) -> bool {
        self.duart.rx_ready()
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
