use crate::bus::{Bus, AccessCode};
use crate::cpu::Cpu;
use crate::err::BusError;
use crate::err::CpuError;
use crate::rom_hi::HI_ROM;
use crate::rom_lo::LO_ROM;
use crate::err::DuartError;

pub struct Dmd {
    cpu: Cpu,
    bus: Bus,
}

impl Dmd {
    pub fn new<CB: 'static + FnMut(u8) + Send + Sync>(tx_callback: CB) -> Dmd {
        let cpu = Cpu::new();
        let bus = Bus::new(0x100000, tx_callback);
        Dmd {
            cpu,
            bus,
        }
    }

    pub fn reset(&mut self) -> Result<(), BusError> {
        self.bus.load(0, &LO_ROM)?;
        self.bus.load(0x10000, &HI_ROM)?;
        self.cpu.reset(&mut self.bus)?;

        Ok(())
    }

    pub fn video_ram(&self) -> Result<&[u8], BusError> {
        self.bus.video_ram()
    }

    pub fn step(&mut self) {
        self.cpu.step(&mut self.bus);
    }

    pub fn get_pc(&self) -> u32 {
        self.cpu.get_pc()
    }

    pub fn get_ap(&self) -> u32 {
        self.cpu.get_ap()
    }

    pub fn get_psw(&self) -> u32 {
        self.cpu.get_psw()
    }

    pub fn get_register(&self, reg: u8) -> u32 {
        self.cpu.r[reg as usize]
    }

    pub fn read(&mut self, addr: usize) -> Option<u32> {
        match self.bus.read_word(addr, AccessCode::AddressFetch) {
            Ok(d) => Some(d),
            _ => None,
        }
    }

    pub fn step_with_error(&mut self) -> Result<(), CpuError> {
        self.cpu.step_with_error(&mut self.bus)
    }

    pub fn rx_char(&mut self, character: u8) -> Result<(), DuartError> {
        self.bus.rx_char(character)
    }

    pub fn rx_ready(&self) -> bool {
        self.bus.rx_ready()
    }

    pub fn keyboard(&mut self, keycode: u8) {
        self.bus.keyboard(keycode);
    }

    pub fn mouse_move(&mut self, x: u16, y: u16) {
        self.bus.mouse_move(x, y);
    }

    pub fn mouse_down(&mut self, button: u8) {
        self.bus.mouse_down(button);
    }

    pub fn mouse_up(&mut self, button: u8) {
        self.bus.mouse_up(button);
    }
}

#[cfg(test)]
mod tests {
    use crate::dmd::Dmd;

    fn tx_callback(_char: u8) {}

    #[test]
    fn creates_dmd() {
        let mut dmd = Dmd::new(tx_callback);
        dmd.reset().unwrap();
    }
}
