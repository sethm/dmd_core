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
    ///
    /// Construct a new DMD Terminal
    ///
    pub fn new() -> Dmd {
        let cpu = Cpu::new();
        let bus = Bus::new(0x100000);
        Dmd {
            cpu,
            bus,
        }
    }

    ///
    /// Reset the terminal's CPU. This is equivalent to a hard power reset.
    ///
    pub fn reset(&mut self) -> Result<(), BusError> {
        self.bus.load(0, &LO_ROM)?;
        self.bus.load(0x10000, &HI_ROM)?;
        self.cpu.reset(&mut self.bus)?;

        Ok(())
    }

    ///
    /// Return a view of the terminal's Video Memory
    ///
    pub fn video_ram(&self) -> Result<&[u8], BusError> {
        self.bus.video_ram()
    }

    ///
    /// Return the contents of the CPU's Program Counter.
    ///
    pub fn get_pc(&self) -> u32 {
        self.cpu.get_pc()
    }

    ///
    /// Return the contents of the CPU's Argument Pointer.
    ///
    pub fn get_ap(&self) -> u32 {
        self.cpu.get_ap()
    }

    ///
    /// Return the contents of the CPU's Processor Status Word.
    ///
    pub fn get_psw(&self) -> u32 {
        self.cpu.get_psw()
    }

    ///
    /// Return the contents of a CPU register (0-15)
    ///
    pub fn get_register(&self, reg: u8) -> u32 {
        self.cpu.r[(reg & 0xf) as usize]
    }

    ///
    /// Read a word from the terminal's memory. NB: Address must be word aligned.
    ///
    pub fn read(&mut self, addr: usize) -> Option<u32> {
        match self.bus.read_word(addr, AccessCode::AddressFetch) {
            Ok(d) => Some(d),
            _ => None,
        }
    }

    ///
    /// Step the terminal's CPU one time, allowing the CPU's internal error and
    /// exception handling to take care of all error / exception types.
    ///
    pub fn step(&mut self) {
        self.cpu.step(&mut self.bus);
    }

    ///
    /// Step the terminal's CPU one time, returning any error that may have occured.
    /// Useful for debugging.
    ///
    pub fn step_with_error(&mut self) -> Result<(), CpuError> {
        self.cpu.step_with_error(&mut self.bus)
    }

    ///
    /// Poll for a character to transmit from the terminal to the host.
    ///
    pub fn tx_poll(&mut self) -> Option<u8> {
        self.bus.tx_poll()
    }

    ///
    /// Receive a character from the host to the terminal.
    ///
    pub fn rx_char(&mut self, character: u8) -> Result<(), DuartError> {
        self.bus.rx_char(character)
    }

    ///
    /// Receive a character from the keyboard to the terminal.
    ///
    pub fn rx_keyboard(&mut self, keycode: u8) -> Result<(), DuartError> {
        self.bus.rx_keyboard(keycode)
    }

    ///
    /// Check to see if the terminal is ready to receive a new character.
    ///
    pub fn rx_ready(&self) -> bool {
        self.bus.rx_ready()
    }

    ///
    /// Register a new mouse position with the terminal.
    ///
    pub fn mouse_move(&mut self, x: u16, y: u16) {
        self.bus.mouse_move(x, y);
    }

    ///
    /// Register a "mouse down" event with the terminal.
    pub fn mouse_down(&mut self, button: u8) {
        self.bus.mouse_down(button);
    }

    ///
    /// Register a "mouse up" event with the terminal.
    ///
    pub fn mouse_up(&mut self, button: u8) {
        self.bus.mouse_up(button);
    }

    ///
    /// Return the current state of the DUART's Output Port
    ///
    pub fn duart_output(&self) -> u8 {
        self.bus.duart_output()
    }

    ///
    /// Load NVRAM into the emulator
    ///
    pub fn set_nvram(&mut self, nvram: &[u8; 8192]) {
        self.bus.set_nvram(nvram);
    }

    ///
    /// Get NVRAM from the emulator
    ///
    pub fn get_nvram(&self) -> [u8; 8192] {
        self.bus.get_nvram()
    }
}

#[cfg(test)]
mod tests {
    use crate::dmd::Dmd;

    #[test]
    fn creates_dmd() {
        let mut dmd = Dmd::new();
        dmd.reset().unwrap();
    }

    #[test]
    fn loads_and_reads_nvram() {
        let mut dmd = Dmd::new();

        let mut to_load: [u8; 8192] = [0; 8192];
        to_load[0] = 0x5a;
        to_load[0xfff] = 0xa5;
        to_load[0x1fff] = 0xff;

        let old_nvram = dmd.get_nvram();

        assert_eq!(0, old_nvram[0]);
        assert_eq!(0, old_nvram[0xfff]);
        assert_eq!(0, old_nvram[0x1fff]);

        dmd.set_nvram(&to_load);

        let new_nvram = dmd.get_nvram();

        assert_eq!(0x5a, new_nvram[0]);
        assert_eq!(0xa5, new_nvram[0xfff]);
        assert_eq!(0xff, new_nvram[0x1fff]);
    }
}
