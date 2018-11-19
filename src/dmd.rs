use bus::Bus;
use cpu::Cpu;
use rom_lo::LO_ROM;
use rom_hi::HI_ROM;
use err::*;

#[allow(dead_code)]
pub struct Dmd<'a> {
    bus: Bus<'a>,
    cpu: Cpu<'a>,
}

#[allow(dead_code)]
impl<'a> Dmd<'a> {
    pub fn new() -> Dmd<'a> {
        let cpu = Cpu::new();
        let bus = Bus::new(0x20000);
        Dmd { cpu, bus }
    }

    pub fn reset(&mut self) -> Result<(), BusError> {
        self.bus.load(0, &LO_ROM)?;
        self.bus.load(0x10000, &HI_ROM)?;
        self.cpu.reset(&mut self.bus)?;

        Ok(())
    }

}
