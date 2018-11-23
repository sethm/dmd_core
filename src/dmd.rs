use bus::Bus;
use cpu::Cpu;
use rom_lo::LO_ROM;
use rom_hi::HI_ROM;
use err::BusError;
use err::CpuError;

#[derive(Debug)]
pub struct Dmd {
    cpu: Cpu,
    bus: Bus,
}

impl Dmd {
    pub fn new() -> Dmd {
        let cpu = Cpu::new();
        let bus = Bus::new(0x100000);
        let dmd = Dmd { cpu, bus };
        dmd
    }

    pub fn reset(&mut self) -> Result<(), BusError> {
        self.bus.load(0, &LO_ROM)?;
        self.bus.load(0x10000, &HI_ROM)?;
        self.cpu.reset(&mut self.bus)?;

        Ok(())
    }

    pub fn step(&mut self) {
        self.cpu.step(&mut self.bus);
    }

    pub fn step_with_error(&mut self) -> Result<(), CpuError> {
        self.cpu.step_with_error(&mut self.bus)
    }
}

#[cfg(test)]
mod tests {
    use dmd::Dmd;

    #[test]
    fn creates_dmd() {
        let mut dmd = Dmd::new();
        dmd.reset().unwrap();
    }
}