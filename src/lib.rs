#[macro_use]
mod macros;

pub mod bus;
pub mod cpu;
pub mod dmd;
pub mod err;
pub mod instr;
pub mod mem;
pub mod duart;
pub mod mouse;
pub mod rom_hi;
pub mod rom_lo;

#[macro_use]
extern crate lazy_static;

use std::time::Instant;

lazy_static! {
    pub static ref START_TIME: Instant = Instant::now();
}