use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum CpuException {
    IllegalOpcode,
    InvalidDescriptor
}

impl fmt::Display for CpuException {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CpuException::IllegalOpcode => write!(f, "Illegal Opcode"),
            CpuException::InvalidDescriptor => write!(f, "Invalid Descriptor"),
        }
    }
}

impl Error for CpuException {
    fn description(&self) -> &str {
        match *self {
            CpuException::IllegalOpcode => "illegal opcode",
            CpuException::InvalidDescriptor => "invalid descriptor",
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            CpuException::IllegalOpcode => None,
            CpuException::InvalidDescriptor => None,
        }
    }
}

#[derive(Debug)]
pub enum BusError {
    Init,
    Read,
    Write,
    NoDevice,
    Range,
    Permission,
    Alignment,
}

impl fmt::Display for BusError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BusError::Init => write!(f, "Could not initialize bus"),
            BusError::Read => write!(f, "Could not read from bus"),
            BusError::Write => write!(f, "Could not write to bus"),
            BusError::NoDevice => write!(f, "No device at address"),
            BusError::Range => write!(f, "Address out of range"),
            BusError::Permission => write!(f, "Invalid permission"),
            BusError::Alignment => write!(f, "Memory Alignment"),
        }
    }
}

impl Error for BusError {
    fn description(&self) -> &str {
        match *self {
            BusError::Init => "initialize",
            BusError::Read => "read",
            BusError::Write => "store",
            BusError::NoDevice => "no device",
            BusError::Range => "out of range",
            BusError::Permission => "invalid permission",
            BusError::Alignment => "alignment",
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            BusError::Init => None,
            BusError::Read => None,
            BusError::Write => None,
            BusError::NoDevice => None,
            BusError::Range => None,
            BusError::Permission => None,
            BusError::Alignment => None,
        }
    }
}

#[derive(Debug)]
pub enum CpuError {
    Exception(CpuException),
    Bus(BusError),
}

impl fmt::Display for CpuError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CpuError::Exception(ref e) => e.fmt(f),
            CpuError::Bus(ref e) => e.fmt(f),
        }
    }
}

impl Error for CpuError {
    fn description(&self) -> &str {
        match *self {
            CpuError::Exception(ref e) => e.description(),
            CpuError::Bus(ref e) => e.description(),
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            CpuError::Exception(ref e) => Some(e),
            CpuError::Bus(ref e) => Some(e),
        }
    }
}

impl From<CpuException> for CpuError {
    fn from(err: CpuException) -> CpuError {
        CpuError::Exception(err)
    }
}
impl From<BusError> for CpuError {
    fn from(err: BusError) -> CpuError {
        CpuError::Bus(err)
    }
}
