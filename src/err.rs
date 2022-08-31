use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum CpuException {
    IllegalOpcode,
    InvalidDescriptor,
    PrivilegedOpcode,
    IntegerZeroDivide,
}

impl fmt::Display for CpuException {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CpuException::IllegalOpcode => write!(f, "Illegal Opcode"),
            CpuException::InvalidDescriptor => write!(f, "Invalid Descriptor"),
            CpuException::PrivilegedOpcode => write!(f, "Privileged Opcode"),
            CpuException::IntegerZeroDivide => write!(f, "Integer Zero Divide"),
        }
    }
}

impl Error for CpuException {
    fn cause(&self) -> Option<&dyn Error> {
        match *self {
            CpuException::IllegalOpcode => None,
            CpuException::InvalidDescriptor => None,
            CpuException::PrivilegedOpcode => None,
            CpuException::IntegerZeroDivide => None,
        }
    }
}

#[derive(Debug)]
pub enum BusError {
    Init,
    Read(usize),
    Write(usize),
    NoDevice(usize),
    Range,
    Permission,
    Alignment(usize),
}

impl fmt::Display for BusError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BusError::Init => write!(f, "Could not initialize bus"),
            BusError::Read(addr) => write!(f, "Could not read from bus at address {:x}", addr),
            BusError::Write(addr) => write!(f, "Could not write to bus at address {:x}", addr),
            BusError::NoDevice(addr) => write!(f, "No device at address {:x}", addr),
            BusError::Range => write!(f, "Address out of range"),
            BusError::Permission => write!(f, "Invalid permission"),
            BusError::Alignment(addr) => write!(f, "Memory Alignment at address {:08x}", addr),
        }
    }
}

impl Error for BusError {
    fn cause(&self) -> Option<&dyn Error> {
        match *self {
            BusError::Init => None,
            BusError::Read(_) => None,
            BusError::Write(_) => None,
            BusError::NoDevice(_) => None,
            BusError::Range => None,
            BusError::Permission => None,
            BusError::Alignment(_) => None,
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
    fn cause(&self) -> Option<&dyn Error> {
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
