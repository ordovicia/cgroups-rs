#![cfg(target_os = "linux")]

mod error;
pub mod v1;

pub use error::{Error, ErrorKind, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pid {
    pid: u32, // Maximum PID is 2^15 on 32-bit systems, 2^22 on 64-bit systems
}

impl From<u32> for Pid {
    fn from(pid: u32) -> Self {
        Self { pid }
    }
}

impl From<&std::process::Child> for Pid {
    fn from(child: &std::process::Child) -> Self {
        Self { pid: child.id() }
    }
}

impl std::ops::Deref for Pid {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.pid
    }
}
