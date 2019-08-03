#![cfg(target_os = "linux")]
#![warn(missing_docs)]

//! Native Rust crate for operating on cgroups.
//!
//! TODO

#[macro_use]
mod util;
mod error;
pub mod v1;

pub use error::{Error, ErrorKind, Result};

/// PID for attaching a task in a cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pid(u32); // Max PID is 2^15 on 32-bit systems, 2^22 on 64-bit systems
                     // TODO: Is this true for thread IDs?

impl From<u32> for Pid {
    fn from(pid: u32) -> Self {
        Self(pid)
    }
}

impl From<&std::process::Child> for Pid {
    fn from(child: &std::process::Child) -> Self {
        Self(child.id())
    }
}

impl std::ops::Deref for Pid {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
