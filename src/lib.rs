#![cfg(target_os = "linux")]
#![warn(missing_docs)]

//! Native Rust crate for operating on cgroups.
//!
//! Currently this crate supports only cgroup v1 hierarchy, implementes in [`v1`](v1/index.html) module.
//!
//! ## Examples for v1 hierarchy
//!
//! ### Create a cgroup controlled by the CPU subsystem
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! use std::path::PathBuf;
//! use cgroups::{Pid, v1::{cpu, Cgroup, CgroupPath, SubsystemKind, Resources}};
//!
//! // Define and create a new cgroup controlled by the CPU subsystem.
//! let name = PathBuf::from("my_cgroup");
//! let mut cgroup = cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, name));
//! cgroup.create()?;
//!
//! // Attach the self process to the cgroup.
//! let pid = Pid::from(std::process::id());
//! cgroup.add_task(pid)?;
//!
//! // Define resource limits and constraints for this cgroup.
//! // Here we just use the default (no limits and constraints) for an example.
//! let resources = Resources::default();
//!
//! // Apply the resource limits.
//! cgroup.apply(&resources, true)?;
//!
//! // Low-level file operations are also supported.
//! let stat_file = cgroup.open_file_read("cpu.stat")?;
//!
//! // do something ...
//!
//! // Now, remove self process from the cgroup.
//! cgroup.remove_task(pid)?;
//!
//! // And delete the cgroup.
//! cgroup.delete()?;
//!
//! // Note that cgroup handlers does not implement `Drop` and therefore when the
//! // handler is dropped, the cgroup will stay around.
//! # Ok(())
//! # }
//! ```
//!
//! ### Create a set of cgroups controlled by multiple subsystems
//!
//! `v1::Builder` provides a way to configure cgroups in the builder pattern.
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! use std::path::PathBuf;
//! use cgroups::v1::Builder;
//!
//! let mut cgroups =
//!     // Start building a (set of) cgroup(s).
//!     Builder::new(PathBuf::from("students/charlie"))
//!     // Start configurating the CPU resource limits.
//!     .cpu()
//!         .shares(1000)
//!         .cfs_quota(500 * 1000)
//!         .cfs_period(1000 * 1000)
//!         // Finish configurating the CPU resource limits.
//!         .done()
//!     // Actually build cgroups with the configuration.
//!     // Only create a directory for the CPU subsystem.
//!     .build(true)?;
//!
//! // Attach the self process to the cgroups.
//! let pid = std::process::id().into();
//! cgroups.add_task(pid)?;
//!
//! // do something ...
//!
//! // Remove self process from the cgroups.
//! cgroups.remove_task(pid)?;
//!
//! // And delete the cgroups.
//! cgroups.delete()?;
//!
//! // Note that cgroup handlers does not implement `Drop` and therefore when the
//! // handler is dropped, the cgroup will stay around.
//! # Ok(())
//! # }
//! ```

#[macro_use]
mod util;
mod error;
pub mod v1;

pub use error::{Error, ErrorKind, Result};

/// PID or thread ID for attaching a task in a cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
