//! Operations on cgroups in a v1 hierarchy.
//!
//! See the kernel's documentation for more information about cgroup v1, found at
//! [Documentation/cgroup-v1/cgroups.txt](https://www.kernel.org/doc/Documentation/cgroup-v1/cgroups.txt).

use std::fmt;

pub mod builder;
mod cgroup;
pub mod cpu;
mod unified_repr;

pub use builder::Builder;
pub use cgroup::{Cgroup, CgroupPath};
pub use unified_repr::UnifiedRepr;

pub(crate) const CGROUPFS_MOUNT_POINT: &str = "/sys/fs/cgroup";

/// Kinds of subsystems that are now available in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubsystemKind {
    /// CPU subsystem.
    Cpu,
}

/// Resource limits and constraints that will be set on a cgroup.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// Resource limits about how a cgroup can use CPUs.
    pub cpu: cpu::Resources,
}

impl fmt::Display for SubsystemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SubsystemKind::*;

        match self {
            Cpu => write!(f, "cpu"),
        }
    }
}
