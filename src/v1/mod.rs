use std::fmt;

mod cgroup;
pub mod cpu;
mod unified_repr;

pub use cgroup::{Cgroup, CgroupPath};
pub use unified_repr::UnifiedRepr;

pub(crate) const CGROUPFS_MOUNT_POINT: &str = "/sys/fs/cgroup";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubsystemKind {
    Cpu,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
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
