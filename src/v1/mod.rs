//! Operations on cgroups in a v1 hierarchy.
//!
//! Operations for each subsystem are implemented in each module. See [`cpu::Subsystem`] for
//! example. Currently this crate supports [CPU], [cpuset], [cpuacct], [memory], [hugetlb],
//! [devices], [blkio], [RDMA], [net_prio], [net_cls], [pids], [freezer], and [perf_event]
//! subsystems.
//!
//! [`Cgroup`] trait defines the common operations on a cgroup. Each subsystem handler implements
//! this trait and subsystem-specific operations.
//!
//! [`UnifiedRepr`] provides an access to a set of cgroups in the v1 hierarchies as if it is in a v2
//! hierarchy.
//!
//! [`Builder`] provides a way to configure a set of cgroups in the builder pattern.
//!
//! For more information about cgroup v1, see the kernel's documentation
//! [Documentation/cgroup-v1/cgroups.txt].
//!
//! [`cpu::Subsystem`]: cpu/struct.Subsystem.html
//! [CPU]: cpu/index.html
//! [cpuset]: cpuset/index.html
//! [cpuacct]: cpuacct/index.html
//! [memory]: memory/index.html
//! [hugetlb]: hugetlb/index.html
//! [devices]: devices/index.html
//! [blkio]: blkio/index.html
//! [RDMA]: rdma/index.html
//! [net_prio]: net_prio/index.html
//! [net_cls]: net_cls/index.html
//! [pids]: pids/index.html
//! [freezer]: freezer/index.html
//! [perf_event]: perf_event/index.html
//!
//! [`Cgroup`]: trait.Cgroup.html
//! [`UnifiedRepr`]: struct.UnifiedRepr.html
//! [`Builder`]: builder/struct.Builder.html
//!
//! [Documentation/cgroup-v1/cgroups.txt]: https://www.kernel.org/doc/Documentation/cgroup-v1/cgroups.txt

use std::{fmt, path::Path};

#[macro_use]
mod macros;

#[macro_use]
mod cgroup;
pub mod blkio;
pub mod builder;
pub mod cpu;
pub mod cpuacct;
pub mod cpuset;
pub mod devices;
pub mod freezer;
pub mod hugetlb;
pub mod memory;
pub mod net_cls;
pub mod net_prio;
pub mod perf_event;
pub mod pids;
pub mod rdma;
mod unified_repr;

pub use builder::Builder;
pub use cgroup::{Cgroup, CgroupPath};
pub use unified_repr::UnifiedRepr;

const CGROUPFS_MOUNT_POINT: &str = "/sys/fs/cgroup";

/// Kinds of subsystems that are now available in this crate.
///
/// `SubsystemKind` implements [`AsRef`]`<`[`Path`]`>` and [`Display`]. The resulting path or string
/// is a standard directory name for the subsystem (e.g. `SubsystemKind::Cpu` => `cpu`).
///
/// ```
/// use std::path::Path;
/// use controlgroup::v1::SubsystemKind;
///
/// assert_eq!(SubsystemKind::Cpu.as_ref(), Path::new("cpu"));
/// assert_eq!(SubsystemKind::Memory.as_ref(), Path::new("memory"));
///
/// assert_eq!(SubsystemKind::Devices.to_string(), "devices");
/// assert_eq!(SubsystemKind::PerfEvent.to_string(), "perf_event");
/// ```
///
/// [`AsRef`]: https://doc.rust-lang.org/std/convert/trait.AsRef.html
/// [`Path`]: https://doc.rust-lang.org/std/path/struct.Path.html
/// [`Display`]: https://doc.rust-lang.org/std/fmt/trait.Display.html
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubsystemKind {
    /// CPU subsystem.
    Cpu,
    /// cpuset subsystem.
    Cpuset,
    /// cpuacct (CPU accounting) subsystem.
    Cpuacct,
    /// memory subsystem.
    Memory,
    /// hugetlb subsystem.
    HugeTlb,
    /// devices subsystem.
    Devices,
    /// blkio subsystem.
    BlkIo,
    /// RDMA subsystem.
    Rdma,
    /// net_prio subsystem.
    NetPrio,
    /// net_cls subsystem.
    NetCls,
    /// pids subsystem.
    Pids,
    /// freezer subsystem.
    Freezer,
    /// perf_event subsystem.
    PerfEvent,
}

/// Compound of resource limits and constraints for each subsystem.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// Resource limit on how much CPU time this cgroup can use.
    pub cpu: cpu::Resources,
    /// Resource limit on which CPUs and memory nodes this cgroup can use, and how they are
    /// controlled by the system.
    pub cpuset: cpuset::Resources,
    /// Resource limit on what amount and how this cgroup can use memory.
    pub memory: memory::Resources,
    /// Resource limit no how many hugepage TLBs this cgroup can use.
    pub hugetlb: hugetlb::Resources,
    /// Allow or deny this cgroup to perform specific accesses to devices.
    pub devices: devices::Resources,
    /// Throttle bandwidth of block I/O by this cgroup.
    pub blkio: blkio::Resources,
    /// Resource limit on how much this cgroup can use RDMA/IB devices.
    pub rdma: rdma::Resources,
    /// Priority map of traffic originating from this cgroup.
    pub net_prio: net_prio::Resources,
    /// Tag network packets from this cgroup with a class ID.
    pub net_cls: net_cls::Resources,
    /// Resource limit on how many processes this cgroup can have.
    pub pids: pids::Resources,
    /// Freeze tasks in this cgroup.
    pub freezer: freezer::Resources,
}

impl AsRef<Path> for SubsystemKind {
    fn as_ref(&self) -> &Path {
        Path::new(self.as_str())
    }
}

impl fmt::Display for SubsystemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl SubsystemKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Cpuset => "cpuset",
            Self::Cpuacct => "cpuacct",
            Self::Memory => "memory",
            Self::HugeTlb => "hugetlb",
            Self::Devices => "devices",
            Self::BlkIo => "blkio",
            Self::Rdma => "rdma",
            Self::NetPrio => "net_prio",
            Self::NetCls => "net_cls",
            Self::Pids => "pids",
            Self::Freezer => "freezer",
            Self::PerfEvent => "perf_event",
        }
    }
}
