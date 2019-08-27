//! Operations on cgroups in a v1 hierarchy.
//!
//! Operations for each subsystem are implemented in each module. See [`cpu::Subsystem`] for
//! example. Currently this crate supports [CPU], [cpuset], [cpuacct], [memory], [pids], [devices],
//! [hugetlb], [net_cls], [net_prio], [blkio], [RDMA], [freezer], and [perf_event] subsystems.
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
//! [pids]: pids/index.html
//! [devices]: devices/index.html
//! [hugetlb]: hugetlb/index.html
//! [net_cls]: net_cls/index.html
//! [net_prio]: net_prio/index.html
//! [blkio]: blkio/index.html
//! [RDMA]: rdma/index.html
//! [freezer]: freezer/index.html
//! [perf_event]: perf_event/index.html
//!
//! [`Cgroup`]: trait.Cgroup.html
//! [`UnifiedRepr`]: struct.UnifiedRepr.html
//! [`Builder`]: builder/struct.Builder.html
//!
//! [Documentation/cgroup-v1/cgroups.txt]: https://www.kernel.org/doc/Documentation/cgroup-v1/cgroups.txt

use std::fmt;

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
/// `SubsystemKind` implements [`Display`]. The resulting string is a standard directory name for
/// the subsystem (e.g. `SubsystemKind::Cpu` => `cpu`).
///
/// ```
/// use cgroups::v1::SubsystemKind;
///
/// assert_eq!(SubsystemKind::Cpu.to_string(), "cpu");
/// assert_eq!(SubsystemKind::PerfEvent.to_string(), "perf_event");
/// ```
///
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
    /// pids subsystem.
    Pids,
    /// devices subsystem.
    Devices,
    /// hugetlb subsystem.
    HugeTlb,
    /// net_cls subsystem.
    NetCls,
    /// net_prio subsystem.
    NetPrio,
    /// blkio subsystem.
    BlkIo,
    /// RDMA subsystem.
    Rdma,
    /// freezer subsystem.
    Freezer,
    /// perf_event subsystem.
    PerfEvent,
}

// NOTE: What to do when adding a subsystem (and compiler doesn't tell you):
// - Implement builder if necessary
//   - Add to `builder::gen_subsystem_builder_call` arg`
// - Add to `cgroup::tests::test_cgroup_subsystem_kind`
// - Add to `mod.rs` doc

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
    /// Resource limit on how many processes this cgroup can have.
    pub pids: pids::Resources,
    /// Allow or deny this cgroup to perform specific accesses to devices.
    pub devices: devices::Resources,
    /// Resource limit no how many hugepage TLBs this cgroup can use.
    pub hugetlb: hugetlb::Resources,
    /// Tag network packets from this cgroup with a class ID.
    pub net_cls: net_cls::Resources,
    /// Priority map of traffic originating from this cgroup.
    pub net_prio: net_prio::Resources,
    /// Throttle bandwidth of block I/O by this cgroup.
    pub blkio: blkio::Resources,
    /// Resource limit on how much this cgroup can use RDMA/IB devices.
    pub rdma: rdma::Resources,
    /// Freeze tasks in this cgroup.
    pub freezer: freezer::Resources,
}

impl fmt::Display for SubsystemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Cpu => "cpu",
            Self::Cpuset => "cpuset",
            Self::Cpuacct => "cpuacct",
            Self::Memory => "memory",
            Self::Pids => "pids",
            Self::Devices => "devices",
            Self::HugeTlb => "hugetlb",
            Self::NetCls => "net_cls",
            Self::NetPrio => "net_prio",
            Self::BlkIo => "blkio",
            Self::Rdma => "rdma",
            Self::Freezer => "freezer",
            Self::PerfEvent => "perf_event",
        })
    }
}
