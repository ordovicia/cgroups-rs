//! Operations on cgroups in a v1 hierarchy.
//!
//! For more information about cgroup v1, see the kernel's documentation
//! [Documentation/cgroup-v1/cgroups.txt](https://www.kernel.org/doc/Documentation/cgroup-v1/cgroups.txt).
//!
//! Operations for each subsystem are implemented in each module. See [`cpu::Subsystem`] for
//! example. Currently this crate supports [CPU], [cpuset], [cpuacct], [pids], [hugetlb], [net_cls],
//! [net_prio], [freezer], and [perf_event] subsystems.
//!
//! [`Cgroup`] trait defines the common operations on a cgroup. Each subsystem handler implements
//! this trait and subsystem-specific operations.
//!
//! [`UnifiedRepr`] provides an access to a set of cgroups in the v1 hierarchies as if it is in the
//! v2 hierarchy.
//!
//! [`Builder`] allows you to configure a cgroup in the builder pattern.
//!
//! [`cpu::Subsystem`]: cpu/struct.Subsystem.html
//! [CPU]: cpu/index.html
//! [cpuset]: cpuset/index.html
//! [cpuacct]: cpuacct/index.html
//! [pids]: pids/index.html
//! [hugetlb]: hugetlb/index.html
//! [net_cls]: net_cls/index.html
//! [net_prio]: net_prio/index.html
//! [freezer]: freezer/index.html
//! [perf_event]: perf_event/index.html
//!
//! [`Cgroup`]: trait.Cgroup.html
//! [`UnifiedRepr`]: struct.UnifiedRepr.html
//! [`Builder`]: builder/struct.Builder.html

use std::fmt;

#[macro_use]
mod cgroup;
pub mod builder;
pub mod cpu;
pub mod cpuacct;
pub mod cpuset;
pub mod freezer;
pub mod hugetlb;
pub mod net_cls;
pub mod net_prio;
pub mod perf_event;
pub mod pids;
mod unified_repr;

pub use builder::Builder;
pub use cgroup::{Cgroup, CgroupPath};
pub use unified_repr::UnifiedRepr;

pub(crate) const CGROUPFS_MOUNT_POINT: &str = "/sys/fs/cgroup";

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubsystemKind {
    /// CPU subsystem.
    Cpu,
    /// cpuset subsystem.
    Cpuset,
    /// cpuacct (CPU accounting) subsystem.
    Cpuacct,
    /// pids subsystem.
    Pids,
    /// hugetlb subsystem.
    HugeTlb,
    /// net_cls subsystem.
    NetCls,
    /// net_prio subsystem.
    NetPrio,
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

/// Resource limits and constraints that will be set to a cgroup.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// Resource limit on how much CPU time this cgroup can use.
    pub cpu: cpu::Resources,
    /// Resource limit on which CPUs and which memory nodes this cgroup can use, and how they are
    /// controlled by the system.
    pub cpuset: cpuset::Resources,
    /// Resource limit on how many processes this cgroup can have.
    pub pids: pids::Resources,
    /// Resource limit no how many hugepage TLBs this cgroup can use.
    pub hugetlb: hugetlb::Resources,
    /// Tag network packets from this cgroup with a class ID.
    pub net_cls: net_cls::Resources,
    /// Priority map of traffic originating from this cgroup.
    pub net_prio: net_prio::Resources,
    /// Whether tasks in this cgroup is freezed.
    pub freezer: freezer::Resources,
}

impl fmt::Display for SubsystemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SubsystemKind::*;

        match self {
            Cpu => write!(f, "cpu"),
            Cpuset => write!(f, "cpuset"),
            Cpuacct => write!(f, "cpuacct"),
            Pids => write!(f, "pids"),
            HugeTlb => write!(f, "hugetlb"),
            NetCls => write!(f, "net_cls"),
            NetPrio => write!(f, "net_prio"),
            Freezer => write!(f, "freezer",),
            PerfEvent => write!(f, "perf_event",),
        }
    }
}
