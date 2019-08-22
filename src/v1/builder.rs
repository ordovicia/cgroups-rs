//! Configuring cgroups using the builder pattern.
//!
//! [`Builder`] struct is the entry point of the pattern. See its documentation.
//!
//! [`Builder`]: struct.Builder.html

use std::{collections::HashMap, path::PathBuf};

use crate::{
    v1::{cpuset, devices, hugetlb, net_cls, rdma, Resources, SubsystemKind, UnifiedRepr},
    Max, Result,
};

// NOTE: Keep the example below in sync with README.md and lib.rs

/// Cgroup builder.
///
/// By using `Builder`, you can configure a (set of) cgroup(s) in the builder pattern. This
/// builder creates directories for the cgroups, but only for the configured subsystems. e.g. If
/// you call only [`cpu`], only one cgroup directory is created for the CPU subsystem.
///
/// ```no_run
/// # fn main() -> cgroups::Result<()> {
/// use std::{collections::HashMap, path::PathBuf};
/// use cgroups::{Max, v1::{cpuset, devices, hugetlb, net_cls, pids, rdma, Builder}};
///
/// let mut cgroups =
///     // Start building a (set of) cgroup(s).
///     Builder::new(PathBuf::from("students/charlie"))
///     // Start configuring the CPU resource limits.
///     .cpu()
///         .shares(1000)
///         .cfs_quota_us(500 * 1000)
///         .cfs_period_us(1000 * 1000)
///         // Finish configuring the CPU resource limits.
///         .done()
///     // Start configuring the cpuset resource limits.
///     .cpuset()
///         .cpus([0].iter().copied().collect())
///         .mems([0].iter().copied().collect())
///         .memory_migrate(true)
///         .done()
///     .pids()
///         .max(Max::<u32>::Limit(42))
///         .done()
///     .devices()
///         .deny(vec!["a *:* rwm".parse::<devices::Access>().unwrap()])
///         .allow(vec!["c 1:3 mr".parse::<devices::Access>().unwrap()])
///         .done()
///     .hugetlb()
///         .limit_2mb(hugetlb::Limit::Pages(4))
///         .limit_1gb(hugetlb::Limit::Pages(2))
///         .done()
///     .net_cls()
///         .classid(net_cls::ClassId { major: 0x10, minor: 0x1 })
///         .done()
///     .net_prio()
///         .ifpriomap(
///             [("lo".to_string(), 0), ("wlp1s0".to_string(), 1)]
///                 .iter()
///                 .cloned()
///                 .collect(),
///         )
///         .done()
///     .rdma()
///         .max(
///             [(
///                 "mlx4_0".to_string(),
///                 rdma::Limit {
///                     hca_handle: Max::<u32>::Limit(2),
///                     hca_object: Max::<u32>::Max,
///                 },
///             )]
///                 .iter()
///                 .cloned()
///                 .collect(),
///         )
///         .done()
///     // Enable monitoring this cgroup via `perf` tool.
///     .perf_event()
///         // perf_event subsystem has no parameter, so this method does not
///         // return a subsystem builder, just enables the monitoring.
///     // Actually build cgroups with the configuration.
///     // Only create a directory for the CPU, cpuset, and pids subsystems.
///     .build()?;
///
/// let pid = std::process::id().into();
/// cgroups.add_task(pid)?;
///
/// // Do something ...
///
/// cgroups.remove_task(pid)?;
/// cgroups.delete()?;
/// # Ok(())
/// # }
/// ```
///
/// Note that calling the same method of the same subsystem builder twice overrides the previous
/// configuration if set.
///
/// ```no_run
/// # fn main() -> cgroups::Result<()> {
/// # use std::path::PathBuf;
/// # use cgroups::v1::Builder;
/// let mut cgroups = Builder::new(PathBuf::from("students/charlie"))
///     .cpu()
///         .shares(1000)
///         .shares(2000)   // Override.
///         .done()
///     .build()?;
///
/// assert_eq!(cgroups.cpu().unwrap().shares()?, 2000);
/// # Ok(())
/// # }
/// ```
///
/// But building the same subsystem twice does not reset the subsystem configuration.
///
/// ```no_run
/// # fn main() -> cgroups::Result<()> {
/// # use std::path::PathBuf;
/// # use cgroups::v1::Builder;
/// let mut cgroups = Builder::new(PathBuf::from("students/charlie"))
///     .cpu()
///         .shares(1000)
///         .done()
///     .cpu()  // Not reset shares.
///         .cfs_quota_us(500 * 1000)
///         .cfs_period_us(1000 * 1000)
///         .done()
///     .build()?;
///
/// assert_eq!(cgroups.cpu().unwrap().shares()?, 1000);
/// # Ok(())
/// # }
/// ```
///
/// [`cpu`]: struct.Builder.html#method.cpu
#[derive(Debug)]
pub struct Builder {
    name: PathBuf,
    subsystem_kinds: Vec<SubsystemKind>,
    resources: Resources,
}

macro_rules! gen_subsystem_builder_call {
    ( $( ($subsystem: ident, $kind: ident, $builder: ident, $name: literal) ),* ) => { $(
        with_doc! {
            concat!("Starts configuring the ", $name, " subsystem."),
            pub fn $subsystem(mut self) -> $builder {
                self.subsystem_kinds.push(SubsystemKind::$kind);
                $builder { builder: self }
            }
        }
    )* }
}

impl Builder {
    /// Creates a new cgroup builder.
    ///
    /// The resulting (set of) cgroup(s) will have the given name. For the directory name of each
    /// subsystem, the standard name (e.g. `cpu` for the CPU subsystem) is used.
    pub fn new(name: PathBuf) -> Self {
        Self {
            name,
            subsystem_kinds: Vec::new(),
            resources: Resources::default(),
        }
    }

    gen_subsystem_builder_call! {
        (cpu, Cpu, CpuBuilder, "CPU"),
        (cpuset, Cpuset, CpusetBuilder, "cpuset"),
        (pids, Pids, PidsBuilder, "pids"),
        (devices, Devices, DevicesBuilder, "devices"),
        (hugetlb, HugeTlb, HugeTlbBuilder, "hugetlb"),
        (net_cls, NetCls, NetClsBuilder, "net_cls"),
        (net_prio, NetPrio, NetPrioBuilder, "net_prio"),
        (rdma, Rdma, RdmaBuilder, "rdma")
    }

    // Calling `cpu()` twice will push duplicated `SubsystemKind::Cpu`, but it is not a problem for
    // `UnifiedRepr::with_subsystems()`.

    /// Enables monitoring this cgroup via `perf` tool.
    pub fn perf_event(mut self) -> Self {
        self.subsystem_kinds.push(SubsystemKind::PerfEvent);
        self
    }

    /// Builds a (set of) cgroup(s) with the configuration.
    ///
    /// This method creates directories for the cgroups, but only for the configured subsystems.
    /// i.e. if you called only `cpu`, only one cgroup directory is created for the CPU subsystem.
    pub fn build(self) -> Result<UnifiedRepr> {
        let mut unified_repr = UnifiedRepr::with_subsystems(self.name, &self.subsystem_kinds);
        unified_repr.create()?;
        unified_repr.apply(&self.resources)?;
        Ok(unified_repr)
    }
}

macro_rules! gen_setter_opt {
    ($subsystem: ident; $resource: ident, $ty: ty, $desc: literal) => { with_doc! {
        concat!(
"Sets ", $desc, ".

See [`", stringify!($subsystem), "::Subsystem::set_", stringify!($resource), "`](../", stringify!($subsystem), "/struct.Subsystem.html#method.set_", stringify!($resource), ")
for more information."
),
        pub fn $resource(mut self, $resource: $ty) -> Self {
            self.builder.resources.$subsystem.$resource = Some($resource);
            self
        }
    } };
}

macro_rules! gen_setter {
    ($subsystem: ident; $resource: ident, $ty: ty, $desc: literal) => { with_doc! {
        concat!(
"Sets ", $desc, ".

See [`", stringify!($subsystem), "::Subsystem::set_", stringify!($resource), "`](../", stringify!($subsystem), "/struct.Subsystem.html#method.set_", stringify!($resource), ")
for more information."
),
        pub fn $resource(mut self, $resource: $ty) -> Self {
            self.builder.resources.$subsystem.$resource = $resource;
            self
        }
    } };
}

/// CPU subsystem builder.
///
/// This struct is created by [`Builder::cpu`](struct.Builder.html#method.cpu) method.
#[derive(Debug)]
pub struct CpuBuilder {
    builder: Builder,
}

impl CpuBuilder {
    gen_setter_opt!(cpu; shares, u64, "CPU time shares");

    gen_setter_opt!(
        cpu;
        cfs_period_us,
        u64,
        "length of period (in microseconds)"
    );

    gen_setter_opt!(
        cpu;
        cfs_quota_us,
        i64,
        "total available CPU time within a period (in microseconds)"
    );

    /// Finishes configuring this CPU subsystem.
    pub fn done(self) -> Builder {
        self.builder
    }
}

/// cpuset subsystem builder.
///
/// This struct is created by [`Builder::cpuset`](struct.Builder.html#method.cpuset) method.
#[derive(Debug)]
pub struct CpusetBuilder {
    builder: Builder,
}

impl CpusetBuilder {
    gen_setter_opt!(
        cpuset;
        cpus,
        cpuset::IdSet,
        "a set of Cpus on which task in this cgroup can run"
    );

    gen_setter_opt!(
        cpuset;
        mems,
        cpuset::IdSet,
        "a set of memory nodes which tasks in this cgroup can use"
    );
    gen_setter_opt!(
        cpuset;
        memory_migrate,
        bool,
        "whether the memory used by tasks in this cgroup should beb migrated when memory selection is updated"
    );
    gen_setter_opt!(
        cpuset;
        cpu_exclusive,
        bool,
        "whether the selected CPUs should be exclusive to this cgroup"
    );

    gen_setter_opt!(
        cpuset;
        mem_exclusive,
        bool,
        "whether the selected memory nodes should be exclusive to this cgroup"
    );

    gen_setter_opt!(
        cpuset;
        mem_hardwall,
        bool,
        "whether this cgroup is \"hardwalled\""
    );

    /// Sets whether the kernel computes the memory pressure of this cgroup.
    ///
    /// This field is valid only for the root cgroup. Building a non-root cgroup with memory
    /// pressure computation enabled will raises an error with kind [`ErrorKind::InvalidOperation`].
    ///
    /// [`ErrorKind::InvalidOperation`]: ../../enum.ErrorKind.html#variant.InvalidOperation
    pub fn memory_pressure_enabled(mut self, enabled: bool) -> Self {
        self.builder.resources.cpuset.memory_pressure_enabled = Some(enabled);
        self
    }

    gen_setter_opt!(
        cpuset;
        memory_spread_page,
        bool,
        "whether file system buffers are spread across the selected memory nodes"
    );

    gen_setter_opt!(
        cpuset;
        memory_spread_slab,
        bool,
        "whether file system buffers are spread across the selected memory nodes"
    );

    gen_setter_opt!(
        cpuset;
        sched_load_balance,
        bool,
        "whether the kernel balances the load across the selected CPUs"
    );

    gen_setter_opt!(
        cpuset;
        sched_relax_domain_level,
        i32,
        "how much work the kernel do to balance the load on this cgroup"
    );

    /// Finishes configuring this cpuset subsystem.
    pub fn done(self) -> Builder {
        self.builder
    }
}

/// pids subsystem builder.
///
/// This struct is created by [`Builder::pids`](struct.Builder.html#method.pids) method.
#[derive(Debug)]
pub struct PidsBuilder {
    builder: Builder,
}

impl PidsBuilder {
    gen_setter_opt!(
        pids;
        max,
        Max<u32>,
        "a maximum number of tasks this cgroup can have"
    );

    /// Finishes configuring this pids subsystem.
    pub fn done(self) -> Builder {
        self.builder
    }
}

/// devices subsystem builder.
///
/// This struct is created by [`Builder::devices`](struct.Builder.html#method.devices) method.
#[derive(Debug)]
pub struct DevicesBuilder {
    builder: Builder,
}

impl DevicesBuilder {
    gen_setter!(
        devices;
        allow,
        Vec<devices::Access>,
        "a list of allowed device accesses"
    );

    gen_setter!(
        devices;
        deny,
        Vec<devices::Access>,
        "a list of denied device accesses"
    );

    /// Finishes configuring this devices subsystem.
    pub fn done(self) -> Builder {
        self.builder
    }
}

/// hugetlb subsystem builder.
///
/// This struct is created by [`Builder::hugetlb`](struct.Builder.html#method.hugetlb) method.
#[derive(Debug)]
pub struct HugeTlbBuilder {
    builder: Builder,
}

impl HugeTlbBuilder {
    /// Sets a limit of 2 MB hugepage TLB usage.
    ///
    /// See [`hugetlb::Subsystem::set_limit`](../hugetlb/struct.Subsystem.html#method.set_limit) for
    /// more information.
    pub fn limit_2mb(mut self, limit: hugetlb::Limit) -> Self {
        self.builder.resources.hugetlb.limit_2mb = Some(limit);
        self
    }

    /// Sets a limit of 1 GB hugepage TLB usage.
    ///
    /// See [`hugetlb::Subsystem::set_limit`](../hugetlb/struct.Subsystem.html#method.set_limit) for
    /// more information.
    pub fn limit_1gb(mut self, limit: hugetlb::Limit) -> Self {
        self.builder.resources.hugetlb.limit_1gb = Some(limit);
        self
    }

    /// Finishes configuring this hugetlb subsystem.
    pub fn done(self) -> Builder {
        self.builder
    }
}

/// net_cls subsystem builder.
///
/// This struct is created by [`Builder::net_cls`](struct.Builder.html#method.net_cls) method.
#[derive(Debug)]
pub struct NetClsBuilder {
    builder: Builder,
}

impl NetClsBuilder {
    /// Tags network packet from this cgroup with a class ID.
    ///
    /// See [`net_cls::Subsystem::set_classid`](../net_cls/struct.Subsystem.html#method.set_classid)
    /// for more information.
    pub fn classid(mut self, class_id: net_cls::ClassId) -> Self {
        self.builder.resources.net_cls.classid = Some(class_id);
        self
    }

    /// Finishes configuring this net_cls subsystem.
    pub fn done(self) -> Builder {
        self.builder
    }
}

/// net_prio subsystem builder.
///
/// This struct is created by [`Builder::net_prio`](struct.Builder.html#method.net_prio) method.
#[derive(Debug)]
pub struct NetPrioBuilder {
    builder: Builder,
}

impl NetPrioBuilder {
    gen_setter!(
        net_prio;
        ifpriomap,
        HashMap<String, u32>,
        "a map of priorities assigned to traffic originating from this cgroup"
    );

    /// Finishes configuring this net_prio subsystem.
    pub fn done(self) -> Builder {
        self.builder
    }
}

/// RDMA subsystem builder.
///
/// This struct is created by [`Builder::rdma`](struct.Builder.html#method.rdma) method.
#[derive(Debug)]
pub struct RdmaBuilder {
    builder: Builder,
}

impl RdmaBuilder {
    gen_setter!(
        rdma;
        max,
        HashMap<String, rdma::Limit>,
        "limits of the usage of RDMA/IB devices"
    );

    /// Finishes configuring this RDMA subsystem.
    pub fn done(self) -> Builder {
        self.builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder() -> Result<()> {
        use crate::v1::Cgroup;

        let id_set = [0].iter().copied().collect::<cpuset::IdSet>();

        #[rustfmt::skip]
        let mut cgroups = Builder::new(gen_cgroup_name!())
            .cpu()
                .shares(1000)
                .cfs_quota_us(500 * 1000)
                .cfs_period_us(1000 * 1000)
                .done()
            .cpuset()
                .cpus(id_set.clone())
                .mems(id_set.clone())
                .memory_migrate(true)
                .done()
            .build()?;

        let cpu = cgroups.cpu().unwrap();
        assert!(cpu.path().exists());
        assert_eq!(cpu.shares()?, 1000);
        assert_eq!(cpu.cfs_quota_us()?, 500 * 1000);
        assert_eq!(cpu.cfs_period_us()?, 1000 * 1000);

        let cpuset = cgroups.cpuset().unwrap();
        assert!(cpuset.path().exists());
        assert_eq!(cpuset.cpus()?, id_set.clone());
        assert_eq!(cpuset.mems()?, id_set.clone());
        assert_eq!(cpuset.memory_migrate()?, true);

        cgroups.delete()
    }

    #[test]
    fn err_builder() -> Result<()> {
        use crate::{
            v1::{cpuset, Cgroup, CgroupPath},
            ErrorKind,
        };

        let name = gen_cgroup_name!();

        #[rustfmt::skip]
        let cgroups = Builder::new(name.clone())
            .cpuset()
                .memory_pressure_enabled(true)
                .done()
            .build();

        assert_eq!(cgroups.unwrap_err().kind(), ErrorKind::InvalidOperation);

        // cleanup the created directories
        let mut cgroup = cpuset::Subsystem::new(CgroupPath::new(SubsystemKind::Cpuset, name));
        cgroup.delete()
    }

    #[test]
    fn test_builder_not_create_unused_subsystem_directory() -> Result<()> {
        use crate::v1::{pids, Cgroup, CgroupPath};

        let name = gen_cgroup_name!();
        #[rustfmt::skip]
        let mut cgroups = Builder::new(name.clone())
            .cpu()
                .done()
            .cpuset()
                .done()
            .build()?;

        let pids = pids::Subsystem::new(CgroupPath::new(SubsystemKind::Pids, name));
        assert!(!pids.path().exists());

        cgroups.delete()
    }

    #[test]
    fn test_builder_override() -> Result<()> {
        #[rustfmt::skip]
        let mut cgroup = Builder::new(gen_cgroup_name!())
            .cpu()
                .shares(1000)
                .shares(2000)
                .done()
            .build()?;

        let cpu = cgroup.cpu().unwrap();
        assert_eq!(cpu.shares()?, 2000);

        cgroup.delete()?;

        #[rustfmt::skip]
        let mut cgroup = Builder::new(gen_cgroup_name!())
            .cpu()
                .shares(1000)
                .done()
            .cpu()
                .shares(2000)
                .done()
            .build()?;

        let cpu = cgroup.cpu().unwrap();
        assert_eq!(cpu.shares()?, 2000);

        cgroup.delete()
    }

    #[test]
    fn test_builder_not_reset() -> Result<()> {
        #[rustfmt::skip]
        let mut cgroup = Builder::new(gen_cgroup_name!())
            .cpu()
                .shares(1000)
                .done()
            .cpu()
                .cfs_quota_us(500 * 1000)
                .cfs_period_us(1000 * 1000)
                .done()
            .build()?;

        let cpu = cgroup.cpu().unwrap();
        assert_eq!(cpu.shares()?, 1000);
        assert_eq!(cpu.cfs_quota_us()?, 500 * 1000);
        assert_eq!(cpu.cfs_period_us()?, 1000 * 1000);

        cgroup.delete()
    }
}
