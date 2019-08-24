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
///     .memory()
///         .limit_in_bytes(4 * (1 << 30))
///         .soft_limit_in_bytes(3 * (1 << 30))
///         .use_hierarchy(true)
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

macro_rules! gen_subsystem_builder_calls {
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

    gen_subsystem_builder_calls! {
        (cpu, Cpu, CpuBuilder, "CPU"),
        (cpuset, Cpuset, CpusetBuilder, "cpuset"),
        (memory, Memory, MemoryBuilder, "memory"),
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

macro_rules! gen_subsystem_builder {
    ($subsystem: ident, $builder: ident, $name: literal, $($tt: tt)*) => {
        with_doc! {
            concat!(
                $name, " subsystem builder.\n\n",
                "This struct is crated by [`Builder::", stringify!($subsystem), "`](struct.Builder.html#method.", stringify!($subsystem), ") method."
            ),
            #[derive(Debug)]
            pub struct $builder {
                builder: Builder,
            }
        }

        impl $builder {
            $($tt)*

            with_doc! {
                concat!("Finishes configuring this ", $name, " subsystem."),
                pub fn done(self) -> Builder {
                    self.builder
                }
            }
        }
    };
}

macro_rules! gen_setter_opt {
    ($subsystem: ident; $desc: literal, $resource: ident, $ty: ty $( as $as: ty )?) => { with_doc! {
        concat!(
"Sets ", $desc, ".

See [`", stringify!($subsystem), "::Subsystem::set_", stringify!($resource), "`](../", stringify!($subsystem), "/struct.Subsystem.html#method.set_", stringify!($resource), ")
for more information."
),
        pub fn $resource(mut self, $resource: $ty) -> Self {
            self.builder.resources.$subsystem.$resource = Some($resource $( as $as )*);
            self
        }
    } };
}

macro_rules! gen_setter {
    ($subsystem: ident; $desc: literal, $resource: ident, $ty: ty $(, $tt: tt )*) => { with_doc! {
        concat!(
"Sets ", $desc, ".

See [`", stringify!($subsystem), "::Subsystem::set_", stringify!($resource), "`](../", stringify!($subsystem), "/struct.Subsystem.html#method.set_", stringify!($resource), ")
for more information."
),
        pub fn $resource(mut self, $resource: $ty) -> Self {
            self.builder.resources.$subsystem.$resource = $resource $( $tt )*;
            self
        }
    } };
}

gen_subsystem_builder! {
    cpu,
    CpuBuilder,
    "CPU",

    gen_setter_opt!(cpu; "CPU time shares", shares, u64);
    gen_setter_opt!(cpu; "length of period (in microseconds)", cfs_period_us, u64);
    gen_setter_opt!(cpu; "total available CPU time within a period (in microseconds)", cfs_quota_us, i64);
}

gen_subsystem_builder! {
    cpuset,
    CpusetBuilder,
    "cpuset",

    gen_setter_opt!(
        cpuset;
        "a set of Cpus on which task in this cgroup can run",
        cpus,
        cpuset::IdSet
    );

    gen_setter_opt!(
        cpuset;
        "a set of memory nodes which tasks in this cgroup can use",
        mems,
        cpuset::IdSet
    );

    gen_setter_opt!(
        cpuset;
        "whether the memory used by tasks in this cgroup should beb migrated when memory selection is updated",
        memory_migrate,
        bool
    );

    gen_setter_opt!(
        cpuset;
        "whether the selected CPUs should be exclusive to this cgroup",
        cpu_exclusive,
        bool
    );

    gen_setter_opt!(
        cpuset;
        "whether the selected memory nodes should be exclusive to this cgroup",
        mem_exclusive,
        bool
    );

    gen_setter_opt!(
        cpuset;
        "whether this cgroup is \"hardwalled\"",
        mem_hardwall,
        bool
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
        "whether file system buffers are spread across the selected memory nodes",
        memory_spread_page,
        bool
    );

    gen_setter_opt!(
        cpuset;
        "whether file system buffers are spread across the selected memory nodes",
        memory_spread_slab,
        bool
    );

    gen_setter_opt!(
        cpuset;
        "whether the kernel balances the load across the selected CPUs",
        sched_load_balance,
        bool
    );

    gen_setter_opt!(
        cpuset;
        "how much work the kernel do to balance the load on this cgroup",
        sched_relax_domain_level,
        i32
    );
}

gen_subsystem_builder! {
    memory,
    MemoryBuilder,
    "memory",

    gen_setter_opt!(
        memory;
        "limit on memory usage by this cgroup",
        limit_in_bytes,
        u64 as i64 // not i64 because setting `-1` to a new cgroup does not make sense
    );

    gen_setter_opt!(
        memory;
        "limit on total of memory and swap usage by this cgroup",
        memsw_limit_in_bytes,
        u64 as i64
    );

    gen_setter_opt!(
        memory;
        "limit on kernel memory usage by this cgroup",
        kmem_limit_in_bytes,
        u64 as i64
    );

    gen_setter_opt!(
        memory;
        "limit on kernel memory usage for TCP by this cgroup",
        kmem_tcp_limit_in_bytes,
        u64 as i64
    );

    gen_setter_opt!(
        memory;
        "soft limit on memory usage by this cgroup",
        soft_limit_in_bytes,
        u64 as i64
    );

    gen_setter_opt!(
        memory;
        "whether pages may be recharged to the new cgroup when a task is moved",
        move_charge_at_immigrate,
        bool
    );

    gen_setter_opt!(
        memory;
        "kernel's tendency to swap out pages consumed by this cgroup",
        swappiness,
        u64
    );

    gen_setter_opt!(
        memory;
        "whether the OOM killer tries to reclaim memory from the self and descendant cgroups",
        use_hierarchy,
        bool
    );
}

gen_subsystem_builder! {
    pids,
    PidsBuilder,
    "pids",

    gen_setter_opt!(
        pids;
        "a maximum number of tasks this cgroup can have",
        max,
        Max<u32>
    );
}

gen_subsystem_builder! {
    devices,
    DevicesBuilder,
    "devices",

    gen_setter!(
        devices;
        "a list of allowed device accesses",
        allow,
        Vec<devices::Access>
    );

    gen_setter!(
        devices;
        "a list of denied device accesses",
        deny,
        Vec<devices::Access>
    );
}

gen_subsystem_builder! {
    hugetlb,
    HugeTlbBuilder,
    "hugetlb",

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
}

gen_subsystem_builder! {
    net_cls,
    NetClsBuilder,
    "net_cls",

    /// Tags network packet from this cgroup with a class ID.
    ///
    /// See [`net_cls::Subsystem::set_classid`](../net_cls/struct.Subsystem.html#method.set_classid)
    /// for more information.
    pub fn classid(mut self, class_id: net_cls::ClassId) -> Self {
        self.builder.resources.net_cls.classid = Some(class_id);
        self
    }
}

gen_subsystem_builder! {
    net_prio,
    NetPrioBuilder,
    "net_prio",

    gen_setter!(
        net_prio;
        "a map of priorities assigned to traffic originating from this cgroup",
        ifpriomap,
        HashMap<String, u32>
    );
}

gen_subsystem_builder! {
    rdma,
    RdmaBuilder,
    "RDMA",

    gen_setter!(
        rdma;
        "limits of the usage of RDMA/IB devices",
        max,
        HashMap<String, rdma::Limit>
    );
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
