//! Configurating cgroups using the builder pattern.
//!
//! By using [`Builder`], you can configure a (set of) cgroup(s) in the builder pattern. This
//! builder creates directories for the cgroups, but only for the configured subsystems. e.g. If
//! you call only [`cpu()`], only one cgroup directory is created for the CPU subsystem.
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! use std::path::PathBuf;
//! use cgroups::v1::{cpuset::IdSet, Builder};
//!
//! let mut cgroups =
//!     // Start building a (set of) cgroup(s).
//!     Builder::new(PathBuf::from("students/charlie"))
//!     // Start configurating the CPU resource limits.
//!     .cpu()
//!         .shares(1000)
//!         .cfs_quota_us(500 * 1000)
//!         .cfs_period_us(1000 * 1000)
//!         // Finish configurating the CPU resource limits.
//!         .done()
//!     // Start configurating the cpuset resource limits.
//!     .cpuset()
//!         .cpus([0].iter().copied().collect::<IdSet>())
//!         .mems([0].iter().copied().collect::<IdSet>())
//!         .memory_migrate(true)
//!         .done()
//!     // Actually build cgroups with the configuration.
//!     // Only create a directory for the CPU subsystem.
//!     .build(true)?;
//!
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
//!
//! Note that calling the same method of the same subsystem builder twice overrides the previous
//! configuration if set.
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! # use std::path::PathBuf;
//! # use cgroups::v1::Builder;
//! let mut cgroups = Builder::new(PathBuf::from("students/charlie"))
//!     .cpu()
//!         .shares(1000)
//!         .shares(2000)   // Override.
//!         .done()
//!     .build(true)?;
//!
//! assert_eq!(cgroups.cpu().unwrap().shares()?, 2000);
//! # Ok(())
//! # }
//! ```
//!
//! But building the same subsystem twice does not reset the subsystem configuration.
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! # use std::path::PathBuf;
//! # use cgroups::v1::Builder;
//! let mut cgroups = Builder::new(PathBuf::from("students/charlie"))
//!     .cpu()
//!         .shares(1000)
//!         .done()
//!     .cpu()  // Not reset shares.
//!         .cfs_quota_us(500 * 1000)
//!         .cfs_period_us(1000 * 1000)
//!         .done()
//!     .build(true)?;
//!
//! assert_eq!(cgroups.cpu().unwrap().shares()?, 1000);
//! # Ok(())
//! # }
//! ```
//!
//! [`Builder`]: struct.Builder.html
//! [`cpu()`]: struct.Builder.html#method.cpu

// Keep the example above in sync with README.md and lib.rs

use std::path::PathBuf;

use crate::{
    v1::{cpuset::IdSet, Resources, SubsystemKind, UnifiedRepr},
    Result,
};

/// Cgroup builder.
///
/// See also the [module-level documentation](index.html).
#[derive(Debug)]
pub struct Builder {
    name: PathBuf,
    subsystem_kinds: Vec<SubsystemKind>,
    resources: Resources,
}

impl Builder {
    /// Creats a new cgroup builder.
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

    /// Starts configurating the CPU subsystem.
    pub fn cpu(mut self) -> CpuBuilder {
        // Calling `cpu()` twice will push duplicated `SubsystemKind::Cpu`, but it is not a problem
        // for `UnifiedRepr::with_subsystems()`.
        self.subsystem_kinds.push(SubsystemKind::Cpu);
        CpuBuilder { builder: self }
    }

    /// Starts configurating the cpuset subsystem.
    pub fn cpuset(mut self) -> CpusetBuilder {
        self.subsystem_kinds.push(SubsystemKind::Cpuset);
        CpusetBuilder { builder: self }
    }

    /// Builds a (set of) cgroup(s) with the configuration.
    ///
    /// If `validate` is `true`, this method validates that the resource limits are
    /// correctly set, and returns an error with kind [`ErrorKind::Apply`] if the validation failed.
    ///
    /// This method creates directories for the cgroups, but only for the configured subsystems.
    /// i.e. if you called only `cpu()`, only one cgroup directory is created for the CPU subsystem.
    ///
    /// [`ErrorKind::Apply`]: ../../enum.ErrorKind.html#variant.Apply
    pub fn build(self, validate: bool) -> Result<UnifiedRepr> {
        let mut unified_repr = UnifiedRepr::with_subsystems(self.name, &self.subsystem_kinds);
        unified_repr.create()?;
        unified_repr.apply(&self.resources, validate)?;
        Ok(unified_repr)
    }
}

macro_rules! gen_setter {
    ($subsystem: ident; $resource: ident, $ty: ty, $doc: literal) => { with_doc! {
        concat!(
"Sets ", $doc, " to this cgroup.

See [`", stringify!($subsystem), "::Subsystem::set_", stringify!($resource), "()`](../", stringify!($subsystem), "/struct.Subsystem.html#method.set_", stringify!($resource), ")
for more information."
),
        pub fn $resource(mut self, $resource: $ty) -> Self {
            self.builder.resources.$subsystem.$resource = Some($resource);
            self
        }
    } };
}

/// CPU subsystem builder.
///
/// This struct is created by [`Builder::cpu()`](struct.Builder.html#method.cpu) method.
pub struct CpuBuilder {
    builder: Builder,
}

impl CpuBuilder {
    gen_setter!(cpu; shares, u64, "CPU time shares");

    gen_setter!(
        cpu;
        cfs_period_us,
        u64,
        "length of period (in microseconds)"
    );

    gen_setter!(
        cpu;
        cfs_quota_us,
        i64,
        "total available CPU time within a period (in microseconds)"
    );

    /// Finishes configurating this CPU subsystem.
    pub fn done(self) -> Builder {
        self.builder
    }
}

/// Cpuset subsystem builder.
///
/// This struct is created by [`Builder::cpuset()`](struct.Builder.html#method.cpu) method.
pub struct CpusetBuilder {
    builder: Builder,
}

impl CpusetBuilder {
    gen_setter!(
        cpuset;
        cpus,
        IdSet,
        "a set of Cpus on which task in this cgroup can run"
    );

    gen_setter!(
        cpuset;
        mems,
        IdSet,
        "a set of memory nodes which tasks in this cgroup can use"
    );
    gen_setter!(
        cpuset;
        memory_migrate,
        bool,
        "whether the memory used by tasks in this cgroup should beb migrated when memory selection is updated"
    );
    gen_setter!(
        cpuset;
        cpu_exclusive,
        bool,
        "whether the selected CPUs should be exclusive to this cgroup"
    );

    gen_setter!(
        cpuset;
        mem_exclusive,
        bool,
        "whether the selected memory nodes should be exclusive to this cgroup"
    );

    gen_setter!(
        cpuset;
        mem_hardwall,
        bool,
        "whether this cgroup is \"hardwalled\""
    );

    /// Sets whether the kernel computes the memory pressure of this cgroup.
    ///
    /// This field is valid only for the root cgroup. Building a non-root cgroup with memory
    /// pressure computation enabled will raises an error with kind `ErrorKind::InvalidOperation`.
    pub fn memory_pressure_enabled(mut self, enabled: bool) -> Self {
        self.builder.resources.cpuset.memory_pressure_enabled = Some(enabled);
        self
    }

    gen_setter!(
        cpuset;
        memory_spread_page,
        bool,
        "whether file system buffers are spread across the selected memory nodes"
    );

    gen_setter!(
        cpuset;
        memory_spread_slab,
        bool,
        "whether file system buffers are spread across the selected memory nodes"
    );

    gen_setter!(
        cpuset;
        sched_load_balance,
        bool,
        "whether the kernel rebalances the load across the selected CPUs"
    );

    gen_setter!(
        cpuset;
        sched_relax_domain_level,
        i32,
        "how much work the kernel do to rebalance the load on this cgroup"
    );

    /// Finishes configurating this CPU subsystem.
    pub fn done(self) -> Builder {
        self.builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_builder() -> Result<()> {
        let id_set = [0].iter().copied().collect::<IdSet>();

        #[rustfmt::skip]
        let mut cgroups = Builder::new(PathBuf::from(gen_cgroup_name!()))
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
            .build(true)?;

        let cpu = cgroups.cpu().unwrap();
        assert_eq!(cpu.shares()?, 1000);
        assert_eq!(cpu.cfs_quota_us()?, 500 * 1000);
        assert_eq!(cpu.cfs_period_us()?, 1000 * 1000);

        let cpuset = cgroups.cpuset().unwrap();
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

        let name = PathBuf::from(gen_cgroup_name!());

        #[rustfmt::skip]
        let cgroups = Builder::new(name.clone())
            .cpuset()
                .memory_pressure_enabled(true)
                .done()
            .build(false);

        assert_eq!(cgroups.unwrap_err().kind(), ErrorKind::InvalidOperation);

        // cleanup the created directories
        let mut cgroup = cpuset::Subsystem::new(CgroupPath::new(SubsystemKind::Cpuset, name));
        cgroup.delete()
    }

    #[test]
    fn test_builder_override() -> Result<()> {
        #[rustfmt::skip]
        let mut cgroup = Builder::new(PathBuf::from(gen_cgroup_name!()))
            .cpu()
                .shares(1000)
                .shares(2000)
                .done()
            .build(true)?;

        let cpu = cgroup.cpu().unwrap();
        assert_eq!(cpu.shares()?, 2000);

        cgroup.delete()?;

        #[rustfmt::skip]
        let mut cgroup = Builder::new(PathBuf::from(gen_cgroup_name!()))
            .cpu()
                .shares(1000)
                .done()
            .cpu()
                .shares(2000)
                .done()
            .build(true)?;

        let cpu = cgroup.cpu().unwrap();
        assert_eq!(cpu.shares()?, 2000);

        cgroup.delete()
    }

    #[test]
    fn test_builder_not_reset() -> Result<()> {
        #[rustfmt::skip]
        let mut cgroup = Builder::new(PathBuf::from(gen_cgroup_name!()))
            .cpu()
                .shares(1000)
                .done()
            .cpu()
                .cfs_quota_us(500 * 1000)
                .cfs_period_us(1000 * 1000)
                .done()
            .build(true)?;

        let cpu = cgroup.cpu().unwrap();
        assert_eq!(cpu.shares()?, 1000);
        assert_eq!(cpu.cfs_quota_us()?, 500 * 1000);
        assert_eq!(cpu.cfs_period_us()?, 1000 * 1000);

        cgroup.delete()
    }
}
