//! Configurating cgroups using the builder pattern.
//!
//! [`Builder`](struct.Builder.html) builds a cgroup. Subsystem builders
//! (e.g. [`CpuBuilder`](struct.CpuBuilder.html)) are intermediate builders for each subsystem.

use std::path::PathBuf;

use crate::{
    v1::{Resources, SubsystemKind, UnifiedRepr},
    Result,
};

// Keep the example below in sync with README.md

/// Cgroup builder.
///
/// By using `Builder`, you can configure a (set of) cgroup(s) in the builder pattern. This builder
/// creates directories for the cgroups, but only for the configured subsystems. e.g. if you call
/// only `cpu()`, only one cgroup directory is created for the CPU subsystem.
///
/// ```no_run
/// # fn main() -> cgroups::Result<()> {
/// use std::path::PathBuf;
/// use cgroups::v1::Builder;
///
/// let mut cgroups =
///     // Start building a (set of) cgroup(s).
///     Builder::new(PathBuf::from("students/charlie"))
///     // Start configurating the CPU resource limits.
///     .cpu()
///         .shares(1000)
///         .cfs_quota(500 * 1000)
///         .cfs_period(1000 * 1000)
///         // Finish configurating the CPU resource limits.
///         .done()
///     // Actually build cgroups with the configuration.
///     // Only create a directory for the CPU subsystem.
///     .build(true)?;
///
/// let pid = std::process::id().into();
/// cgroups.add_task(pid)?;
///
/// // do something ...
///
/// // Remove self process from the cgroups.
/// cgroups.remove_task(pid)?;
///
/// // And delete the cgroups.
/// cgroups.delete()?;
///
/// // Note that cgroup handlers does not implement `Drop` and therefore when the
/// // handler is dropped, the cgroup will stay around.
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
///     .build(true)?;
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
///         .cfs_quota(500 * 1000)
///         .cfs_period(1000 * 1000)
///         .done()
///     .build(true)?;
///
/// assert_eq!(cgroups.cpu().unwrap().shares()?, 1000);
/// # Ok(())
/// # }
/// ```
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
    /// subsystem, the standard name (e.g. `cpu` for CPU subsystem) is used.
    pub fn new(name: PathBuf) -> Self {
        Self {
            name,
            subsystem_kinds: Vec::new(),
            resources: Resources::default(),
        }
    }

    /// Starts configurating the CPU subsystem.
    pub fn cpu(mut self) -> CpuBuilder {
        // Calling `cpu()` twice will push duplicated `SubsystemKind::Cpu`, but it is fine for
        // `UnifiedRepr::with_subsystems()`.
        self.subsystem_kinds.push(SubsystemKind::Cpu);
        CpuBuilder { builder: self }
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
    ($subsystem: ident, $resource: ident, $type: ty, $doc: literal) => {
        with_doc! {
            concat!("Sets ", $doc, " to this cgroup."),
            pub fn $resource(mut self, $resource: $type) -> Self {
                self.builder.resources.$subsystem.$resource = Some($resource);
                self
            }
        }
    };
}

/// CPU subsystem builder.
///
/// This struct is created by [`Builder::cpu()`](struct.Builder.html#method.cpu) method.
pub struct CpuBuilder {
    builder: Builder,
}

impl CpuBuilder {
    gen_setter!(cpu, shares, u64, "CPU time shares");
    gen_setter!(cpu, cfs_period, u64, "length of period (in microseconds)");
    gen_setter!(
        cpu,
        cfs_quota,
        i64,
        "total available CPU time within a period (in microseconds)"
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
        #[rustfmt::skip]
        let mut cgroups = Builder::new(PathBuf::from(make_cgroup_name!()))
            .cpu()
                .shares(1000)
                .cfs_quota(500 * 1000)
                .cfs_period(1000 * 1000)
                .done()
            .build(true)?;

        let cpu = cgroups.cpu().unwrap();
        assert_eq!(cpu.shares()?, 1000);
        assert_eq!(cpu.cfs_quota()?, 500 * 1000);
        assert_eq!(cpu.cfs_period()?, 1000 * 1000);

        cgroups.delete()
    }

    #[test]
    fn test_builder_override() -> Result<()> {
        #[rustfmt::skip]
        let mut cgroup = Builder::new(PathBuf::from(make_cgroup_name!()))
            .cpu()
                .shares(1000)
                .shares(2000)
                .done()
            .build(true)?;

        let cpu = cgroup.cpu().unwrap();
        assert_eq!(cpu.shares()?, 2000);

        cgroup.delete()?;

        #[rustfmt::skip]
        let mut cgroup = Builder::new(PathBuf::from(make_cgroup_name!()))
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
        let mut cgroup = Builder::new(PathBuf::from(make_cgroup_name!()))
            .cpu()
                .shares(1000)
                .done()
            .cpu()
                .cfs_quota(500 * 1000)
                .cfs_period(1000 * 1000)
                .done()
            .build(true)?;

        let cpu = cgroup.cpu().unwrap();
        assert_eq!(cpu.shares()?, 1000);
        assert_eq!(cpu.cfs_quota()?, 500 * 1000);
        assert_eq!(cpu.cfs_period()?, 1000 * 1000);

        cgroup.delete()
    }
}
