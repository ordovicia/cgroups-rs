//! Configurating cgroups using the builder pattern.

use std::path::PathBuf;

use crate::{
    v1::{Resources, SubsystemKind, UnifiedRepr},
    Result,
};

/// Cgroups builder.
///
/// This builder creates only directories of the configured subsystems. Note that calling the
/// same method twice will override the configuration previously set.
///
/// # Examples
///
/// ```no_run
/// # fn main() -> cgroups::Result<()> {
/// use std::path::PathBuf;
/// use cgroups::v1::Builder;
///
/// let cgroup = Builder::new(PathBuf::from("students/charlie"))
///     .cpu()  // Start configurating the CPU subsystem
///         .shares(1000)
///         .cfs_quota(500 * 1000)
///         .cfs_period(1000 * 1000)
///         .done() // Finish configurating the CPU subsystem
///     .build(true)?;  // Build a cgroup with the configuration.
///                     // Only create the directory for the CPU subsystem.
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
    /// The resulting cgroup will have the given name. For the directory name of each subsystem,
    /// the standard name (e.g. `cpu` for CPU subsystem) is used.
    pub fn new(name: PathBuf) -> Self {
        Self {
            name,
            subsystem_kinds: Vec::new(),
            resources: Resources::default(),
        }
    }

    /// Starts configurating the CPU subsystem.
    pub fn cpu(mut self) -> CpuBuilder {
        self.subsystem_kinds.push(SubsystemKind::Cpu);
        CpuBuilder { builder: self }
    }

    /// Builds a cgroup with the configuration.
    ///
    /// If `validate` is `true`, this method validates that the resource limits are
    /// correctly set, and returns an error with kind `ErrorKind::Apply` if the validation failed.
    ///
    /// This method creates directories for the cgroup, but only for the configured subsystems.
    /// i.e. if you called only `cpu()`, only one cgroup directory is created for the CPU subsystem.
    pub fn build(self, validate: bool) -> Result<UnifiedRepr> {
        let mut unified_repr = UnifiedRepr::with_subsystems(self.name, &self.subsystem_kinds);
        unified_repr.create()?;
        unified_repr.apply(&self.resources, validate)?;
        Ok(unified_repr)
    }
}

macro_rules! gen_setter {
    ($subsystem: ident, $resource: ident, $type: ty) => {
        pub fn $resource(mut self, $resource: $type) -> Self {
            self.builder.resources.$subsystem.$resource = Some($resource);
            self
        }
    }
}

/// CPU subsystem builder.
pub struct CpuBuilder {
    builder: Builder,
}

impl CpuBuilder {
    gen_setter!(cpu, shares, u64);
    gen_setter!(cpu, cfs_period, u64);
    gen_setter!(cpu, cfs_quota, i64);

    /// Finishes configurating this CPU subsystem.
    pub fn done(self) -> Builder {
        self.builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder() -> Result<()> {
        use std::path::PathBuf;

        #[rustfmt::skip]
        let mut cgroup = Builder::new(PathBuf::from(make_cgroup_name!()))
            .cpu()
                .shares(1000)
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
