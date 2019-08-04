use std::path::PathBuf;

use crate::{
    v1::{Resources, UnifiedRepr},
    Result,
};

/// Configurating cgroups using the builder pattern.
///
/// # Examples
///
/// ```no_run
/// use std::path::PathBuf;
/// use cgroups::v1::Builder;
///
/// let cgroup = Builder::new(PathBuf::from("students/charlie"))
///     .cpu()
///         .shares(1000)
///         .cfs_quota(500 * 1000)
///         .cfs_period(1000 * 1000)
///         .done()
///     .build(true);
/// ```
#[derive(Debug, Clone)]
pub struct Builder {
    name: PathBuf,
    resources: Resources,
}

impl Builder {
    pub fn new(name: PathBuf) -> Self {
        Self {
            name,
            resources: Resources::default(),
        }
    }

    pub fn cpu(self) -> CpuBuilder {
        CpuBuilder { builder: self }
    }

    pub fn build(self, validate: bool) -> Result<UnifiedRepr> {
        let mut unified_repr = UnifiedRepr::new(self.name);
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

pub struct CpuBuilder {
    builder: Builder,
}

impl CpuBuilder {
    gen_setter!(cpu, shares, u64);
    gen_setter!(cpu, cfs_period, u64);
    gen_setter!(cpu, cfs_quota, i64);

    pub fn done(self) -> Builder {
        self.builder
    }
}
