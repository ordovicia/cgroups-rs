//! Definition of a perf_event subsystem.
//!
//! By using perf_event subsystem, you can monitor processes using `perf` tool in cgroup unit. This
//! subsystem does not have any configurable parameters.

// TODO: module-level doc

use std::path::PathBuf;

use crate::{
    v1::{self, Cgroup, CgroupPath, SubsystemKind},
    Result,
};

/// Handler of a perf_event subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

impl_cgroup! {
    PerfEvent,

    /// Does nothing as a perf_event cgroup has no parameters.
    ///
    /// See [`Cgroup.apply()`] for general information.
    ///
    /// [`Cgroup.apply()`]: ../trait.Cgroup.html#tymethod.apply
    fn apply(&mut self, _resources: &v1::Resources, _validate: bool) -> Result<()> {
        Ok(())
    }
}
