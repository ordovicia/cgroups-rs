//! Definition of a perf_event subsystem.
//!
//! [`Subsystem`] implements [`Cgroup`] trait and subsystem-specific operations.
//!
//! By using perf_event subsystem, you can monitor processes using `perf` tool in cgroup unit. This
//! subsystem does not have any configurable parameters.
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! use std::{path::PathBuf, process::Command};
//! use cgroups::{Pid, v1::{perf_event, Cgroup, CgroupPath, SubsystemKind}};
//!
//! let mut perf_event_cgroup = perf_event::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::PerfEvent, PathBuf::from("students/charlie")));
//! perf_event_cgroup.create()?;
//!
//! // Add tasks to this cgroup.
//! let child = Command::new("sleep")
//!                     .arg("10")
//!                     .spawn()
//!                     .expect("command failed");
//! let child_pid = Pid::from(&child);
//! perf_event_cgroup.add_task(child_pid)?;
//!
//! // You can monitor the child process with `perf` in the cgroup unit.
//!
//! // Do something ...
//!
//! perf_event_cgroup.remove_task(child_pid)?;
//! perf_event_cgroup.delete()?;
//! # Ok(())
//! # }
//! ```
//!
//! [`Subsystem`]: struct.Subsystem.html
//! [`Cgroup`]: ../trait.Cgroup.html

use std::path::PathBuf;

use crate::{
    v1::{self, Cgroup, CgroupPath},
    Result,
};

/// Handler of a perf_event subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

impl_cgroup! {
    Subsystem, PerfEvent,

    /// Does nothing as a perf_event cgroup has no parameters.
    ///
    /// See [`Cgroup::apply`] for general information.
    ///
    /// [`Cgroup::apply`]: ../trait.Cgroup.html#tymethod.apply
    fn apply(&mut self, _resources: &v1::Resources) -> Result<()> {
        Ok(())
    }
}
