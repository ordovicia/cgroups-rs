#![cfg(target_os = "linux")]
#![warn(
    future_incompatible,
    missing_docs,
    missing_debug_implementations,
    nonstandard_style,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused
)]

//! Native Rust crate for operating on cgroups.
//!
//! Currently this crate supports only cgroup v1 hierarchy, implemented in [`v1`] module.
//!
//! ## Examples for v1 hierarchy
//!
//! ### Create a cgroup controlled by the CPU subsystem
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! use std::path::PathBuf;
//! use cgroups::{Pid, Max, v1::{cpu, Cgroup, CgroupPath, SubsystemKind, Resources}};
//!
//! // Define and create a new cgroup controlled by the CPU subsystem.
//! let name = PathBuf::from("students/charlie");
//! let mut cgroup = cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, name));
//! cgroup.create()?;
//!
//! // Attach the self process to the cgroup.
//! let pid = Pid::from(std::process::id());
//! cgroup.add_task(pid)?;
//!
//! // Define resource limits and constraints for this cgroup.
//! // Here we just use the default (no limits and constraints) for an example.
//! let resources = Resources::default();
//!
//! // Apply the resource limits.
//! cgroup.apply(&resources)?;
//!
//! // Low-level file operations are also supported.
//! let stat_file = cgroup.open_file_read("cpu.stat")?;
//!
//! // Do something ...
//!
//! // Now, remove self process from the cgroup.
//! cgroup.remove_task(pid)?;
//!
//! // And delete the cgroup.
//! cgroup.delete()?;
//!
//! // Note that cgroup handlers does not implement `Drop` and therefore when the
//! // handler is dropped, the cgroup will stay around.
//! # Ok(())
//! # }
//! ```
//!
//! ### Create a set of cgroups controlled by multiple subsystems
//!
//! [`v1::Builder`] provides a way to configure cgroups in the builder pattern.
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! use std::{collections::HashMap, path::PathBuf};
//! use cgroups::{Max, v1::{cpuset, hugetlb, net_cls, pids, Builder}};
//!
//! let mut cgroups =
//!     // Start building a (set of) cgroup(s).
//!     Builder::new(PathBuf::from("students/charlie"))
//!     // Start configuring the CPU resource limits.
//!     .cpu()
//!         .shares(1000)
//!         .cfs_quota_us(500 * 1000)
//!         .cfs_period_us(1000 * 1000)
//!         // Finish configuring the CPU resource limits.
//!         .done()
//!     // Start configuring the cpuset resource limits.
//!     .cpuset()
//!         .cpus([0].iter().copied().collect())
//!         .mems([0].iter().copied().collect())
//!         .memory_migrate(true)
//!         .done()
//!     .pids()
//!         .max(Max::<u32>::Limit(42))
//!         .done()
//!     .hugetlb()
//!         .limit_2mb(hugetlb::Limit::Pages(4))
//!         .limit_1gb(hugetlb::Limit::Pages(2))
//!         .done()
//!     .net_cls()
//!         .classid(net_cls::ClassId { major: 0x10, minor: 0x1 })
//!         .done()
//!     .net_prio()
//!         .ifpriomap(
//!             [("lo".to_string(), 0), ("wlp1s0".to_string(), 1)]
//!                 .iter()
//!                 .cloned()
//!                 .collect(),
//!         )
//!         .done()
//!     // Enable monitoring this cgroup via `perf` tool.
//!     .perf_event()
//!         // perf_event subsystem has no parameter, so this method does not return a subsystem
//!         // builder, just enable the monitoring.
//!     // Actually build cgroups with the configuration.
//!     // Only create a directory for the CPU, cpuset, and pids subsystems.
//!     .build()?;
//!
//! let pid = std::process::id().into();
//! cgroups.add_task(pid)?;
//!
//! // Do something ...
//!
//! cgroups.remove_task(pid)?;
//! cgroups.delete()?;
//! # Ok(())
//! # }
//! ```
//!
//! [`v1`]: v1/index.html
//! [`v1::Builder`]: v1/struct.Builder.html

#[macro_use]
mod util;
mod error;
pub mod v1;

use std::{fmt, str::FromStr};

pub use error::{Error, ErrorKind, Result};

/// PID or thread ID for attaching a task in a cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pid(u32); // Max PID is 2^15 on 32-bit systems, 2^22 on 64-bit systems
                     // FIXME: ^ also true for thread IDs?

impl From<u32> for Pid {
    fn from(pid: u32) -> Self {
        Self(pid)
    }
}

impl From<&std::process::Child> for Pid {
    fn from(child: &std::process::Child) -> Self {
        Self(child.id())
    }
}

impl Pid {
    /// Returns the underlying PID or thread ID value.
    ///
    /// # Examples
    ///
    /// ```
    /// use cgroups::Pid;
    ///
    /// let pid = Pid::from(42);
    /// assert_eq!(pid.to_inner(), 42);
    /// ```
    pub fn to_inner(self) -> u32 {
        self.0
    }
}

/// Limit a number/amount of resources, or not limit.
///
/// `Max` implements [`FromStr`], so you can [`parse`] a string into a `Max`. If failed,
/// `parse` returns an error with kind [`ErrorKind::Parse`].
///
/// ```
/// use cgroups::Max;
///
/// let max = "max".parse::<Max<u32>>().unwrap();
/// assert_eq!(max, Max::<u32>::Max);
///
/// let num = "42".parse::<Max<u32>>().unwrap();
/// assert_eq!(num, Max::<u32>::Limit(42));
/// ```
///
/// `Max` also implements [`Display`]. The resulting format is the number or "max".
///
/// ```
/// use std::string::ToString;
/// use cgroups::Max;
///
/// assert_eq!(Max::<u32>::Max.to_string(), "max");
/// assert_eq!(Max::<u32>::Limit(42).to_string(), "42");
/// ```
///
/// `Max` implements [`Default`]. The default value is `Max::Max`.
///
/// ```
/// use cgroups::Max;
///
/// assert_eq!(Max::<u32>::default(), Max::<u32>::Max);
/// ```
///
/// [`FromStr`]: https://doc.rust-lang.org/std/str/trait.FromStr.html
/// [`parse`]: https://doc.rust-lang.org/std/primitive.str.html#method.parse
/// [`ErrorKind::Parse`]: enum.ErrorKind.html#variant.Parse
///
/// [`Display`]: https://doc.rust-lang.org/std/fmt/trait.Display.html
///
/// [`Default`]: https://doc.rust-lang.org/std/default/trait.Default.html
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Max<T> {
    /// Not limit the number/amount of resources.
    Max,
    /// Limits the number/amount of resources to this value.
    Limit(T),
}

impl<T> Default for Max<T> {
    fn default() -> Self {
        Self::Max
    }
}

impl<T> From<T> for Max<T> {
    fn from(n: T) -> Self {
        Self::Limit(n)
    }
}

impl<T> FromStr for Max<T>
where
    T: FromStr,
    <T as FromStr>::Err: std::error::Error + Send + Sync + 'static,
    Error: From<<T as FromStr>::Err>,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "max" => Ok(Self::Max),
            n => Ok(Self::Limit(n.parse()?)),
        }
    }
}

impl<T: fmt::Display> fmt::Display for Max<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Max => write!(f, "max"),
            Self::Limit(n) => write!(f, "{}", n),
        }
    }
}
