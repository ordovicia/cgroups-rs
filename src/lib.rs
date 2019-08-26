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
//! // ... and delete the cgroup.
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
//! use cgroups::{Device, Max, v1::{devices, hugetlb, net_cls, rdma, Builder}};
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
//!     .memory()
//!         .limit_in_bytes(4 * (1 << 30))
//!         .soft_limit_in_bytes(3 * (1 << 30))
//!         .use_hierarchy(true)
//!         .done()
//!     .pids()
//!         .max(Max::<u32>::Limit(42))
//!         .done()
//!     .devices()
//!         .deny(vec!["a *:* rwm".parse::<devices::Access>().unwrap()])
//!         .allow(vec!["c 1:3 mr".parse::<devices::Access>().unwrap()])
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
//!     .blkio()
//!         .weight(1000)
//!         .weight_device([([8, 0].into(), 100)].iter().copied().collect())
//!         .read_bps_device([([8, 0].into(), 10 * (1 << 20))].iter().copied().collect())
//!         .write_iops_device([([8, 0].into(), 100)].iter().copied().collect())
//!         .done()
//!     .rdma()
//!         .max(
//!             [(
//!                 "mlx4_0".to_string(),
//!                 rdma::Limit {
//!                     hca_handle: Max::<u32>::Limit(2),
//!                     hca_object: Max::<u32>::Max,
//!                 },
//!             )]
//!                 .iter()
//!                 .cloned()
//!                 .collect(),
//!         )
//!         .done()
//!     // Enable monitoring this cgroup via `perf` tool.
//!     .perf_event()
//!         // perf_event subsystem has no parameter, so this method does not
//!         // return a subsystem builder, just enables the monitoring.
//!     // Actually build cgroups with the configuration.
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
//! [`v1::Builder`]: v1/builder/struct.Builder.html

#[macro_use]
mod macros;
mod error;
mod parse;
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

impl Into<u32> for Pid {
    /// Returns the underlying PID or thread ID value.
    ///
    /// # Examples
    ///
    /// ```
    /// use cgroups::Pid;
    ///
    /// let pid: u32 = Pid::from(42).into();
    /// assert_eq!(pid, 42);
    /// ```
    fn into(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Pid {
    /// Formats the underlying PID or thread ID value.
    ///
    /// ```
    /// use cgroups::Pid;
    ///
    /// assert_eq!(Pid::from(42).to_string(), "42");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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

/// Linux device number.
///
/// `Device` implements [`FromStr`] and [`Display`]. You can convert a `Device` into a string and
/// vice versa. [`parse`] returns an error with kind [`ErrorKind::Parse`] if failed.
///
/// ```
/// use cgroups::{Device, DeviceNumber};
///
/// let dev = "8:16".parse::<Device>().unwrap();
/// assert_eq!(dev, Device { major: DeviceNumber::Number(8), minor: DeviceNumber::Number(16) });
///
/// let dev = "8:*".parse::<Device>().unwrap();
/// assert_eq!(dev, Device { major: DeviceNumber::Number(8), minor: DeviceNumber::Any });
/// ```
///
/// ```
/// use cgroups::{Device, DeviceNumber};
///
/// let dev = Device { major: DeviceNumber::Number(8), minor: DeviceNumber::Number(16) };
/// assert_eq!(dev.to_string(), "8:16");
///
/// let dev = Device { major: DeviceNumber::Number(8), minor: DeviceNumber::Any };
/// assert_eq!(dev.to_string(), "8:*");
/// ```
///
/// `Device` also implements [`From`]`<[u16; 2]>` and `From<[DeviceNumber; 2]`.
///
/// ```
/// use cgroups::{Device, DeviceNumber};
///
/// assert_eq!(
///     Device::from([8, 16]),
///     Device { major: DeviceNumber::Number(8), minor: DeviceNumber::Number(16) }
/// );
///
/// assert_eq!(
///     Device::from([DeviceNumber::Number(1), DeviceNumber::Any]),
///     Device { major: DeviceNumber::Number(1), minor: DeviceNumber::Any }
/// );
/// ```
///
/// [`FromStr`]: https://doc.rust-lang.org/std/str/trait.FromStr.html
/// [`Display`]: https://doc.rust-lang.org/std/fmt/trait.Display.html
/// [`parse`]: https://doc.rust-lang.org/std/primitive.str.html#method.parse
/// [`ErrorKind::Parse`]: enum.ErrorKind.html#variant.Parse
/// [`From`]: https://doc.rust-lang.org/std/convert/trait.From.html
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Device {
    /// Major number.
    pub major: DeviceNumber,
    /// Minor number.
    pub minor: DeviceNumber,
}

/// Device major/minor number.
///
/// `DeviceNumber` implements [`FromStr`] and [`Display`]. You can convert a `DeviceNumber` into
/// a string and vice versa. [`parse`] returns an error with kind [`ErrorKind::Parse`] if failed.
///
/// ```
/// use cgroups::DeviceNumber;
///
/// let n = "8".parse::<DeviceNumber>().unwrap();
/// assert_eq!(n, DeviceNumber::Number(8));
///
/// let n = "*".parse::<DeviceNumber>().unwrap();
/// assert_eq!(n, DeviceNumber::Any);
/// ```
///
/// ```
/// use cgroups::DeviceNumber;
///
/// assert_eq!(DeviceNumber::Number(8).to_string(), "8");
/// assert_eq!(DeviceNumber::Any.to_string(), "*");
/// ```
///
/// `DeviceNumber` also implements [`From`]`<u16>`, which results in `DeviceNumber::Number`.
///
/// ```
/// use cgroups::DeviceNumber;
///
/// assert_eq!(DeviceNumber::from(8), DeviceNumber::Number(8));
/// ```
///
/// [`FromStr`]: https://doc.rust-lang.org/std/str/trait.FromStr.html
/// [`Display`]: https://doc.rust-lang.org/std/fmt/trait.Display.html
/// [`parse`]: https://doc.rust-lang.org/std/primitive.str.html#method.parse
/// [`ErrorKind::Parse`]: enum.ErrorKind.html#variant.Parse
/// [`From`]: https://doc.rust-lang.org/std/convert/trait.From.html
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceNumber {
    /// Any number matches.
    Any,
    /// Specific number.
    Number(u16),
}

impl From<[u16; 2]> for Device {
    fn from(n: [u16; 2]) -> Self {
        Self {
            major: n[0].into(),
            minor: n[1].into(),
        }
    }
}

impl From<[DeviceNumber; 2]> for Device {
    fn from(n: [DeviceNumber; 2]) -> Self {
        Self {
            major: n[0],
            minor: n[1],
        }
    }
}

impl FromStr for Device {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut comma_sp = s.split(':');
        let major = parse::parse_option(comma_sp.next())?;
        let minor = parse::parse_option(comma_sp.next())?;

        Ok(Device { major, minor })
    }
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}

impl From<u16> for DeviceNumber {
    fn from(n: u16) -> Self {
        Self::Number(n)
    }
}

impl FromStr for DeviceNumber {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s == "*" {
            Ok(Self::Any)
        } else {
            Ok(Self::Number(s.parse::<u16>()?))
        }
    }
}

impl fmt::Display for DeviceNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Write;
        match self {
            Self::Any => f.write_char('*'),
            Self::Number(n) => write!(f, "{}", n),
        }
    }
}
