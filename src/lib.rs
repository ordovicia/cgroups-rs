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
//! # fn main() -> controlgroup::Result<()> {
//! use std::path::PathBuf;
//! use controlgroup::{Pid, v1::{cpu, Cgroup, CgroupPath, SubsystemKind, Resources}};
//!
//! // Define and create a new cgroup controlled by the CPU subsystem.
//! let mut cgroup = cpu::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
//! cgroup.create()?;
//!
//! // Attach the self process to the cgroup.
//! let pid = Pid::from(std::process::id());
//! cgroup.add_task(pid)?;
//!
//! // Define resource limits and constraints for this cgroup.
//! // Here we just use the default for an example.
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
//! // Note that subsystem handlers does not implement `Drop` and therefore when the
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
//! # fn main() -> controlgroup::Result<()> {
//! use std::{collections::HashMap, path::PathBuf};
//! use controlgroup::{Max, v1::{devices, hugetlb, net_cls, rdma, Builder, SubsystemKind}};
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
//!     .hugetlb()
//!         .limit_2mb(hugetlb::Limit::Pages(4))
//!         .limit_1gb(hugetlb::Limit::Pages(2))
//!         .done()
//!     .devices()
//!         .deny(vec!["a *:* rwm".parse::<devices::Access>().unwrap()])
//!         .allow(vec!["c 1:3 mr".parse::<devices::Access>().unwrap()])
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
//!                     hca_handle: 2.into(),
//!                     hca_object: Max::Max,
//!                 },
//!             )]
//!                 .iter()
//!                 .cloned()
//!                 .collect(),
//!         )
//!         .done()
//!     .net_prio()
//!         .ifpriomap(
//!             [("lo".to_string(), 0), ("wlp1s0".to_string(), 1)]
//!                 .iter()
//!                 .cloned()
//!                 .collect(),
//!         )
//!         .done()
//!     .net_cls()
//!         .classid([0x10, 0x1].into())
//!         .done()
//!     .pids()
//!         .max(42.into())
//!         .done()
//!     .freezer()
//!         // Tasks in this cgroup will be frozen.
//!         .freeze()
//!         .done()
//!     // Enable CPU accounting for this cgroup.
//!     // cpuacct subsystem has no parameter, so this method does not return a subsystem builder,
//!     // just enables the accounting.
//!     .cpuacct()
//!     // Enable monitoring this cgroup via `perf` tool.
//!     // Like `cpuacct()` method, this method does not return a subsystem builder.
//!     .perf_event()
//!     // Skip creating directories for cpuacct subsystem and net_cls subsystem.
//!     // This is useful when some subsystems share hierarchy with others.
//!     .skip_create(vec![SubsystemKind::Cpuacct, SubsystemKind::NetCls])
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

use std::{
    fmt::{self, Display},
    str::FromStr,
};

pub use error::{Error, ErrorKind, Result};

/// PID or thread ID for attaching a task to a cgroup.
///
/// `Pid` can be converted from [`u32`] and [`&std::process::Child`].
///
/// ```
/// use controlgroup::Pid;
///
/// let pid = Pid::from(42_u32);
///
/// let child = std::process::Command::new("sleep").arg("1").spawn().unwrap();
/// let pid = Pid::from(&child);
/// ```
///
/// [`u32`]: https://doc.rust-lang.org/std/primitive.u32.html
/// [`&std::process::Child`]: https://doc.rust-lang.org/std/process/struct.Child.html
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
    fn into(self) -> u32 {
        self.0
    }
}

impl FromStr for Pid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let n = s.parse::<u32>()?;
        Ok(Self(n))
    }
}

impl Display for Pid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Limit the maximum number or amount of a resource, or not limit.
///
/// `Max` implements [`FromStr`] and [`Display`]. You can convert a string into a `Max` and vice
/// versa. [`parse`] returns an error with kind [`ErrorKind::Parse`] if failed.
///
/// ```
/// use controlgroup::Max;
///
/// let max = "max".parse::<Max>().unwrap();
/// assert_eq!(max, Max::Max);
///
/// let num = "42".parse::<Max>().unwrap();
/// assert_eq!(num, Max::Limit(42));
///
/// assert_eq!(Max::Max.to_string(), "max");
/// assert_eq!(Max::Limit(42).to_string(), "42");
/// ```
///
/// `Max` also implements [`Default`], which yields `Max::Max`.
///
/// ```
/// use controlgroup::Max;
///
/// assert_eq!(Max::default(), Max::Max);
/// ```
///
/// [`FromStr`]: https://doc.rust-lang.org/std/str/trait.FromStr.html
/// [`Display`]: https://doc.rust-lang.org/std/fmt/trait.Display.html
/// [`parse`]: https://doc.rust-lang.org/std/primitive.str.html#method.parse
/// [`ErrorKind::Parse`]: enum.ErrorKind.html#variant.Parse
///
/// [`Default`]: https://doc.rust-lang.org/std/default/trait.Default.html
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Max {
    /// Not limit the maximum number or amount of a resource.
    Max,
    /// Limits the maximum number or amount of a resource to this value.
    Limit(u32), // only `u32` is used for the integer type of `Max` in this crate
}

impl Default for Max {
    fn default() -> Self {
        Self::Max
    }
}

impl From<u32> for Max {
    fn from(n: u32) -> Self {
        Self::Limit(n)
    }
}

impl FromStr for Max {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "max" => Ok(Self::Max),
            n => Ok(Self::Limit(n.parse()?)),
        }
    }
}

impl Display for Max {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Max => write!(f, "max"),
            Self::Limit(n) => write!(f, "{}", n),
        }
    }
}

/// Linux device number.
///
/// `Device` implements [`FromStr`] and [`Display`]. You can convert a string into a `Device` and
/// vice versa. [`parse`] returns an error with kind [`ErrorKind::Parse`] if failed.
///
/// ```
/// use controlgroup::{Device, DeviceNumber};
///
/// let dev = "8:16".parse::<Device>().unwrap();
/// assert_eq!(dev, Device { major: DeviceNumber::Number(8), minor: DeviceNumber::Number(16) });
///
/// let dev = "8:*".parse::<Device>().unwrap();
/// assert_eq!(dev, Device { major: DeviceNumber::Number(8), minor: DeviceNumber::Any });
/// ```
///
/// ```
/// use controlgroup::{Device, DeviceNumber};
///
/// let dev = Device { major: DeviceNumber::Number(8), minor: DeviceNumber::Number(16) };
/// assert_eq!(dev.to_string(), "8:16");
///
/// let dev = Device { major: DeviceNumber::Number(8), minor: DeviceNumber::Any };
/// assert_eq!(dev.to_string(), "8:*");
/// ```
///
/// `Device` also implements [`From`]`<[u16; 2]>` and `From<[DeviceNumber; 2]>`.
///
/// ```
/// use controlgroup::{Device, DeviceNumber};
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
///
/// [`From`]: https://doc.rust-lang.org/std/convert/trait.From.html
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Device {
    /// Major number.
    pub major: DeviceNumber,
    /// Minor number.
    pub minor: DeviceNumber,
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
        let mut parts = s.split(':');
        let major = parse::parse_next(&mut parts)?;
        let minor = parse::parse_next(&mut parts)?;

        Ok(Device { major, minor })
    }
}

impl Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}

/// Device major/minor number.
///
/// `DeviceNumber` implements [`FromStr`] and [`Display`]. You can convert a string into a
/// `DeviceNumber` and vice versa. [`parse`] returns an error with kind [`ErrorKind::Parse`] if
/// failed.
///
/// ```
/// use controlgroup::DeviceNumber;
///
/// let n = "8".parse::<DeviceNumber>().unwrap();
/// assert_eq!(n, DeviceNumber::Number(8));
///
/// let n = "*".parse::<DeviceNumber>().unwrap();
/// assert_eq!(n, DeviceNumber::Any);
/// ```
///
/// ```
/// use controlgroup::DeviceNumber;
///
/// assert_eq!(DeviceNumber::Number(8).to_string(), "8");
/// assert_eq!(DeviceNumber::Any.to_string(), "*");
/// ```
///
/// `DeviceNumber` also implements [`From`]`<u16>`, which results in `DeviceNumber::Number`.
///
/// ```
/// use controlgroup::DeviceNumber;
///
/// assert_eq!(DeviceNumber::from(8), DeviceNumber::Number(8));
/// ```
///
/// [`FromStr`]: https://doc.rust-lang.org/std/str/trait.FromStr.html
/// [`Display`]: https://doc.rust-lang.org/std/fmt/trait.Display.html
/// [`parse`]: https://doc.rust-lang.org/std/primitive.str.html#method.parse
/// [`ErrorKind::Parse`]: enum.ErrorKind.html#variant.Parse
///
/// [`From`]: https://doc.rust-lang.org/std/convert/trait.From.html
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceNumber {
    /// Any number matches.
    Any,
    /// Specific number.
    Number(u16),
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
            let n = s.parse::<u16>()?;
            Ok(Self::Number(n))
        }
    }
}

impl Display for DeviceNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Write;

        match self {
            Self::Any => f.write_char('*'),
            Self::Number(n) => write!(f, "{}", n),
        }
    }
}

/// Yields a pair of a references, each of which points to a key and a value.
///
/// This trait is used to convert a reference to a pair `&(K, V)` into a pair of references
/// `(&K, &V)`.
pub trait RefKv<K, V> {
    /// Yields a pair of a references, each of which points to a key and a value.
    fn ref_kv(&self) -> (&K, &V);
}

impl<K, V> RefKv<K, V> for (&K, &V) {
    fn ref_kv(&self) -> (&K, &V) {
        *self
    }
}

impl<K, V> RefKv<K, V> for &(K, V) {
    fn ref_kv(&self) -> (&K, &V) {
        (&self.0, &self.1)
    }
}

// Consume CPU time on the all logical cores until a condition holds. Panics if the condition does
// not hold in the given timeout.
// FIXME: consume system time
#[cfg(test)]
pub fn consume_cpu_until(condition: impl Fn() -> bool, timeout_secs: u64) {
    use std::{sync, thread, time};

    let finished = sync::Arc::new(sync::Mutex::new(false));

    let handlers = (0..(num_cpus::get() - 1))
        .map(|_| {
            let fin = finished.clone();
            thread::spawn(move || {
                while !*fin.lock().unwrap() {
                    // spin
                }
            })
        })
        .collect::<Vec<_>>();

    let start = time::Instant::now();
    while start.elapsed() < time::Duration::from_secs(timeout_secs) {
        if condition() {
            *finished.lock().unwrap() = true;
            for handler in handlers {
                handler.join().expect("Failed to join a thread");
            }

            return;
        }

        // spin
    }

    panic!("consume_cpu_until timeout")
}
