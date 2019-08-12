//! Operations on a CPU subsystem.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/scheduler/sched-design-CFS.txt](https://www.kernel.org/doc/Documentation/scheduler/sched-design-CFS.txt)
//! paragraph 7 ("GROUP SCHEDULER EXTENSIONS TO CFS"), and
//! [Documentation/scheduler/sched-bwc.txt](https://www.kernel.org/doc/Documentation/scheduler/sched-bwc.txt).
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! use std::path::PathBuf;
//! use cgroups::{Pid, v1::{self, cpu, Cgroup, CgroupPath, SubsystemKind}};
//!
//! let mut cpu_cgroup = cpu::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
//! cpu_cgroup.create()?;
//!
//! // Define a resource limit about how a cgroup can use CPU time.
//! let cpu_resources = v1::Resources {
//!     cpu: cpu::Resources {
//!         shares: Some(1024),
//!         cfs_quota_us: Some(500_000),
//!         cfs_period_us: Some(1000_000),
//!     },
//!     ..v1::Resources::default()
//! };
//!
//! // Apply the resource limit to this cgroup.
//! cpu_cgroup.apply(&cpu_resources)?;
//!
//! // Add tasks to this cgroup.
//! let pid = Pid::from(std::process::id());
//! cpu_cgroup.add_task(pid)?;
//!
//! // Get the throttling statistics of this cgroup.
//! println!("{:?}", cpu_cgroup.stat()?);
//!
//! cpu_cgroup.remove_task(pid)?;
//! cpu_cgroup.delete()?;
//! # Ok(())
//! # }
//! ```

use std::path::PathBuf;

use crate::{
    v1::{self, Cgroup, CgroupPath, SubsystemKind},
    Error, ErrorKind, Result,
};

use crate::{
    util::{parse, parse_option},
    v1::cgroup::CgroupHelper,
};

/// Handler of a CPU subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// How CPU time is provided to a cgroup.
///
/// See the kernel's documentation for more information about the fields.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// Weight of how much of the total CPU time should be provided to this cgroup.
    pub shares: Option<u64>,
    /// Total available CPU time for this cgroup within a period (in microseconds).
    pub cfs_quota_us: Option<i64>,
    /// Length of a period (in microseconds).
    pub cfs_period_us: Option<u64>,
    // pub realtime_runtime: Option<i64>,
    // pub realtime_period: Option<u64>,
}

/// Throttling statistics of a cgroup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    /// Number of periods (as specified in `Resources.cfs_period_us`) that have elapsed.
    pub nr_periods: u64,
    /// Number of times this cgroup has been throttled.
    pub nr_throttled: u64,
    /// Total time duration for which this cgroup has been throttled (in nanoseconds).
    pub throttled_time: u64,
}

impl_cgroup! {
    Cpu,

    /// Applies the `Some` fields in `resources.cpu`.
    ///
    /// See [`Cgroup::apply`] for general information.
    ///
    /// [`Cgroup::apply`]: ../trait.Cgroup.html#tymethod.apply
    fn apply(&mut self, resources: &v1::Resources) -> Result<()> {
        let res: &self::Resources = &resources.cpu;

        macro_rules! a {
            ($resource: ident, $setter: ident) => {
                if let Some(r) = res.$resource {
                    self.$setter(r)?;
                }
            };
        }

        a!(shares, set_shares);
        a!(cfs_period_us, set_cfs_period_us);
        a!(cfs_quota_us, set_cfs_quota_us);

        Ok(())
    }
}

#[rustfmt::skip]
macro_rules! gen_doc {
    ($desc: literal, $resource: ident) => { concat!(
        "Reads ", $desc, " of this cgroup from `cpu.", stringify!($resource), "` file.\n\n",
        "See [`Resources.", stringify!($resource), "`](struct.Resources.html#structfield.", stringify!($resource), ") ",
        "and the kernel's documentation for more information about this field.\n\n",
        gen_doc!(err_eg; $resource)
    ) };

    ($desc: literal, $resource: ident, $val: expr) => { concat!(
        "Sets ", $desc, " to this cgroup by writing to `cpu.", stringify!($resource), "` file.\n\n",
        "See [`Resources.", stringify!($resource), "`](struct.Resources.html#structfield.", stringify!($resource), ") ",
        "and the kernel's documentation for more information about this field.\n\n",
        gen_doc!(err_eg; $resource, $val)
    ) };


    // Errors and Examples
    (err_eg; $resource: ident) => { concat!(
        "# Errors\n\n",
        "Returns an error if failed to read and parse `cpu.", stringify!($resource), "` file of this cgroup.\n\n",
        "# Examples\n\n",
"```no_run
# fn main() -> cgroups::Result<()> {
use std::path::PathBuf;
use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};

let cgroup = cpu::Subsystem::new(
    CgroupPath::new(SubsystemKind::Cpu, PathBuf::from(\"students/charlie\")));

let ", stringify!($resource), " = cgroup.", stringify!($resource), "()?;
# Ok(())
# }
```") };

    (err_eg; $resource: ident, $val: expr) => { concat!(
        "# Errors\n\n",
        "Returns an error if failed to write to `cpu.", stringify!($resource), "` file of this cgroup.\n\n",
        "# Examples\n\n",
"```no_run
# fn main() -> cgroups::Result<()> {
use std::path::PathBuf;
use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};

let mut cgroup = cpu::Subsystem::new(
    CgroupPath::new(SubsystemKind::Cpu, PathBuf::from(\"students/charlie\")));

cgroup.set_", stringify!($resource), "(", stringify!($val), ")?;
# Ok(())
# }
```") };
}

const STAT: &str = "cpu.stat";
const SHARES: &str = "cpu.shares";
const CFS_PERIOD: &str = "cpu.cfs_period_us";
const CFS_QUOTA: &str = "cpu.cfs_quota_us";

impl Subsystem {
    with_doc! { concat!(
        "Reads the throttling statistics of this cgroup from `cpu.stat` file.\n\n",
        "See the kernel's documentation for more information about this field.\n\n",
        gen_doc!(err_eg; stat)),
        pub fn stat(&self) -> Result<Stat> {
            use std::io::{BufRead, BufReader};

            let (mut nr_periods, mut nr_throttled, mut throttled_time) = (None, None, None);

            let buf = BufReader::new(self.open_file_read(STAT)?);
            for line in buf.lines() {
                let line = line.map_err(Error::io)?;
                let mut entry = line.split_whitespace();
                match entry.next().ok_or_else(|| Error::new(ErrorKind::Parse))? {
                    "nr_periods" => {
                        nr_periods = Some(parse_option(entry.next())?);
                    }
                    "nr_throttled" => {
                        nr_throttled = Some(parse_option(entry.next())?);
                    }
                    "throttled_time" => {
                        throttled_time = Some(parse_option(entry.next())?);
                    }
                    _ => return Err(Error::new(ErrorKind::Parse)),
                }
            }

            if let Some(nr_periods) = nr_periods {
                if let Some(nr_throttled) = nr_throttled {
                    if let Some(throttled_time) = throttled_time {
                        return Ok(Stat {
                            nr_periods,
                            nr_throttled,
                            throttled_time,
                        });
                    }
                }
            }

            Err(Error::new(ErrorKind::Parse))
        }
    }

    with_doc! {
        gen_doc!("the CPU time shares", shares),
        pub fn shares(&self) -> Result<u64> {
            self.open_file_read(SHARES).and_then(parse)
        }
    }

    with_doc! {
        gen_doc!("CPU time shares", shares, 2048),
        pub fn set_shares(&mut self, shares: u64) -> Result<()> {
            self.write_file(SHARES, shares)
        }
    }

    with_doc! {
        gen_doc!("the total available CPU time within a period (in microseconds)", cfs_quota_us),
        pub fn cfs_quota_us(&self) -> Result<i64> {
            self.open_file_read(CFS_QUOTA).and_then(parse)
        }
    }

    with_doc! {
        gen_doc!(
            "total available CPU time within a period (in microseconds)",
            cfs_quota_us,
            500 * 1000
        ),
        pub fn set_cfs_quota_us(&mut self, quota_us: i64) -> Result<()> {
            self.write_file(CFS_QUOTA, quota_us)
        }
    }

    with_doc! {
        gen_doc!("the length of period (in microseconds)", cfs_period_us),
        pub fn cfs_period_us(&self) -> Result<u64> {
            self.open_file_read(CFS_PERIOD).and_then(parse)
        }
    }

    with_doc! {
        gen_doc!("length of period (in microseconds)", cfs_period_us, 1000 * 1000),
        pub fn set_cfs_period_us(&mut self, period_us: u64) -> Result<()> {
            self.write_file(CFS_PERIOD, period_us)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subsystem_create_file_exists() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, gen_cgroup_name!()));
        cgroup.create()?;
        assert!([STAT, SHARES, CFS_QUOTA, CFS_PERIOD]
            .iter()
            .all(|f| cgroup.file_exists(f)));
        assert!(!cgroup.file_exists("does_not_exist"));

        cgroup.delete()?;
        assert!([STAT, SHARES, CFS_QUOTA, CFS_PERIOD]
            .iter()
            .all(|f| !cgroup.file_exists(f)));

        Ok(())
    }

    #[test]
    fn test_subsystem_stat() -> Result<()> {
        gen_subsystem_test!(
            Cpu;
            stat,
            Stat {
                nr_periods: 0,
                nr_throttled: 0,
                throttled_time: 0
            }
        )
    }

    #[test]
    fn test_subsystem_shares() -> Result<()> {
        gen_subsystem_test!(Cpu; shares, 1024, set_shares, 2048)
    }

    #[test]
    fn test_subsystem_cfs_quota_us() -> Result<()> {
        gen_subsystem_test!(Cpu; cfs_quota_us, -1, set_cfs_quota_us, 100 * 1000)
    }

    #[test]
    fn test_subsystem_cfs_period_us() -> Result<()> {
        gen_subsystem_test!(
            Cpu;
            cfs_period_us,
            100 * 1000,
            set_cfs_period_us,
            1000 * 1000
        )
    }
}
