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
//! let resources = cpu::Resources {
//!     shares: Some(1024),
//!     cfs_quota_us: Some(500_000),
//!     cfs_period_us: Some(1000_000),
//! };
//!
//! // Apply the resource limit to this cgroup.
//! cpu_cgroup.apply(&resources.into())?;
//!
//! // Add tasks to this cgroup.
//! let pid = Pid::from(std::process::id());
//! cpu_cgroup.add_task(pid)?;
//!
//! // Do something ...
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
    parse::{parse, parse_option},
    v1::{self, cgroup::CgroupHelper, Cgroup, CgroupPath, SubsystemKind},
    Error, ErrorKind, Result,
};

/// Handler of a CPU subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Resource limit on how much CPU time a cgroup can use.
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
            ($field: ident, $setter: ident) => {
                if let Some(r) = res.$field {
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

macro_rules! gen_read {
    ($desc: literal, $field: ident, $ty: ty, $parser: ident) => {
        _gen_read!(cpu, Cpu, $desc, $field, $ty, $parser);
    };
}

macro_rules! gen_write {
    ($desc: literal, $field: ident, $setter: ident, $ty: ty, $val: expr) => {
        _gen_write!(cpu, Cpu, $desc, $field, $setter, $ty, $val);
    };
}

impl Subsystem {
    _gen_read!(
        no_ref; cpu, Cpu,
        "the throttling statistics of this cgroup",
        stat,
        Stat,
        parse_stat
    );

    gen_read!("the CPU time shares", shares, u64, parse);

    gen_write!("CPU time shares", shares, set_shares, u64, 2048);

    gen_read!(
        "the total available CPU time within a period (in microseconds)",
        cfs_quota_us,
        i64,
        parse
    );

    gen_write!(
        "total available CPU time within a period (in microseconds)",
        cfs_quota_us,
        set_cfs_quota_us,
        i64,
        500 * 1000
    );

    gen_read!(
        "the length of period (in microseconds)",
        cfs_period_us,
        u64,
        parse
    );

    gen_write!(
        "length of period (in microseconds)",
        cfs_period_us,
        set_cfs_period_us,
        u64,
        1000 * 1000
    );
}

fn parse_stat(reader: impl std::io::Read) -> Result<Stat> {
    use std::io::{BufRead, BufReader};

    let (mut nr_periods, mut nr_throttled, mut throttled_time) = (None, None, None);
    let buf = BufReader::new(reader);

    for line in buf.lines() {
        let line = line?;
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

    match (nr_periods, nr_throttled, throttled_time) {
        (Some(nr_periods), Some(nr_throttled), Some(throttled_time)) => Ok(Stat {
            nr_periods,
            nr_throttled,
            throttled_time,
        }),
        _ => Err(Error::new(ErrorKind::Parse)),
    }
}

impl Into<v1::Resources> for Resources {
    fn into(self) -> v1::Resources {
        v1::Resources {
            cpu: self,
            ..v1::Resources::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subsystem_create_file_exists() -> Result<()> {
        gen_subsystem_test!(Cpu; cpu, ["stat", "shares", "cfs_quota_us", "cfs_period_us"])
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

    #[test]
    fn test_parse_stat() -> Result<()> {
        const CONTENT: &str = "\
nr_periods 256
nr_throttled 8
throttled_time 32
";

        assert_eq!(
            parse_stat(CONTENT.as_bytes())?,
            Stat {
                nr_periods: 256,
                nr_throttled: 8,
                throttled_time: 32
            }
        );

        assert_eq!(parse_stat(&b""[..]).unwrap_err().kind(), ErrorKind::Parse);

        Ok(())
    }
}
