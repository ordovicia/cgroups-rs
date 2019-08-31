//! Operations on a CPU subsystem.
//!
//! [`Subsystem`] implements [`Cgroup`] trait and subsystem-specific operations.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/scheduler/sched-design-CFS.txt]
//! paragraph 7 ("GROUP SCHEDULER EXTENSIONS TO CFS"), and [Documentation/scheduler/sched-bwc.txt].
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
//!     cfs_period_us: Some(1_000_000),
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
//!
//! [`Subsystem`]: struct.Subsystem.html
//! [`Cgroup`]: ../trait.Cgroup.html
//!
//! [Documentation/scheduler/sched-design-CFS.txt]: https://www.kernel.org/doc/Documentation/scheduler/sched-design-CFS.txt
//! [Documentation/scheduler/sched-bwc.txt]: https://www.kernel.org/doc/Documentation/scheduler/sched-bwc.txt

use std::path::PathBuf;

use crate::{
    parse::{parse, parse_next},
    v1::{self, cgroup::CgroupHelper, Cgroup, CgroupPath},
    Result,
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
    ///
    /// Setting -1 removes the current limit.
    pub cfs_quota_us: Option<i64>,
    /// Length of a period (in microseconds).
    pub cfs_period_us: Option<u64>,
    // TODO: realtime support
    // pub realtime_runtime: Option<i64>,
    // pub realtime_period: Option<u64>,
}

/// Throttling statistics of a cgroup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    /// Number of periods (as specified in [`Resources.cfs_period_us`]) that have elapsed.
    ///
    /// [`Resources.cfs_period_us`]: struct.Resources.html#structfield.cfs_period_us
    pub nr_periods: u64,
    /// Number of times this cgroup has been throttled.
    pub nr_throttled: u64,
    /// Total time duration for which this cgroup has been throttled (in nanoseconds).
    pub throttled_time: u64,
}

impl_cgroup! {
    Subsystem, Cpu,

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

impl Subsystem {
    gen_getter!(
        cpu,
        "the throttling statistics of this cgroup",
        stat,
        Stat,
        parse_stat
    );

    gen_getter!(cpu, "the CPU time shares", shares: link, u64, parse);
    gen_setter!(cpu, "CPU time shares", shares: link, set_shares, u64, 2048);

    gen_getter!(
        cpu,
        "the total available CPU time within a period (in microseconds)",
        cfs_quota_us: link,
        i64,
        parse
    );
    gen_setter!(
        cpu, "total available CPU time within a period (in microseconds)"
        : "Setting -1 removes the current limit.",
        cfs_quota_us : link, set_cfs_quota_us, quota: i64, 500 * 1000
    );

    gen_getter!(
        cpu,
        "the length of period (in microseconds)",
        cfs_period_us: link,
        u64,
        parse
    );
    gen_setter!(
        cpu,
        "length of period (in microseconds)",
        cfs_period_us: link,
        set_cfs_period_us,
        period: u64,
        1000 * 1000
    );
}

fn parse_stat(reader: impl std::io::Read) -> Result<Stat> {
    use std::io::{BufRead, BufReader};

    let (mut nr_periods, mut nr_throttled, mut throttled_time) = (None, None, None);

    for line in BufReader::new(reader).lines() {
        let line = line?;
        let mut entry = line.split_whitespace();

        match entry.next() {
            Some("nr_periods") => {
                if nr_periods.is_some() {
                    bail_parse!();
                }
                nr_periods = Some(parse_next(entry.by_ref())?);
            }
            Some("nr_throttled") => {
                if nr_throttled.is_some() {
                    bail_parse!();
                }
                nr_throttled = Some(parse_next(entry.by_ref())?);
            }
            Some("throttled_time") => {
                if throttled_time.is_some() {
                    bail_parse!();
                }
                throttled_time = Some(parse_next(entry.by_ref())?);
            }
            _ => bail_parse!(),
        };

        if entry.next().is_some() {
            bail_parse!();
        }
    }

    match (nr_periods, nr_throttled, throttled_time) {
        (Some(nr_periods), Some(nr_throttled), Some(throttled_time)) => Ok(Stat {
            nr_periods,
            nr_throttled,
            throttled_time,
        }),
        _ => {
            bail_parse!();
        }
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
    use crate::ErrorKind;

    #[test]
    fn test_subsystem_create_file_exists() -> Result<()> {
        gen_subsystem_test!(Cpu, ["stat", "shares", "cfs_quota_us", "cfs_period_us"])
    }

    #[test]
    fn test_subsystem_stat() -> Result<()> {
        gen_subsystem_test!(
            Cpu,
            stat,
            Stat {
                nr_periods: 0,
                nr_throttled: 0,
                throttled_time: 0
            }
        )
    }

    #[test]
    #[ignore] // must not executed in parallel
    fn test_subsystem_stat_throttled() -> Result<()> {
        let mut cgroup =
            Subsystem::new(CgroupPath::new(v1::SubsystemKind::Cpu, gen_cgroup_name!()));
        cgroup.create()?;

        let pid = crate::Pid::from(std::process::id());
        cgroup.add_proc(pid)?;

        cgroup.set_cfs_quota_us(1000)?; // 1%

        crate::consume_cpu_until(|| cgroup.stat().unwrap().nr_throttled > 0, 10);
        // dbg!(cgroup.stat()?);

        let stat = cgroup.stat()?;
        assert!(stat.nr_periods > 0);
        assert!(stat.throttled_time > 0);

        cgroup.remove_proc(pid)?;
        cgroup.delete()
    }

    #[test]
    fn test_subsystem_shares() -> Result<()> {
        gen_subsystem_test!(Cpu, shares, 1024, set_shares, 2048)
    }

    #[test]
    fn test_subsystem_cfs_quota_us() -> Result<()> {
        gen_subsystem_test!(Cpu, cfs_quota_us, -1, set_cfs_quota_us, 100 * 1000)
    }

    #[test]
    fn test_subsystem_cfs_period_us() -> Result<()> {
        gen_subsystem_test!(
            Cpu,
            cfs_period_us,
            100 * 1000,
            set_cfs_period_us,
            1000 * 1000
        )
    }

    #[test]
    fn test_parse_stat() -> Result<()> {
        const CONTENT_OK: &str = "\
nr_periods 256
nr_throttled 8
throttled_time 32
";

        assert_eq!(
            parse_stat(CONTENT_OK.as_bytes())?,
            Stat {
                nr_periods: 256,
                nr_throttled: 8,
                throttled_time: 32
            }
        );

        assert_eq!(
            parse_stat("".as_bytes()).unwrap_err().kind(),
            ErrorKind::Parse
        );

        const CONTENT_NG_NOT_INT: &str = "\
nr_periods invalid
nr_throttled 8
throttled_time 32
";

        const CONTENT_NG_MISSING_DATA: &str = "\
nr_periods 256
throttled_time 32
";

        const CONTENT_NG_EXTRA_DATA: &str = "\
nr_periods 256
nr_throttled 8 256
throttled_time 32
";

        const CONTENT_NG_EXTRA_ROW: &str = "\
nr_periods 256
nr_throttled 8 
throttled_time 32
invalid 256
";

        for case in &[
            CONTENT_NG_NOT_INT,
            CONTENT_NG_MISSING_DATA,
            CONTENT_NG_EXTRA_DATA,
            CONTENT_NG_EXTRA_ROW,
        ] {
            assert_eq!(
                parse_stat(case.as_bytes()).unwrap_err().kind(),
                ErrorKind::Parse
            );
        }

        Ok(())
    }
}
