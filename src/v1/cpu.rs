//! Operations on a CPU subsystem.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/scheduler/sched-design-CFS.txt](https://www.kernel.org/doc/Documentation/scheduler/sched-design-CFS.txt),
//! paragraph 7 ("GROUP SCHEDULER EXTENSIONS TO CFS"), and
//! [Documentation/scheduler/sched-bwc.txt](https://www.kernel.org/doc/Documentation/scheduler/sched-bwc.txt).

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

/// Throttling statistics of a cgroup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    /// Number of periods (as specifiec in `Resources.cfs_period`) that have elapsed.
    pub nr_periods: u64,
    /// Number of times this cgroup has been throttled.
    pub nr_throttled: u64,
    /// Total time duration for which this cgroup has been throttled (in nanoseconds).
    pub throttled_time: u64,
}

/// Resource limits about how CPU time is provided to a cgroup.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// Weight of how much of the total CPU time should be provided to this cgroup.
    pub shares: Option<u64>,
    /// Total available CPU time for this cgroup within a period (in microseconds).
    pub cfs_quota: Option<i64>,
    /// Length of a period (in microseconds).
    pub cfs_period: Option<u64>,
    // pub realtime_runtime: Option<i64>,
    // pub realtime_period: Option<u64>,
}

impl Cgroup for Subsystem {
    fn new(path: CgroupPath) -> Self {
        Self { path }
    }

    fn subsystem_kind(&self) -> SubsystemKind {
        SubsystemKind::Cpu
    }

    fn path(&self) -> PathBuf {
        self.path.to_path_buf()
    }

    fn root_cgroup(&self) -> Box<Self> {
        Box::new(Self::new(self.path.subsystem_root()))
    }

    /// Apply the `Some` fields in `resources.cpu`.
    ///
    /// If `validate` is `true`, this method validates that the resource limits are
    /// correctly set, and returns an error with kind `ErrorKind::Apply` if the validation failed.
    fn apply(&mut self, resources: &v1::Resources, validate: bool) -> Result<()> {
        let res: &self::Resources = &resources.cpu;

        macro_rules! a {
            ($resource: ident, $setter: ident) => {
                if let Some(r) = res.$resource {
                    self.$setter(r)?;
                    if validate && r != self.$resource()? {
                        return Err(Error::new(ErrorKind::Apply));
                    }
                }
            };
        }

        a!(shares, set_shares);
        a!(cfs_period, set_cfs_period);
        a!(cfs_quota, set_cfs_quota);

        Ok(())
    }
}

const STAT_FILE_NAME: &str = "cpu.stat";
const SHARES_FILE_NAME: &str = "cpu.shares";
const CFS_PERIOD_FILE_NAME: &str = "cpu.cfs_period_us";
const CFS_QUOTA_FILE_NAME: &str = "cpu.cfs_quota_us";

impl Subsystem {
    /// Reads throttling statistics of this cgroup from `cpu.stat` file.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to read and parse `cpu.stat` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    /// println!("{:?}", cgroup.stat()?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn stat(&self) -> Result<Stat> {
        use std::io::{BufRead, BufReader};

        let mut nr_periods = None;
        let mut nr_throttled = None;
        let mut throttled_time = None;

        let file = self.open_file_read(STAT_FILE_NAME)?;
        let buf = BufReader::new(file);

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

    /// Reads the CPU time shares of this cgroup from `cpu.shares` file.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to read and parse `cpu.shares` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    /// let shares = cgroup.shares()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn shares(&self) -> Result<u64> {
        self.open_file_read(SHARES_FILE_NAME).and_then(parse)
    }

    /// Sets CPU time shares to this cgroup by writing to `cpu.shares` file.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to write to `cpu.shares` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let mut cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    /// cgroup.set_shares(2048)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_shares(&mut self, shares: u64) -> Result<()> {
        self.write_file(SHARES_FILE_NAME, shares)
    }

    /// Reads the total available CPU time within a period (in microseconds) of this cgroup from
    /// `cpu.cfs_quota_us` file.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to read and parse `cpu.cfs_quota_us` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    /// let cfs_quota = cgroup.cfs_quota()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn cfs_quota(&self) -> Result<i64> {
        self.open_file_read(CFS_QUOTA_FILE_NAME).and_then(parse)
    }

    /// Sets total available CPU time within a period (in microseconds) of this cgroup by
    /// writing to `cpu.cfs_quota_us` file.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to write to `cpu.cfs_quota_us` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let mut cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    /// cgroup.set_cfs_quota(500 * 1000)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_cfs_quota(&mut self, quota_us: i64) -> Result<()> {
        self.write_file(CFS_QUOTA_FILE_NAME, quota_us)
    }

    /// Reads the length of period (in microseconds) of this cgroup from `cpu.cfs_period_us` file.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to read and parse `cpu.cfs_period_us` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    /// let cfs_period = cgroup.cfs_period()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn cfs_period(&self) -> Result<u64> {
        self.open_file_read(CFS_PERIOD_FILE_NAME).and_then(parse)
    }

    /// Sets length of period (in microseconds) of this cgroup by writing to `cpu.cfs_period_us` file.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to write to `cpu.cfs_period_us` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let mut cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    /// cgroup.set_cfs_period(1000 * 1000)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_cfs_period(&mut self, period_us: u64) -> Result<()> {
        self.write_file(CFS_PERIOD_FILE_NAME, period_us)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subsystem_stat() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, make_cgroup_name!()));
        cgroup.create()?;

        assert_eq!(
            cgroup.stat()?,
            Stat {
                nr_periods: 0,
                nr_throttled: 0,
                throttled_time: 0
            }
        );

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_shares() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, make_cgroup_name!()));
        cgroup.create()?;
        assert_eq!(cgroup.shares()?, 1024); // default value

        cgroup.set_shares(2048)?;
        assert_eq!(cgroup.shares()?, 2048);

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_quota() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, make_cgroup_name!()));
        cgroup.create()?;
        assert_eq!(cgroup.cfs_quota()?, -1);

        cgroup.set_cfs_quota(100 * 1000)?;
        assert_eq!(cgroup.cfs_quota()?, 100 * 1000);

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_period() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, make_cgroup_name!()));
        cgroup.create()?;
        assert_eq!(cgroup.cfs_period()?, 100 * 1000); // default value

        cgroup.set_cfs_period(1000 * 1000)?;
        assert_eq!(cgroup.cfs_period()?, 1000 * 1000);

        cgroup.delete()
    }
}
