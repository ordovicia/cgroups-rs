use std::{io::Write, path::PathBuf};

use crate::{
    util::{parse_file, parse_option},
    v1::{self, Cgroup, CgroupPath},
    Error, ErrorKind, Result,
};

#[derive(Debug, Clone)]
pub struct Subsystem {
    path: CgroupPath,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    pub shares: Option<u64>,
    pub cfs_quota: Option<i64>,
    pub cfs_period: Option<u64>,
    // pub realtime_runtime: Option<i64>,
    // pub realtime_period: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_time: u64,
}

impl Cgroup for Subsystem {
    fn new(path: CgroupPath) -> Self {
        Self { path }
    }

    // fn subsystem_kind(&self) ->SubsystemKind {
    //     SubsystemKind::Cpu
    // }

    fn path(&self) -> PathBuf {
        self.path.to_path_buf()
    }

    fn root_cgroup(&self) -> Box<Self> {
        Box::new(Self::new(self.path.subsystem_root()))
    }

    fn apply(&mut self, resources: &v1::Resources, validate: bool) -> Result<()> {
        let res: &self::Resources = &resources.cpu;

        macro_rules! a {
            ($resource: ident, $setter: ident) => {
                if let Some(resource) = res.$resource {
                    self.$setter(resource)?;
                    if validate && resource != self.$resource()? {
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
            match entry.next().ok_or(Error::new(ErrorKind::Parse))? {
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

    pub fn shares(&self) -> Result<u64> {
        self.open_file_read(SHARES_FILE_NAME).and_then(parse_file)
    }

    pub fn set_shares(&mut self, shares: u64) -> Result<()> {
        let mut file = self.open_file_write(SHARES_FILE_NAME, false)?;
        write!(file, "{}", shares).map_err(Error::io)
    }

    pub fn cfs_period(&self) -> Result<u64> {
        self.open_file_read(CFS_PERIOD_FILE_NAME)
            .and_then(parse_file)
    }

    pub fn set_cfs_period(&mut self, us: u64) -> Result<()> {
        let mut file = self.open_file_write(CFS_PERIOD_FILE_NAME, false)?;
        write!(file, "{}", us).map_err(Error::io)
    }

    pub fn cfs_quota(&self) -> Result<i64> {
        self.open_file_read(CFS_QUOTA_FILE_NAME)
            .and_then(parse_file)
    }

    pub fn set_cfs_quota(&mut self, us: i64) -> Result<()> {
        let mut file = self.open_file_write(CFS_QUOTA_FILE_NAME, false)?;
        write!(file, "{}", us).map_err(Error::io)
    }
}
