//! Operations on a cpuacct (CPU accounting) subsystem.
//!
//! [`Subsystem`] implements [`Cgroup`] trait and subsystem-specific behaviors.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/cpuacct.txt].
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! use std::path::PathBuf;
//! use cgroups::{Pid, v1::{cpuacct, Cgroup, CgroupPath, SubsystemKind}};
//!
//! let mut cpuacct_cgroup = cpuacct::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::Cpuacct, PathBuf::from("students/charlie")));
//! cpuacct_cgroup.create()?;
//!
//! // Add a task to this cgroup to monitor CPU usage.
//! let pid = Pid::from(std::process::id());
//! cpuacct_cgroup.add_task(pid)?;
//!
//! // Do something ...
//!
//! // Get the statistics on CPU usage.
//! let stat_hz = cpuacct_cgroup.stat()?;
//! println!(
//!     "cgroup used {} USER_HZ in system mode, {} USER_HZ in user mode.",
//!     stat_hz.system, stat_hz.user
//! );
//!
//! cpuacct_cgroup.remove_task(pid)?;
//! cpuacct_cgroup.delete()?;
//! # Ok(())
//! # }
//! ```
//!
//! [`Subsystem`]: struct.Subsystem.html
//! [`Cgroup`]: ../trait.Cgroup.html
//!
//! [Documentation/cgroup-v1/cpuacct.txt]: https://www.kernel.org/doc/Documentation/cgroup-v1/cpuacct.txt

use std::{
    io::{self, BufRead},
    path::PathBuf,
};

use crate::{
    parse::{parse, parse_option, parse_vec},
    v1::{self, cgroup::CgroupHelper, Cgroup, CgroupPath, SubsystemKind},
    Error, ErrorKind, Result,
};

/// Handler of a cpuacct subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Statistics about how much CPU time is consumed by tasks in a cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    /// CPU time consumed in the system (kernel) mode.
    pub system: u64,
    /// CPU time consumed in the user mode.
    pub user: u64,
}

impl_cgroup! {
    Cpuacct,

    /// Does nothing as a cpuacct subsystem is basically read-only.
    ///
    /// See [`Cgroup::apply`] for general information.
    ///
    /// [`Cgroup::apply`]: ../trait.Cgroup.html#tymethod.apply
    fn apply(&mut self, _resources: &v1::Resources) -> Result<()> {
        Ok(())
    }
}

macro_rules! _gen_reader {
    ($desc: literal $( : $detail: literal )?, $field: ident, $ty: ty, $parser: ident) => {
        gen_reader!(cpuacct, Cpuacct, $desc $( : $detail )?, $field, $ty, $parser);
    };
}

impl Subsystem {
    _gen_reader!(
        "statistics about how much CPU time is consumed by this cgroup (in `USER_HZ` unit)" :
        "The CPU time is further divided into user and system times.",
        stat, Stat, parse_stat
    );

    _gen_reader!(
        "the total CPU time consumed by this cgroup (in nanoseconds)",
        usage,
        u64,
        parse
    );

    _gen_reader!(
        "the per-CPU total CPU time consumed by this cgroup (in nanoseconds)" :
        "The CPU time is further divided into user and system times.",
        usage_all, Vec<Stat>, parse_usage_all
    );

    _gen_reader!(
        "the per-CPU total CPU times consumed by this cgroup (in nanoseconds)",
        usage_percpu,
        Vec<u64>,
        parse_vec
    );

    _gen_reader!(
        "the per-CPU total CPU times consumed by this cgroup in the system (kernel) mode (in nanoseconds)",
        usage_percpu_sys, Vec<u64>, parse_vec
    );

    _gen_reader!(
        "the per-CPU total CPU times consumed by this cgroup in the user mode (in nanoseconds)",
        usage_percpu_user,
        Vec<u64>,
        parse_vec
    );

    _gen_reader!(
        "the total CPU time consumed by this cgroup in the system (kernel) mode (in nanoseconds)",
        usage_sys,
        u64,
        parse
    );

    _gen_reader!(
        "the total CPU time consumed by this cgroup in the user mode (in nanoseconds)",
        usage_user,
        u64,
        parse
    );

    with_doc! { concat!(
        "Resets the accounted CPU time of this cgroup by writing to `cpuacct.usage` file.\n\n",
        gen_doc!(err_write; cpuacct, usage),
        gen_doc!(eg_write; cpuacct, Cpuacct, reset)),
        pub fn reset(&mut self) -> Result<()> {
            self.write_file("cpuacct.usage", 0)
        }
    }
}

fn parse_stat(reader: impl io::Read) -> Result<Stat> {
    let (mut system, mut user) = (None, None);
    let buf = io::BufReader::new(reader);

    for line in buf.lines() {
        let line = line?;
        let mut entry = line.split_whitespace();

        match entry.next().ok_or_else(|| Error::new(ErrorKind::Parse))? {
            "system" => {
                system = Some(parse_option(entry.next())?);
            }
            "user" => {
                user = Some(parse_option(entry.next())?);
            }
            _ => return Err(Error::new(ErrorKind::Parse)),
        }
    }

    match (system, user) {
        (Some(system), Some(user)) => Ok(Stat { system, user }),
        _ => Err(Error::new(ErrorKind::Parse)),
    }
}

fn parse_usage_all(reader: impl io::Read) -> Result<Vec<Stat>> {
    let mut buf = io::BufReader::new(reader);

    let mut header = String::new();
    buf.read_line(&mut header).map_err(Error::parse)?;
    let mut header = header.split_whitespace();

    if !header.next().map(|h| h == "cpu").unwrap_or(false) {
        return Err(Error::new(ErrorKind::Parse));
    }

    let sys_col_num = match (header.next(), header.next()) {
        (Some("user"), Some("system")) => 1, // FIXME: column order is guaranteed ?
        (Some("system"), Some("user")) => 0,
        _ => {
            return Err(Error::new(ErrorKind::Parse));
        }
    };

    let mut stats = Vec::new();
    for line in buf.lines() {
        let line = line?;
        let mut entry = line.split_whitespace().skip(1); // skip CPU ID
                                                         // FIXME: IDs are guaranteed to be sorted ?

        let usage_0 = parse_option(entry.next())?;
        let usage_1 = parse_option(entry.next())?;
        if sys_col_num == 0 {
            stats.push(Stat {
                system: usage_0,
                user: usage_1,
            });
        } else {
            stats.push(Stat {
                system: usage_1,
                user: usage_0,
            });
        }
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subsystem_create_file_exists() -> Result<()> {
        gen_subsystem_test!(
            Cpuacct; cpuacct,
            [
                "stat", "usage", "usage_all", "usage_percpu", "usage_percpu_sys",
                "usage_percpu_user", "usage_sys", "usage_user"
            ]
        )
    }

    // TODO: test adding tasks

    #[test]
    fn test_subsystem_stat() -> Result<()> {
        gen_subsystem_test!(Cpuacct; stat, Stat { system: 0, user: 0 })
    }

    #[test]
    fn test_subsystem_usage() -> Result<()> {
        gen_subsystem_test!(Cpuacct; usage, 0)
    }

    #[test]
    fn test_subsystem_usage_all() -> Result<()> {
        gen_subsystem_test!(Cpuacct; usage_all, vec![Stat { system: 0, user: 0}; num_cpus::get()])
    }

    #[test]
    fn test_subsystem_usage_percpu() -> Result<()> {
        gen_subsystem_test!(Cpuacct; usage_percpu, vec![0; num_cpus::get()])
    }

    #[test]
    fn test_subsystem_usage_percpu_sys() -> Result<()> {
        gen_subsystem_test!(Cpuacct; usage_percpu_sys, vec![0; num_cpus::get()])
    }

    #[test]
    fn test_subsystem_usage_percpu_user() -> Result<()> {
        gen_subsystem_test!(Cpuacct; usage_percpu_user, vec![0; num_cpus::get()])
    }

    #[test]
    fn test_subsystem_usage_sys() -> Result<()> {
        gen_subsystem_test!(Cpuacct; usage_sys, 0)
    }

    #[test]
    fn test_subsystem_usage_user() -> Result<()> {
        gen_subsystem_test!(Cpuacct; usage_user, 0)
    }

    #[test]
    fn test_subsystem_reset() -> Result<()> {
        let mut cgroup =
            Subsystem::new(CgroupPath::new(SubsystemKind::Cpuacct, gen_cgroup_name!()));
        cgroup.create()?;

        cgroup.reset()?;
        assert_eq!(cgroup.stat()?, Stat { system: 0, user: 0 });

        cgroup.delete()
    }
}
