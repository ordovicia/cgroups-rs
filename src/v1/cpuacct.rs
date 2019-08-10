//! Operations on a cpuacct (CPU accounting) subsystem.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/cpuacct.txt](https://www.kernel.org/doc/Documentation/cgroup-v1/cpuacct.txt).

// TODO: module-level doc

use std::path::PathBuf;

use crate::{
    v1::{self, Cgroup, CgroupPath, SubsystemKind},
    Error, ErrorKind, Result,
};

use crate::{
    util::{parse, parse_option, parse_vec},
    v1::cgroup::CgroupHelper,
};

/// Handler of a cpuacct subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Statistics about how much CPU time is consumed by tasks in a cgroup.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// See [`Cgroup.apply()`] for general information.
    ///
    /// [`Cgroup.apply()`]: ../trait.Cgroup.html#tymethod.apply
    fn apply(&mut self, _resource: &v1::Resources, _validate: bool) -> Result<()> {
        Ok(())
    }
}

const STAT_FILE_NAME: &str = "cpuacct.stat";
const USAGE_FILE_NAME: &str = "cpuacct.usage";
const USAGE_ALL_FILE_NAME: &str = "cpuacct.usage_all";
const USAGE_PERCPU_FILE_NAME: &str = "cpuacct.usage_percpu";
const USAGE_PERCPU_SYS_FILE_NAME: &str = "cpuacct.usage_percpu_sys";
const USAGE_PERCPU_USER_FILE_NAME: &str = "cpuacct.usage_percpu_user";
const USAGE_SYS_FILE_NAME: &str = "cpuacct.usage_sys";
const USAGE_USER_FILE_NAME: &str = "cpuacct.usage_user";

#[rustfmt::skip]
macro_rules! gen_doc {
    ($resource: ident) => { concat!(
        "# Errors\n\n",
        "Returns an error if failed to read and parse `cpuacct.", stringify!($resource), "` file of this cgroup.\n\n",
        "# Examples\n\n",
"```no_run
# fn main() -> cgroups::Result<()> {
use std::path::PathBuf;
use cgroups::v1::{cpuacct, Cgroup, CgroupPath, SubsystemKind};

let cgroup = cpuacct::Subsystem::new(
    CgroupPath::new(SubsystemKind::Cpuacct, PathBuf::from(\"students/charlie\")));
let ", stringify!($resource), " = cgroup.", stringify!($resource), "()?;
# Ok(())
# }
```"
        )
    };
}

impl Subsystem {
    with_doc! { concat!(
        "Reads statistics about how much CPU time is consumed by this cgroup, form `cpuacct.stat` ",
        "file. The CPU time is divided into user and system times. The values are in `USER_HZ` ",
        "unit.\n\n",
        gen_doc!(stat)),
        pub fn stat(&self) -> Result<Stat> {
            use std::io::{BufRead, BufReader};

            let (mut system, mut user) = (None, None);

            let buf = BufReader::new(self.open_file_read(STAT_FILE_NAME)?);
            for line in buf.lines() {
                let line = line.map_err(Error::io)?;
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

            if let Some(system) = system {
                if let Some(user) = user {
                    return Ok(Stat { system, user });
                }
            }

            Err(Error::new(ErrorKind::Parse))
        }
    }

    with_doc! { concat!(
        "Reads the total CPU time consumed by this cgroup, from `cpuacct.usage` file.",
        "The value is in nanoseconds.\n\n",
        gen_doc!(usage)),
        pub fn usage(&self) -> Result<u64> {
            self.open_file_read(USAGE_FILE_NAME).and_then(parse)
        }
    }

    with_doc! { concat!(
        "Reads the per-CPU total CPU times consumed by this cgroup, from `cpuacct.usage_all` file.",
        "The CPU times are divided into user and system times. The values are in nanoseconds.\n\n",
        gen_doc!(usage_all)),
        pub fn usage_all(&self) -> Result<Vec<Stat>> {
            use std::io::{BufRead, BufReader};

            let mut buf = BufReader::new(self.open_file_read(USAGE_ALL_FILE_NAME)?);

            let mut header = String::new();
            buf.read_line(&mut header).map_err(Error::parse)?;
            let mut header = header.split_whitespace();

            if !header.next().map(|h| h == "cpu").unwrap_or(false) {
                return Err(Error::new(ErrorKind::Parse));
            }

            let sys_col_num = match (header.next(), header.next()) {
                (Some("user"), Some("system")) => 1, // TODO: are the column order guaranteed ?
                (Some("system"), Some("user")) => 0,
                _ => { return Err(Error::new(ErrorKind::Parse)); }
            };

            let mut stats = Vec::new();
            for line in buf.lines() {
                let entry = line.map_err(Error::io)?;
                let mut entry = entry.split_whitespace().skip(1); // skip CPU ID
                // TODO: are the IDs guaranteed to be sorted ?

                let usage_0 = parse_option(entry.next())?;
                let usage_1 = parse_option(entry.next())?;
                if sys_col_num == 0 {
                    stats.push(Stat { system: usage_0, user: usage_1 });
                } else {
                    stats.push(Stat { system: usage_1, user: usage_0 });
                }
            }

            Ok(stats)
        }
    }

    with_doc! { concat!(
        "Reads the per-CPU total CPU times consumed by this cgroup, from `cpuacct.usage_percpu` ",
        "file. The values are in nanoseconds.\n\n",
        gen_doc!(usage_percpu)),
        pub fn usage_percpu(&self) -> Result<Vec<u64>> {
            self.open_file_read(USAGE_PERCPU_FILE_NAME)
                .and_then(parse_vec)
        }
    }

    with_doc! { concat!(
        "Reads the per-CPU total CPU times consumed by this cgroup in the system (kernel) mode,",
        "from `cpuacct.usage_percpu_sys` file. The values are in nanoseconds.\n\n",
        gen_doc!(usage_percpu_sys)),
        pub fn usage_percpu_sys(&self) -> Result<Vec<u64>> {
            self.open_file_read(USAGE_PERCPU_SYS_FILE_NAME)
                .and_then(parse_vec)
        }
    }

    with_doc! { concat!(
        "Reads the per-CPU total CPU times consumed by this cgroup in the user mode, from",
        "`cpuacct.usage_percpu_sys` file. The values are in nanoseconds.\n\n",
        gen_doc!(usage_percpu_user)),
        pub fn usage_percpu_user(&self) -> Result<Vec<u64>> {
            self.open_file_read(USAGE_PERCPU_USER_FILE_NAME)
                .and_then(parse_vec)
        }
    }

    with_doc! { concat!(
        "Reads the total CPU times consumed by this cgroup in the system (kernel) mode, from",
        "`cpuacct.usage_sys` file. The values are in nanoseconds.\n\n",
        gen_doc!(usage_sys)),
        pub fn usage_sys(&self) -> Result<u64> {
            self.open_file_read(USAGE_SYS_FILE_NAME).and_then(parse)
        }
    }

    with_doc! { concat!(
        "Reads the total CPU times consumed by this cgroup in the user mode, from",
        "`cpuacct.usage_user` file. The values are in nanoseconds.\n\n",
        gen_doc!(usage_user)),
        pub fn usage_user(&self) -> Result<u64> {
            self.open_file_read(USAGE_USER_FILE_NAME)
                .and_then(parse)
        }
    }

    /// Resets the accounted CPU time of this cgroup by writing to `cpuacct.usage` file.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to write to `cpuacct.usage` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpuacct, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let mut cgroup = cpuacct::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpuacct, PathBuf::from("students/charlie")));
    /// cgroup.reset()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn reset(&mut self) -> Result<()> {
        self.write_file(USAGE_FILE_NAME, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subsystem_create_file_exists() -> Result<()> {
        let mut cgroup =
            Subsystem::new(CgroupPath::new(SubsystemKind::Cpuacct, gen_cgroup_name!()));
        cgroup.create()?;

        [
            STAT_FILE_NAME,
            USAGE_FILE_NAME,
            USAGE_ALL_FILE_NAME,
            USAGE_PERCPU_FILE_NAME,
            USAGE_PERCPU_SYS_FILE_NAME,
            USAGE_PERCPU_USER_FILE_NAME,
            USAGE_SYS_FILE_NAME,
            USAGE_USER_FILE_NAME,
        ]
        .iter()
        .all(|f| cgroup.file_exists(f));

        assert!(!cgroup.file_exists("does_not_exist"));

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_stat() -> Result<()> {
        gen_subsystem_test!(Cpuacct; stat, Stat { system: 0, user: 0 })
        // TODO: add task
    }

    #[test]
    fn test_subsystem_usage() -> Result<()> {
        gen_subsystem_test!(Cpuacct; usage, 0)
        // TODO: add task
    }

    #[test]
    fn test_subsystem_usage_all() -> Result<()> {
        gen_subsystem_test!(Cpuacct; usage_all, vec![Stat { system: 0, user: 0}; num_cpus::get()])
        // TODO: add task
    }

    #[test]
    fn test_subsystem_usage_percpu() -> Result<()> {
        gen_subsystem_test!(Cpuacct; usage_percpu, vec![0; num_cpus::get()])
        // TODO: add task
    }

    #[test]
    fn test_subsystem_usage_percpu_sys() -> Result<()> {
        gen_subsystem_test!(Cpuacct; usage_percpu_sys, vec![0; num_cpus::get()])
        // TODO: add task
    }

    #[test]
    fn test_subsystem_usage_percpu_user() -> Result<()> {
        gen_subsystem_test!(Cpuacct; usage_percpu_user, vec![0; num_cpus::get()])
        // TODO: add task
    }

    #[test]
    fn test_subsystem_usage_sys() -> Result<()> {
        gen_subsystem_test!(Cpuacct; usage_sys, 0)
        // TODO: add task
    }

    #[test]
    fn test_subsystem_usage_user() -> Result<()> {
        gen_subsystem_test!(Cpuacct; usage_user, 0)
        // TODO: add task
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
