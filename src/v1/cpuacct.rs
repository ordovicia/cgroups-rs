//! Operations on a cpuacct (CPU accounting) subsystem.
//!
//! [`Subsystem`] implements [`Cgroup`] trait and subsystem-specific operations.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/cpuacct.txt].
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> controlgroup::Result<()> {
//! use std::path::PathBuf;
//! use controlgroup::{Pid, v1::{cpuacct, Cgroup, CgroupPath, SubsystemKind}};
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
//! // Get the statistics about CPU usage.
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
    parse::{parse, parse_next, parse_vec},
    v1::{self, cgroup::CgroupHelper, Cgroup, CgroupPath},
    Error, Result,
};

/// Handler of a Cpuacct subsystem.
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
    Subsystem, Cpuacct,

    /// Does nothing as a Cpuacct subsystem is basically read-only.
    fn apply(&mut self, _resources: &v1::Resources) -> Result<()> {
        Ok(())
    }
}

macro_rules! _gen_getter {
    ($desc: literal $( : $detail: literal )?, $field: ident, $ty: ty, $parser: ident) => {
        gen_getter!(cpuacct, $desc $( : $detail )?, $field, $ty, $parser);
    };
}

impl Subsystem {
    _gen_getter!(
        "the statistics about how much CPU time is consumed by this cgroup (in `USER_HZ` unit)"
        : "The CPU time is further divided into user and system times.",
        stat, Stat, parse_stat
    );

    _gen_getter!(
        "the total CPU time consumed by this cgroup (in nanoseconds)",
        usage,
        u64,
        parse
    );

    _gen_getter!(
        "the per-CPU total CPU time consumed by this cgroup (in nanoseconds)" :
        "The CPU time is further divided into user and system times.",
        usage_all, Vec<Stat>, parse_usage_all
    );

    _gen_getter!(
        "the per-CPU total CPU times consumed by this cgroup (in nanoseconds)",
        usage_percpu,
        Vec<u64>,
        parse_vec
    );

    _gen_getter!(
        "the per-CPU total CPU times consumed by this cgroup
        in the system (kernel) mode (in nanoseconds)",
        usage_percpu_sys,
        Vec<u64>,
        parse_vec
    );

    _gen_getter!(
        "the per-CPU total CPU times consumed by this cgroup in the user mode (in nanoseconds)",
        usage_percpu_user,
        Vec<u64>,
        parse_vec
    );

    _gen_getter!(
        "the total CPU time consumed by this cgroup in the system (kernel) mode (in nanoseconds)",
        usage_sys,
        u64,
        parse
    );

    _gen_getter!(
        "the total CPU time consumed by this cgroup in the user mode (in nanoseconds)",
        usage_user,
        u64,
        parse
    );

    with_doc! { concat!(
        "Resets the accounted CPU time of this cgroup by writing to `cpuacct.usage` file.\n\n",
        gen_doc!(err_write; cpuacct, usage),
        gen_doc!(eg_write; cpuacct, reset)),
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

        match entry.next() {
            Some("system") => {
                if system.is_some() {
                    bail_parse!();
                }
                system = Some(parse_next(&mut entry)?);
            }
            Some("user") => {
                if user.is_some() {
                    bail_parse!();
                }
                user = Some(parse_next(&mut entry)?);
            }
            _ => {
                bail_parse!();
            }
        }

        if entry.next().is_some() {
            bail_parse!();
        }
    }

    match (system, user) {
        (Some(system), Some(user)) => Ok(Stat { system, user }),
        _ => {
            bail_parse!();
        }
    }
}

fn parse_usage_all(reader: impl io::Read) -> Result<Vec<Stat>> {
    let mut buf = io::BufReader::new(reader);

    let mut header = String::new();
    buf.read_line(&mut header).map_err(Error::parse)?;
    let mut header = header.split_whitespace();

    if header.next() != Some("cpu") {
        bail_parse!();
    }

    // FIXME: column order is guaranteed?
    let system_column = match (header.next(), header.next()) {
        (Some("system"), Some("user")) => 0,
        (Some("user"), Some("system")) => 1,
        _ => {
            bail_parse!();
        }
    };

    let mut stats = Vec::new();
    for line in buf.lines() {
        let line = line?;

        let mut entry = line.split_whitespace();

        // FIXME: IDs are guaranteed to be sorted ?
        let _id: u32 = parse_next(&mut entry)?;

        if system_column == 0 {
            stats.push(Stat {
                system: parse_next(&mut entry)?,
                user: parse_next(&mut entry)?,
            });
        } else {
            stats.push(Stat {
                user: parse_next(&mut entry)?,
                system: parse_next(&mut entry)?,
            });
        }

        if entry.next().is_some() {
            bail_parse!();
        }
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;

    #[test]
    #[rustfmt::skip]
    fn test_subsystem_create_file_exists() -> Result<()> {
        gen_subsystem_test!(
            Cpuacct,
            [
                "stat", "usage", "usage_all", "usage_percpu", "usage_percpu_sys",
                "usage_percpu_user", "usage_sys", "usage_user"
            ]
        )
    }

    #[test]
    fn test_subsystem_stat() -> Result<()> {
        gen_subsystem_test!(Cpuacct, stat, Stat { system: 0, user: 0 })
    }

    #[test]
    fn test_subsystem_usage() -> Result<()> {
        gen_subsystem_test!(Cpuacct, usage, 0)
    }

    #[test]
    fn test_subsystem_usage_all() -> Result<()> {
        gen_subsystem_test!(
            Cpuacct,
            usage_all,
            vec![Stat { system: 0, user: 0 }; num_cpus::get()]
        )
    }

    #[test]
    fn test_subsystem_usage_percpu() -> Result<()> {
        gen_subsystem_test!(Cpuacct, usage_percpu, vec![0; num_cpus::get()])
    }

    #[test]
    fn test_subsystem_usage_percpu_sys() -> Result<()> {
        gen_subsystem_test!(Cpuacct, usage_percpu_sys, vec![0; num_cpus::get()])
    }

    #[test]
    fn test_subsystem_usage_percpu_user() -> Result<()> {
        gen_subsystem_test!(Cpuacct, usage_percpu_user, vec![0; num_cpus::get()])
    }

    #[test]
    fn test_subsystem_usage_sys() -> Result<()> {
        gen_subsystem_test!(Cpuacct, usage_sys, 0)
    }

    #[test]
    fn test_subsystem_usage_user() -> Result<()> {
        gen_subsystem_test!(Cpuacct, usage_user, 0)
    }

    #[test]
    fn test_subsystem_reset() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(
            v1::SubsystemKind::Cpuacct,
            gen_cgroup_name!(),
        ));
        cgroup.create()?;

        cgroup.reset()?;
        assert_eq!(cgroup.stat()?, Stat { system: 0, user: 0 });

        cgroup.delete()
    }

    #[test]
    #[ignore] // must not be executed in parallel
    fn test_subsystem_stat_updated() -> Result<()> {
        fn wait(millis: u64) {
            std::thread::sleep(std::time::Duration::from_millis(millis));
        }

        let mut cgroup = Subsystem::new(CgroupPath::new(
            v1::SubsystemKind::Cpuacct,
            gen_cgroup_name!(),
        ));
        cgroup.create()?;

        let pid = crate::Pid::from(std::process::id());
        cgroup.add_proc(pid)?;

        crate::consume_cpu_until(|| cgroup.usage().unwrap() > 0, 30);
        wait(100);
        // dbg!(cgroup.max_usage_all()?);

        let usage = cgroup.usage()?;
        let usage_all = cgroup.usage_all()?;
        let usage_percpu = cgroup.usage_percpu()?;
        let usage_percpu_sys = cgroup.usage_percpu_sys()?;
        let usage_percpu_user = cgroup.usage_percpu_user()?;
        let usage_sys = cgroup.usage_sys()?;
        let usage_user = cgroup.usage_user()?;

        let usage_all_sys_sum = usage_all.iter().map(|u| u.system).sum::<u64>();
        let usage_all_user_sum = usage_all.iter().map(|u| u.user).sum::<u64>();

        let mut failed = false;

        macro_rules! assert_sign {
            ($left: expr, $right: expr) => {{
                let line = line!();
                match ($left, $right) {
                    (left, right) if (left == 0) != (right == 0) => {
                        eprintln!("sign-assertion failed at line {}", line);
                        eprintln!("{}: {}", stringify!($left), left);
                        eprintln!("{}: {}", stringify!($right), right);
                        failed = true;
                    }
                    _ => {}
                }
            }};

            (vec; $left: expr, $right: expr) => {
                let line = line!();
                match ($left, $right) {
                    (left, right) => {
                        if left.iter().all(|e| *e == 0) != right.iter().all(|e| *e == 0) {
                            eprintln!("sign-assertion failed at line {}", line);
                            eprintln!("{}: {:?}", stringify!($left), left);
                            eprintln!("{}: {:?}", stringify!($right), right);
                            failed = true;
                        }
                    }
                }
            };
        }

        assert_sign!(usage, usage_all_sys_sum + usage_all_user_sum);
        assert_sign!(usage_sys, usage_all_sys_sum);
        assert_sign!(usage_user, usage_all_user_sum);
        assert_sign!(
            vec;
            usage_percpu_sys,
            usage_all.iter().map(|u| u.system).collect::<Vec<_>>()
        );
        assert_sign!(
            vec;
            usage_percpu_user,
            usage_all.iter().map(|u| u.user).collect::<Vec<_>>()
        );
        assert_sign!(
            vec;
            usage_percpu,
            usage_all
                .iter()
                .map(|u| u.system + u.user)
                .collect::<Vec<_>>()
        );

        if failed {
            panic!("sign-assertion failed");
        }

        wait(100);
        cgroup.remove_proc(pid)?;

        cgroup.reset()?;
        assert_eq!(cgroup.usage()?, 0);

        cgroup.delete()
    }

    #[test]
    fn tets_parse_stat() -> Result<()> {
        #![allow(clippy::unreadable_literal)]

        const CONTENT_OK: &str = "\
user 9434783
system 2059970
";

        assert_eq!(
            parse_stat(CONTENT_OK.as_bytes())?,
            Stat {
                system: 2059970,
                user: 9434783
            }
        );

        assert_eq!(
            parse_stat("".as_bytes()).unwrap_err().kind(),
            ErrorKind::Parse
        );

        const CONTENT_NG_NOT_INT: &str = "\
user 9434783
system invalid
";

        const CONTENT_NG_MISSING_DATA: &str = "\
user 9434783
";

        const CONTENT_NG_EXTRA_DATA: &str = "\
user 9434783 256
system 2059970
";

        const CONTENT_NG_EXTRA_ROW: &str = "\
user 9434783 256
system 2059970
user 9434783 256
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

    #[test]
    fn test_parse_usage_all() -> Result<()> {
        #![allow(clippy::unreadable_literal)]

        const CONTENT_OK: &str = "\
cpu user system
0 29308474949876 365961153038
1 29360907385495 300617395557
2 29097088553941 333686385015
3 28649065680082 311282670956
";

        assert_eq!(
            parse_usage_all(CONTENT_OK.as_bytes())?,
            vec![
                Stat {
                    user: 29308474949876,
                    system: 365961153038
                },
                Stat {
                    user: 29360907385495,
                    system: 300617395557
                },
                Stat {
                    user: 29097088553941,
                    system: 333686385015
                },
                Stat {
                    user: 28649065680082,
                    system: 311282670956
                },
            ]
        );

        const CONTENT_NG_NOT_INT_0: &str = "\
cpu user system
0 29308474949876 365961153038
1 29360907385495 300617395557
2 29097088553941 invalid
3 28649065680082 311282670956
";

        const CONTENT_NG_NOT_INT_1: &str = "\
cpu user system
invalid 29308474949876 365961153038
1 29360907385495 300617395557
2 29097088553941 333686385015
3 28649065680082 311282670956
";

        const CONTENT_NG_MISSING_DATA: &str = "\
cpu user system
0 29308474949876 365961153038
1 29360907385495
2 29097088553941 333686385015
3 28649065680082 311282670956
";

        const CONTENT_NG_EXTRA_DATA: &str = "\
cpu user system
0 29308474949876 365961153038
1 29360907385495 300617395557 256
2 29097088553941 333686385015
3 28649065680082 311282670956
";

        for case in &[
            CONTENT_NG_NOT_INT_0,
            CONTENT_NG_NOT_INT_1,
            CONTENT_NG_MISSING_DATA,
            CONTENT_NG_EXTRA_DATA,
        ] {
            assert_eq!(
                parse_usage_all(case.as_bytes()).unwrap_err().kind(),
                ErrorKind::Parse
            );
        }

        Ok(())
    }
}
