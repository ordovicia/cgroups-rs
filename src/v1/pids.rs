//! Operations on a pids subsystem.
//!
//! [`Subsystem`] implements [`Cgroup`] trait and subsystem-specific operations.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/pids.txt].
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! use std::path::PathBuf;
//! use cgroups::{Pid, Max, v1::{pids, Cgroup, CgroupPath, SubsystemKind}};
//!
//! let mut pids_cgroup = pids::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::Pids, PathBuf::from("students/charlie")));
//! pids_cgroup.create()?;
//!
//! // Limit the maximum number of processes this cgroup can have.
//! pids_cgroup.set_max(Max::Limit(42))?;
//!
//! // Add a task to this cgroup.
//! let pid = Pid::from(std::process::id());
//! pids_cgroup.add_task(pid)?;
//!
//! // Do something ...
//!
//! println!("cgroup now has {} processes", pids_cgroup.current()?);
//! println!("cgroup has hit the limit {} times", pids_cgroup.events()?.1);
//!
//! pids_cgroup.remove_task(pid)?;
//! pids_cgroup.delete()?;
//! # Ok(())
//! # }
//! ```
//!
//! [`Subsystem`]: struct.Subsystem.html
//! [`Cgroup`]: ../trait.Cgroup.html
//!
//! [Documentation/cgroup-v1/pids.txt]: https://www.kernel.org/doc/Documentation/cgroup-v1/pids.txt

use std::path::PathBuf;

use crate::{
    parse::{parse, parse_next},
    v1::{self, cgroup::CgroupHelper, Cgroup, CgroupPath},
    Max, Result,
};

/// Handler of a pids subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Resource limit on how many processes a cgroup can have.
///
/// See the kernel's documentation for more information about the fields.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// If [`Max::Max`], the system does not limit the number of processes this cgroup can have. If
    /// [`Max::Limit(n)`], this cgroup can have `n` processes at most.
    ///
    /// [`Max::Max`]: ../../enum.Max.html#variant.Max
    /// [`Max::Limit(n)`]: ../../enum.Max.html#variant.Limit
    pub max: Option<Max>,
}

impl_cgroup! {
    Subsystem, Pids,

    /// Applies `resources.pids.max` if it is `Some`.
    ///
    /// See [`Cgroup::apply`] method for general information.
    ///
    /// [`Cgroup::apply`]: ../trait.Cgroup.html#tymethod.apply
    fn apply(&mut self, resources: &v1::Resources) -> Result<()> {
        if let Some(max) = resources.pids.max {
            self.set_max(max)?;
        }

        Ok(())
    }
}

impl Subsystem {
    gen_getter!(
        pids,
        "the maximum number of processes this cgroup can have",
        max: link,
        Max,
        parse
    );

    gen_setter!(
        pids,
        "a maximum number of processes this cgroup can have,",
        max: link,
        set_max,
        Max,
        cgroups::Max::Limit(2)
    );

    gen_getter!(
        pids,
        "the number of processes this cgroup currently has",
        current,
        u32,
        parse
    );

    gen_getter!(
        pids,
        "the event counter, i.e. a pair of the maximum number of processes, 
        and the number of times fork failed due to the limit",
        events,
        (Max, u64),
        parse_events
    );
}

impl Into<v1::Resources> for Resources {
    fn into(self) -> v1::Resources {
        v1::Resources {
            pids: self,
            ..v1::Resources::default()
        }
    }
}

fn parse_events(mut reader: impl std::io::Read) -> Result<(Max, u64)> {
    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;

    let mut entry = buf.split_whitespace();
    let max = parse_next(&mut entry)?;
    let cnt = parse_next(&mut entry)?;

    if entry.next().is_some() {
        bail_parse!();
    }

    Ok((max, cnt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subsystem_create_file_exists() -> Result<()> {
        gen_subsystem_test!(Pids, ["max", "current", "events"])
    }

    #[test]
    fn test_subsystem_max() -> Result<()> {
        gen_subsystem_test!(Pids, max, Max::Max, set_max, Max::Limit(42))
    }

    #[test]
    #[ignore] // must not be executed in parallel
    fn test_subsystem_current() -> Result<()> {
        let mut cgroup =
            Subsystem::new(CgroupPath::new(v1::SubsystemKind::Pids, gen_cgroup_name!()));
        cgroup.create()?;
        assert_eq!(cgroup.current()?, 0);

        let pid = crate::Pid::from(std::process::id());
        cgroup.add_proc(pid)?;
        assert!(cgroup.current()? > 0);

        cgroup.remove_proc(pid)?;
        assert_eq!(cgroup.current()?, 0);

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_events() -> Result<()> {
        gen_subsystem_test!(Pids, events, (Max::Max, 0))
    }

    #[test]
    fn test_parse_events() -> Result<()> {
        const CONTENT_OK_MAX: &str = "max 0\n";
        assert_eq!(
            parse_events(CONTENT_OK_MAX.as_bytes())?,
            (Max::Max, 0)
        );

        const CONTENT_OK_LIM: &str = "42 7\n";
        assert_eq!(
            parse_events(CONTENT_OK_LIM.as_bytes())?,
            (Max::Limit(42), 7)
        );

        const CONTENT_NG_MAX: &str = "invalid 0\n";
        const CONTENT_NG_LIM: &str = "max invalid\n";
        const CONTENT_NG_MISSING_DATA: &str = "42\n";
        const CONTENT_NG_EXTRA_DATA: &str = "max 0 invalid\n";

        for case in &[
            CONTENT_NG_MAX,
            CONTENT_NG_LIM,
            CONTENT_NG_MISSING_DATA,
            CONTENT_NG_EXTRA_DATA,
            "",
        ] {
            assert_eq!(
                parse_events(case.as_bytes()).unwrap_err().kind(),
                crate::ErrorKind::Parse
            );
        }

        Ok(())
    }
}
