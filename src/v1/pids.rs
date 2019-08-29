//! Operations on a pids subsystem.
//!
//! [`Subsystem`] implements [`Cgroup`] trait and subsystem-specific behaviors.
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
    parse::{parse, parse_option},
    v1::{self, cgroup::CgroupHelper, Cgroup, CgroupPath, SubsystemKind},
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
    /// If `Max::Max`, the system does not limit the number of processes this cgroup can have. If
    /// `Max::Limit(n)`, this cgroup can have `n` processes at most.
    pub max: Option<Max<u32>>,
}

impl_cgroup! {
    Pids,

    /// Applies the `Some` fields in `resources.pids`.
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

macro_rules! _gen_getter {
    ($desc: literal, $field: ident $( : $link : ident )?, $ty: ty, $parser: ident) => {
        gen_getter!(pids, Pids, $desc, $field $( : $link )?, $ty, $parser);
    };
}

impl Subsystem {
    _gen_getter!(
        "the maximum number of processes this cgroup can have",
        max: link,
        Max<u32>,
        parse
    );

    gen_setter!(
        pids,
        Pids,
        "a maximum number of processes this cgroup can have,",
        max: link,
        set_max,
        Max<u32>,
        cgroups::Max::<u32>::Limit(2)
    );

    _gen_getter!(
        "the number of processes this cgroup currently has",
        current,
        u32,
        parse
    );

    _gen_getter!(
        "the event counter, i.e. a pair of the maximum number of processes, and the number of times fork failed due to the limit",
        events, (Max<u32>, u64), parse_events
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

fn parse_events(mut reader: impl std::io::Read) -> Result<(Max<u32>, u64)> {
    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;

    let mut entry = buf.split_whitespace();
    let max = parse_option(entry.next())?;
    let cnt = parse_option(entry.next())?;

    Ok((max, cnt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subsystem_create_file_exists() -> Result<()> {
        gen_subsystem_test!(Pids; pids, ["max", "current", "events"])
    }

    #[test]
    fn test_subsystem_max() -> Result<()> {
        gen_subsystem_test!(Pids; max, Max::<u32>::Max, set_max, Max::<u32>::Limit(42))
    }

    #[test]
    #[ignore] // `cargo test` must not be executed in parallel for this test
    fn test_subsystem_current() -> Result<()> {
        use crate::Pid;

        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Pids, gen_cgroup_name!()));
        cgroup.create()?;
        assert_eq!(cgroup.current()?, 0);

        let pid = Pid::from(std::process::id());
        cgroup.add_proc(pid)?;
        assert!(cgroup.current()? > 0);

        cgroup.remove_proc(pid)?;
        assert_eq!(cgroup.current()?, 0);

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_events() -> Result<()> {
        gen_subsystem_test!(Pids; events, (Max::<u32>::Max, 0))
    }
}
