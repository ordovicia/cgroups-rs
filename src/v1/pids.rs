//! Operations on a pids subsystem.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/pids.txt](https://www.kernel.org/doc/Documentation/cgroup-v1/pids.txt).
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
//! println!("cgroup now has {} processes", pids_cgroup.current()?);
//! println!("cgroup has hit the limit {} times", pids_cgroup.events()?.1);
//!
//! pids_cgroup.remove_task(pid)?;
//! pids_cgroup.delete()?;
//! # Ok(())
//! # }
//! ```

use std::path::PathBuf;

use crate::{
    v1::{self, Cgroup, CgroupPath, SubsystemKind},
    Max, Result,
};

use crate::{
    util::{parse, parse_option},
    v1::cgroup::CgroupHelper,
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

#[rustfmt::skip]
macro_rules! gen_doc {
    ($desc: literal, $resource: ident) => { concat!(
        "Reads ", $desc, " from `pids.", stringify!($resource), "` file.\n\n",
        "See the kernel's documentation for more information about this field.\n\n",
        "# Errors\n\n",
        "Returns an error if failed to read and parse `pids.", stringify!($resource), "` file of this cgroup.\n\n",
        "# Examples\n\n",
"```no_run
# fn main() -> cgroups::Result<()> {
use std::path::PathBuf;
use cgroups::v1::{pids, Cgroup, CgroupPath, SubsystemKind};

let cgroup = pids::Subsystem::new(
    CgroupPath::new(SubsystemKind::Pids, PathBuf::from(\"students/charlie\")));

let ", stringify!($resource), " = cgroup.", stringify!($resource), "()?;
# Ok(())
# }
```") };
}

const MAX: &str = "pids.max";
const CURRENT: &str = "pids.current";
const EVENTS: &str = "pids.events";

impl Subsystem {
    with_doc! {
        gen_doc!("the maximum number of processes this cgroup can have", max),
        pub fn max(&self) -> Result<Max<u32>> {
            self.open_file_read(MAX).and_then(parse)
        }
    }

    /// Sets the maximum number of processes this cgroup can have, by writing to `pids.max` file.
    ///
    /// See the kernel's documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to write to `pids.max` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::{Max, v1::{pids, Cgroup, CgroupPath, SubsystemKind}};
    ///
    /// let mut cgroup = pids::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Pids, PathBuf::from("students/charlie")));
    /// cgroup.set_max(Max::<u32>::Limit(2))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_max(&mut self, max: Max<u32>) -> Result<()> {
        self.write_file(MAX, max)
    }

    with_doc! {
        gen_doc!("the number of processes this cgroup currently has", current),
        pub fn current(&self) -> Result<u32> {
            self.open_file_read(CURRENT).and_then(parse)
        }
    }

    with_doc! {
        gen_doc!(
            "the event counter, i.e. a pair of the maximum number of processes, and the number of times fork failed due to the limit",
            events
        ),
        pub fn events(&self) -> Result<(Max<u32>, u64)> {
            use std::io::Read;

            let mut file = self.open_file_read(EVENTS)?;
            let mut buf = String::new();
            file.read_to_string(&mut buf)?;

            let mut entry = buf.split_whitespace();
            let max = parse_option(entry.next())?;
            let cnt = parse_option(entry.next())?;

            Ok((max, cnt))
        }
    }
}

impl Into<v1::Resources> for Resources {
    fn into(self) -> v1::Resources {
        v1::Resources {
            pids: self,
            ..v1::Resources::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subsystem_create_file_exists() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Pids, gen_cgroup_name!()));
        cgroup.create()?;
        assert!([MAX, CURRENT, EVENTS].iter().all(|f| cgroup.file_exists(f)));
        assert!(!cgroup.file_exists("does_not_exist"));

        cgroup.delete()?;
        assert!([MAX, CURRENT, EVENTS]
            .iter()
            .all(|f| !cgroup.file_exists(f)));

        Ok(())
    }

    #[test]
    fn test_subsystem_max() -> Result<()> {
        gen_subsystem_test!(Pids; max, Max::<u32>::Max, set_max, Max::<u32>::Limit(42))
    }

    #[test]
    fn test_subsystem_current() -> Result<()> {
        use crate::Pid;

        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Pids, gen_cgroup_name!()));
        cgroup.create()?;
        assert_eq!(cgroup.current()?, 0);

        let pid = Pid::from(std::process::id());
        cgroup.add_proc(pid)?;
        assert!(cgroup.current()? > 0);

        cgroup.remove_proc(pid)?;
        std::thread::sleep(std::time::Duration::from_millis(100)); // FIXME: wait for system
        assert_eq!(cgroup.current()?, 0);

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_events() -> Result<()> {
        gen_subsystem_test!(Pids; events, (Max::<u32>::Max, 0))
    }
}
