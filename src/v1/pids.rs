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
//! use cgroups::{Pid, v1::{pids, Cgroup, CgroupPath, SubsystemKind}};
//!
//! let mut pids_cgroup = pids::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::Pids, PathBuf::from("students/charlie")));
//! pids_cgroup.create()?;
//!
//! // Limit the maximum number of processes this cgroup can have.
//! pids_cgroup.set_max(pids::Max::Number(42))?;
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

use std::{fmt, path::PathBuf};

use crate::{
    v1::{self, Cgroup, CgroupPath, SubsystemKind},
    Error, Result,
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

/// Limit on the number of processes a cgroup can have.
///
/// `Max` implements [`FromStr`], so you can [`parse`] a string into a `Max`. If failed,
/// `parse` returns an error with kind [`ErrorKind::Parse`].
///
/// ```
/// use cgroups::v1::pids;
///
/// let max = "max".parse::<pids::Max>().unwrap();
/// assert_eq!(max, pids::Max::Max);
///
/// let num = "42".parse::<pids::Max>().unwrap();
/// assert_eq!(num, pids::Max::Number(42));
/// ```
///
/// `Max` also implements [`Display`]. The resulting format is same as in `pids.max` file.
///
/// ```
/// use std::string::ToString;
/// use cgroups::v1::pids;
///
/// assert_eq!(pids::Max::Max.to_string(), "max");
/// assert_eq!(pids::Max::Number(42).to_string(), "42");
/// ```
///
/// `Max` implements [`Default`]. The default value is `Max::Max`, same as the value a cgroup has
/// when created.
///
/// ```
/// use cgroups::v1::pids;
///
/// assert_eq!(pids::Max::default(), pids::Max::Max);
/// ```
///
/// [`FromStr`]: https://doc.rust-lang.org/std/str/trait.FromStr.html
/// [`parse`]: https://doc.rust-lang.org/std/primitive.str.html#method.parse
/// [`ErrorKind::Parse`]: ../../enum.ErrorKind.html#variant.Parse
///
/// [`Display`]: https://doc.rust-lang.org/std/fmt/trait.Display.html
///
/// [`Default`]: https://doc.rust-lang.org/std/default/trait.Default.html
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Max {
    /// Not limit the number of processes this cgroup can have.
    Max,
    /// Limits the number of processes this cgroup can have to this number.
    Number(u32),
}

/// How many processes a cgroup can have.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// If `Max::Max`, the system does not limit the number of processes this cgroup can have. If
    /// `Max::Number(n)`, this cgroup can have `n` processes at most.
    pub max: Option<Max>,
}

impl_cgroup! {
    Pids,

    /// Sets a maximum number of processes this cgroup can have according to `resources.pids.max`.
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
        pub fn max(&self) -> Result<Max> {
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
    /// use cgroups::v1::{pids, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let mut cgroup = pids::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Pids, PathBuf::from("students/charlie")));
    /// cgroup.set_max(pids::Max::from(2))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_max(&mut self, max: Max) -> Result<()> {
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
        pub fn events(&self) -> Result<(Max, u64)> {
            use std::io::Read;

            let mut file = self.open_file_read(EVENTS)?;
            let mut buf = String::new();
            file.read_to_string(&mut buf).map_err(Error::io)?;

            let mut entry = buf.split_whitespace();
            let max = parse_option(entry.next())?;
            let cnt = parse_option(entry.next())?;

            Ok((max, cnt))
        }
    }
}

impl Default for Max {
    fn default() -> Self {
        Max::Max
    }
}

impl From<u32> for Max {
    fn from(n: u32) -> Self {
        Max::Number(n)
    }
}

impl std::str::FromStr for Max {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "max" => Ok(Max::Max),
            n => {
                let n = n.parse().map_err(Error::parse)?;
                Ok(Max::Number(n))
            }
        }
    }
}

impl fmt::Display for Max {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Max::Max => write!(f, "max"),
            Max::Number(n) => write!(f, "{}", n),
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

        [MAX, CURRENT, EVENTS].iter().all(|n| cgroup.file_exists(n));

        assert!(!cgroup.file_exists("does_not_exist"));

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_max() -> Result<()> {
        gen_subsystem_test!(Pids; max, Max::Max, set_max, Max::Number(42))
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
        gen_subsystem_test!(Pids; events, (Max::Max, 0))
    }
}
