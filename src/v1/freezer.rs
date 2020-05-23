//! Operations on a Freezer subsystem.
//!
//! [`Subsystem`] implements [`Cgroup`] trait and subsystem-specific operations.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/freezer-subsystem.txt].
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> controlgroup::Result<()> {
//! use std::{path::PathBuf, process::Command};
//! use controlgroup::{Pid, v1::{freezer, Cgroup, CgroupPath, SubsystemKind}};
//!
//! let mut freezer_cgroup = freezer::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::Freezer, PathBuf::from("students/charlie")));
//! freezer_cgroup.create()?;
//!
//! // Add a task to this cgroup.
//! let mut child = Command::new("sleep")
//!                     .arg("10")
//!                     .spawn()
//!                     .expect("command failed");
//! let child_pid = Pid::from(&child);
//! freezer_cgroup.add_task(child_pid)?;
//!
//! freezer_cgroup.freeze()?;
//! // Child process is now frozen.
//!
//! freezer_cgroup.thaw()?;
//! // Child process has been thawed.
//!
//! println!("cgroup is now {}", freezer_cgroup.state()?);
//!
//! freezer_cgroup.remove_task(child_pid)?;
//! freezer_cgroup.delete()?;
//! # Ok(())
//! # }
//! ```
//!
//! [`Subsystem`]: struct.Subsystem.html
//! [`Cgroup`]: ../trait.Cgroup.html
//!
//! [Documentation/cgroup-v1/freezer-subsystem.txt]: https://www.kernel.org/doc/Documentation/cgroup-v1/freezer-subsystem.txt

use std::{fmt, path::PathBuf};

use crate::{
    parse::{parse, parse_01_bool},
    v1::{self, cgroup::CgroupHelper, Cgroup, CgroupPath},
    Error, ErrorKind, Result,
};

/// Handler of a Freezer subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Freeze tasks in a cgroup.
///
/// See the kernel's documentation for more information about the field.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// If `State::Frozen`, tasks in this cgroup will be frozen. If `State::Thawed`, they will be
    /// thawed. Note that applying `State::Freezing` is invalid, and `apply` will raise an error.
    pub state: Option<State>,
}

impl Into<v1::Resources> for Resources {
    fn into(self) -> v1::Resources {
        v1::Resources {
            freezer: self,
            ..v1::Resources::default()
        }
    }
}

/// Freezer state of a cgroup.
///
/// `State` implements [`FromStr`], so you can [`parse`] a string into a `State`. If failed,
/// `parse` returns an error with kind [`ErrorKind::Parse`].
///
/// ```
/// use controlgroup::v1::freezer;
///
/// let thawed = "THAWED".parse::<freezer::State>().unwrap();
/// assert_eq!(thawed, freezer::State::Thawed);
///
/// let freezing = "FREEZING".parse::<freezer::State>().unwrap();
/// assert_eq!(freezing, freezer::State::Freezing);
///
/// let frozen = "FROZEN".parse::<freezer::State>().unwrap();
/// assert_eq!(frozen, freezer::State::Frozen);
/// ```
///
/// `State` also implements [`Display`]. The resulting string is in upper case, as in
/// `freezer.state` file.
///
/// ```
/// use std::string::ToString;
/// use controlgroup::v1::freezer;
///
/// assert_eq!(freezer::State::Thawed.to_string(), "THAWED");
/// assert_eq!(freezer::State::Freezing.to_string(), "FREEZING");
/// assert_eq!(freezer::State::Frozen.to_string(), "FROZEN");
/// ```
///
/// [`FromStr`]: https://doc.rust-lang.org/std/str/trait.FromStr.html
/// [`parse`]: https://doc.rust-lang.org/std/primitive.str.html#method.parse
/// [`ErrorKind::Parse`]: ../../enum.ErrorKind.html#variant.Parse
///
/// [`Display`]: https://doc.rust-lang.org/std/fmt/trait.Display.html
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    /// Tasks in this cgroup are thawed, i.e. not frozen.
    Thawed,
    /// Tasks in this cgroup are in the processes of being frozen.
    Freezing,
    /// Tasks in this cgroup are frozen.
    Frozen,
}

impl std::str::FromStr for State {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "THAWED" => Ok(Self::Thawed),
            "FREEZING" => Ok(Self::Freezing),
            "FROZEN" => Ok(Self::Frozen),
            _ => {
                bail_parse!();
            }
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Thawed => write!(f, "THAWED"),
            Self::Freezing => write!(f, "FREEZING"),
            Self::Frozen => write!(f, "FROZEN"),
        }
    }
}

impl_cgroup! {
    Subsystem, Freezer,

    /// Freezes or thaws tasks in this cgroup according to `resources.freezer.state`.
    ///
    /// Note that only `State::Frozen` and `State::Thawed` are valid. Applying `State::Freezing`
    /// will return an error with kind `ErrorKind::InvalidArgument`.
    fn apply(&mut self, resources: &v1::Resources) -> Result<()> {
        match resources.freezer.state {
            Some(State::Frozen) => self.freeze(),
            Some(State::Thawed) => self.thaw(),
            Some(State::Freezing) => Err(Error::new(ErrorKind::InvalidArgument)),
            None => Ok(())
        }
    }
}

const STATE: &str = "freezer.state";
const SELF_FREEZING: &str = "freezer.self_freezing";
const PARENT_FREEZING: &str = "freezer.parent_freezing";

impl Subsystem {
    /// Reads the current state of this cgroup from `freezer.state` file.
    pub fn state(&self) -> Result<State> {
        self.open_file_read(STATE).and_then(parse)
    }

    /// Reads whether this cgroup itself is frozen or in processes of being frozen, from
    /// `freezer.self_freezing` file.
    pub fn self_freezing(&self) -> Result<bool> {
        self.open_file_read(SELF_FREEZING).and_then(parse_01_bool)
    }

    /// Reads whether any parent of this cgroup is frozen or in processes of being frozen, from
    /// `freezer.parent_freezing` file.
    pub fn parent_freezing(&self) -> Result<bool> {
        self.open_file_read(PARENT_FREEZING).and_then(parse_01_bool)
    }

    /// Freezes tasks in this cgroup by writing to `freezer.state` file.
    pub fn freeze(&mut self) -> Result<()> {
        self.write_file(STATE, State::Frozen)
    }

    /// Thaws, i.e. un-freezes tasks in this cgroup by writing to `freezer.state` file.
    pub fn thaw(&mut self) -> Result<()> {
        self.write_file(STATE, State::Thawed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subsystem_create_file_exists_delete() -> Result<()> {
        gen_test_subsystem_create_delete!(Freezer, STATE, SELF_FREEZING, PARENT_FREEZING)
    }

    #[test]
    fn test_subsystem_apply() -> Result<()> {
        gen_test_subsystem_apply!(
            Freezer,
            Resources {
                state: Some(State::Frozen),
            },
            (state, State::Frozen),
        )
    }

    #[test]
    fn test_subsystem_state_freeze_thaw() -> Result<()> {
        let mut cgroup =
            Subsystem::new(CgroupPath::new(SubsystemKind::Freezer, gen_cgroup_name!()));
        cgroup.create()?;
        assert_eq!(cgroup.state()?, State::Thawed);

        cgroup.freeze()?;
        assert_eq!(cgroup.state()?, State::Frozen);

        cgroup.thaw()?;
        assert_eq!(cgroup.state()?, State::Thawed);

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_self_freezing_freeze_thaw() -> Result<()> {
        let mut cgroup =
            Subsystem::new(CgroupPath::new(SubsystemKind::Freezer, gen_cgroup_name!()));
        cgroup.create()?;
        assert!(!cgroup.self_freezing()?);

        cgroup.freeze()?;
        assert!(cgroup.self_freezing()?);

        cgroup.thaw()?;
        assert!(!cgroup.self_freezing()?);

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_parent_freezing_freeze_thaw() -> Result<()> {
        let name = gen_cgroup_name!();

        let mut child = Subsystem::new(CgroupPath::new(SubsystemKind::Freezer, name.join("child")));
        let mut parent = Subsystem::new(CgroupPath::new(SubsystemKind::Freezer, name));

        parent.create()?;
        child.create()?;

        assert!(!parent.parent_freezing()?);
        assert!(!child.parent_freezing()?);

        parent.freeze()?;
        assert!(child.parent_freezing()?);

        parent.thaw()?;
        assert!(!child.parent_freezing()?);

        child.delete()?;
        parent.delete()
    }
}
