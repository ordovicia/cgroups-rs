//! Operations on a freezer subsystem.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/freezer-subsystem.txt](https://www.kernel.org/doc/Documentation/cgroup-v1/freezer-subsystem.txt).

// TODO: module-level doc

use std::{fmt, path::PathBuf};

use crate::{
    v1::{self, Cgroup, CgroupPath, SubsystemKind},
    Error, ErrorKind, Result,
};

use crate::{
    util::{parse, parse_01_bool},
    v1::cgroup::CgroupHelper,
};

/// Handler of a freezer subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Freezer state of a cgroup.
///
/// `State` implements [`FromStr`], so you can [`parse()`] a string into a `State`. If failed,
/// `parse()` returns an error with kind [`ErrorKind::Parse`].
///
/// ```
/// use cgroups::v1::freezer;
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
/// use cgroups::v1::freezer;
///
/// assert_eq!(freezer::State::Thawed.to_string(), "THAWED");
/// assert_eq!(freezer::State::Freezing.to_string(), "FREEZING");
/// assert_eq!(freezer::State::Frozen.to_string(), "FROZEN");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Tasks in this cgroup are thawed, i.e. not frozen.
    Thawed,
    /// Tasks in this cgroup are in the processes of being frozen.
    Freezing,
    /// Tasks in this cgroup are frozen.
    Frozen,
}

/// Whether tasks in a cgruop is freezed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// If `State::Frozen`, tasks in this cgroup will be frozen. If `State::Thawed`, they will be
    /// thawed. Note that applying `State::Freezing` is invalid, and `apply()` will raise an error.
    state: Option<State>,
}

impl_cgroup! {
    Freezer,

    /// Freeze or thaw tasks in this cgroup according to `resource.freezer.state`.
    ///
    /// Note that only `State::Frozen` and `State::Thawed` are valid. Applying `State::Freezing`
    /// will return an error with kind [`ErrorKind::InvalidArgument`].
    ///
    /// See [`Cgroup.apply()`] for general information.
    ///
    /// [`ErrorKind::InvalidArgument`]: ../../enum.ErrorKind.html#variant.InvalidArgument
    /// [`Cgroup.apply()`]: ../trait.Cgroup.html#tymethod.apply
    fn apply(&mut self, resource: &v1::Resources, validate: bool) -> Result<()> {
        use State::*;

        match resource.freezer.state {
            Some(Frozen) => {
                self.freeze()?;
                if validate && !self.self_freezing()? {
                    return Err(Error::new(ErrorKind::Apply));
                }
            }
            Some(Thawed) => {
                self.thaw()?;
                if validate && self.self_freezing()? {
                    return Err(Error::new(ErrorKind::Apply));
                }
            }
            Some(Freezing) => return Err(Error::new(ErrorKind::InvalidArgument)),
            _ => {}
        }

        Ok(())
    }
}

#[rustfmt::skip]
macro_rules! gen_doc {
    (reads; $desc: literal, $resource: ident) => { concat!(
        "Reads ", $desc, " from `freezer.", stringify!($resource), "` file.\n\n",
        "See the kernel's documentation for more information about this field.\n\n",
        "# Errors\n\n",
        "Returns an error if failed to read and parse `freezer.", stringify!($resource), "` file of this cgroup.\n\n",
        "# Examples\n\n",
"```no_run
# fn main() -> cgroups::Result<()> {
use std::path::PathBuf;
use cgroups::v1::{freezer, Cgroup, CgroupPath, SubsystemKind};

let cgroup = freezer::Subsystem::new(
    CgroupPath::new(SubsystemKind::Freezer, PathBuf::from(\"students/charlie\")));
let ", stringify!($resource), " = cgroup.", stringify!($resource), "()?;
# Ok(())
# }
```") };

    (sets; $desc: literal, $setter: ident) => { concat!(
        $desc, " tasks in this cgroup by writing to `freezer.state` file.\n\n",
        "See the kernel's documentation for more information about this field.\n\n",
        "# Errors\n\n",
        "Returns an error if failed to write to `freezer.state` file of this cgroup.\n\n",
        "# Examples\n\n",
"```no_run
# fn main() -> cgroups::Result<()> {
use std::path::PathBuf;
use cgroups::v1::{freezer, Cgroup, CgroupPath, SubsystemKind};

let mut cgroup = freezer::Subsystem::new(
    CgroupPath::new(SubsystemKind::Freezer, PathBuf::from(\"students/charlie\")));
cgroup.", stringify!($setter), "()?;
# Ok(())
# }
```") };
}

const STATE_FILE_NAME: &str = "freezer.state";
const SELF_FREEZING_FILE_NAME: &str = "freezer.self_freezing";
const PARENT_FREEZING_FILE_NAME: &str = "freezer.parent_freezing";

impl Subsystem {
    with_doc! {
        gen_doc!(reads; "the current state of this cgroup", state),
        pub fn state(&self) -> Result<State> {
            self.open_file_read(STATE_FILE_NAME).and_then(parse)
        }
    }

    with_doc! {
        gen_doc!(reads; "whether this cgroup itself is being freezing or frozen", self_freezing),
        pub fn self_freezing(&self) -> Result<bool> {
            self.open_file_read(SELF_FREEZING_FILE_NAME)
                .and_then(parse_01_bool)
        }
    }

    with_doc! {
        gen_doc!(
            reads;
            "whether any parent cgroups of this cgroup is being freezing or frozen",
            parent_freezing
        ),
        pub fn parent_freezing(&self) -> Result<bool> {
            self.open_file_read(PARENT_FREEZING_FILE_NAME)
                .and_then(parse_01_bool)
        }
    }

    with_doc! {
        gen_doc!(sets; "Freezes", freeze),
        pub fn freeze(&mut self) -> Result<()> {
            self.write_file(STATE_FILE_NAME, State::Frozen)
        }
    }

    with_doc! {
        gen_doc!(sets; "Thaws, i.e. un-freezes", thaw),
        pub fn thaw(&mut self) -> Result<()> {
            self.write_file(STATE_FILE_NAME, State::Thawed)
        }
    }
}

impl std::str::FromStr for State {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        use State::*;
        match s {
            "THAWED" => Ok(Thawed),
            "FREEZING" => Ok(Freezing),
            "FROZEN" => Ok(Frozen),
            _ => Err(Error::new(ErrorKind::Parse)),
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use State::*;
        match self {
            Thawed => write!(f, "THAWED"),
            Freezing => write!(f, "FREEZING"),
            Frozen => write!(f, "FROZEN"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subsystem_create_file_exists() -> Result<()> {
        let mut cgroup =
            Subsystem::new(CgroupPath::new(SubsystemKind::Freezer, gen_cgroup_name!()));
        cgroup.create()?;

        [
            STATE_FILE_NAME,
            SELF_FREEZING_FILE_NAME,
            PARENT_FREEZING_FILE_NAME,
        ]
        .iter()
        .all(|n| cgroup.file_exists(n));

        assert!(!cgroup.file_exists("does_not_exist"));

        cgroup.delete()
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
    fn test_self_freezing_freeze_thaw() -> Result<()> {
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
    fn test_parent_freezing_freeze_thaw() -> Result<()> {
        let name = gen_cgroup_name!();

        let mut parent = Subsystem::new(CgroupPath::new(SubsystemKind::Freezer, name.clone()));
        parent.create()?;

        let mut child = Subsystem::new(CgroupPath::new(SubsystemKind::Freezer, name.join("child")));
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