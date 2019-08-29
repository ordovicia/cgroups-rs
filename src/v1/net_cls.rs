//! Operations on a net_cls subsystem.
//!
//! [`Subsystem`] implements [`Cgroup`] trait and subsystem-specific behaviors.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/net_cls.txt].
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! use std::path::PathBuf;
//! use cgroups::{Pid, v1::{self, net_cls, Cgroup, CgroupPath, SubsystemKind}};
//!
//! let mut net_cls_cgroup = net_cls::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::NetCls, PathBuf::from("students/charlie")));
//! net_cls_cgroup.create()?;
//!
//! // Tag network packets from this cgroup with a class ID.
//! net_cls_cgroup.set_classid(net_cls::ClassId { major: 0x10, minor: 0x1 })?;
//!
//! // Add a task to this cgroup.
//! let pid = Pid::from(std::process::id());
//! net_cls_cgroup.add_task(pid)?;
//!
//! // Do something ...
//!
//! net_cls_cgroup.remove_task(pid)?;
//! net_cls_cgroup.delete()?;
//! # Ok(())
//! # }
//! ```
//!
//! [`Subsystem`]: struct.Subsystem.html
//! [`Cgroup`]: ../trait.Cgroup.html
//!
//! [Documentation/cgroup-v1/net_cls.txt]: https://www.kernel.org/doc/Documentation/cgroup-v1/net_cls.txt

use std::{fmt, path::PathBuf, str::FromStr};

use crate::{
    parse::parse,
    v1::{self, Cgroup, CgroupPath},
    Error, ErrorKind, Result,
};

/// Handler of a net_cls subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Tag network packets from a cgroup with a class ID.
///
/// See the kernel's documentation for more information about the fields.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// Class ID to be attached to network packets originating from this cgroup.
    pub classid: Option<ClassId>,
}

/// Class ID.
///
/// Besides writing a struct literal, `ClassId` can be instantiated by [`parse`]-ing a class ID
/// string. If failed, `parse` returns an error with kind [`ErrorKind::Parse`].
///
/// ```
/// use cgroups::v1::net_cls::ClassId;
///
/// assert_eq!("0x100001".parse::<ClassId>().unwrap(), ClassId { major: 0x10, minor: 0x1});
/// assert_eq!("0X0123ABCD".parse::<ClassId>().unwrap(), ClassId { major: 0x0123, minor: 0xABCD});
/// ```
///
/// `ClassId` implements [`Display`]. The result is a hexadecimal string, same as one written to
/// `net_cls.classid` file.
///
/// ```
/// use std::string::ToString;
/// use cgroups::v1::net_cls::ClassId;
///
/// assert_eq!(ClassId { major: 0x10, minor: 0x1}.to_string(), "0x100001");
/// assert_eq!(ClassId { major: 0x0123, minor: 0xABCD}.to_string(), "0x123ABCD");
/// ```
///
/// `ClassId` also supports conversion from/into `u32` and from/into `[u16; 2]`.
///
/// ```
/// use cgroups::v1::net_cls::ClassId;
///
/// assert_eq!(ClassId::from(0x10_0001), ClassId { major: 0x10, minor: 0x1});
/// assert_eq!(ClassId::from(0x0123_ABCD), ClassId { major: 0x0123, minor: 0xABCD});
///
/// let id: u32 = ClassId { major: 0x10, minor: 0x1}.into();
/// assert_eq!(id, 0x10_0001);
///
/// let id: u32 = ClassId { major: 0x0123, minor: 0xABCD}.into();
/// assert_eq!(id, 0x0123_ABCD);
/// ```
///
/// ```
/// use cgroups::v1::net_cls::ClassId;
///
/// assert_eq!(ClassId::from([0x10, 0x1]), ClassId { major: 0x10, minor: 0x1});
/// assert_eq!(ClassId::from([0x0123, 0xABCD]), ClassId { major: 0x0123, minor: 0xABCD});
///
/// let id: [u16; 2] = ClassId { major: 0x10, minor: 0x1}.into();
/// assert_eq!(id, [0x10, 0x1]);
///
/// let id: [u16; 2] = ClassId { major: 0x0123, minor: 0xABCD}.into();
/// assert_eq!(id, [0x0123, 0xABCD]);
/// ```
///
/// [`parse`]: https://doc.rust-lang.org/std/primitive.str.html#method.parse
/// [`ErrorKind::Parse`]: ../../enum.ErrorKind.html#variant.Parse
///
/// [`Display`]: https://doc.rust-lang.org/std/fmt/trait.Display.html
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClassId {
    /// Major number.
    pub major: u16,
    /// Minor number.
    pub minor: u16,
}

impl_cgroup! {
    Subsystem, NetCls,

    /// Applies the `Some` fields in `resources.net_cls`.
    ///
    /// See [`Cgroup::apply`] for general information.
    ///
    /// [`Cgroup::apply`]: ../trait.Cgroup.html#tymethod.apply
    fn apply(&mut self, resources: &v1::Resources) -> Result<()> {
        if let Some(id) = resources.net_cls.classid {
            self.set_classid(id)?;
        }

        Ok(())
    }
}

const CLASSID: &str = "net_cls.classid";

impl Subsystem {
    with_doc! { concat!(
        gen_doc!(reads; net_cls, "the class ID of network packets from this cgroup,", classid),
        gen_doc!(see; classid),
        gen_doc!(err_read; net_cls, classid),
        gen_doc!(eg_read; net_cls, NetCls, classid)),
        pub fn classid(&self) -> Result<ClassId> {
            let raw: u32 = self.open_file_read(CLASSID).and_then(parse)?;
            Ok(raw.into())
        }
    }

    with_doc! { concat!(
        gen_doc!(sets; net_cls, "a class ID to network packets from this cgroup,", classid),
        gen_doc!(see; classid),
        gen_doc!(err_write; net_cls, classid),
        gen_doc!(eg_write; net_cls, NetCls, set_classid, [0x10, 0x1].into())),
        pub fn set_classid(&mut self, id: ClassId) -> Result<()> {
            let raw: u32 = id.into();
            std::fs::write(self.path().join(CLASSID), format!("{:#08X}", raw)).map_err(Into::into)
        }
    }
}

impl Into<v1::Resources> for Resources {
    fn into(self) -> v1::Resources {
        v1::Resources {
            net_cls: self,
            ..v1::Resources::default()
        }
    }
}

impl FromStr for ClassId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let len = s.len();
        if len < 7 || len > 10 || (&s[0..2] != "0x" && &s[0..2] != "0X") {
            return Err(Error::new(ErrorKind::Parse));
        }

        let major = u16::from_str_radix(&s[2..(len - 4)], 16)?;
        let minor = u16::from_str_radix(&s[(len - 4)..len], 16)?;

        Ok(ClassId { major, minor })
    }
}

impl fmt::Display for ClassId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#X}{:04X}", self.major, self.minor)
    }
}

impl From<u32> for ClassId {
    fn from(id: u32) -> Self {
        Self {
            major: ((id & 0xffff_0000) >> 16) as u16,
            minor: (id & 0xffff) as u16,
        }
    }
}

impl From<[u16; 2]> for ClassId {
    fn from(id: [u16; 2]) -> Self {
        Self {
            major: id[0],
            minor: id[1],
        }
    }
}

impl Into<u32> for ClassId {
    fn into(self) -> u32 {
        (u32::from(self.major) << 16) | u32::from(self.minor)
    }
}

impl Into<[u16; 2]> for ClassId {
    fn into(self) -> [u16; 2] {
        [self.major, self.minor]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subsystem_create_file_exists() -> Result<()> {
        gen_subsystem_test!(NetCls, net_cls, ["classid"])
    }

    #[test]
    fn test_subsystem_classid() -> Result<()> {
        gen_subsystem_test!(
            NetCls,
            classid,
            ClassId { major: 0, minor: 0 },
            set_classid,
            ClassId {
                major: 0x10,
                minor: 0x1
            }
        )
    }

    #[test]
    fn err_class_id_from_str() {
        for case in &["", "01234567", "0xffff", "0x012345678"] {
            assert_eq!(
                case.parse::<ClassId>().unwrap_err().kind(),
                ErrorKind::Parse
            );
        }
    }
}
