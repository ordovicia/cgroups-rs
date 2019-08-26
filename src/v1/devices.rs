//! Operations on a devices subsystem.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/devices.txt](https://www.kernel.org/doc/Documentation/cgroup-v1/devices.txt).
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! use std::{collections::HashMap, path::PathBuf};
//! use cgroups::{Pid, v1::{self, devices::{self, Access}, Cgroup, CgroupPath, SubsystemKind}};
//!
//! let mut devices_cgroup = devices::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::Devices, PathBuf::from("students/charlie")));
//! devices_cgroup.create()?;
//!
//! // Deny and allow accesses to devices by this cgroup.
//! let denied = "a *:* rwm".parse::<Access>().unwrap();
//! devices_cgroup.deny(&denied)?;
//!
//! let allowed = "c 1:3 mr".parse::<Access>().unwrap();
//! devices_cgroup.allow(&allowed)?;
//!
//! // Add tasks to this cgroup.
//! let pid = Pid::from(std::process::id());
//! devices_cgroup.add_task(pid)?;
//!
//! // Print allowed accesses.
//! for access in devices_cgroup.list()? {
//!     println!("{}", access);
//! }
//!
//! // Do something ...
//!
//! devices_cgroup.remove_task(pid)?;
//! devices_cgroup.delete()?;
//! # Ok(())
//! # }
//! ```

use std::{fmt, path::PathBuf, str::FromStr};

use crate::{
    util::parse_option,
    v1::{self, cgroup::CgroupHelper, Cgroup, CgroupPath, SubsystemKind},
    Error, ErrorKind, Result,
};

/// Handler of a devices subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Allow or deny a cgroup to perform specific accesses to devices.
///
/// See the kernel's documentation for more information about the fields.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// Allow this cgroup to perform these accesses.
    pub allow: Vec<Access>,
    /// Deny this cgroup to perform these accesses.
    pub deny: Vec<Access>,
}

/// Access to devices of specific type and number.
///
/// `Access` implements [`FromStr`] and [`Display`]. You can convert a `Access` into a string and
/// vice versa. `parse` returns an error with kind [`ErrorKind::Parse`] if failed.
///
/// ```
/// use cgroups::{Device, DeviceNumber, v1::devices::{Access, AccessType, DeviceType}};
///
/// let access = "c 1:3 mr".parse::<Access>().unwrap();
/// assert_eq!(
///     access,
///     Access {
///         device_type: DeviceType::Char,
///         device_number: Device { major: DeviceNumber::Number(1), minor: DeviceNumber::Number(3) },
///         access_type: AccessType { read: true, write: false, mknod: true },
///     }
/// );
///
/// let access = "a *:* rwm".parse::<Access>().unwrap();
/// assert_eq!(
///     access,
///     Access {
///         device_type: DeviceType::All,
///         device_number: Device { major: DeviceNumber::Any, minor: DeviceNumber::Any },
///         access_type: AccessType { read: true, write: true, mknod: true },
///     }
/// );
/// ```
///
/// ```
/// use cgroups::{Device, DeviceNumber, v1::devices::{Access, AccessType, DeviceType}};
///
/// let access = Access {
///     device_type: DeviceType::Char,
///     device_number: Device { major: DeviceNumber::Number(1), minor: DeviceNumber::Number(3) },
///     access_type: AccessType { read: true, write: false, mknod: true },
/// };
/// assert_eq!(access.to_string(), "c 1:3 rm");
///
/// let access = Access {
///     device_type: DeviceType::All,
///     device_number: Device { major: DeviceNumber::Any, minor: DeviceNumber::Any },
///     access_type: AccessType { read: true, write: true, mknod: true },
/// };
/// assert_eq!(access.to_string(), "a *:* rwm");
/// ```
///
/// [`FromStr`]: https://doc.rust-lang.org/std/str/trait.FromStr.html
/// [`Display`]: https://doc.rust-lang.org/std/fmt/trait.Display.html
/// [`ErrorKind::Parse`]: ../../enum.ErrorKind.html#variant.Parse
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    /// Type of device for which access is permitted or denied.
    pub device_type: DeviceType,
    /// Number of device for which access is permitted or denied.
    pub device_number: crate::Device,
    /// What kinds of access is permitted or denied.
    pub access_type: AccessType,
}

/// Device type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceType {
    /// Both character and block devices, and all major and minor numbers.
    All,
    /// Character device.
    Char,
    /// Block device.
    Block,
}

/// Type of device access.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccessType {
    /// Read access.
    pub read: bool,
    /// Write access.
    pub write: bool,
    /// Make-node access
    pub mknod: bool,
}

impl_cgroup! {
    Devices,

    /// Applies `resources.devices`. `deny` list is applied first, and `allow` list then.
    ///
    /// See [`Cgroup::apply`] for general information.
    ///
    /// [`Cgroup::apply`]: ../trait.Cgroup.html#tymethod.apply
    fn apply(&mut self, resources: &v1::Resources) -> Result<()> {
        for denied in &resources.devices.deny {
            self.deny(denied)?;
        }

        for allowed in &resources.devices.allow {
            self.allow(allowed)?;
        }

        Ok(())
    }
}

const LIST: &str = "devices.list";
const ALLOW: &str = "devices.allow";
const DENY: &str = "devices.deny";

impl Subsystem {
    /// Reads allowed accesses of this cgroup from `devices.list` file.
    ///
    /// See the kernel's documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to write to `devices.list` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{devices, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = devices::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Devices, PathBuf::from("students/charlie")));
    ///
    /// let accesses = cgroup.list()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn list(&self) -> Result<Vec<Access>> {
        use std::io::{BufRead, BufReader};

        let mut result = Vec::new();
        let buf = BufReader::new(self.open_file_read(LIST)?);

        for line in buf.lines() {
            let line = line?;
            result.push(line.parse::<Access>()?);
        }

        Ok(result)
    }

    /// Denies this cgroup to perform an access to devices with specific type and number, by
    /// writing to `devices.deny` file.
    ///
    /// See [`Resources.deny`](struct.Resources.html#structfield.deny) and the kernel's
    /// documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to write to `devices.deny` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::{
    ///     Device, DeviceNumber,
    ///     v1::{
    ///         devices::{self, Access, AccessType, DeviceType},
    ///         Cgroup, CgroupPath, SubsystemKind,
    ///     }
    /// };
    ///
    /// let mut cgroup = devices::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Devices, PathBuf::from("students/charlie")));
    ///
    /// cgroup.deny(&Access {
    ///     device_type: DeviceType::Char,
    ///     device_number: Device { major: DeviceNumber::Number(1), minor: DeviceNumber::Number(3) },
    ///     access_type: AccessType { read: true, write: false, mknod: true },
    /// })?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn deny(&mut self, access: &Access) -> Result<()> {
        self.write_file(DENY, access)
    }

    /// Allows this cgroup to perform an access to devices with specific type and number, by
    /// writing to `devices.allow` file.
    ///
    /// See [`Resources.allow`](struct.Resources.html#structfield.allow) and the kernel's
    /// documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to write to `devices.allow` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::{
    ///     Device, DeviceNumber,
    ///     v1::{
    ///         devices::{self, Access, AccessType, DeviceType},
    ///         Cgroup, CgroupPath, SubsystemKind,
    ///     }
    /// };
    ///
    /// let mut cgroup = devices::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Devices, PathBuf::from("students/charlie")));
    ///
    /// cgroup.deny(&Access {
    ///     device_type: DeviceType::Char,
    ///     device_number: Device { major: DeviceNumber::Number(1), minor: DeviceNumber::Number(3) },
    ///     access_type: AccessType { read: true, write: false, mknod: true },
    /// })?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn allow(&mut self, access: &Access) -> Result<()> {
        self.write_file(ALLOW, access)
    }
}

impl Into<v1::Resources> for Resources {
    fn into(self) -> v1::Resources {
        v1::Resources {
            devices: self,
            ..v1::Resources::default()
        }
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.device_type, self.device_number, self.access_type
        )
    }
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::fmt::Write;

        f.write_char(match self {
            Self::All => 'a',
            Self::Char => 'c',
            Self::Block => 'b',
        })
    }
}

impl fmt::Display for AccessType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::fmt::Write;

        if self.read {
            f.write_char('r')?;
        }
        if self.write {
            f.write_char('w')?;
        }
        if self.mknod {
            f.write_char('m')?;
        }

        Ok(())
    }
}

impl FromStr for Access {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut sp = s.split_whitespace();

        let device_type = parse_option(sp.next())?;
        let device_number = parse_option(sp.next())?;
        let access_type = parse_option(sp.next())?;

        Ok(Self {
            device_type,
            device_number,
            access_type,
        })
    }
}

impl FromStr for DeviceType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "a" => Ok(Self::All),
            "c" => Ok(Self::Char),
            "b" => Ok(Self::Block),
            _ => Err(Error::new(ErrorKind::Parse)),
        }
    }
}

impl FromStr for AccessType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut access = AccessType::default();

        for c in s.chars() {
            match c {
                'r' => {
                    if access.read {
                        return Err(Error::new(ErrorKind::Parse));
                    } else {
                        access.read = true;
                    }
                }
                'w' => {
                    if access.write {
                        return Err(Error::new(ErrorKind::Parse));
                    } else {
                        access.write = true;
                    }
                }
                'm' => {
                    if access.mknod {
                        return Err(Error::new(ErrorKind::Parse));
                    } else {
                        access.mknod = true;
                    }
                }
                _ => {
                    return Err(Error::new(ErrorKind::Parse));
                }
            }
        }

        Ok(access)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Device, DeviceNumber};

    #[test]
    fn test_subsystem_create_file_exists() -> Result<()> {
        let mut cgroup =
            Subsystem::new(CgroupPath::new(SubsystemKind::Devices, gen_cgroup_name!()));
        cgroup.create()?;
        assert!([ALLOW, DENY, LIST].iter().all(|f| cgroup.file_exists(f)));
        assert!(!cgroup.file_exists("does_not_exist"));

        cgroup.delete()?;
        assert!([ALLOW, DENY, LIST].iter().all(|f| !cgroup.file_exists(f)));

        Ok(())
    }

    #[test]
    fn test_subsystem_list() -> Result<()> {
        let allowed_all = Access {
            device_type: DeviceType::All,
            device_number: Device {
                major: DeviceNumber::Any,
                minor: DeviceNumber::Any,
            },
            access_type: AccessType {
                read: true,
                write: true,
                mknod: true,
            },
        };

        gen_subsystem_test!(
            Devices;
            list,
            vec![allowed_all]
        )
    }

    #[test]
    fn test_subsystem_deny_allow() -> Result<()> {
        let mut cgroup =
            Subsystem::new(CgroupPath::new(SubsystemKind::Devices, gen_cgroup_name!()));
        cgroup.create()?;

        let all = "a *:* rwm".parse::<Access>().unwrap();
        cgroup.deny(&all)?;
        assert!(cgroup.list()?.is_empty());

        let c_1_3_rm = "c 1:3 rm".parse::<Access>().unwrap();
        cgroup.allow(&c_1_3_rm)?;
        assert_eq!(cgroup.list()?, vec![c_1_3_rm]);

        cgroup.delete()
    }
}
