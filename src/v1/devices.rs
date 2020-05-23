//! Operations on a Devices subsystem.
//!
//! [`Subsystem`] implements [`Cgroup`] trait and subsystem-specific operations.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/devices.txt].
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> controlgroup::Result<()> {
//! use std::{collections::HashMap, path::PathBuf};
//! use controlgroup::{Pid, v1::{self, devices::{self, Access}, Cgroup, CgroupPath, SubsystemKind}};
//!
//! let mut devices_cgroup = devices::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::Devices, PathBuf::from("students/charlie")));
//! devices_cgroup.create()?;
//!
//! // Deny and allow accesses to devices by this cgroup.
//! let denied = "a".parse::<Access>().unwrap();
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
//!
//! [`Subsystem`]: struct.Subsystem.html
//! [`Cgroup`]: ../trait.Cgroup.html
//!
//! [Documentation/cgroup-v1/devices.txt]: https://www.kernel.org/doc/Documentation/cgroup-v1/devices.txt

use std::{fmt, path::PathBuf, str::FromStr};

use crate::{
    parse::parse_next,
    v1::{self, cgroup::CgroupHelper, Cgroup, CgroupPath},
    Error, Result,
};

/// Handler of a Devices subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Allow or deny a cgroup to perform specific accesses to devices.
///
/// See the kernel's documentation for more information about the fields.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// Deny this cgroup to perform these accesses.
    pub deny: Vec<Access>,
    /// Allow this cgroup to perform these accesses.
    pub allow: Vec<Access>,
}

impl Into<v1::Resources> for Resources {
    fn into(self) -> v1::Resources {
        v1::Resources {
            devices: self,
            ..v1::Resources::default()
        }
    }
}

/// Access to devices of specific type and number.
///
/// `Access` implements [`FromStr`] and [`Display`]. You can convert a `Access` into a string and
/// vice versa. `parse` returns an error with kind [`ErrorKind::Parse`] if failed.
///
/// ```
/// use controlgroup::{Device, DeviceNumber, v1::devices::{Access, AccessType, DeviceType}};
///
/// let access = "c 1:3 mr".parse::<Access>().unwrap();
/// assert_eq!(
///     access,
///     Access {
///         device_type: DeviceType::Char,
///         device_number: [1, 3].into(),
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
///
/// let access = "a".parse::<Access>().unwrap();    // equivalent to "a *:* rwm"
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
/// use controlgroup::{Device, DeviceNumber, v1::devices::{Access, AccessType, DeviceType}};
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

impl FromStr for Access {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut entry = s.split_whitespace();

        let device_type = parse_next(&mut entry)?;

        if let Some(device_number) = entry.next() {
            let device_number = device_number.parse()?;
            let access_type = parse_next(&mut entry)?;

            if entry.next().is_some() {
                bail_parse!();
            }

            Ok(Self {
                device_type,
                device_number,
                access_type,
            })
        } else if device_type == DeviceType::All {
            use crate::{Device, DeviceNumber};

            Ok(Self {
                device_type,
                device_number: Device {
                    major: DeviceNumber::Any,
                    minor: DeviceNumber::Any,
                },
                access_type: AccessType {
                    read: true,
                    write: true,
                    mknod: true,
                },
            })
        } else {
            bail_parse!();
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

impl FromStr for DeviceType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "a" => Ok(Self::All),
            "c" => Ok(Self::Char),
            "b" => Ok(Self::Block),
            _ => {
                bail_parse!();
            }
        }
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

impl FromStr for AccessType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut access = AccessType::default();

        macro_rules! s {
            ($r: ident) => {{
                if access.$r {
                    bail_parse!();
                }
                access.$r = true;
            }};
        }

        for c in s.chars() {
            match c {
                'r' => s!(read),
                'w' => s!(write),
                'm' => s!(mknod),
                _ => {
                    bail_parse!();
                }
            }
        }

        Ok(access)
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

impl_cgroup! {
    Subsystem, Devices,

    /// Applies `resources.devices`. `deny` list is applied first, and then `allow` list is.
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
    /// Reads the allowed device accesses of this cgroup from `devices.list` file.
    pub fn list(&self) -> Result<Vec<Access>> {
        self.open_file_read(LIST).and_then(parse_list)
    }

    /// Allows this cgroup to perform a type of access to devices with a specific type and number,
    /// by writing to `devices.allow` file.
    pub fn allow(&mut self, access: &Access) -> Result<()> {
        self.write_file(ALLOW, access)
    }

    /// Denies this cgroup to perform a type of access to devices with a specific type and number,
    /// by writing to `devices.deny` file.
    pub fn deny(&mut self, access: &Access) -> Result<()> {
        self.write_file(DENY, access)
    }
}

fn parse_list(reader: impl std::io::Read) -> Result<Vec<Access>> {
    use std::io::{BufRead, BufReader};

    let mut result = Vec::new();
    for line in BufReader::new(reader).lines() {
        let line = line?;
        result.push(line.parse::<Access>()?);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Device, DeviceNumber};

    #[test]
    fn test_subsystem_create_file_exists_delete() -> Result<()> {
        gen_test_subsystem_create_delete!(Devices, LIST, ALLOW, DENY)
    }

    #[test]
    fn test_subsystem_apply() -> Result<()> {
        gen_test_subsystem_apply!(
            Devices,
            Resources {
                deny: vec!["a".parse::<Access>().unwrap()],
                allow: vec!["c 1:3 rm".parse::<Access>().unwrap()],
            },
            (list, vec!["c 1:3 rm".parse::<Access>().unwrap()]),
        )
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

        gen_test_subsytem_get!(Devices, list, vec![allowed_all])
    }

    #[test]
    fn test_subsystem_deny_allow() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(
            v1::SubsystemKind::Devices,
            gen_cgroup_name!(),
        ));
        cgroup.create()?;

        let all = "a".parse::<Access>().unwrap();
        cgroup.deny(&all)?;
        assert!(cgroup.list()?.is_empty());

        let c_1_3_rm = "c 1:3 rm".parse::<Access>().unwrap();
        cgroup.allow(&c_1_3_rm)?;
        assert_eq!(cgroup.list()?, vec![c_1_3_rm]);

        cgroup.delete()
    }

    #[test]
    fn err_parse_access() {
        for case in &[
            "c",
            "d *:* rwm",
            "a *:* invalid",
            "a invalid rwm",
            "a rwm",
            "a 1:3",
            "a 1:3 rwm invalid",
        ] {
            assert_eq!(
                case.parse::<Access>().unwrap_err().kind(),
                crate::ErrorKind::Parse
            );
        }
    }

    #[test]
    fn test_parse_list() -> Result<()> {
        const CONTENT_OK: &str = "\
c 1:3 rm
b 8:0 rw
";
        assert_eq!(
            parse_list(CONTENT_OK.as_bytes())?,
            vec![
                Access {
                    device_type: DeviceType::Char,
                    device_number: Device {
                        major: DeviceNumber::Number(1),
                        minor: DeviceNumber::Number(3)
                    },
                    access_type: AccessType {
                        read: true,
                        write: false,
                        mknod: true
                    }
                },
                Access {
                    device_type: DeviceType::Block,
                    device_number: Device {
                        major: DeviceNumber::Number(8),
                        minor: DeviceNumber::Number(0)
                    },
                    access_type: AccessType {
                        read: true,
                        write: true,
                        mknod: false
                    }
                },
            ]
        );

        assert_eq!(parse_list("".as_bytes())?, vec![]);

        Ok(())
    }
}
