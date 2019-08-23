//! Operations on an RDMA subsystem.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/rdma.txt](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt).
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! use std::{collections::HashMap, path::PathBuf};
//! use cgroups::{Pid, Max, v1::{self, rdma, Cgroup, CgroupPath, SubsystemKind}};
//!
//! let mut rdma_cgroup = rdma::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::Rdma, PathBuf::from("students/charlie")));
//! rdma_cgroup.create()?;
//!
//! // Limit the usage of RDMA/IB devices.
//! let rdma_limits = [
//!     (
//!         "mlx4_0",
//!         rdma::Limit {
//!             hca_handle: Max::<u32>::Limit(2),
//!             hca_object: Max::<u32>::Limit(2000),
//!         },
//!     ),
//!     (
//!         "ocrdma1",
//!         rdma::Limit {
//!             hca_handle: Max::<u32>::Limit(3),
//!             hca_object: Max::<u32>::Max,
//!         },
//!     ),
//! ]
//! .iter()
//! .cloned()
//! .collect::<HashMap<_, _>>();
//!
//! rdma_cgroup.set_max(rdma_limits)?;
//!
//! // Add tasks to this cgroup.
//! let pid = Pid::from(std::process::id());
//! rdma_cgroup.add_task(pid)?;
//!
//! // Print the current usage of RDMA/IB devices.
//! for (device, usage) in rdma_cgroup.current()? {
//!     println!("{}: {}", device, usage);
//! }
//!
//! rdma_cgroup.remove_task(pid)?;
//! rdma_cgroup.delete()?;
//! # Ok(())
//! # }
//! ```

use std::{collections::HashMap, fmt, io, path::PathBuf};

use crate::{
    util::parse_option,
    v1::{self, Cgroup, CgroupPath, SubsystemKind},
    Error, ErrorKind, Max, Result,
};

/// Handler of an RDMA subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Resource limit on how much a cgroup can use RDMA/IB devices.
///
/// See the kernel's documentation for more information about the fields.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// How much this cgroup can use each RDMA/IB device. The key is the device name, and the value
    /// is limit for the device.
    ///
    /// No limits will be applied if this map is empty.
    pub max: HashMap<String, Limit>,
}

/// Limit or usage of an RDMA/IB device.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Limit {
    /// Max number or usage of HCA handles.
    pub hca_handle: Max<u32>,
    /// Max number or usage of HCA objects.
    pub hca_object: Max<u32>,
}

impl_cgroup! {
    Rdma,

    /// Applies `resources.rdma`.
    ///
    /// See [`Cgroup::apply`] for general information.
    ///
    /// [`Cgroup::apply`]: ../trait.Cgroup.html#tymethod.apply
    fn apply(&mut self, resources: &v1::Resources) -> Result<()> {
        let max = &resources.rdma.max;

        if max.is_empty() {
            Ok(())
        } else {
            // FIXME: avoid clone
            self.set_max(max.iter().map(|(d, lim)| (d, lim.clone())))
        }
    }
}

const MAX: &str = "rdma.max";
const CURRENT: &str = "rdma.current";

impl Subsystem {
    /// Reads the current usage of RDMA/IB devices from `rdma.current` file.
    ///
    /// See the kernel's documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to read and parse `rdma.current` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{rdma, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = rdma::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Rdma, PathBuf::from("students/charlie")));
    ///
    /// let current = cgroup.current()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn current(&self) -> Result<HashMap<String, Limit>> {
        let buf = io::BufReader::new(self.open_file_read(CURRENT)?);
        parse_limits(buf)
    }

    /// Reads the usage limits on RDMA/IB devices from `rdma.max` file.
    ///
    /// See the kernel's documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to read and parse `rdma.max` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{rdma, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = rdma::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Rdma, PathBuf::from("students/charlie")));
    ///
    /// let max = cgroup.max()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn max(&self) -> Result<HashMap<String, Limit>> {
        let buf = io::BufReader::new(self.open_file_read(MAX)?);
        parse_limits(buf)
    }

    /// Sets usage limits on RDMA/IB devices by writing to `rdma.max` file.
    ///
    /// See the kernel's documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to write to `rdma.max` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::{collections::HashMap, path::PathBuf};
    /// use cgroups::{Max, v1::{rdma::{self, Limit}, Cgroup, CgroupPath, SubsystemKind}};
    ///
    /// let mut cgroup = rdma::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Rdma, PathBuf::from("students/charlie")));
    ///
    /// let rdma_limits = [
    ///     (
    ///         "mlx4_0",
    ///         Limit {
    ///             hca_handle: Max::<u32>::Limit(2),
    ///             hca_object: Max::<u32>::Limit(2000),
    ///         },
    ///     ),
    ///     (
    ///         "ocrdma1",
    ///         Limit {
    ///             hca_handle: Max::<u32>::Limit(3),
    ///             hca_object: Max::<u32>::Max,
    ///         },
    ///     ),
    /// ].iter().cloned().collect::<HashMap<_, _>>();
    ///
    /// cgroup.set_max(rdma_limits)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_max<I, T>(&mut self, limits: I) -> Result<()>
    where
        I: IntoIterator<Item = (T, Limit)>,
        T: AsRef<str> + fmt::Display,
    {
        use std::io::Write;

        let mut file = self.open_file_write(MAX)?;
        for (device, limit) in limits.into_iter() {
            // write!(file, "{} {}", interface, prio)?;
            file.write_all(format!("{} {}", device, limit).as_bytes())?;
        }

        Ok(())
    }
}

// takes `io::BufRead` for testing on systems that does not have RDMA/IB devices.
fn parse_limits(buf: impl io::BufRead) -> Result<HashMap<String, Limit>> {
    let mut result = HashMap::new();

    for line in buf.lines() {
        let line = line?;
        let mut entry = line.split_whitespace();

        let device = entry.next().ok_or_else(|| Error::new(ErrorKind::Parse))?;

        let (mut hca_handle, mut hca_object) = (None, None);
        for e in entry.by_ref().take(2) {
            let mut kv = e.split('=');
            match kv.next() {
                Some("hca_handle") => hca_handle = Some(parse_option(kv.next())?),
                Some("hca_object") => hca_object = Some(parse_option(kv.next())?),
                _ => {
                    return Err(Error::new(ErrorKind::Parse));
                }
            }
        }

        match (entry.next(), hca_handle, hca_object) {
            (None, Some(hca_handle), Some(hca_object)) => {
                result.insert(
                    device.to_string(),
                    Limit {
                        hca_handle,
                        hca_object,
                    },
                );
            }
            _ => {
                return Err(Error::new(ErrorKind::Parse));
            }
        }
    }

    Ok(result)
}

impl Into<v1::Resources> for Resources {
    fn into(self) -> v1::Resources {
        v1::Resources {
            rdma: self,
            ..v1::Resources::default()
        }
    }
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hca_handle={} hca_object={}",
            self.hca_handle, self.hca_object
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: test on systems with RDMA/IB devices

    #[test]
    #[ignore] // some systems have no RDMA/IB devices
    fn test_subsystem_create_file_exists() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Rdma, gen_cgroup_name!()));
        cgroup.create()?;
        assert!([MAX, CURRENT].iter().all(|f| cgroup.file_exists(f)));
        assert!(!cgroup.file_exists("does_not_exist"));

        cgroup.delete()?;
        assert!([MAX, CURRENT].iter().all(|f| !cgroup.file_exists(f)));

        Ok(())
    }

    #[test]
    #[ignore] // some systems have no RDMA/IB devices
    fn test_subsystem_current() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Rdma, gen_cgroup_name!()));
        cgroup.create()?;

        let _ = cgroup.current()?;

        cgroup.delete()
    }

    #[test]
    #[ignore] // some systems have no RDMA/IB devices
    fn test_subsystem_max() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Rdma, gen_cgroup_name!()));
        cgroup.create()?;

        let mut limits = cgroup.max()?;
        for (_, limit) in limits.iter_mut() {
            limit.hca_handle = match limit.hca_handle {
                Max::<u32>::Max => Max::<u32>::Limit(3),
                Max::<u32>::Limit(_) => Max::<u32>::Max,
            };

            limit.hca_object = match limit.hca_object {
                Max::<u32>::Max => Max::<u32>::Limit(3000),
                Max::<u32>::Limit(_) => Max::<u32>::Max,
            };
        }

        cgroup.set_max(limits.clone())?;
        assert_eq!(cgroup.max()?, limits);

        cgroup.delete()
    }

    #[test]
    fn test_parse_limits() -> Result<()> {
        let buf = "\
mlx4_0 hca_handle=2 hca_object=2000
ocrdma1 hca_handle=3 hca_object=max
";

        let actual = parse_limits(buf.as_bytes())?;

        let expected = [
            (
                "mlx4_0".to_string(),
                Limit {
                    hca_handle: Max::<u32>::Limit(2),
                    hca_object: Max::<u32>::Limit(2000),
                },
            ),
            (
                "ocrdma1".to_string(),
                Limit {
                    hca_handle: Max::<u32>::Limit(3),
                    hca_object: Max::<u32>::Max,
                },
            ),
        ]
        .iter()
        .cloned()
        .collect::<HashMap<_, _>>();

        assert_eq!(expected, actual);
        Ok(())
    }
}
