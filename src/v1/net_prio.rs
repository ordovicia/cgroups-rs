//! Operations on a net_prio subsystem.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/net_prio.txt](https://www.kernel.org/doc/Documentation/cgroup-v1/net_prio.txt).
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! use std::{collections::HashMap, path::PathBuf};
//! use cgroups::{Pid, v1::{self, net_prio, Cgroup, CgroupPath, SubsystemKind}};
//!
//! let mut net_cls_cgroup = net_prio::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::NetPrio, PathBuf::from("students/charlie")));
//! net_cls_cgroup.create()?;
//!
//! // Set a map of priorities assigned to traffic originating from this cgroup.
//! let priorities = [("lo", 0), ("wlp1s0", 1)].iter().copied().collect::<HashMap<_, u32>>();
//! net_cls_cgroup.set_ifpriomap(priorities)?;
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

use std::{collections::HashMap, path::PathBuf};

use crate::{
    util::{parse, parse_option},
    v1::{self, Cgroup, CgroupPath, SubsystemKind},
    Error, ErrorKind, Result,
};

/// Handler of a net_prio subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Priority map of traffic originating from a cgroup.
///
/// See the kernel's documentation for more information about the fields.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// Map of priorities assigned to traffic originating from this cgroup.
    ///
    /// No priority will be set if this map is empty.
    pub ifpriomap: HashMap<String, u32>,
}

impl_cgroup! {
    NetPrio,

    /// Applies `resources.net_prio.ifpriomap`.
    ///
    /// See [`Cgroup::apply`] for general information.
    ///
    /// [`Cgroup::apply`]: ../trait.Cgroup.html#tymethod.apply
    fn apply(&mut self, resources: &v1::Resources) -> Result<()> {
        let prio_map = &resources.net_prio.ifpriomap;

        if prio_map.is_empty() {
            Ok(())
        } else {
            self.set_ifpriomap(prio_map.iter().map(|(i, prio)| (i, *prio)))
        }
    }
}

const PRIOIDX: &str = "net_prio.prioidx";
const IFPRIOMAP: &str = "net_prio.ifpriomap";

impl Subsystem {
    /// Reads the system-internal representation of this cgroup from `net_prio.prioidx` file.
    ///
    /// See the kernel's documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to read and parse `net_prio.prioidx` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{net_prio, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = net_prio::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::NetPrio, PathBuf::from("students/charlie")));
    ///
    /// let prio_idx = cgroup.prioidx()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn prioidx(&self) -> Result<u64> {
        self.open_file_read(PRIOIDX).and_then(parse)
    }

    /// Reads the map of priorities assigned to traffic originating from this cgroup, from
    /// `net_prio.ifpriomap` file.
    ///
    /// See [`Resources.ifpriomap`] and the kernel's documentation for more information about this
    /// field.
    ///
    /// [`Resources.ifpriomap`]: struct.Resources.html#structfield.ifpriomap
    ///
    /// # Errors
    ///
    /// Returns an error if failed to read and parse `net_prio.ifpriomap` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{net_prio, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = net_prio::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::NetPrio, PathBuf::from("students/charlie")));
    ///
    /// let prio_map = cgroup.ifpriomap()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn ifpriomap(&self) -> Result<HashMap<String, u32>> {
        use std::io::{BufRead, BufReader};

        let mut prio_map = HashMap::new();
        let buf = BufReader::new(self.open_file_read(IFPRIOMAP)?);

        for line in buf.lines() {
            let line = line?;
            let mut entry = line.split_whitespace();

            let interface = entry.next().ok_or_else(|| Error::new(ErrorKind::Parse))?;
            let prio = parse_option(entry.next())?;

            prio_map.insert(interface.to_string(), prio);
        }

        Ok(prio_map)
    }

    /// Sets a map of priorities assigned to traffic originating from this cgroup, by writing to
    /// `net_prio.ifpriomap` file.
    ///
    /// See [`Resources.ifpriomap`] and the kernel's documentation for more information about this
    /// field.
    ///
    /// [`Resources.ifpriomap`]: struct.Resources.html#structfield.ifpriomap
    ///
    /// # Errors
    ///
    /// Returns an error if failed to write to `net_prio.ifpriomap` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::{collections::HashMap, path::PathBuf};
    /// use cgroups::v1::{net_prio, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let mut cgroup = net_prio::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::NetPrio, PathBuf::from("students/charlie")));
    ///
    /// let prio_map = [("lo", 0), ("wlp1s0", 1)].iter().copied().collect::<HashMap<_, _>>();
    /// cgroup.set_ifpriomap(prio_map)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_ifpriomap<I, T>(&mut self, prio_map: I) -> Result<()>
    where
        I: IntoIterator<Item = (T, u32)>,
        T: AsRef<str> + std::fmt::Display,
    {
        use std::io::Write;

        let mut file = self.open_file_write(IFPRIOMAP)?;
        for (interface, prio) in prio_map.into_iter() {
            // write!(file, "{} {}", interface, prio)?; // not work
            file.write_all(format!("{} {}", interface, prio).as_bytes())?;
        }

        Ok(())
    }
}

impl Into<v1::Resources> for Resources {
    fn into(self) -> v1::Resources {
        v1::Resources {
            net_prio: self,
            ..v1::Resources::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subsystem_create_file_exists() -> Result<()> {
        let mut cgroup =
            Subsystem::new(CgroupPath::new(SubsystemKind::NetPrio, gen_cgroup_name!()));
        cgroup.create()?;

        assert!([PRIOIDX, IFPRIOMAP].iter().all(|f| cgroup.file_exists(f)));
        assert!(!cgroup.file_exists("does_not_exist"));

        cgroup.delete()?;
        assert!([PRIOIDX, IFPRIOMAP].iter().all(|f| !cgroup.file_exists(f)));

        Ok(())
    }

    #[test]
    fn test_subsystem_prioidx() -> Result<()> {
        let mut cgroup =
            Subsystem::new(CgroupPath::new(SubsystemKind::NetPrio, gen_cgroup_name!()));
        cgroup.create()?;

        let _ = cgroup.prioidx()?;

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_ifpriomap() -> Result<()> {
        let mut cgroup =
            Subsystem::new(CgroupPath::new(SubsystemKind::NetPrio, gen_cgroup_name!()));
        cgroup.create()?;

        let mut priorities = cgroup.ifpriomap()?;
        for (_, prio) in priorities.iter_mut() {
            *prio += 1;
        }

        cgroup.set_ifpriomap(
            priorities
                .iter()
                .map(|(interface, prio)| (interface, *prio)),
        )?;
        assert_eq!(cgroup.ifpriomap()?, priorities);

        cgroup.delete()
    }
}
