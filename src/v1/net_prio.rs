//! Operations on a net_prio subsystem.
//!
//! [`Subsystem`] implements [`Cgroup`] trait and subsystem-specific behaviors.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/net_prio.txt].
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! use std::{collections::HashMap, path::PathBuf};
//! use cgroups::{Pid, v1::{self, net_prio, Cgroup, CgroupPath, SubsystemKind}};
//!
//! let mut net_prio_cgroup = net_prio::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::NetPrio, PathBuf::from("students/charlie")));
//! net_prio_cgroup.create()?;
//!
//! // Set a map of priorities assigned to traffic originating from this cgroup.
//! let priorities = [("lo", 0), ("wlp1s0", 1)].iter().copied().collect::<HashMap<_, u32>>();
//! net_prio_cgroup.set_ifpriomap(priorities)?;
//!
//! // Add a task to this cgroup.
//! let pid = Pid::from(std::process::id());
//! net_prio_cgroup.add_task(pid)?;
//!
//! // Do something ...
//!
//! net_prio_cgroup.remove_task(pid)?;
//! net_prio_cgroup.delete()?;
//! # Ok(())
//! # }
//! ```
//!
//! [`Subsystem`]: struct.Subsystem.html
//! [`Cgroup`]: ../trait.Cgroup.html
//!
//! [Documentation/cgroup-v1/net_prio.txt]: https://www.kernel.org/doc/Documentation/cgroup-v1/net_prio.txt

use std::{collections::HashMap, path::PathBuf};

use crate::{
    parse::{parse, parse_option},
    v1::{self, Cgroup, CgroupPath},
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
    Subsystem, NetPrio,

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

impl Subsystem {
    gen_getter!(
        net_prio,
        "the system-internal representation of this cgroup",
        prioidx,
        u64,
        parse
    );

    gen_getter!(
        net_prio, "the map of priorities assigned to traffic originating from this cgroup,",
        ifpriomap : link, HashMap<String, u32>, parse_ifpriomap
    );

    with_doc! { concat!(
        gen_doc!(
            sets; net_prio,
            "a map of priorities assigned to traffic originating from this cgroup,"
            : "The first element of the iterator item is traffic name, and the second is its priority.",
            ifpriomap
        ),
        gen_doc!(see; ifpriomap),
        gen_doc!(err_write; net_prio, ifpriomap),
"# Examples

```no_run
# fn main() -> cgroups::Result<()> {
use std::{collections::HashMap, path::PathBuf};
use cgroups::v1::{net_prio, Cgroup, CgroupPath, SubsystemKind};

let mut cgroup = net_prio::Subsystem::new(
    CgroupPath::new(SubsystemKind::NetPrio, PathBuf::from(\"students/charlie\")));

let prio_map = [(\"lo\", 0), (\"wlp1s\", 1)].iter().copied().collect::<HashMap<_, _>>();
cgroup.set_ifpriomap(prio_map)?;
# Ok(())
# }
```"),
        pub fn set_ifpriomap<I, T>(&mut self, prio_map: I) -> Result<()>
        where
            I: IntoIterator<Item = (T, u32)>,
            T: AsRef<str> + std::fmt::Display,
        {
            use std::io::Write;

            let mut file = self.open_file_write("net_prio.ifpriomap")?;
            for (interface, prio) in prio_map.into_iter() {
                // write!(file, "{} {}", interface, prio)?; // not work
                file.write_all(format!("{} {}", interface, prio).as_bytes())?;
            }

            Ok(())
        }
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

fn parse_ifpriomap(reader: impl std::io::Read) -> Result<HashMap<String, u32>> {
    use std::io::{BufRead, BufReader};

    let mut prio_map = HashMap::new();
    let buf = BufReader::new(reader);

    for line in buf.lines() {
        let line = line?;
        let mut entry = line.split_whitespace();

        let interface = entry.next().ok_or_else(|| Error::new(ErrorKind::Parse))?;
        let prio = parse_option(entry.next())?;

        prio_map.insert(interface.to_string(), prio);
    }

    Ok(prio_map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use v1::SubsystemKind;

    #[test]
    fn test_subsystem_create_file_exists() -> Result<()> {
        gen_subsystem_test!(NetPrio, ["prioidx", "ifpriomap"])
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

    #[test]
    fn test_parse_ifpriomap() -> Result<()> {
        const CONTENT: &str = "\
lo 0
wlp1s0 1
";

        assert_eq!(
            parse_ifpriomap(CONTENT.as_bytes())?,
            hashmap![("lo".to_string(), 0), ("wlp1s0".to_string(), 1),]
        );

        assert_eq!(parse_ifpriomap("".as_bytes())?, HashMap::new(),);

        Ok(())
    }
}
