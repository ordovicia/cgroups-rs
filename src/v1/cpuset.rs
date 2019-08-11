//! Operations on a cpuset subsystem.
//!
//! For more information about Cpuset subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/cpusets.txt](https://www.kernel.org/doc/Documentation/cgroup-v1/cpusets.txt).

// TODO: module-level doc

use std::{collections::HashSet, fmt, iter::FromIterator, path::PathBuf};

use crate::{
    v1::{self, Cgroup, CgroupPath, SubsystemKind},
    Error, ErrorKind, Result,
};

use crate::{
    util::{parse, parse_01_bool},
    v1::cgroup::CgroupHelper,
};

/// Handler of a cpuset subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Which CPUs and which memory nodes a cgroup can use, and how they are controlled by the kernel.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// Set of CPUs the tasks of the cgroup can run on.
    pub cpus: Option<IdSet>,

    /// Set of memory nodes the tasks of the cgroup can use.
    pub mems: Option<IdSet>,

    /// If true, when a task is attached to the cgroup, pages allocated to the task on memory nodes
    /// in its previous cpuset are migrated to the new node selected by `mems`. Also, whenever
    /// `cpuset.mems` file is modified, pages allocated to a task in this cgroup on nodes in the
    /// previous `mems` setting are migrated to the new nodes.
    pub memory_migrate: Option<bool>,

    /// If true, no other cgroups, other than a direct ancestor or descendant, can share any of the
    /// same CPUs listed in the `cpus` field.
    pub cpu_exclusive: Option<bool>,

    /// If true, no other cgroups, other than a direct ancestor or descendant, can share any of the
    /// same memory nodes listed in the `mems` field.
    pub mem_exclusive: Option<bool>,

    /// If true, the cgroup is "hardwalled". i.e. Kernel memory allocations (except for a few minor
    /// exceptions) are made from the memory nodes designated in the `mems` field.
    pub mem_hardwall: Option<bool>,

    /// If true, the kernel will compute the memory pressure for the cgroup.
    pub memory_pressure_enabled: Option<bool>,

    /// If true, file system buffers are evenly spread across the memory nodes specified in the
    /// `mems` field.
    pub memory_spread_page: Option<bool>,

    /// If true, the kernel slab caches for file I/O are evenly spread across the memory nodes specified
    /// in the `mems` field.
    pub memory_spread_slab: Option<bool>,

    /// If true, the kernel will attempt to rebalance the load between the CPUs specified in the
    /// `cpus` field. This field is ignored if an ancestor cgroup already has enabled the load
    /// balancing at that hierarchy level.
    pub sched_load_balance: Option<bool>,

    /// Indicates how much work the kernel should do to rebalance the load on this cpuset.
    ///
    /// See the kernel's documentation for more information.
    pub sched_relax_domain_level: Option<i32>,
    // pub effective_cpus: Vec<usize>,
    // pub effective_mems: Vec<usize>,
}

/// Set of CPU ID or memory node ID for which CPUs and memory nodes a cgroup can use.
///
/// # Instantiation
///
/// `IdSet` can be instantiated in three ways.
///
/// ### Parse a cpuset IDs string (e.g. "0,1,3-5,7")
///
/// `IdSet` implements [`FromStr`], so you can [`parse()`] a string into a `IdSet`. If failed,
/// `parse()` returns an error with kind [`ErrorKind::Parse`].
///
/// ```
/// use cgroups::v1::cpuset::IdSet;
///
/// let id_set = "0,1,3-5,7".parse::<IdSet>().unwrap();
/// assert_eq!(
///     id_set.to_hash_set(),
///     [0, 1, 3, 4, 5, 7].iter().copied().collect(),
/// );
/// ```
///
/// ### Collect an iterator
///
/// `IdSet` implements [`FromIterator`], so you can [`collect()`] an iterator over `usize` into
/// an `IdSet`.
///
/// ```
/// use cgroups::v1::cpuset::IdSet;
///
/// let id_set = [0, 1, 3, 4, 5, 7].iter().copied().collect::<IdSet>();
/// assert_eq!(
///     id_set.to_hash_set(),
///     [0, 1, 3, 4, 5, 7].iter().copied().collect(),
/// );
/// ```
///
/// ### Use `new()` to create an empty set and then `add()` IDs one by one
///
/// ```
/// use cgroups::v1::cpuset::IdSet;
///
/// let mut id_set = IdSet::new();
/// id_set.add(0);
/// id_set.add(1);
/// ```
///
/// # Formatting
///
/// `IdSet` implements [`Display`]. The resulting string is a cpuset IDs string. e.g. Formatting
/// `IdSet` that consists of CPU 0, 1, 3, 4, 5, 7 will generate "0,1,3-5,7".
///
/// ```
/// use std::string::ToString;
/// use cgroups::v1::cpuset::IdSet;
///
/// let id_set = "0,1,3-5,7".parse::<IdSet>().unwrap();
/// assert_eq!(id_set.to_string(), "0,1,3-5,7");
/// ```
///
/// [`FromStr`]: https://doc.rust-lang.org/std/str/trait.FromStr.html
/// [`parse()`]: https://doc.rust-lang.org/std/primitive.str.html#method.parse
/// [`ErrorKind::Parse`]: ../../enum.ErrorKind.html#variant.Parse
///
/// [`FromIterator`]: https://doc.rust-lang.org/std/iter/trait.FromIterator.html
/// [`collect()`]: https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.collect
///
/// [`Display`]: https://doc.rust-lang.org/std/fmt/trait.Display.html
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdSet(HashSet<usize>);

impl_cgroup! {
    Cpuset,

    /// Apply the `Some` fields in `resources.cpuset`.
    ///
    /// See [`Cgroup::apply`] for general information.
    ///
    /// [`Cgroup::apply`]: ../trait.Cgroup.html#tymethod.apply
    fn apply(&mut self, resources: &v1::Resources) -> Result<()> {
        let res: &self::Resources = &resources.cpuset;

        macro_rules! a {
            ($resource: ident, $setter: ident) => {
                if let Some(r) = res.$resource {
                    self.$setter(r)?;
                }
            };
            (ref $resource: ident, $setter: ident) => {
                if let Some(ref r) = res.$resource {
                    self.$setter(r)?;
                }
            };
        }

        a!(ref cpus, set_cpus);
        a!(ref mems, set_mems);
        a!(memory_migrate, set_memory_migrate);
        a!(cpu_exclusive, set_cpu_exclusive);
        a!(mem_exclusive, set_mem_exclusive);
        a!(mem_hardwall, set_mem_hardwall);
        a!(memory_pressure_enabled, set_memory_pressure_enabled);
        a!(memory_spread_page, set_memory_spread_page);
        a!(memory_spread_slab, set_memory_spread_slab);
        a!(sched_load_balance, set_sched_load_balance);
        a!(sched_relax_domain_level, set_sched_relax_domain_level);

        Ok(())
    }
}

#[rustfmt::skip]
macro_rules! gen_doc {
    ($desc: literal, $resource: ident) => { concat!(
        gen_doc!(reads; $desc, $resource), "\n\n",
        gen_doc!(err_read; $resource), "\n\n",
        gen_doc!(eg; $resource), "\n",
    ) };
    ($desc: literal, $resource: ident, $val: expr) => { concat!(
        gen_doc!(sets; $desc, $resource), "\n\n",
        gen_doc!(err_write; $resource), "\n\n",
        gen_doc!(eg; $resource, $val), "\n",
    ) };

    // Description
    (reads; $desc: literal, $resource: ident) => { concat!(
        "Reads ", $desc, ", from `cpuset.", stringify!($resource), "` file.\n\n",
        gen_doc!(ref; $resource)
    ) };
    (sets; $desc: literal, $resource: ident) => { concat!(
        "Sets ", $desc, ", by writing to `cpuset.", stringify!($resource), "` file.\n\n",
        gen_doc!(ref; $resource)
    ) };
    (ref; $resource: ident) => { concat!(
        "See [`Resources.", stringify!($resource), "`](struct.Resources.html#structfield.", stringify!($resource), ") ",
        "and the kernel's documentation for more information about this field.",
    ) };

    // Errors
    (err_read; $resource: ident) => { concat!(
        "# Errors\n\n",
        "Returns an error if failed to read and parse `cpuset.", stringify!($resource), "` file of this cgroup."
    ) };
    (err_write; $resource: ident) => { concat!(
        "# Errors\n\n",
        "Returns an error if failed to write to `cpuset.", stringify!($resource), "` file of this cgroup."
    ) };

    // Examples
    (eg; $resource: ident) => { concat!(
"# Examples

```no_run
# fn main() -> cgroups::Result<()> {
use std::path::PathBuf;
use cgroups::v1::{cpuset, Cgroup, CgroupPath, SubsystemKind};

let cgroup = cpuset::Subsystem::new(
    CgroupPath::new(SubsystemKind::Cpuset, PathBuf::from(\"students/charlie\")));
let ", stringify!($resource), " = cgroup.", stringify!($resource), "()?;
# Ok(())
# }
```"
    ) };

    (eg; $resource: ident, $val: expr) => { concat!(
"# Examples

```no_run
# fn main() -> cgroups::Result<()> {
use std::path::PathBuf;
use cgroups::v1::{cpuset, Cgroup, CgroupPath, SubsystemKind};

let mut cgroup = cpuset::Subsystem::new(
    CgroupPath::new(SubsystemKind::Cpuset, PathBuf::from(\"students/charlie\")));
cgroup.set_", stringify!($resource), "(", stringify!($val), ")?;
# Ok(())
# }
```"
    ) };
}

const CPUS: &str = "cpuset.cpus";
const MEMS: &str = "cpuset.mems";

const MEMORY_MIGRATE: &str = "cpuset.memory_migrate";

const CPU_EXCLUSIVE: &str = "cpuset.cpu_exclusive";
const MEM_EXCLUSIVE: &str = "cpuset.mem_exclusive";

const MEM_HARDWALL: &str = "cpuset.mem_hardwall";

const MEMORY_PRESSURE: &str = "cpuset.memory_pressure";
const MEMORY_PRESSURE_ENABLED: &str = "cpuset.memory_pressure_enabled";

const MEMORY_SPREAD_PAGE: &str = "cpuset.memory_spread_page";
const MEMORY_SPREAD_SLAB: &str = "cpuset.memory_spread_slab";

const SCHED_LOAD_BALANCE: &str = "cpuset.sched_load_balance";
const SCHED_RELAX_DOMAIN_LEVEL: &str = "cpuset.sched_relax_domain_level";

impl Subsystem {
    with_doc! {
        gen_doc!("the set of CPUs on which tasks in this cgroup can run", cpus),
        pub fn cpus(&self) -> Result<IdSet> {
            self.open_file_read(CPUS).and_then(parse)
        }
    }

    with_doc! {
        gen_doc!(
            "a set of CPUs on which tasks in this cgroup can run",
            cpus,
            &"0,1".parse::<cpuset::IdSet>()?
        ),
        pub fn set_cpus(&mut self, cpus: &IdSet) -> Result<()> {
            self.write_file(CPUS, cpus)
        }
    }

    with_doc! {
        gen_doc!("the set of memory nodes which tasks in this cgroup can use", mems),
        pub fn mems(&self) -> Result<IdSet> {
            self.open_file_read(MEMS).and_then(parse)
        }
    }

    with_doc! {
        gen_doc!(
            "a set of memory nodes which tasks in this cgroup can use",
            mems,
            &"0,1".parse::<cpuset::IdSet>()?
        ),
        pub fn set_mems(&mut self, mems: &IdSet) -> Result<()> {
            self.write_file(MEMS, mems)
        }
    }

    with_doc! {
        gen_doc!(
            "whether the memory used by tasks in this cgroup should beb migrated when memory selection is updated",
            memory_migrate
        ),
        pub fn memory_migrate(&self) -> Result<bool> {
            self.open_file_read(MEMORY_MIGRATE)
                .and_then(parse_01_bool)
        }
    }

    with_doc! {
        gen_doc!(
            "whether the memory used by tasks in this cgroup should beb migrated when memory selection is updated",
            memory_migrate,
            true
        ),
        pub fn set_memory_migrate(&mut self, enable: bool) -> Result<()> {
            self.write_file(MEMORY_MIGRATE, enable as i32)
        }
    }

    with_doc! {
        gen_doc!("whether the selected CPUs should be exclusive to this cgroup", cpu_exclusive),
        pub fn cpu_exclusive(&self) -> Result<bool> {
            self.open_file_read(CPU_EXCLUSIVE)
                .and_then(parse_01_bool)
        }
    }

    with_doc! {
        gen_doc!(
            "whether the selected CPUs should be exclusive to this cgroup",
            cpu_exclusive,
            true
        ),
        pub fn set_cpu_exclusive(&mut self, exclusive: bool) -> Result<()> {
            self.write_file(CPU_EXCLUSIVE, exclusive as i32)
        }
    }

    with_doc! {
        gen_doc!(
            "whether the selected memory nodes should be exclusive to this cgroup",
            mem_exclusive
        ),
        pub fn mem_exclusive(&self) -> Result<bool> {
            self.open_file_read(MEM_EXCLUSIVE)
                .and_then(parse_01_bool)
        }
    }

    with_doc! {
        gen_doc!(
            "whether the selected memory nodes should be exclusive to this cgroup",
            mem_exclusive,
            true
        ),
        pub fn set_mem_exclusive(&mut self, exclusive: bool) -> Result<()> {
            self.write_file(MEM_EXCLUSIVE, exclusive as i32)
        }
    }

    with_doc! {
        gen_doc!("whether this cgroup is \"hardwalled\"", mem_hardwall),
        pub fn mem_hardwall(&self) -> Result<bool> {
            self.open_file_read(MEM_HARDWALL)
                .and_then(parse_01_bool)
        }
    }

    with_doc! {
        gen_doc!("whether this cgroup is \"hardwalled\"", mem_hardwall, true),
        pub fn set_mem_hardwall(&mut self, enable: bool) -> Result<()> {
            self.write_file(MEM_HARDWALL, enable as i32)
        }
    }

    with_doc! { concat!(
            "Reads running average of the memory pressure faced by tasks in this cgroup, from ",
            "`cpuset.memory_pressure` file.\n\n",
            "See the kernel's documentation for more information.\n\n",
            gen_doc!(err_read; memory_pressure), "\n\n",
            gen_doc!(eg; memory_pressure),
        ),
        pub fn memory_pressure(&self) -> Result<u64> {
            self.open_file_read(MEMORY_PRESSURE)
                .and_then(parse)
        }
    }

    with_doc! {
        concat!(
            gen_doc!(
                reads;
                "whether the kernel computes the memory pressure of this cgroup",
                memory_pressure_enabled
            ), "\n\n",
            "# Errors\n\n",
            "This field is present only in the root cgroup. If you call this method on a non-root ",
            "cgroup, an error is returned with kind `ErrorKind::InvalidOperation`.\n\n",
            "On the root cgroup, returns an error if failed to read and parse ",
            "`cpuset.memory_pressure_enabled` file.\n\n",
            gen_doc!(eg; memory_pressure_enabled)
        ),
        pub fn memory_pressure_enabled(&self) -> Result<bool> {
            if self.is_root() {
                self.open_file_read(MEMORY_PRESSURE_ENABLED)
                    .and_then(parse_01_bool)
            } else {
                Err(Error::new(ErrorKind::InvalidOperation))
            }
        }
    }

    with_doc! {
        concat!(
            gen_doc!(
                sets;
                "whether the kernel computes the memory pressure of this cgroup",
                memory_pressure_enabled
            ), "\n\n",
            "# Errors\n\n",
            "This field is present only in the root cgroup. If you call this method on a non-root ",
            "cgroup, an error is returned with kind `ErrorKind::InvalidOperation`.\n\n",
            "On the root cgroup, returns an error if failed to write to ",
            "`cpuset.memory_pressure_enabled` file.\n\n",
            gen_doc!(eg; memory_pressure_enabled, true)
        ),
        pub fn set_memory_pressure_enabled(&mut self, enable: bool) -> Result<()> {
            if self.is_root() {
                self.write_file(MEMORY_PRESSURE_ENABLED, enable as i32)
            } else {
                Err(Error::new(ErrorKind::InvalidOperation))
            }
        }
    }

    with_doc! {
        gen_doc!(
            "whether file system buffers are spread across the selected memory nodes",
            memory_spread_page
        ),
        pub fn memory_spread_page(&self) -> Result<bool> {
            self.open_file_read(MEMORY_SPREAD_PAGE)
                .and_then(parse_01_bool)
        }
    }

    with_doc! {
        gen_doc!(
            "whether file system buffers are spread across the selected memory nodes",
            memory_spread_page,
            true
        ),
        pub fn set_memory_spread_page(&mut self, enable: bool) -> Result<()> {
            self.write_file(MEMORY_SPREAD_PAGE, enable as i32)
        }
    }

    with_doc! {
        gen_doc!(
            "whether the kernel slab caches for file I/O are spread across the selected memory nodes",
            memory_spread_slab
        ),
        pub fn memory_spread_slab(&self) -> Result<bool> {
            self.open_file_read(MEMORY_SPREAD_SLAB)
                .and_then(parse_01_bool)
        }
    }

    with_doc! {
        gen_doc!(
            "whether the kernel slab caches for file I/O are spread across the selected memory nodes",
            memory_spread_slab,
            true
        ),
        pub fn set_memory_spread_slab(&mut self, enable: bool) -> Result<()> {
            self.write_file(MEMORY_SPREAD_SLAB, enable as i32)
        }
    }

    with_doc! {
        gen_doc!(
            "whether the kernel rebalances the load across the selected CPUs",
            sched_load_balance
        ),
        pub fn sched_load_balance(&self) -> Result<bool> {
            self.open_file_read(SCHED_LOAD_BALANCE)
                .and_then(parse_01_bool)
        }
    }

    with_doc! {
        gen_doc!(
            "whether the kernel rebalances the load across the selected CPUs",
            sched_load_balance,
            true
        ),
        pub fn set_sched_load_balance(&mut self, enable: bool) -> Result<()> {
            self.write_file(SCHED_LOAD_BALANCE, enable as i32)
        }
    }

    with_doc! {
        gen_doc!(
            "how much work the kernel do to rebalance the load on this cgroup",
            sched_relax_domain_level
        ),
        pub fn sched_relax_domain_level(&self) -> Result<i32> {
            self.open_file_read(SCHED_RELAX_DOMAIN_LEVEL)
                .and_then(parse)
        }
    }

    with_doc! {
        gen_doc!(
            "how much work the kernel do to rebalance the load on this cgroup",
            sched_relax_domain_level,
            -1
        ),
        pub fn set_sched_relax_domain_level(&mut self, level: i32) -> Result<()> {
            self.write_file(SCHED_RELAX_DOMAIN_LEVEL, level)
        }
    }
}

impl FromIterator<usize> for IdSet {
    fn from_iter<I: IntoIterator<Item = usize>>(iter: I) -> Self {
        let mut s = IdSet::new();
        for id in iter {
            s.add(id);
        }
        s
    }
}

impl std::str::FromStr for IdSet {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Ok(IdSet::new());
        }

        let mut result = Vec::new();

        for comma_splitted in s.split(',') {
            if comma_splitted.contains('-') {
                let dash_splitted = comma_splitted.split('-').collect::<Vec<_>>();
                if dash_splitted.len() != 2 {
                    return Err(Error::new(ErrorKind::Parse));
                }

                let start = dash_splitted[0].parse::<usize>().map_err(Error::parse)?;
                let end = dash_splitted[1].parse::<usize>().map_err(Error::parse)?; // inclusive
                if end < start {
                    return Err(Error::new(ErrorKind::Parse));
                }

                for n in start..=end {
                    result.push(n);
                }
            } else {
                result.push(comma_splitted.parse::<usize>().map_err(Error::parse)?);
            }
        }

        Ok(Self::from_iter(result.into_iter()))
    }
}

impl fmt::Display for IdSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return Ok(());
        }

        let mut ids = self.0.iter().collect::<Vec<_>>();
        ids.sort();
        let mut ids = ids.into_iter().copied();

        // Convert IDs into a list of segments.
        // e.g. [0, 1, 3, 4, 5, 7] => [Range(0, 1), Range(3, 5), Single(7)]

        #[derive(Debug)]
        enum IdSegment {
            Single(usize),
            Range(usize, usize),
        }

        let mut current = IdSegment::Single(ids.next().unwrap());
        let mut segments = Vec::new();
        for id in ids {
            use IdSegment::*;
            match current {
                Single(c) if id == c + 1 => {
                    current = Range(c, id);
                }
                Range(s, e) if id == e + 1 => {
                    current = Range(s, id);
                }
                _ => {
                    segments.push(current);
                    current = Single(id);
                }
            }
        }
        segments.push(current);

        // Format segments into a string

        let mut buf = String::new();
        for seg in segments {
            use IdSegment::*;
            let s = match seg {
                Single(id) => format!("{},", id),
                Range(s, e) => {
                    if e == s + 1 {
                        format!("{},{},", s, e)
                    } else {
                        format!("{}-{},", s, e)
                    }
                }
            };
            buf.push_str(&s);
        }

        buf.truncate(buf.len() - 1);
        f.write_str(&buf)
    }
}

impl IdSet {
    /// Creates a new empty set of cpuset IDs.
    ///
    /// # Examples
    ///
    /// ```
    /// use cgroups::v1::cpuset::IdSet;
    ///
    /// let id_set = IdSet::new();
    /// assert!(id_set.to_hash_set().is_empty());
    /// ```
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(HashSet::new())
    }

    /// Copies cpuset IDs in this set into a new `Vec` in an arbitrary order.
    ///
    /// # Examples
    ///
    /// ```
    /// use cgroups::v1::cpuset::IdSet;
    ///
    /// let id_set = [1, 2, 3, 5, 6, 7].iter().copied().collect::<IdSet>();
    /// assert_eq!(
    ///     id_set.to_hash_set(),
    ///     [1, 2, 3, 5, 6, 7].iter().copied().collect(),
    /// );
    /// ```
    pub fn to_hash_set(&self) -> HashSet<usize> {
        self.0.clone()
    }

    /// Add a cpuset ID to this set.
    ///
    /// # Examples
    ///
    /// ```
    /// use cgroups::v1::cpuset::IdSet;
    ///
    /// let mut id_set = IdSet::new();
    /// id_set.add(7);
    /// assert_eq!(id_set.to_hash_set(), [7].iter().copied().collect());
    /// ```
    pub fn add(&mut self, id: usize) {
        self.0.insert(id);
    }

    /// Remove a cpuset ID from this set.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> cgroups::Result<()> {
    /// use cgroups::v1::cpuset::IdSet;
    ///
    /// let mut id_set = "0,1,3-5,7".parse::<IdSet>()?;
    /// id_set.remove(0);
    /// assert_eq!(
    ///     id_set.to_hash_set(),
    ///     [1, 3, 4, 5, 7].iter().copied().collect(),
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn remove(&mut self, id: usize) {
        self.0.remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subsystem_create_file_exists() -> Result<()> {
        let root = Subsystem::new(CgroupPath::new(SubsystemKind::Cpuset, PathBuf::new()));
        assert!(root.file_exists(MEMORY_PRESSURE_ENABLED));

        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Cpuset, gen_cgroup_name!()));
        cgroup.create()?;

        [
            CPUS,
            MEMS,
            MEMORY_MIGRATE,
            CPU_EXCLUSIVE,
            MEM_EXCLUSIVE,
            MEM_HARDWALL,
            MEMORY_PRESSURE,
            // MEMORY_PRESSURE_ENABLED,
            MEMORY_SPREAD_PAGE,
            MEMORY_SPREAD_SLAB,
            SCHED_LOAD_BALANCE,
            SCHED_RELAX_DOMAIN_LEVEL,
        ]
        .iter()
        .all(|n| cgroup.file_exists(n));

        assert!(!cgroup.file_exists(MEMORY_PRESSURE_ENABLED));
        assert!(!cgroup.file_exists("does_not_exist"));

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_cpus() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Cpuset, gen_cgroup_name!()));
        cgroup.create()?;

        let id_set = [0].iter().copied().collect();

        cgroup.set_cpus(&id_set)?;
        assert_eq!(cgroup.cpus()?, id_set);

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_mems() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Cpuset, gen_cgroup_name!()));
        cgroup.create()?;

        let id_set = [0].iter().copied().collect();

        cgroup.set_mems(&id_set)?;
        assert_eq!(cgroup.mems()?, id_set);

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_memory_migrate() -> Result<()> {
        gen_subsystem_test!(Cpuset; memory_migrate, false, set_memory_migrate, true)
    }

    #[test]
    fn test_subsystem_cpu_exclusive() -> Result<()> {
        gen_subsystem_test!(Cpuset; cpu_exclusive, false, set_cpu_exclusive, true)
    }

    #[test]
    fn test_subsystem_mem_exclusive() -> Result<()> {
        gen_subsystem_test!(Cpuset; mem_exclusive, false, set_mem_exclusive, true)
    }

    #[test]
    fn test_subsystem_mem_hardwall() -> Result<()> {
        gen_subsystem_test!(Cpuset; mem_hardwall, false, set_mem_hardwall, true)
    }

    #[test]
    fn test_subsystem_memory_pressure() -> Result<()> {
        gen_subsystem_test!(Cpuset; memory_pressure, 0)
    }

    #[test]
    #[ignore] // (temporarily) overrides the root cgroup
    fn test_subsystem_memory_pressure_enabled() -> Result<()> {
        let mut root = Subsystem::new(CgroupPath::new(SubsystemKind::Cpuset, PathBuf::new()));
        let enabled = root.memory_pressure_enabled()?;

        root.set_memory_pressure_enabled(!enabled)?;
        assert_eq!(root.memory_pressure_enabled()?, !enabled);

        root.set_memory_pressure_enabled(enabled)?;
        assert_eq!(root.memory_pressure_enabled()?, enabled);

        Ok(())
    }

    #[test]
    fn err_subsystem_memory_pressure_enabled() {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Cpuset, gen_cgroup_name!()));
        assert_eq!(
            cgroup.set_memory_pressure_enabled(true).unwrap_err().kind(),
            ErrorKind::InvalidOperation
        );
    }

    #[test]
    fn test_subsystem_memory_spread_page() -> Result<()> {
        gen_subsystem_test!(Cpuset; memory_spread_page, false, set_memory_spread_page, true)
    }

    #[test]
    fn test_subsystem_memory_spread_slab() -> Result<()> {
        gen_subsystem_test!(Cpuset; memory_spread_slab, false, set_memory_spread_slab, true)
    }

    #[test]
    fn test_subsystem_sched_load_balance() -> Result<()> {
        gen_subsystem_test!(Cpuset; sched_load_balance, true, set_sched_load_balance, false)
    }

    #[test]
    fn test_subsystem_sched_relax_domain_level() -> Result<()> {
        // TODO: `set_sched_relax_domain_level()` raises io::Error with kind InvalidInput ?
        gen_subsystem_test!(Cpuset; sched_relax_domain_level, -1)
    }

    #[test]
    fn test_id_set_from_str() {
        macro_rules! hashset {
            ($($x: expr),*) => {{
                #![allow(unused_mut)]
                let mut s = HashSet::new();
                $(
                    s.insert($x);
                )*
                s
            }};
        }

        let test_cases = vec![
            ("", hashset! {}),
            ("0", hashset! {0}),
            ("1,2", hashset! {1, 2}),
            ("0,2,4,6", hashset! {0, 2, 4, 6}),
            ("2-6", hashset! {2, 3, 4, 5, 6}),
            ("0-2,5-7", hashset! {0, 1, 2, 5, 6, 7}),
            ("2-3,4-5,6-7", hashset! {2, 3, 4, 5, 6, 7}),
            ("1,3,5-7,9,10", hashset! {1, 3, 5, 6, 7, 9, 10}),
            ("0-65535", (0..65536).collect()),
        ]
        .into_iter();

        for (case, expected) in test_cases {
            assert_eq!(case.parse::<IdSet>().unwrap().to_hash_set(), expected);
        }
    }

    #[test]
    fn err_id_set_from_str() {
        let testcases = [
            ",", ",0", "0,", "-", "-0", "0-", "0-,1", "0,-1", "1-0", "-1", "0.1", "invalid",
        ]
        .into_iter();

        for case in testcases {
            assert_eq!(case.parse::<IdSet>().unwrap_err().kind(), ErrorKind::Parse);
        }
    }

    #[test]
    fn test_id_set_fmt() {
        let test_cases = vec![
            (vec![], ""),
            (vec![0], "0"),
            (vec![1, 2], "1,2"),
            (vec![0, 2, 4, 6], "0,2,4,6"),
            (vec![2, 3, 4, 5, 6], "2-6"),
            (vec![0, 1, 2, 5, 6, 7], "0-2,5-7"),
            (vec![1, 3, 4, 5, 7, 9, 10, 11], "1,3-5,7,9-11"),
            (vec![1, 3, 5, 6, 7, 9, 10], "1,3,5-7,9,10"),
            ((0..65536).collect(), "0-65535"),
        ]
        .into_iter();

        for (case, expected) in test_cases {
            let id_set = case.iter().copied().collect::<IdSet>();
            assert_eq!(id_set.to_string(), expected.to_string());
        }
    }
}
