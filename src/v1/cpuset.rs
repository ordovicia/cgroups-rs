//! Operations on a Cpuset subsystem.
//!
//! [`Subsystem`] implements [`Cgroup`] trait and subsystem-specific operations.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/cpusets.txt].
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> controlgroup::Result<()> {
//! use std::path::PathBuf;
//! use controlgroup::{Pid, v1::{self, cpuset, Cgroup, CgroupPath, SubsystemKind}};
//!
//! let mut cpuset_cgroup = cpuset::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::Cpuset, PathBuf::from("students/charlie")));
//! cpuset_cgroup.create()?;
//!
//! // Define a resource limit about which CPU and memory nodes a cgroup can use.
//! let id_set = [0].iter().copied().collect::<cpuset::IdSet>();
//!
//! let resources = cpuset::Resources {
//!     cpus: Some(id_set.clone()),
//!     mems: Some(id_set),
//!     memory_migrate: Some(true),
//!     ..cpuset::Resources::default()
//! };
//!
//! // Apply the resource limit to this cgroup.
//! cpuset_cgroup.apply(&resources.into())?;
//!
//! // Add tasks to this cgroup.
//! let pid = Pid::from(std::process::id());
//! cpuset_cgroup.add_task(pid)?;
//!
//! // Do something ...
//!
//! cpuset_cgroup.remove_task(pid)?;
//! cpuset_cgroup.delete()?;
//! # Ok(())
//! # }
//! ```
//!
//! [`Subsystem`]: struct.Subsystem.html
//! [`Cgroup`]: ../trait.Cgroup.html
//!
//! [Documentation/cgroup-v1/cpusets.txt]: https://www.kernel.org/doc/Documentation/cgroup-v1/cpusets.txt

use std::{collections::HashSet, fmt, iter::FromIterator, path::PathBuf};

use crate::{
    parse::{parse, parse_01_bool},
    v1::{self, cgroup::CgroupHelper, Cgroup, CgroupPath},
    Error, ErrorKind, Result,
};

/// Handler of a Cpuset subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Resource limit on which CPUs and which memory nodes a cgroup can use, and how they are
/// controlled by the system.
///
/// See the kernel's documentation for more information about the fields.
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

    /// If true, the kernel slab caches for file I/O are evenly spread across the memory nodes
    /// specified in the `mems` field.
    pub memory_spread_slab: Option<bool>,

    /// If true, the kernel will attempt to balance the load between the CPUs specified in the
    /// `cpus` field. This field is ignored if an ancestor cgroup already has enabled the load
    /// balancing at that hierarchy level.
    pub sched_load_balance: Option<bool>,

    /// Indicates how much work the kernel should do to balance the load on this cpuset.
    pub sched_relax_domain_level: Option<i32>,
    // pub effective_cpus: Vec<IdSet>,
    // pub effective_mems: Vec<IdSet>,
}

impl Into<v1::Resources> for Resources {
    fn into(self) -> v1::Resources {
        v1::Resources {
            cpuset: self,
            ..v1::Resources::default()
        }
    }
}

/// Set of CPU ID or memory node ID for which CPUs and memory nodes.
///
/// # Instantiation
///
/// `IdSet` can be instantiated in three ways.
///
/// ### Parse a cpuset IDs string (e.g. "0,1,3-5,7")
///
/// `IdSet` implements [`FromStr`], so you can [`parse`] a string into a `IdSet`. If failed, `parse`
/// returns an error with kind [`ErrorKind::Parse`].
///
/// ```
/// use controlgroup::v1::cpuset::IdSet;
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
/// `IdSet` implements [`FromIterator`], so you can [`collect`] an iterator over `u32` into an
/// `IdSet`.
///
/// ```
/// use controlgroup::v1::cpuset::IdSet;
///
/// let id_set = [0, 1, 3, 4, 5, 7].iter().copied().collect::<IdSet>();
/// assert_eq!(
///     id_set.to_hash_set(),
///     [0, 1, 3, 4, 5, 7].iter().copied().collect(),
/// );
/// ```
///
/// ### Use `new` to create an empty set and then `add` IDs one by one
///
/// ```
/// use controlgroup::v1::cpuset::IdSet;
///
/// let mut id_set = IdSet::new();
/// id_set.add(0);
/// id_set.add(1);
///
/// assert_eq!(id_set.to_hash_set(), [0, 1].iter().copied().collect());
/// ```
///
/// # Formatting
///
/// `IdSet` implements [`Display`]. The resulting string is a cpuset IDs string. e.g. Formatting
/// `IdSet` that consists of CPU 0, 1, 3, 4, 5, 7 will generate "0,1,3-5,7".
///
/// ```
/// use std::string::ToString;
/// use controlgroup::v1::cpuset::IdSet;
///
/// let id_set = "0,1,3-5,7".parse::<IdSet>().unwrap();
/// assert_eq!(id_set.to_string(), "0,1,3-5,7");
/// ```
///
/// [`FromStr`]: https://doc.rust-lang.org/std/str/trait.FromStr.html
/// [`parse`]: https://doc.rust-lang.org/std/primitive.str.html#method.parse
/// [`ErrorKind::Parse`]: ../../enum.ErrorKind.html#variant.Parse
///
/// [`FromIterator`]: https://doc.rust-lang.org/std/iter/trait.FromIterator.html
/// [`collect`]: https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.collect
///
/// [`Display`]: https://doc.rust-lang.org/std/fmt/trait.Display.html
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdSet(HashSet<u32>);

impl FromIterator<u32> for IdSet {
    fn from_iter<I: IntoIterator<Item = u32>>(iter: I) -> Self {
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
        let s = s.trim();
        if s.is_empty() {
            return Ok(IdSet::new());
        }

        let mut result = Vec::new();

        for comma_split in s.split(',') {
            let mut dash_split = comma_split.split('-');
            match (dash_split.next(), dash_split.next(), dash_split.next()) {
                (Some(start), Some(end), None) => {
                    let start = start.parse()?;
                    let end = end.parse()?; // inclusive

                    if end < start {
                        bail_parse!();
                    }

                    for n in start..=end {
                        result.push(n);
                    }
                }
                (Some(single), None, None) => {
                    result.push(single.parse()?);
                }
                _ => {
                    bail_parse!();
                }
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
            Single(u32),
            Range(u32, u32),
        }

        let mut current = IdSegment::Single(ids.next().unwrap());
        let mut segments = Vec::new();
        for id in ids {
            use IdSegment::*;

            match current {
                Single(cur) if id == cur + 1 => {
                    current = Range(cur, id);
                }
                Range(start, end) if id == end + 1 => {
                    current = Range(start, id);
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
    /// use controlgroup::v1::cpuset::IdSet;
    ///
    /// let id_set = IdSet::new();
    /// assert!(id_set.to_hash_set().is_empty());
    /// ```
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(HashSet::new())
    }

    /// Clones cpuset IDs in this set into a new [`HashSet`].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashSet;
    /// use controlgroup::v1::cpuset::IdSet;
    ///
    /// let id_set = [1, 2, 3, 5, 6, 7].iter().copied().collect::<IdSet>();
    /// assert_eq!(
    ///     id_set.to_hash_set(),
    ///     [1, 2, 3, 5, 6, 7].iter().copied().collect::<HashSet<u32>>(),
    /// );
    /// ```
    ///
    /// [`HashSet`]: https://doc.rust-lang.org/std/collections/struct.HashSet.html
    pub fn to_hash_set(&self) -> HashSet<u32> {
        self.0.clone()
    }

    /// Adds a cpuset ID to this set.
    ///
    /// # Examples
    ///
    /// ```
    /// use controlgroup::v1::cpuset::IdSet;
    ///
    /// let mut id_set = IdSet::new();
    /// id_set.add(7);
    /// assert_eq!(id_set.to_hash_set(), [7].iter().copied().collect());
    /// ```
    pub fn add(&mut self, id: u32) {
        self.0.insert(id);
    }

    /// Remove a cpuset ID from this set.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> controlgroup::Result<()> {
    /// use controlgroup::v1::cpuset::IdSet;
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
    pub fn remove(&mut self, id: u32) {
        self.0.remove(&id);
    }
}

impl_cgroup! {
    Subsystem, Cpuset,

    /// Applies the `Some` fields in `resources.cpuset`.
    fn apply(&mut self, resources: &v1::Resources) -> Result<()> {
        let res: &self::Resources = &resources.cpuset;

        if let Some(ref cpus) = res.cpus {
            self.set_cpus(cpus)?;
        }
        if let Some(ref mems) = res.mems {
            self.set_mems(mems)?;
        }

        macro_rules! a {
            ($field: ident, $setter: ident) => {
                if let Some(r) = res.$field {
                    self.$setter(r)?;
                }
            };
        }

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

macro_rules! def_file {
    ($var: ident, $name: literal) => {
        const $var: &str = concat!("cpuset.", $name);
    };
}

def_file!(CPUS, "cpus");
def_file!(MEMS, "mems");

def_file!(MEMORY_MIGRATE, "memory_migrate");

def_file!(CPU_EXCLUSIVE, "cpu_exclusive");
def_file!(MEM_EXCLUSIVE, "mem_exclusive");

def_file!(MEM_HARDWALL, "mem_hardwall");

def_file!(MEMORY_PRESSURE, "memory_pressure");
def_file!(MEMORY_PRESSURE_ENABLED, "memory_pressure_enabled");

def_file!(MEMORY_SPREAD_PAGE, "memory_spread_page");
def_file!(MEMORY_SPREAD_SLAB, "memory_spread_slab");

def_file!(SCHED_LOAD_BALANCE, "sched_load_balance");
def_file!(SCHED_RELAX_DOMAIN_LEVEL, "sched_relax_domain_level");

const CLONE_CHILDREN: &str = "cgroup.clone_children";

const DOMAIN_LEVEL_MIN: i32 = -1;
const DOMAIN_LEVEL_MAX: i32 = 5;

impl Subsystem {
    /// Reads the set of CPUs this cgroup can use from `cpuset.cpus` file.
    pub fn cpus(&self) -> Result<IdSet> {
        self.open_file_read(CPUS).and_then(parse)
    }

    /// Sets a set of CPUs this cgroup can use by writing to `cpuset.cpus` file.
    pub fn set_cpus(&mut self, cpus: &IdSet) -> Result<()> {
        self.write_file(CPUS, cpus)
    }

    /// Reads the set of memory nodes this cgroup can use from `cpuset.mems` file.
    pub fn mems(&self) -> Result<IdSet> {
        self.open_file_read(MEMS).and_then(parse)
    }

    /// Sets a set of memory nodes this cgroup can use by writing to `cpuset.mems` file.
    pub fn set_mems(&mut self, mems: &IdSet) -> Result<()> {
        self.write_file(MEMS, mems)
    }

    /// Reads whether the memory used by this cgroup should be migrated when memory selection is
    /// updated, from `cpuset.memory_migrate` file.
    pub fn memory_migrate(&self) -> Result<bool> {
        self.open_file_read(MEMORY_MIGRATE).and_then(parse_01_bool)
    }

    /// Sets whether the memory used by this cgroup should be migrated when memory selection is
    /// updated, by writing to `cpuset.memory_migrate` file.
    pub fn set_memory_migrate(&mut self, enable: bool) -> Result<()> {
        self.write_file(MEMORY_MIGRATE, enable as i32)
    }

    /// Reads whether the selected CPUs should be exclusive to this cgroup, from
    /// `cpuset.cpu_exclusive` file.
    pub fn cpu_exclusive(&self) -> Result<bool> {
        self.open_file_read(CPU_EXCLUSIVE).and_then(parse_01_bool)
    }

    /// Sets whether the selected CPUs should be exclusive to this cgroup, by writing to
    /// `cpuset.cpu_exclusive` file.
    pub fn set_cpu_exclusive(&mut self, exclusive: bool) -> Result<()> {
        self.write_file(CPU_EXCLUSIVE, exclusive as i32)
    }

    /// Reads whether the selected memory nodes should be exclusive to this cgroup, from
    /// `cpuset.mem_exclusive` file.
    pub fn mem_exclusive(&self) -> Result<bool> {
        self.open_file_read(MEM_EXCLUSIVE).and_then(parse_01_bool)
    }

    /// Sets whether the selected memory nodes should be exclusive to this cgroup, by writing to
    /// `cpuset.mem_exclusive` file.
    pub fn set_mem_exclusive(&mut self, exclusive: bool) -> Result<()> {
        self.write_file(MEM_EXCLUSIVE, exclusive as i32)
    }

    /// Reads whether this cgroup is "hardwalled" from `cpuset.mem_hardwall` file.
    pub fn mem_hardwall(&self) -> Result<bool> {
        self.open_file_read(MEM_HARDWALL).and_then(parse_01_bool)
    }

    /// Sets whether this cgroup is "hardwalled" by writing to `cpuset.mem_hardwall` file.
    pub fn set_mem_hardwall(&mut self, enable: bool) -> Result<()> {
        self.write_file(MEM_HARDWALL, enable as i32)
    }

    /// Reads the running average of the memory pressure faced by this cgroup, from
    /// `cpuset.memory_pressure` file.
    pub fn memory_pressure(&self) -> Result<u64> {
        self.open_file_read(MEMORY_PRESSURE).and_then(parse)
    }

    /// Reads whether the kernel computes the memory pressure of this cgroup, from
    /// `cpuset.memory_pressure_enabled` file.
    ///
    /// # Errors
    ///
    /// This field is present only in the root cgroup. If you call this method on a non-root cgroup,
    /// an error is returned with kind [`ErrorKind::InvalidOperation`].
    ///
    /// [`ErrorKind::InvalidOperation`]: ../../enum.ErrorKind.html#variant.InvalidOperation
    pub fn memory_pressure_enabled(&self) -> Result<bool> {
        if self.is_root() {
            self.open_file_read(MEMORY_PRESSURE_ENABLED)
                .and_then(parse_01_bool)
        } else {
            Err(Error::new(ErrorKind::InvalidOperation))
        }
    }

    /// Sets whether the kernel computes the memory pressure of this cgroup, by writing to
    /// `cpuset.memory_pressure_enabled` file.
    ///
    /// # Errors
    ///
    /// This field is present only in the root cgroup. If you call this method on a non-root cgroup,
    /// an error is returned with kind [`ErrorKind::InvalidOperation`].
    ///
    /// [`ErrorKind::InvalidOperation`]: ../../enum.ErrorKind.html#variant.InvalidOperation
    pub fn set_memory_pressure_enabled(&mut self, enable: bool) -> Result<()> {
        if self.is_root() {
            self.write_file(MEMORY_PRESSURE_ENABLED, enable as i32)
        } else {
            Err(Error::new(ErrorKind::InvalidOperation))
        }
    }

    /// Reads whether file system buffers are spread across the selected memory nodes, from
    /// `cpuset.memory_spread_page` file.
    pub fn memory_spread_page(&self) -> Result<bool> {
        self.open_file_read(MEMORY_SPREAD_PAGE)
            .and_then(parse_01_bool)
    }

    /// Sets whether file system buffers are spread across the selected memory nodes, by writing to
    /// `cpuset.memory_spread_page` file.
    pub fn set_memory_spread_page(&mut self, enable: bool) -> Result<()> {
        self.write_file(MEMORY_SPREAD_PAGE, enable as i32)
    }

    /// Reads whether the kernel slab caches for file I/O are spread across the selected memory
    /// nodes, from `cpuset.memory_spread_slab` file.
    pub fn memory_spread_slab(&self) -> Result<bool> {
        self.open_file_read(MEMORY_SPREAD_SLAB)
            .and_then(parse_01_bool)
    }

    /// Sets whether the kernel slab caches for file I/O are spread across the selected memory
    /// nodes, by writing to `cpuset.memory_spread_slab` file.
    pub fn set_memory_spread_slab(&mut self, enable: bool) -> Result<()> {
        self.write_file(MEMORY_SPREAD_SLAB, enable as i32)
    }

    /// Reads whether the kernel balances the load across the selected CPUs, from
    /// `cpuset.sched_load_balance` file.
    pub fn sched_load_balance(&self) -> Result<bool> {
        self.open_file_read(SCHED_LOAD_BALANCE)
            .and_then(parse_01_bool)
    }

    /// Reads whether the kernel balances the load across the selected CPUs, by writing to
    /// `cpuset.sched_load_balance` file.
    pub fn set_sched_load_balance(&mut self, enable: bool) -> Result<()> {
        self.write_file(SCHED_LOAD_BALANCE, enable as i32)
    }

    /// Reads how much work the kernel do to balance the load on this cgroup, from
    /// `cpuset.sched_relax_domain_level` file.
    pub fn sched_relax_domain_level(&self) -> Result<i32> {
        self.open_file_read(SCHED_RELAX_DOMAIN_LEVEL)
            .and_then(parse)
    }

    /// Sets how much work the kernel do to balance the load on this cgroup, by writing to
    /// `cpuset.sched_relax_domain_level` file.
    ///
    /// The value must be between -1 and 5 (inclusive). If the value is out-of-range, this method
    /// returns an eror with kind [`ErrorKind::InvalidArgument`].
    ///
    /// [`ErrorKind::InvalidArgument`]: ../../enum.ErrorKind.html#variant.InvalidArgument
    pub fn set_sched_relax_domain_level(&mut self, level: i32) -> Result<()> {
        if level < DOMAIN_LEVEL_MIN || level > DOMAIN_LEVEL_MAX {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }

        self.write_file(SCHED_RELAX_DOMAIN_LEVEL, level)
    }

    /// Reads whether a new cpuset cgroup will copy the configuration from its parent cgroup, from
    /// `cgoup.clone_children` file.
    pub fn clone_children(&self) -> Result<bool> {
        self.open_file_read(CLONE_CHILDREN).and_then(parse_01_bool)
    }

    /// Sets whether a new cpuset cgroup will copy the configuration from its parent cgroup, by
    /// writing to `cgoup.clone_children` file.
    pub fn set_clone_children(&mut self, clone: bool) -> Result<()> {
        self.write_file(CLONE_CHILDREN, clone as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use v1::SubsystemKind;

    #[test]
    fn test_subsystem_create_file_exists_delete() -> Result<()> {
        // root
        let root = Subsystem::new(CgroupPath::new(SubsystemKind::Cpuset, PathBuf::new()));
        assert!(root.file_exists(MEMORY_PRESSURE_ENABLED));

        // non-root
        gen_test_subsystem_create_delete!(
            Cpuset,
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
        )?;

        let mut non_root =
            Subsystem::new(CgroupPath::new(SubsystemKind::Cpuset, gen_cgroup_name!()));
        non_root.create()?;

        assert!(non_root.file_exists(CLONE_CHILDREN));
        assert!(!non_root.file_exists(MEMORY_PRESSURE_ENABLED));
        assert!(!non_root.file_exists("does_not_exist"));

        non_root.delete()
    }

    #[test]
    #[ignore] // must not be executed in parallel because of `{cpu,mem}_exclusive`
    fn test_subsystem_apply() -> Result<()> {
        let id_set = [0].iter().copied().collect::<IdSet>();

        gen_test_subsystem_apply!(
            Cpuset,
            Resources {
                cpus: Some(id_set.clone()),
                mems: Some(id_set.clone()),
                memory_migrate: Some(true),
                cpu_exclusive: Some(true),
                mem_exclusive: Some(true),
                mem_hardwall: Some(true),
                memory_pressure_enabled: None, // Some(true),
                memory_spread_page: Some(true),
                memory_spread_slab: Some(true),
                sched_load_balance: Some(false),
                sched_relax_domain_level: None, // Some(0)
            },
            (cpus, id_set),
            (mems, id_set),
            (memory_migrate, true),
            (cpu_exclusive, true),
            (mem_exclusive, true),
            (mem_hardwall, true),
            (memory_spread_page, true),
            (memory_spread_slab, true),
            (sched_load_balance, false),
        )
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
        gen_test_subsystem_get_set!(Cpuset, memory_migrate, false, set_memory_migrate, true)
    }

    #[test]
    #[ignore] // must not be executed in parallel
    fn test_subsystem_cpu_exclusive() -> Result<()> {
        gen_test_subsystem_get_set!(Cpuset, cpu_exclusive, false, set_cpu_exclusive, true)
    }

    #[test]
    #[ignore] // must not be executed in parallel
    fn test_subsystem_mem_exclusive() -> Result<()> {
        gen_test_subsystem_get_set!(Cpuset, mem_exclusive, false, set_mem_exclusive, true)
    }

    #[test]
    fn test_subsystem_mem_hardwall() -> Result<()> {
        gen_test_subsystem_get_set!(Cpuset, mem_hardwall, false, set_mem_hardwall, true)
    }

    #[test]
    fn test_subsystem_memory_pressure() -> Result<()> {
        gen_test_subsystem_get!(Cpuset, memory_pressure, 0)
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
    fn err_subsystem_memory_pressure_enabled() -> Result<()> {
        gen_test_subsystem_err!(
            Memory,
            set_memory_pressure_enabled,
            (InvalidOperation, true)
        )
    }

    #[test]
    fn test_subsystem_memory_spread_page() -> Result<()> {
        gen_test_subsystem_get_set!(
            Cpuset,
            memory_spread_page,
            false,
            set_memory_spread_page,
            true
        )
    }

    #[test]
    fn test_subsystem_memory_spread_slab() -> Result<()> {
        gen_test_subsystem_get_set!(
            Cpuset,
            memory_spread_slab,
            false,
            set_memory_spread_slab,
            true
        )
    }

    #[test]
    fn test_subsystem_sched_load_balance() -> Result<()> {
        gen_test_subsystem_get_set!(
            Cpuset,
            sched_load_balance,
            true,
            set_sched_load_balance,
            false
        )
    }

    #[test]
    fn test_subsystem_sched_relax_domain_level() -> Result<()> {
        // NOTE: `set_sched_relax_domain_level()` raises `io::Error` with kind `InvalidInput` on
        //       Xenial and Bionic on Travis-CI
        gen_test_subsystem_get!(Cpuset, sched_relax_domain_level, DOMAIN_LEVEL_MIN)
    }

    #[test]
    fn err_subsystem_sched_relax_domain_level() -> Result<()> {
        gen_test_subsystem_err!(
            Memory,
            set_sched_relax_domain_level,
            (InvalidArgument, DOMAIN_LEVEL_MIN - 1),
            (InvalidArgument, DOMAIN_LEVEL_MAX + 1)
        )
    }

    #[test]
    fn test_subsystem_clone_children() -> Result<()> {
        gen_test_subsystem_get_set!(Cpuset, clone_children, false, set_clone_children, true)
    }

    #[test]
    fn test_id_set_from_str() {
        macro_rules! hashset {
            ( $( $x: expr ),* $(, )? ) => {{
                #![allow(unused_mut, clippy::let_and_return)]
                let mut s = HashSet::new();
                $( s.insert($x); )*
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
            (" 1,3,5-7,9,10 ", hashset! {1, 3, 5, 6, 7, 9, 10}),
            ("0-65535", (0..65536).collect()),
        ]
        .into_iter();

        for (case, expected) in test_cases {
            assert_eq!(case.parse::<IdSet>().unwrap().to_hash_set(), expected);
        }
    }

    #[test]
    fn err_id_set_from_str() {
        for test_case in &[
            ",",
            ",0",
            "0,",
            "0, 1",
            "-",
            "-0",
            "0-",
            "0-,1",
            "0,-1",
            "1-0",
            "-1",
            "0.1",
            "invalid",
            "0,invalid",
        ] {
            assert_eq!(
                test_case.parse::<IdSet>().unwrap_err().kind(),
                ErrorKind::Parse
            );
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
