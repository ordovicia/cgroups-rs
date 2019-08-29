//! Operations on a cpuset subsystem.
//!
//! [`Subsystem`] implements [`Cgroup`] trait and subsystem-specific behaviors.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/cpusets.txt].
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! use std::path::PathBuf;
//! use cgroups::{Pid, v1::{self, cpuset, Cgroup, CgroupPath, SubsystemKind}};
//!
//! let mut cpuset_cgroup = cpuset::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::Cpuset, PathBuf::from("students/charlie")));
//! cpuset_cgroup.create()?;
//!
//! // Define a resource limit about which CPU and memory nodes a cgroup can use.
//! let id_set = {
//!     let mut id_set = cpuset::IdSet::new();
//!     id_set.add(0);
//!     id_set
//! };
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

/// Handler of a cpuset subsystem.
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

    /// If true, the kernel slab caches for file I/O are evenly spread across the memory nodes specified
    /// in the `mems` field.
    pub memory_spread_slab: Option<bool>,

    /// If true, the kernel will attempt to balance the load between the CPUs specified in the
    /// `cpus` field. This field is ignored if an ancestor cgroup already has enabled the load
    /// balancing at that hierarchy level.
    pub sched_load_balance: Option<bool>,

    /// Indicates how much work the kernel should do to balance the load on this cpuset.
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
/// `IdSet` implements [`FromStr`], so you can [`parse`] a string into a `IdSet`. If failed,
/// `parse` returns an error with kind [`ErrorKind::Parse`].
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
/// `IdSet` implements [`FromIterator`], so you can [`collect`] an iterator over `usize` into
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
/// ### Use `new` to create an empty set and then `add` IDs one by one
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
/// [`parse`]: https://doc.rust-lang.org/std/primitive.str.html#method.parse
/// [`ErrorKind::Parse`]: ../../enum.ErrorKind.html#variant.Parse
///
/// [`FromIterator`]: https://doc.rust-lang.org/std/iter/trait.FromIterator.html
/// [`collect`]: https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.collect
///
/// [`Display`]: https://doc.rust-lang.org/std/fmt/trait.Display.html
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdSet(HashSet<usize>);

impl_cgroup! {
    Subsystem, Cpuset,

    /// Applies the `Some` fields in `resources.cpuset`.
    ///
    /// See [`Cgroup::apply`] for general information.
    ///
    /// [`Cgroup::apply`]: ../trait.Cgroup.html#tymethod.apply
    fn apply(&mut self, resources: &v1::Resources) -> Result<()> {
        let res: &self::Resources = &resources.cpuset;

        macro_rules! a {
            ($field: ident, $setter: ident) => {
                if let Some(r) = res.$field {
                    self.$setter(r)?;
                }
            };
        }

        if let Some(ref cpus) = res.cpus {
            self.set_cpus(cpus)?;
        }
        if let Some(ref mems) = res.mems {
            self.set_mems(mems)?;
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

const MEMORY_PRESSURE_ENABLED: &str = "cpuset.memory_pressure_enabled";
const CLONE_CHILDREN: &str = "cgroup.clone_children";

macro_rules! _gen_getter {
    ($desc: literal, $field: ident $( : $link : ident )?, $ty: ty, $parser: ident) => {
        gen_getter!(cpuset, Cpuset, $desc, $field $( : $link )?, $ty, $parser);
    };
}

macro_rules! _gen_setter {
    ($desc: literal, $field: ident : link, $setter: ident, $ty: ty, $val: expr) => {
        gen_setter!(cpuset, Cpuset, $desc, $field: link, $setter, $ty, $val);
    };

    (
        $desc: literal,
        $field: ident : link,
        $setter: ident,
        $arg: ident : $ty: ty as $as: ty,
        $val: expr
    ) => {
        gen_setter!(
            cpuset,
            Cpuset,
            $desc,
            $field: link,
            $setter,
            $arg: $ty as $as,
            $val
        );
    };
}

impl Subsystem {
    _gen_getter!(
        "the set of CPUs this cgroup can use",
        cpus: link,
        IdSet,
        parse
    );

    _gen_setter!(
        "a set of CPUs this cgroup can use",
        cpus: link,
        set_cpus,
        &IdSet,
        &"0,1".parse::<cpuset::IdSet>()?
    );

    _gen_getter!(
        "the set of memory nodes this cgroup can use",
        mems: link,
        IdSet,
        parse
    );

    _gen_setter!(
        "a set of memory nodes this cgroup can use",
        mems: link,
        set_mems,
        &IdSet,
        &"0,1".parse::<cpuset::IdSet>()?
    );

    _gen_getter!(
        "whether the memory used by this cgroup should be migrated when memory selection is updated,",
        memory_migrate : link, bool, parse_01_bool
    );

    _gen_setter!(
        "whether the memory used by this cgroup should be migrated when memory selection is updated,",
        memory_migrate : link, set_memory_migrate, enable : bool as i32, true
    );

    _gen_getter!(
        "whether the selected CPUs should be exclusive to this cgroup,",
        cpu_exclusive: link,
        bool,
        parse_01_bool
    );

    _gen_setter!(
        "whether the selected CPUs should be exclusive to this cgroup,",
        cpu_exclusive: link,
        set_cpu_exclusive,
        exclusive: bool as i32,
        true
    );

    _gen_getter!(
        "whether the selected memory nodes should be exclusive to this cgroup,",
        mem_exclusive: link,
        bool,
        parse_01_bool
    );

    _gen_setter!(
        "whether the selected memory nodes should be exclusive to this cgroup,",
        mem_exclusive: link,
        set_mem_exclusive,
        exclusive: bool as i32,
        true
    );

    _gen_getter!(
        "whether this cgroup is \"hardwalled\"",
        mem_hardwall: link,
        bool,
        parse_01_bool
    );

    _gen_setter!(
        "whether this cgroup is \"hardwalled\"",
        mem_hardwall: link,
        set_mem_hardwall,
        enable: bool as i32,
        true
    );

    _gen_getter!(
        "the running average of the memory pressure faced by this cgroup,",
        memory_pressure,
        u64,
        parse
    );

    with_doc! { concat!(
        gen_doc!(
            reads;
            cpuset, "whether the kernel computes the memory pressure of this cgroup,",
            memory_pressure_enabled
         ),
        gen_doc!(see; memory_pressure_enabled),
"# Errors

This field is present only in the root cgroup. If you call this method on a non-root cgroup, an
error is returned with kind [`ErrorKind::InvalidOperation`]. On the root cgroup, returns an error if
failed to read and parse `cpuset.memory_pressure_enabled` file.

[`ErrorKind::InvalidOperation`]: ../../enum.ErrorKind.html#variant.InvalidOperation\n\n",
        gen_doc!(eg_read; cpuset, Cpuset, memory_pressure_enabled)),
        pub fn memory_pressure_enabled(&self) -> Result<bool> {
            if self.is_root() {
                self.open_file_read(MEMORY_PRESSURE_ENABLED)
                    .and_then(parse_01_bool)
            } else {
                Err(Error::new(ErrorKind::InvalidOperation))
            }
        }
    }

    with_doc! { concat!(
        gen_doc!(
            sets;
            cpuset, "whether the kernel computes the memory pressure of this cgroup,",
            memory_pressure_enabled
        ),
        gen_doc!(see; memory_pressure_enabled),
"# Errors

This field is present only in the root cgroup. If you call this method on a non-root cgroup, an
error is returned with kind [`ErrorKind::InvalidOperation`]. On the root cgroup, returns an error if
failed to write to `cpuset.memory_pressure_enabled` file.

[`ErrorKind::InvalidOperation`]: ../../enum.ErrorKind.html#variant.InvalidOperation\n\n",
        gen_doc!(eg_write; cpuset, Cpuset, set_memory_pressure_enabled, true)),
        pub fn set_memory_pressure_enabled(&mut self, enable: bool) -> Result<()> {
            if self.is_root() {
                self.write_file(MEMORY_PRESSURE_ENABLED, enable as i32)
            } else {
                Err(Error::new(ErrorKind::InvalidOperation))
            }
        }
    }

    _gen_getter!(
        "whether file system buffers are spread across the selected memory nodes,",
        memory_spread_page: link,
        bool,
        parse_01_bool
    );

    _gen_setter!(
        "whether file system buffers are spread across the selected memory nodes,",
        memory_spread_page: link,
        set_memory_spread_page,
        enable: bool as i32,
        true
    );

    _gen_getter!(
        "whether the kernel slab caches for file I/O are spread across the selected memory nodes,",
        memory_spread_slab: link,
        bool,
        parse_01_bool
    );

    _gen_setter!(
        "whether the kernel slab caches for file I/O are spread across the selected memory nodes,",
        memory_spread_slab: link,
        set_memory_spread_slab,
        enable: bool as i32,
        true
    );

    _gen_getter!(
        "whether the kernel balances the load across the selected CPUs,",
        sched_load_balance: link,
        bool,
        parse_01_bool
    );

    _gen_setter!(
        "whether the kernel balances the load across the selected CPUs,",
        sched_load_balance: link,
        set_sched_load_balance,
        enable: bool as i32,
        true
    );

    _gen_getter!(
        "how much work the kernel do to balance the load on this cgroup,",
        sched_relax_domain_level: link,
        i32,
        parse
    );

    with_doc! { concat!(
        gen_doc!(
            sets; cpuset,
            "how much work the kernel do to balance the load on this cgroup,"
            : "The value must be between -1 and 5 (inclusive).",
            sched_relax_domain_level
        ),
        gen_doc!(see; sched_relax_domain_level),
"# Errors

Returns an error with kind [`ErrorKind::InvalidArgument`] if the level is out-of-range. Returns an
error if failed to write to `cpuset.sched_relax_domain_level` file of this cgroup.

[`ErrorKind::InvalidArgument`]: ../../enum.ErrorKind.html#variant.InvalidArgument\n\n",
        gen_doc!(eg_write; cpuset, Cpuset, set_sched_relax_domain_level, 0)),
        pub fn set_sched_relax_domain_level(&mut self, level: i32) -> Result<()> {
            if level < -1 || level > 5 {
                return Err(Error::new(ErrorKind::InvalidArgument));
            }

            self.write_file("cpuset.sched_relax_domain_level", level)
        }
    }

    with_doc! { concat!(
        gen_doc!(
            reads;
            cgroup,
            "whether a new cpuset cgroup will copy the configuration from its parent cgroup,",
            clone_children
        ),
        gen_doc!(see),
        gen_doc!(err_read; cgroup, clone_children),
        gen_doc!(eg_read; cpuset, Cpuset, clone_children)),
        pub fn clone_children(&self) -> Result<bool> {
            self.open_file_read(CLONE_CHILDREN).and_then(parse_01_bool)
        }
    }

    with_doc! { concat!(
        gen_doc!(
            sets;
            cgroup,
            "whether a new cpuset cgroup will copy the configuration from its parent cgroup,",
            clone_children
        ),
        gen_doc!(see),
        gen_doc!(err_write; cgroup, clone_children),
        gen_doc!(eg_write; cpuset, Cpuset, set_clone_children, true)),
        pub fn set_clone_children(&mut self, clone: bool) -> Result<()> {
            self.write_file(CLONE_CHILDREN, clone as i32)
        }
    }
}

impl Into<v1::Resources> for Resources {
    fn into(self) -> v1::Resources {
        v1::Resources {
            cpuset: self,
            ..v1::Resources::default()
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

        for comma_split in s.split(',') {
            if comma_split.contains('-') {
                let dash_split = comma_split.split('-').collect::<Vec<_>>();
                if dash_split.len() != 2 {
                    return Err(Error::new(ErrorKind::Parse));
                }

                let start = dash_split[0].parse::<usize>()?;
                let end = dash_split[1].parse::<usize>()?; // inclusive
                if end < start {
                    return Err(Error::new(ErrorKind::Parse));
                }

                for n in start..=end {
                    result.push(n);
                }
            } else {
                result.push(comma_split.parse::<usize>()?);
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
    use v1::SubsystemKind;

    #[test]
    #[rustfmt::skip]
    fn test_subsystem_create_file_exists() -> Result<()> {
        // root
        let root = Subsystem::new(CgroupPath::new(SubsystemKind::Cpuset, PathBuf::new()));
        assert!(root.file_exists(MEMORY_PRESSURE_ENABLED));

        // non-root
        gen_subsystem_test!(
            Cpuset, cpuset,
            [
                "cpus", "mems", "memory_migrate", "cpu_exclusive", "mem_exclusive", "mem_hardwall",
                "memory_pressure", // "memory_pressure_enabled",
                "memory_spread_page", "memory_spread_slab", "sched_load_balance",
                "sched_relax_domain_level"
            ]
        )?;

        let mut non_root =
            Subsystem::new(CgroupPath::new(SubsystemKind::Cpuset, gen_cgroup_name!()));
        non_root.create()?;

        assert!(!non_root.file_exists(MEMORY_PRESSURE_ENABLED));
        assert!(non_root.file_exists(CLONE_CHILDREN));

        non_root.delete()
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
        gen_subsystem_test!(Cpuset, memory_migrate, false, set_memory_migrate, true)
    }

    #[test]
    fn test_subsystem_cpu_exclusive() -> Result<()> {
        gen_subsystem_test!(Cpuset, cpu_exclusive, false, set_cpu_exclusive, true)
    }

    #[test]
    fn test_subsystem_mem_exclusive() -> Result<()> {
        gen_subsystem_test!(Cpuset, mem_exclusive, false, set_mem_exclusive, true)
    }

    #[test]
    fn test_subsystem_mem_hardwall() -> Result<()> {
        gen_subsystem_test!(Cpuset, mem_hardwall, false, set_mem_hardwall, true)
    }

    #[test]
    fn test_subsystem_memory_pressure() -> Result<()> {
        gen_subsystem_test!(Cpuset, memory_pressure, 0)
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
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Cpuset, gen_cgroup_name!()));
        cgroup.create()?;

        assert_eq!(
            cgroup.set_memory_pressure_enabled(true).unwrap_err().kind(),
            ErrorKind::InvalidOperation
        );

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_memory_spread_page() -> Result<()> {
        gen_subsystem_test!(
            Cpuset,
            memory_spread_page,
            false,
            set_memory_spread_page,
            true
        )
    }

    #[test]
    fn test_subsystem_memory_spread_slab() -> Result<()> {
        gen_subsystem_test!(
            Cpuset,
            memory_spread_slab,
            false,
            set_memory_spread_slab,
            true
        )
    }

    #[test]
    fn test_subsystem_sched_load_balance() -> Result<()> {
        gen_subsystem_test!(
            Cpuset,
            sched_load_balance,
            true,
            set_sched_load_balance,
            false
        )
    }

    #[test]
    fn test_subsystem_sched_relax_domain_level() -> Result<()> {
        // TODO: `set_sched_relax_domain_level()` raises `io::Error` with kind `InvalidInput` on
        // some systems?
        gen_subsystem_test!(Cpuset, sched_relax_domain_level, -1)
    }

    #[test]
    fn err_subsystem_sched_relax_domain_level() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Cpuset, gen_cgroup_name!()));
        cgroup.create()?;

        assert_eq!(
            cgroup.set_sched_relax_domain_level(-2).unwrap_err().kind(),
            ErrorKind::InvalidArgument
        );
        assert_eq!(
            cgroup.set_sched_relax_domain_level(6).unwrap_err().kind(),
            ErrorKind::InvalidArgument
        );

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_clone_children() -> Result<()> {
        gen_subsystem_test!(Cpuset, clone_children, false, set_clone_children, true)
    }

    #[test]
    fn test_id_set_from_str() {
        macro_rules! hashset {
            ( $( $x: expr ),* $(, )? ) => {{
                #![allow(unused_mut)]
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
            ("0-65535", (0..65536).collect()),
        ]
        .into_iter();

        for (case, expected) in test_cases {
            assert_eq!(case.parse::<IdSet>().unwrap().to_hash_set(), expected);
        }
    }

    #[test]
    fn err_id_set_from_str() {
        for case in &[
            ",", ",0", "0,", "-", "-0", "0-", "0-,1", "0,-1", "1-0", "-1", "0.1", "invalid",
        ] {
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
