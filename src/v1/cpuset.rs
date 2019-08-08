//! Operations on a Cpuset subsystem.
//!
//! For more information about Cpuset subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/cpusets.txt](https://www.kernel.org/doc/Documentation/cgroup-v1/cpusets.txt).

use std::{collections::HashSet, fmt, iter::FromIterator, path::PathBuf};

use crate::{
    v1::{self, Cgroup, CgroupPath, SubsystemKind},
    Error, ErrorKind, Result,
};

use crate::{
    util::{parse, parse_01_bool},
    v1::cgroup::CgroupHelper,
};

/// Handler of a Cpuset subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Resource limits about which CPUs and which memory nodes a cgroup can use, and how they are
/// controlled by the kernel.
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

    /// If true, the cgroup is 'hardwalled'. i.e. Kernel memory allocations (except for a few minor
    /// exceptions) are made from the memory nodes designated in the `mems` field.
    pub mem_hardwall: Option<bool>,

    // /// Running average of the memory pressured faced by the tasks in the cgroup.
    // pub memory_pressure: Option<u64>,
    /// If true, the kernel will compute the memory pressure for the cgroup.
    ///
    /// This field is present only at the root cgroup.
    pub memory_pressure_enabled: Option<bool>,

    /// If true, filesystem buffers are evenly spread across the memory nodes specified in the
    /// `mems` field.
    pub memory_spread_page: Option<bool>,

    /// If true, kernel slab caches for file I/O are evenly spread across the memory nodes specified
    /// in the `mems` field.
    pub memory_spread_slab: Option<bool>,

    /// If true, the kernel will attempt to rebalance the load between the CPUs specified in the
    /// `cpus` field. This field is ignored if an ancestor cgroup already has enabled the load
    /// balancing at that hierarchy level.
    pub sched_load_balance: Option<bool>,

    /// Indicates how much work the kernel should do to rebalance the load on this cpuset.
    ///
    /// | Value | Effect                                                                                      |
    /// | ----- | ------------------------------------------------------------------------------------------- |
    /// | -1    | Use the system default value                                                                |
    /// |  0    | Only balance loads periodically, not immediately                                            |
    /// |  1    | Immediately balance the load across threads on the same core                                |
    /// |  2    | Immediately balance the load across cores in the same CPU package                           |
    /// |  3    | Immediately balance the load across CPUs on the same node (system-wide on non-NUMA systems) |
    /// |  4    | Immediately balance the load across CPUs in a chunk of nodes (on NUMA systems)              |
    /// |  5    | Immediately balance the load across all CPUs (on NUMA systems)                              |
    pub sched_relax_domain_level: Option<i32>,
    // pub effective_cpus: Vec<usize>,
    // pub effective_mems: Vec<usize>,
}

/// Set of CPU ID or memory node ID for which CPUs and memory nodes a cgroup can use.
///
/// `IdSet` can be instantiated by
/// - parsing a cpuset IDs string (e.g. "0,1,3-5,7") with `parse()` function in the std;
/// - collecting an iterator with `collect()`; or
/// - using `new()` to create an empty set and then `add()` IDs one by one.
///
/// `IdSet` implements `Display`. The resulting string is a cpuset IDs string. e.g. formatting
/// `IdSet` which consists of CPU 0, 1, 3, 4, 5, 7 will generate "0,1,3-5,7".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdSet(HashSet<usize>);

impl Cgroup for Subsystem {
    fn new(path: CgroupPath) -> Self {
        Self { path }
    }

    fn subsystem_kind(&self) -> SubsystemKind {
        SubsystemKind::Cpuset
    }

    fn path(&self) -> PathBuf {
        self.path.to_path_buf()
    }

    fn root_cgroup(&self) -> Box<Self> {
        Box::new(Self::new(self.path.subsystem_root()))
    }

    /// Apply the `Some` fields in `resources.cpuset`.
    fn apply(&mut self, resources: &v1::Resources, validate: bool) -> Result<()> {
        let res: &self::Resources = &resources.cpuset;

        macro_rules! a {
            ($resource: ident, $setter: ident) => {
                if let Some(r) = res.$resource {
                    self.$setter(r)?;
                    if validate && r != self.$resource()? {
                        return Err(Error::new(ErrorKind::Apply));
                    }
                }
            };
            (ref $resource: ident, $setter: ident) => {
                if let Some(ref r) = res.$resource {
                    self.$setter(r)?;
                    if validate && *r != self.$resource()? {
                        return Err(Error::new(ErrorKind::Apply));
                    }
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

const CPUS_FILE_NAME: &str = "cpuset.cpus";
const MEMS_FILE_NAME: &str = "cpuset.mems";

const MEMORY_MIGRATE_FILE_NAME: &str = "cpuset.memory_migrate";

const CPU_EXCLUSIVE_FILE_NAME: &str = "cpuset.cpu_exclusive";
const MEM_EXCLUSIVE_FILE_NAME: &str = "cpuset.mem_exclusive";

const MEM_HARDWALL_FILE_NAME: &str = "cpuset.mem_hardwall";

const MEMORY_PRESSURE_FILE_NAME: &str = "cpuset.memory_pressure";
const MEMORY_PRESSURE_ENABLED_FILE_NAME: &str = "cpuset.memory_pressure_enabled";

const MEMORY_SPREAD_PAGE_FILE_NAME: &str = "cpuset.memory_spread_page";
const MEMORY_SPREAD_SLAB_FILE_NAME: &str = "cpuset.memory_spread_slab";

const SCHED_LOAD_BALANCE_FILE_NAME: &str = "cpuset.sched_load_balance";
const SCHED_RELAX_DOMAIN_LEVEL_FILE_NAME: &str = "cpuset.sched_relax_domain_level";

impl Subsystem {
    /// Reads the set of CPUs on which the tasks of this cgroup can run, from `cpuset.cpus` file.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to read and parse `cpuset.cpus` file of this cgroup.
    pub fn cpus(&self) -> Result<IdSet> {
        self.open_file_read(CPUS_FILE_NAME).and_then(parse)
    }

    /// Sets a set of CPUs on which the tasks of this cgroup can run, by writing to `cpuset.cpus`
    /// file.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to write to `cpuset.cpus` file of this cgroup.
    pub fn set_cpus(&mut self, cpus: &IdSet) -> Result<()> {
        self.write_file(CPUS_FILE_NAME, cpus)
    }

    /// Reads the set of memory nodes which the tasks of this cgroup can use, from `cpuset.mems`
    /// file.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to read and parse `cpuset.mems` file of this cgroup.
    pub fn mems(&self) -> Result<IdSet> {
        self.open_file_read(MEMS_FILE_NAME).and_then(parse)
    }

    /// Sets a set of memory nodes which the tasks of this cgroup can use, by writing to
    /// `cpuset.mems` file.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to write to `cpuset.mems` file of this cgroup.
    pub fn set_mems(&mut self, mems: &IdSet) -> Result<()> {
        self.write_file(MEMS_FILE_NAME, mems)
    }

    pub fn memory_migrate(&self) -> Result<bool> {
        self.open_file_read(MEMORY_MIGRATE_FILE_NAME)
            .and_then(parse_01_bool)
    }

    pub fn set_memory_migrate(&mut self, enable: bool) -> Result<()> {
        self.write_file(MEMORY_MIGRATE_FILE_NAME, enable as i32)
    }

    pub fn cpu_exclusive(&self) -> Result<bool> {
        self.open_file_read(CPU_EXCLUSIVE_FILE_NAME)
            .and_then(parse_01_bool)
    }

    pub fn set_cpu_exclusive(&mut self, exclusive: bool) -> Result<()> {
        self.write_file(CPU_EXCLUSIVE_FILE_NAME, exclusive as i32)
    }

    pub fn mem_exclusive(&self) -> Result<bool> {
        self.open_file_read(MEM_EXCLUSIVE_FILE_NAME)
            .and_then(parse_01_bool)
    }

    pub fn set_mem_exclusive(&mut self, exclusive: bool) -> Result<()> {
        self.write_file(MEM_EXCLUSIVE_FILE_NAME, exclusive as i32)
    }

    pub fn mem_hardwall(&self) -> Result<bool> {
        self.open_file_read(MEM_HARDWALL_FILE_NAME)
            .and_then(parse_01_bool)
    }

    pub fn set_mem_hardwall(&mut self, enable: bool) -> Result<()> {
        self.write_file(MEM_HARDWALL_FILE_NAME, enable as i32)
    }

    pub fn memory_pressure(&self) -> Result<u64> {
        self.open_file_read(MEMORY_PRESSURE_FILE_NAME)
            .and_then(parse)
    }

    pub fn memory_pressure_enabled(&self) -> Result<bool> {
        if self.file_exists(MEMORY_PRESSURE_ENABLED_FILE_NAME) {
            self.open_file_read(MEMORY_PRESSURE_ENABLED_FILE_NAME)
                .and_then(parse_01_bool)
        } else {
            Err(Error::new(ErrorKind::InvalidOperation)) // TODO
        }
    }

    pub fn set_memory_pressure_enabled(&mut self, enable: bool) -> Result<()> {
        if self.file_exists(MEMORY_PRESSURE_ENABLED_FILE_NAME) {
            self.write_file(MEMORY_PRESSURE_ENABLED_FILE_NAME, enable as i32)
        } else {
            Err(Error::new(ErrorKind::InvalidOperation)) // TODO
        }
    }

    pub fn memory_spread_page(&self) -> Result<bool> {
        self.open_file_read(MEMORY_SPREAD_PAGE_FILE_NAME)
            .and_then(parse_01_bool)
    }

    pub fn set_memory_spread_page(&mut self, enable: bool) -> Result<()> {
        self.write_file(MEMORY_SPREAD_PAGE_FILE_NAME, enable as i32)
    }

    pub fn memory_spread_slab(&self) -> Result<bool> {
        self.open_file_read(MEMORY_SPREAD_SLAB_FILE_NAME)
            .and_then(parse_01_bool)
    }

    pub fn set_memory_spread_slab(&mut self, enable: bool) -> Result<()> {
        self.write_file(MEMORY_SPREAD_SLAB_FILE_NAME, enable as i32)
    }

    pub fn sched_load_balance(&self) -> Result<bool> {
        self.open_file_read(SCHED_LOAD_BALANCE_FILE_NAME)
            .and_then(parse_01_bool)
    }

    pub fn set_sched_load_balance(&mut self, enable: bool) -> Result<()> {
        self.write_file(SCHED_LOAD_BALANCE_FILE_NAME, enable as i32)
    }

    pub fn sched_relax_domain_level(&self) -> Result<i32> {
        self.open_file_read(SCHED_RELAX_DOMAIN_LEVEL_FILE_NAME)
            .and_then(parse)
    }

    pub fn set_sched_relax_domain_level(&mut self, level: i32) -> Result<()> {
        self.write_file(SCHED_RELAX_DOMAIN_LEVEL_FILE_NAME, level)
    }

    /*
    /// Control whether the CPUs selected via `set_cpus()` should be exclusive to this control
    /// group or not.
    pub fn set_cpu_exclusive(&self, b: bool) -> Result<()> {
        self.open_path("cpuset.cpu_exclusive", true)
            .and_then(|mut file| {
                if b {
                    file.write_all(b"1").map_err(|e| Error::with_cause(WriteFailed, e))
                } else {
                    file.write_all(b"0").map_err(|e| Error::with_cause(WriteFailed, e))
                }
            })
    }

    /// Control whether the memory nodes selected via `set_memss()` should be exclusive to this control
    /// group or not.
    pub fn set_mem_exclusive(&self, b: bool) -> Result<()> {
        self.open_path("cpuset.mem_exclusive", true)
            .and_then(|mut file| {
                if b {
                    file.write_all(b"1").map_err(|e| Error::with_cause(WriteFailed, e))
                } else {
                    file.write_all(b"0").map_err(|e| Error::with_cause(WriteFailed, e))
                }
            })
    }

    /// Set the CPUs that the tasks in this cgroup can run on.
    ///
    /// Syntax is a comma separated list of CPUs, with an additional extension that ranges can
    /// be represented via dashes.
    pub fn set_cpus(&self, cpus: &str) -> Result<()> {
        self.open_path("cpuset.cpus", true).and_then(|mut file| {
            file.write_all(cpus.as_ref())
                .map_err(|e| Error::with_cause(WriteFailed, e))
        })
    }

    /// Set the memory nodes that the tasks in this cgroup can use.
    ///
    /// Syntax is the same as with `set_cpus()`.
    pub fn set_mems(&self, mems: &str) -> Result<()> {
        self.open_path("cpuset.mems", true).and_then(|mut file| {
            file.write_all(mems.as_ref())
                .map_err(|e| Error::with_cause(WriteFailed, e))
        })
    }

    /// Controls whether the cgroup should be "hardwalled", i.e., whether kernel allocations
    /// should exclusively use the memory nodes set via `set_mems()`.
    ///
    /// Note that some kernel allocations, most notably those that are made in interrupt handlers
    /// may disregard this.
    pub fn set_hardwall(&self, b: bool) -> Result<()> {
        self.open_path("cpuset.mem_hardwall", true)
            .and_then(|mut file| {
                if b {
                    file.write_all(b"1").map_err(|e| Error::with_cause(WriteFailed, e))
                } else {
                    file.write_all(b"0").map_err(|e| Error::with_cause(WriteFailed, e))
                }
            })
    }

    /// Controls whether the kernel should attempt to rebalance the load between the CPUs specified in the
    /// `cpus` field of this cgroup.
    pub fn set_load_balancing(&self, b: bool) -> Result<()> {
        self.open_path("cpuset.sched_load_balance", true)
            .and_then(|mut file| {
                if b {
                    file.write_all(b"1").map_err(|e| Error::with_cause(WriteFailed, e))
                } else {
                    file.write_all(b"0").map_err(|e| Error::with_cause(WriteFailed, e))
                }
            })
    }

    /// Contorl how much effort the kernel should invest in rebalacing the cgroup.
    ///
    /// See @CpuSet 's similar field for more information.
    pub fn set_rebalance_relax_domain_level(&self, i: i64) -> Result<()> {
        self.open_path("cpuset.sched_relax_domain_level", true)
            .and_then(|mut file| {
                file.write_all(i.to_string().as_ref())
                    .map_err(|e| Error::with_cause(WriteFailed, e))
            })
    }

    /// Control whether when using `set_mems()` the existing memory used by the tasks should be
    /// migrated over to the now-selected nodes.
    pub fn set_memory_migration(&self, b: bool) -> Result<()> {
        self.open_path("cpuset.memory_migrate", true)
            .and_then(|mut file| {
                if b {
                    file.write_all(b"1").map_err(|e| Error::with_cause(WriteFailed, e))
                } else {
                    file.write_all(b"0").map_err(|e| Error::with_cause(WriteFailed, e))
                }
            })
    }

    /// Control whether filesystem buffers should be evenly split across the nodes selected via
    /// `set_mems()`.
    pub fn set_memory_spread_page(&self, b: bool) -> Result<()> {
        self.open_path("cpuset.memory_spread_page", true)
            .and_then(|mut file| {
                if b {
                    file.write_all(b"1").map_err(|e| Error::with_cause(WriteFailed, e))
                } else {
                    file.write_all(b"0").map_err(|e| Error::with_cause(WriteFailed, e))
                }
            })
    }

    /// Control whether the kernel's slab cache for file I/O should be evenly split across the
    /// nodes selected via `set_mems()`.
    pub fn set_memory_spread_slab(&self, b: bool) -> Result<()> {
        self.open_path("cpuset.memory_spread_slab", true)
            .and_then(|mut file| {
                if b {
                    file.write_all(b"1").map_err(|e| Error::with_cause(WriteFailed, e))
                } else {
                    file.write_all(b"0").map_err(|e| Error::with_cause(WriteFailed, e))
                }
            })
    }

    /// Control whether the kernel should collect information to calculate memory pressure for
    /// cgroups.
    ///
    /// Note: This will fail with `InvalidOperation` if the current congrol group is not the root
    /// cgroup.
    pub fn set_enable_memory_pressure(&self, b: bool) -> Result<()> {
        if !self.path_exists("cpuset.memory_pressure_enabled") {
            return Err(Error::new(InvalidOperation));
        }
        self.open_path("cpuset.memory_pressure_enabled", true)
            .and_then(|mut file| {
                if b {
                    file.write_all(b"1").map_err(|e| Error::with_cause(WriteFailed, e))
                } else {
                    file.write_all(b"0").map_err(|e| Error::with_cause(WriteFailed, e))
                }
            })
    }
    */
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

    /// Parses a cpuset IDs string (e.g. "0,1,3-5,7") into an `IdSet`.
    ///
    /// # Errors
    ///
    /// Returns an error with kind [`ErrorKind::Parse`] if failed to parse.
    ///
    /// [`ErrorKind::Parse`]: ../../enum.ErrorKind.html#variant.Parse
    ///
    /// # Examples
    ///
    /// ```
    /// use cgroups::v1::cpuset::IdSet;
    ///
    /// let id_set = "0,1,3-5,7".parse::<IdSet>().unwrap();
    /// assert_eq!(
    ///     { let mut v = id_set.to_vec(); v.sort(); v },
    ///     vec![0, 1, 3, 4, 5, 7],
    /// );
    /// ```
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
    /// Formats this `IdSet` into a string.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::string::ToString;
    /// use cgroups::v1::cpuset::IdSet;
    ///
    /// let id_set = "0,1,3-5,7".parse::<IdSet>().unwrap();
    /// assert_eq!(id_set.to_string(), "0,1,3-5,7");
    /// ```
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
    /// assert!(id_set.to_vec().is_empty());
    /// ```
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
    ///     { let mut v = id_set.to_vec(); v.sort(); v },
    ///     vec![1, 2, 3, 5, 6, 7],
    /// );
    /// ```
    pub fn to_vec(&self) -> Vec<usize> {
        self.0.iter().copied().collect()
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
    /// assert_eq!(id_set.to_vec(), vec![7]);
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
    ///     { let mut v = id_set.to_vec(); v.sort(); v },
    ///     vec![1, 3, 4, 5, 7],
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
    fn test_id_set_from_str() {
        let test_cases = vec![
            "",
            "0",
            "1,2",
            "0,2,4,6",
            "2-6",
            "0-2,5-7",
            "2-3,4-5,6-7",
            "1,3,5-7,9,10",
            "0-65535",
        ]
        .into_iter();

        let expecteds = vec![
            vec![],
            vec![0],
            vec![1, 2],
            vec![0, 2, 4, 6],
            vec![2, 3, 4, 5, 6],
            vec![0, 1, 2, 5, 6, 7],
            vec![2, 3, 4, 5, 6, 7],
            vec![1, 3, 5, 6, 7, 9, 10],
            (0..65536).collect(),
        ]
        .into_iter();

        for (case, expected) in test_cases.zip(expecteds) {
            let mut ids = case.parse::<IdSet>().unwrap().to_vec();
            ids.sort();
            assert_eq!(ids, expected);
        }
    }

    #[test]
    fn err_id_set_from_str() {
        #[rustfmt::skip]
        let testcases = [
            ",",
            ",0",
            "0,",
            "-",
            "-0",
            "0-",
            "0-,1",
            "0,-1",
            "1-0",
            "-1",
            "0.1",
            "invalid",
        ].into_iter();

        for case in testcases {
            assert_eq!(case.parse::<IdSet>().unwrap_err().kind(), ErrorKind::Parse);
        }
    }

    #[test]
    fn test_id_set_fmt() {
        let test_cases = vec![
            vec![],
            vec![0],
            vec![1, 2],
            vec![0, 2, 4, 6],
            vec![2, 3, 4, 5, 6],
            vec![0, 1, 2, 5, 6, 7],
            vec![1, 3, 4, 5, 7, 9, 10, 11],
            vec![1, 3, 5, 6, 7, 9, 10],
            (0..65536).collect(),
        ]
        .into_iter();

        let expecteds = vec![
            "",
            "0",
            "1,2",
            "0,2,4,6",
            "2-6",
            "0-2,5-7",
            "1,3-5,7,9-11",
            "1,3,5-7,9,10",
            "0-65535",
        ]
        .into_iter();

        for (case, expected) in test_cases.zip(expecteds) {
            let id_set = case.iter().copied().collect::<IdSet>();
            assert_eq!(id_set.to_string(), expected.to_string());
        }
    }
}
