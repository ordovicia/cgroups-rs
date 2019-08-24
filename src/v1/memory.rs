//! Operations on a memory subsystem.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/memory.txt](https://www.kernel.org/doc/Documentation/cgroup-v1/memory.txt).
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! use std::path::PathBuf;
//! use cgroups::{Pid, v1::{self, memory, Cgroup, CgroupPath, SubsystemKind}};
//!
//! let mut mem_cgroup = memory::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::Memory, PathBuf::from("students/charlie")));
//! mem_cgroup.create()?;
//!
//! // Define a resource limit about what amount and how a cgroup can use memory.
//! const GB: i64 = 1 << 30;
//! let resources = memory::Resources {
//!     limit_in_bytes: Some(4 * GB),
//!     soft_limit_in_bytes: Some(3 * GB),
//!     use_hierarchy: Some(true),
//!     ..memory::Resources::default()
//! };
//!
//! // Apply the resource limit to this cgroup.
//! mem_cgroup.apply(&resources.into())?;
//!
//! // Add tasks to this cgroup.
//! let pid = Pid::from(std::process::id());
//! mem_cgroup.add_task(pid)?;
//!
//! // Get the statistics about memory usage of this cgroup.
//! println!("{:?}", mem_cgroup.stat()?);
//!
//! mem_cgroup.remove_task(pid)?;
//! mem_cgroup.delete()?;
//! # Ok(())
//! # }
//! ```

use std::{
    io::{self, BufRead},
    path::PathBuf,
};

use crate::{
    util::{parse, parse_01_bool, parse_option},
    v1::{self, cgroup::CgroupHelper, Cgroup, CgroupPath, SubsystemKind},
    Error, ErrorKind, Result,
};

/// Handler of a memory subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Resource limit on what amount and how a cgroup can use memory.
///
/// See the kernel's documentation for more information about the fields.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// Limit the memory usage of this cgroup. Setting `-1` removes the current limit.
    pub limit_in_bytes: Option<i64>,
    /// Limit the total of memory and swap usage of this cgroup. Setting `-1` removes the current
    /// limit.
    pub memsw_limit_in_bytes: Option<i64>,
    /// Limit the usage of kernel memory by this cgroup. Setting `-1` removes the current limit.
    pub kmem_limit_in_bytes: Option<i64>,
    /// Limit the usage of kernel memory for TCP by this cgroup. Setting `-1` removes the current
    /// limit.
    pub kmem_tcp_limit_in_bytes: Option<i64>,
    /// Soft limit on memory usage of this cgroup. Setting `-1` removes the current limit.
    pub soft_limit_in_bytes: Option<i64>,
    /// Whether pages may be recharged to the new cgroup when a task is moved.
    pub move_charge_at_immigrate: Option<bool>,
    /// Kernel's tendency to swap out pages consumed by this cgroup.
    pub swappiness: Option<u64>,
    /// Whether the OOM killer tries to reclaim memory from the self and descendant cgroups.
    pub use_hierarchy: Option<bool>,
}

/// Statistics of memory usage of a cgroup.
///
/// Some fields only present on some systems, so these fields are `Option`.
///
/// See the kernel's documentation for more information about the fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Stat {
    pub cache: u64,
    pub rss: u64,
    pub rss_huge: u64,
    pub shmem: u64,
    pub mapped_file: u64,
    pub dirty: u64,
    pub writeback: u64,
    pub swap: Option<u64>,
    pub pgpgin: u64,
    pub pgpgout: u64,
    pub pgfault: u64,
    pub pgmajfault: u64,
    pub active_anon: u64,
    pub inactive_anon: u64,
    pub active_file: u64,
    pub inactive_file: u64,
    pub unevictable: u64,
    pub hierarchical_memory_limit: u64,
    pub hierarchical_memsw_limit: Option<u64>,

    pub total_cache: u64,
    pub total_rss: u64,
    pub total_rss_huge: u64,
    pub total_shmem: u64,
    pub total_mapped_file: u64,
    pub total_dirty: u64,
    pub total_writeback: u64,
    pub total_swap: Option<u64>,
    pub total_pgpgin: u64,
    pub total_pgpgout: u64,
    pub total_pgfault: u64,
    pub total_pgmajfault: u64,
    pub total_active_anon: u64,
    pub total_inactive_anon: u64,
    pub total_active_file: u64,
    pub total_inactive_file: u64,
    pub total_unevictable: u64,
}

/// Statistics of memory usage per NUMA node.
///
/// The first element of each pair is the system-wide value, and the second is per-node values.
///
/// See the kernel's documentation for more information about the fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct NumaStat {
    pub total: (u64, Vec<u64>),
    pub file: (u64, Vec<u64>),
    pub anon: (u64, Vec<u64>),
    pub unevictable: (u64, Vec<u64>),

    pub hierarchical_total: (u64, Vec<u64>),
    pub hierarchical_file: (u64, Vec<u64>),
    pub hierarchical_anon: (u64, Vec<u64>),
    pub hierarchical_unevictable: (u64, Vec<u64>),
}

/// OOM status and controls.
///
/// See the kernel's documentation for more information about the fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OomControl {
    /// Whether the OOM killer is disabled for this cgroup.
    pub oom_kill_disable: bool,
    /// Whether this cgroup is currently suspended (not killed) because OOM killer is disabled.
    pub under_oom: bool,
    /// Number of times tasks were killed by the OOM killer so far.
    pub oom_kill: Option<u64>,
}

impl_cgroup! {
    Memory,

    /// Applies the `Some` fields in `resources.memory`.
    ///
    /// See [`Cgroup::apply`] for general information.
    ///
    /// [`Cgroup::apply`]: ../trait.Cgroup.html#tymethod.apply
    fn apply(&mut self, resources: &v1::Resources) -> Result<()> {
        macro_rules! a {
            ($resource: ident, $setter: ident) => {
                if let Some(r) = resources.memory.$resource {
                    self.$setter(r)?;
                }
            };
        }

        a!(limit_in_bytes, set_limit_in_bytes);
        a!(memsw_limit_in_bytes, set_memsw_limit_in_bytes);
        a!(kmem_limit_in_bytes, set_kmem_limit_in_bytes);
        a!(kmem_tcp_limit_in_bytes, set_kmem_tcp_limit_in_bytes);
        a!(soft_limit_in_bytes, set_soft_limit_in_bytes);
        a!(move_charge_at_immigrate, set_move_charge_at_immigrate);
        a!(swappiness, set_swappiness);
        a!(use_hierarchy, set_use_hierarchy);

        Ok(())
    }
}

macro_rules! gen_read {
    // Single getter
    ($desc: literal, $resource: ident, $ty: ty) => {
        gen_read!($desc, $resource, $ty, parse);
    };

    // Single getter with custom parser
    ($desc: literal, $resource: ident, $ty: ty, $parser: ident) => {
        with_doc! { concat!(
            "Reads ", $desc, " from `memory.", stringify!($resource), "` file.\n\n",
            "See the kernel's documentation for more information about this field.\n\n",
            gen_read!($resource)),
            pub fn $resource(&self) -> Result<$ty> {
                self.open_file_read(concat!("memory.", stringify!($resource))).and_then($parser)
            }
        }
    };

    // Normal getter with `memsw`, `kmem`, `kmem.tcp` variants
    (
        $desc: literal,
        $resource: ident,
        $memsw: ident,
        $kmem: ident,
        $tcp: ident,
        $ty: ty
    ) => {
        with_doc! { concat!(
            "Reads ", $desc, " from `memory.", stringify!($resource), "` file.\n\n",
            "See the kernel's documentation for more information about this field.\n\n",
            gen_read!($resource)),
            pub fn $resource(&self) -> Result<$ty> {
                self.open_file_read(concat!("memory.", stringify!($resource))).and_then(parse)
            }
        }

        with_doc! { concat!(
            "Reads from `memory.memsw.", stringify!($resource), "` file. ",
            "See `", stringify!($resource), "` for more information."),
            pub fn $memsw(&self) -> Result<$ty> {
                self.open_file_read(concat!("memory.memsw.", stringify!($resource))).and_then(parse)
            }
        }

        with_doc! { concat!(
            "Reads from `memory.kmem.", stringify!($resource), "` file. ",
            "See `", stringify!($resource), "` for more information."),
            pub fn $kmem(&self) -> Result<$ty> {
                self.open_file_read(concat!("memory.kmem.", stringify!($resource))).and_then(parse)
            }
        }

        with_doc! { concat!(
            "Reads from `memory.kmem.tcp.", stringify!($resource), "` file. ",
            "See `", stringify!($resource), "` for more information."),
            pub fn $tcp(&self) -> Result<$ty> {
                self.open_file_read(concat!("memory.kmem.tcp.", stringify!($resource))).and_then(parse)
            }
        }
    };

    // Only Errors and Examples sections
    ($resource: ident) => { concat!(
"# Errors

Returns an error if failed to read and parse `memory.", stringify!($resource), "` file of this cgroup.

# Examples

```no_run
# fn main() -> cgroups::Result<()> {
use std::path::PathBuf;
use cgroups::v1::{memory, Cgroup, CgroupPath, SubsystemKind};

let cgroup = memory::Subsystem::new(
    CgroupPath::new(SubsystemKind::Memory, PathBuf::from(\"students/charlie\")));

let ", stringify!($resource), " = cgroup.", stringify!($resource), "()?;
# Ok(())
# }
```")
    }
}

macro_rules! gen_write {
    // Single setter
    ($desc: literal, $resource: ident, $setter: ident, $val: expr, $ty: ty, $($tt: tt)*) => {
        gen_write!($desc, $resource, $resource, $setter, $val, $ty, $($tt)*);
    };

    // Single setter with custom file name
    (
        $desc: literal,
        $file: ident,
        $resource: ident,
        $setter: ident,
        $val: expr,
        $ty: ty,
        $($tt: tt)*
    ) => {
        with_doc! { concat!(
            "Sets ", $desc, " by writing to `memory.", stringify!($file), "` file.\n\n",
            "See the kernel's documentation for more information about this field.\n\n",
            gen_write!($file, $setter, $val)),
            pub fn $setter(&mut self, $resource: $ty) -> Result<()> {
                self.write_file(concat!("memory.", stringify!($file)), $resource $($tt)*)
            }
        }
    };

    // Only Errors and Examples sections
    ($file: ident, $setter: ident $(, $val: expr)?) => { concat!(
        "# Errors\n\n",
        "Returns an error if failed to write to `memory.", stringify!($file), "` file of this cgroup.\n\n",
        gen_write!(eg; $setter $(, $val )?)
    ) };

    // Only Examples section
    (eg; $setter: ident $(, $val: expr)?) => { concat!(
"# Examples

```no_run
# fn main() -> cgroups::Result<()> {
use std::path::PathBuf;
use cgroups::v1::{memory, Cgroup, CgroupPath, SubsystemKind};

let mut cgroup = memory::Subsystem::new(
    CgroupPath::new(SubsystemKind::Memory, PathBuf::from(\"students/charlie\")));

cgroup.", stringify!($setter), "(", stringify!($( $val )?), ")?;
# Ok(())
# }
```")
    }
}

impl Subsystem {
    gen_read!(
        "statistics of memory usage of this cgroup",
        stat,
        Stat,
        parse_stat
    );

    gen_read!(
        "statistics of memory usage per NUMA node of this cgroup",
        numa_stat,
        NumaStat,
        parse_numa_stat
    );

    gen_read!(
        "the memory usage of this cgroup",
        usage_in_bytes,
        memsw_usage_in_bytes,
        kmem_usage_in_bytes,
        kmem_tcp_usage_in_bytes,
        u64
    );

    gen_read!(
        "the maximum memory usage of this cgroup",
        max_usage_in_bytes,
        memsw_max_usage_in_bytes,
        kmem_max_usage_in_bytes,
        kmem_tcp_max_usage_in_bytes,
        u64
    );

    gen_read!(
        "the limit on memory usage (including file cache) of this cgroup",
        limit_in_bytes,
        memsw_limit_in_bytes,
        kmem_limit_in_bytes,
        kmem_tcp_limit_in_bytes,
        u64
    );

    gen_read!(
        "the soft limit on memory usage of this cgroup",
        soft_limit_in_bytes,
        u64
    );

    with_doc! { concat!(
"Sets a limit on memory usage of this cgroup by writing to `memory.limit_in_bytes` file. Setting
`-1` removes the current limit.

See the kernel's documentation for more information about this field.

# Errors

This field is configurable only for non-root cgroups. If you call this method on the root cgroup, an
error is returned with kind `ErrorKind::InvalidOperation`.

On non-root cgroups, returns an error if failed to write to `memory.limit_in_bytes` file of this
cgroup.\n\n",
        gen_write!(eg; set_limit_in_bytes, 4 * (1 << 30))),
        pub fn set_limit_in_bytes(&mut self, limit: i64) -> Result<()> {
            if self.is_root() {
                Err(Error::new(ErrorKind::InvalidOperation))
            } else {
                self.write_file("memory.limit_in_bytes", limit)
            }
        }
    }

    /// Writes to `memory.memsw.limit_in_bytes` file. See `set_limit_in_bytes` for more information.
    pub fn set_memsw_limit_in_bytes(&mut self, limit: i64) -> Result<()> {
        if self.is_root() {
            Err(Error::new(ErrorKind::InvalidOperation))
        } else {
            self.write_file("memory.memsw.limit_in_bytes", limit)
        }
    }

    /// Writes to `memory.kmem.limit_in_bytes` file. See `set_limit_in_bytes` for more information.
    pub fn set_kmem_limit_in_bytes(&mut self, limit: i64) -> Result<()> {
        if self.is_root() {
            Err(Error::new(ErrorKind::InvalidOperation))
        } else {
            self.write_file("memory.kmem.limit_in_bytes", limit)
        }
    }

    /// Writes to `memory.kmem.tcp.limit_in_bytes` file. See `set_limit_in_bytes` for more
    /// information.
    pub fn set_kmem_tcp_limit_in_bytes(&mut self, limit: i64) -> Result<()> {
        if self.is_root() {
            Err(Error::new(ErrorKind::InvalidOperation))
        } else {
            self.write_file("memory.kmem.tcp.limit_in_bytes", limit)
        }
    }

    with_doc! { concat!(
"Sets a soft limit on memory usage of this cgroup by writing to `memory.soft_limit_in_bytes` file.
Setting `-1` removes the current limit.

See the kernel's documentation for more information about this field.

# Errors

This field is configurable only for non-root cgroups. If you call this method on the root cgroup, an
error is returned with kind `ErrorKind::InvalidOperation`.

On non-root cgroups, returns an error if failed to write to `memory.limit_in_bytes` file of this
cgroup.\n\n",
        gen_write!(soft_limit_in_bytes, set_soft_limit_in_bytes, 4 * (1 << 30))),
        pub fn set_soft_limit_in_bytes(&mut self, limit: i64) -> Result<()> {
            if self.is_root() {
                Err(Error::new(ErrorKind::InvalidOperation))
            } else {
                self.write_file("memory.soft_limit_in_bytes", limit)
            }
        }
    }

    gen_read!(
        "the number of memory allocation failure due to the limit",
        failcnt,
        memsw_failcnt,
        kmem_failcnt,
        kmem_tcp_failcnt,
        u64
    );

    gen_read!(
        "the tendency of the kernel to swap out pages consumed by this cgroup,",
        swappiness,
        u64
    );

    gen_write!(
        "a tendency of the kernel to swap out pages consumed by this cgroup,",
        swappiness,
        set_swappiness,
        60,
        u64,
    );

    gen_read!(
        "the status of OOM killer on this cgroup",
        oom_control,
        OomControl,
        parse_oom_control
    );

    gen_write!(
        "whether the OOM killer is disabled for this cgroup,",
        oom_control,
        disable,
        disable_oom_killer,
        true,
        bool,
        as i32
    );

    gen_read!(
        "whether pages may be recharged to the new cgroup when a task is moved,",
        move_charge_at_immigrate,
        bool,
        parse_01_bool
    );

    gen_write!(
        "whether pages may be recharged to the new cgroup when a task is moved,",
        move_charge_at_immigrate,
        move_,
        set_move_charge_at_immigrate,
        true,
        bool,
        as i32
    );

    gen_read!(
        "whether the OOM killer tries to reclaim memory from the self and descendant cgroups,",
        use_hierarchy,
        bool,
        parse_01_bool
    );

    gen_write!(
        "whether the OOM killer tries to reclaim memory from the self and descendant cgroups,",
        use_hierarchy,
        use_,
        set_use_hierarchy,
        true,
        bool,
        as i32,
    );

    with_doc! { concat!(
        "Makes this cgroup's memory usage empty, by writing to `memory.force_empty` file.\n\n",
        "See the kernel's documentation for more information about this field.\n\n",
        gen_write!(force_empty, force_empty)),
        pub fn force_empty(&mut self) -> Result<()> {
            self.write_file("memory.force_empty", 0)
        }
    }

    // TODO: kmem.slabinfo
}

impl Into<v1::Resources> for Resources {
    fn into(self) -> v1::Resources {
        v1::Resources {
            memory: self,
            ..v1::Resources::default()
        }
    }
}

fn p() -> Error {
    Error::new(ErrorKind::Parse)
}

macro_rules! p {
    () => {
        return Err(p());
    };
}

fn parse_stat(reader: impl io::Read) -> Result<Stat> {
    let buf = io::BufReader::new(reader);

    macro_rules! gen {
        ( keys: [ $($key: ident),* ], keys_opt: [ $($key_opt: ident),* ] ) => {
            $( let mut $key: Option<u64> = None; )*
            $( let mut $key_opt: Option<u64> = None; )*

            for line in buf.lines() {
                let line = line?;
                let mut entry = line.split_whitespace();

                match entry.next().ok_or_else(p)? {
                    $(
                        stringify!($key) => {
                            if $key.is_some() { p!(); }
                            $key = Some(parse_option(entry.next())?);
                        }
                    )*
                    $(
                        stringify!($key_opt) => {
                            if $key_opt.is_some() { p!(); }
                            $key_opt = Some(parse_option(entry.next())?);
                        }
                    )*
                    _ => { p!(); }
                }
            }

            if $( $key.is_some() &&)* true {
                Ok(Stat {
                    $( $key: $key.unwrap(), )*
                    $( $key_opt, )*
                })
            } else {
                Err(p())
            }
        }
    }

    gen! {
        keys: [
            cache, rss, rss_huge, shmem, mapped_file, dirty, writeback, pgpgin, pgpgout,
            pgfault, pgmajfault, active_anon, inactive_anon, active_file, inactive_file,
            unevictable, hierarchical_memory_limit, total_cache, total_rss, total_rss_huge,
            total_shmem, total_mapped_file, total_dirty, total_writeback, total_pgpgin,
            total_pgpgout, total_pgfault, total_pgmajfault, total_active_anon,
            total_inactive_anon, total_active_file, total_inactive_file, total_unevictable
        ],
        keys_opt: [
            swap, total_swap, hierarchical_memsw_limit
        ]
    }
}

fn parse_numa_stat(reader: impl io::Read) -> Result<NumaStat> {
    let buf = io::BufReader::new(reader);

    macro_rules! gen {
        ( $key0: ident, $( $key: ident ),* ) => {
            let mut $key0 = None;
            $( let mut $key = None; )*

            gen!(p; $key0, $($key),*);

            if $( $key.is_some() && )* $key0.is_some() {
                let $key0 = $key0.unwrap();
                $( let $key = $key.unwrap(); )*

                let len = $key0.1.len();
                $( if $key.1.len() != len { p!(); } )*

                Ok(NumaStat {
                    $key0,
                    $( $key, )*
                })
            } else {
                Err(p())
            }
        };

        (p; $( $key: ident ),*) => {
            for line in buf.lines() {
                let line = line?;
                match line.split('=').next().ok_or_else(p)? {
                    $(
                        stringify!($key) => {
                            let mut entry = line.split(|c| c == ' ' || c == '=');

                            let total = parse_option(entry.nth(1))?;
                            let nodes = entry
                                .skip(1)
                                .step_by(2)
                                .map(|n| n.parse::<u64>())
                                .collect::<std::result::Result<Vec<_>, std::num::ParseIntError>>()?;

                            $key = Some((total, nodes));
                        }
                    )*
                    _ => { p!(); }
                }
            }

        };
    }

    gen! {
        total, file, anon, unevictable,
        hierarchical_total, hierarchical_file, hierarchical_anon, hierarchical_unevictable
    }
}

fn parse_oom_control(reader: impl io::Read) -> Result<OomControl> {
    let buf = io::BufReader::new(reader);

    let mut oom_kill_disable = None;
    let mut under_oom = None;
    let mut oom_kill = None;

    for line in buf.lines() {
        let line = line?;
        let mut entry = line.split_whitespace();

        match entry.next().ok_or_else(p)? {
            "oom_kill_disable" => {
                if oom_kill_disable.is_some() {
                    p!();
                }
                oom_kill_disable = Some(parse_01_bool_option(entry.next())?);
            }
            "under_oom" => {
                if under_oom.is_some() {
                    p!();
                }
                under_oom = Some(parse_01_bool_option(entry.next())?);
            }
            "oom_kill" => {
                if oom_kill.is_some() {
                    p!();
                }
                oom_kill = Some(parse_option(entry.next())?);
            }
            _ => {
                p!();
            }
        }
    }

    if let Some(oom_kill_disable) = oom_kill_disable {
        if let Some(under_oom) = under_oom {
            return Ok(OomControl {
                oom_kill_disable,
                under_oom,
                oom_kill,
            });
        }
    }

    Err(p())
}

fn parse_01_bool_option(s: Option<&str>) -> Result<bool> {
    match s {
        Some(s) => match s.parse::<i32>() {
            Ok(0) => Ok(false),
            Ok(1) => Ok(true),
            _ => Err(p()),
        },
        None => Err(p()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const LIMIT_DEFAULT: u64 = 0x7FFF_FFFF_FFFF_F000;

    #[test]
    fn test_subsystem_create_file_exists() -> Result<()> {
        let mut files = [
            "memory.stat",
            "memory.numa_stat",
            "memory.swappiness",
            "memory.oom_control",
            "memory.move_charge_at_immigrate",
            "memory.use_hierarchy",
            "memory.force_empty",
            "memory.soft_limit_in_bytes",
        ]
        .iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>();

        let files_sw = vec![
            "usage_in_bytes",
            "max_usage_in_bytes",
            "limit_in_bytes",
            "failcnt",
        ];

        files.extend(files_sw.iter().map(|f| format!("memory.{}", f)));
        // only presents on some systems
        // files.extend(files_sw.iter().map(|f| format!("memory.memsw.{}", f)));
        files.extend(files_sw.iter().map(|f| format!("memory.kmem.{}", f)));
        files.extend(files_sw.iter().map(|f| format!("memory.kmem.tcp.{}", f)));

        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Memory, gen_cgroup_name!()));
        cgroup.create()?;

        assert!(files.iter().all(|f| cgroup.file_exists(f)));
        assert!(!cgroup.file_exists("does_not_exist"));

        cgroup.delete()?;
        assert!(files.iter().all(|f| !cgroup.file_exists(f)));

        Ok(())
    }

    // TODO: test adding tasks

    #[test]
    fn test_subsystem_stat() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Memory, gen_cgroup_name!()));
        cgroup.create()?;

        let stat = cgroup.stat()?;

        macro_rules! assert_0 {
            ($( $r: ident ),*) => { $( assert_eq!(stat.$r, 0); )* }
        }

        assert_0!(
            cache,
            rss,
            rss_huge,
            shmem,
            mapped_file,
            dirty,
            writeback,
            pgpgin,
            pgpgout,
            pgfault,
            pgmajfault,
            active_anon,
            inactive_anon,
            active_file,
            inactive_file,
            unevictable
        );
        assert_eq!(stat.swap.unwrap_or(0), 0);
        assert_eq!(stat.hierarchical_memory_limit, LIMIT_DEFAULT);
        assert_eq!(
            stat.hierarchical_memsw_limit.unwrap_or(LIMIT_DEFAULT),
            LIMIT_DEFAULT
        );

        assert_0!(
            total_cache,
            total_rss,
            total_rss_huge,
            total_shmem,
            total_mapped_file,
            total_dirty,
            total_writeback,
            total_pgpgin,
            total_pgpgout,
            total_pgfault,
            total_pgmajfault,
            total_active_anon,
            total_inactive_anon,
            total_active_file,
            total_inactive_file,
            total_unevictable
        );
        assert_eq!(stat.total_swap.unwrap_or(0), 0);

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_numa_stat() -> Result<()> {
        // tested on a non-NUMA system

        gen_subsystem_test!(Memory; numa_stat, NumaStat {
            total: (0, vec![0]),
            file: (0, vec![0]),
            anon: (0, vec![0]),
            unevictable: (0, vec![0]),

            hierarchical_total: (0, vec![0]),
            hierarchical_file: (0, vec![0]),
            hierarchical_anon: (0, vec![0]),
            hierarchical_unevictable: (0, vec![0]),
        })

        // TODO: test on NUMA systems
    }

    #[test]
    fn test_subsystem_usage_in_bytes() -> Result<()> {
        gen_subsystem_test!(Memory; usage_in_bytes, 0)?;
        // gen_subsystem_test!(Memory; memsw_usage_in_bytes, 0)?; // TODO
        gen_subsystem_test!(Memory; kmem_usage_in_bytes, 0)?;
        gen_subsystem_test!(Memory; kmem_tcp_usage_in_bytes, 0)?;

        Ok(())
    }

    #[test]
    fn test_subsystem_max_usage_in_bytes() -> Result<()> {
        gen_subsystem_test!(Memory; max_usage_in_bytes, 0)?;
        // gen_subsystem_test!(Memory; memsw_max_usage_in_bytes, 0)?; // TODO
        gen_subsystem_test!(Memory; kmem_max_usage_in_bytes, 0)?;
        gen_subsystem_test!(Memory; kmem_tcp_max_usage_in_bytes, 0)?;

        Ok(())
    }

    #[test]
    fn test_subsystem_limit_in_bytes() -> Result<()> {
        gen_subsystem_test!(Memory; limit_in_bytes, LIMIT_DEFAULT)?;
        // gen_subsystem_test!(Memory; memsw_limit_in_bytes, LIMIT_DEFAULT)?; // TODO
        gen_subsystem_test!(Memory; kmem_limit_in_bytes, LIMIT_DEFAULT)?;
        gen_subsystem_test!(Memory; kmem_tcp_limit_in_bytes, LIMIT_DEFAULT)?;

        Ok(())
    }

    #[test]
    fn test_subsystem_failcnt() -> Result<()> {
        gen_subsystem_test!(Memory; failcnt, 0)?;
        // gen_subsystem_test!(Memory; memsw_failcnt, 0)?; // TODO
        gen_subsystem_test!(Memory; kmem_failcnt, 0)?;
        gen_subsystem_test!(Memory; kmem_tcp_failcnt, 0)?;

        Ok(())
    }

    #[test]
    fn test_subsystem_swappiness() -> Result<()> {
        gen_subsystem_test!(Memory; swappiness, 60, set_swappiness, 100)
    }

    #[test]
    fn test_subsystem_oom_control() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Memory, gen_cgroup_name!()));
        cgroup.create()?;
        assert_eq!(
            cgroup.oom_control()?,
            OomControl {
                oom_kill_disable: false,
                under_oom: false,
                oom_kill: Some(0),
            }
        );

        cgroup.disable_oom_killer(true)?;
        assert_eq!(
            cgroup.oom_control()?,
            OomControl {
                oom_kill_disable: true,
                under_oom: false,
                oom_kill: Some(0),
            }
        );

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_move_charge_at_immigrate() -> Result<()> {
        gen_subsystem_test!(Memory; move_charge_at_immigrate, false, set_move_charge_at_immigrate, true)
    }

    #[test]
    fn test_subsystem_use_hierarchy() -> Result<()> {
        // TODO: `set_use_hierarchy(false)` raises `io::Error` with kind `InvalidInput` on some
        // systems?
        gen_subsystem_test!(Memory; use_hierarchy, true)
    }

    #[test]
    fn test_subsystem_force_empty() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::Memory, gen_cgroup_name!()));
        cgroup.create()?;

        cgroup.force_empty()?;

        cgroup.delete()
    }

    #[test]
    fn test_parse_stat() -> Result<()> {
        let content = "\
cache 806506496
rss 6950912
rss_huge 0
shmem 434176
mapped_file 12664832
dirty 32768
writeback 0
pgpgin 596219
pgpgout 397621
pgfault 609057
pgmajfault 186
inactive_anon 3731456
active_anon 3653632
inactive_file 220020736
active_file 586051584
unevictable 0
hierarchical_memory_limit 9223372036854771712
total_cache 7228424192
total_rss 7746449408
total_rss_huge 0
total_shmem 943890432
total_mapped_file 1212370944
total_dirty 7065600
total_writeback 0
total_pgpgin 3711221840
total_pgpgout 3707566876
total_pgfault 4750639337
total_pgmajfault 82700
total_inactive_anon 1127153664
total_active_anon 7428182016
total_inactive_file 2238832640
total_active_file 4166680576
total_unevictable 14004224
";

        let stat = parse_stat(content.as_bytes())?;

        assert_eq!(
            stat,
            Stat {
                cache: 806506496,
                rss: 6950912,
                rss_huge: 0,
                shmem: 434176,
                mapped_file: 12664832,
                dirty: 32768,
                writeback: 0,
                swap: None,
                pgpgin: 596219,
                pgpgout: 397621,
                pgfault: 609057,
                pgmajfault: 186,
                inactive_anon: 3731456,
                active_anon: 3653632,
                inactive_file: 220020736,
                active_file: 586051584,
                unevictable: 0,
                hierarchical_memory_limit: 9223372036854771712,
                hierarchical_memsw_limit: None,
                total_cache: 7228424192,
                total_rss: 7746449408,
                total_rss_huge: 0,
                total_shmem: 943890432,
                total_mapped_file: 1212370944,
                total_dirty: 7065600,
                total_writeback: 0,
                total_swap: None,
                total_pgpgin: 3711221840,
                total_pgpgout: 3707566876,
                total_pgfault: 4750639337,
                total_pgmajfault: 82700,
                total_inactive_anon: 1127153664,
                total_active_anon: 7428182016,
                total_inactive_file: 2238832640,
                total_active_file: 4166680576,
                total_unevictable: 14004224,
            }
        );

        assert_eq!(parse_stat(&b""[..]).unwrap_err().kind(), ErrorKind::Parse);

        Ok(())
    }

    #[test]
    fn test_parse_numa_stat() -> Result<()> {
        let content = "\
total=200910 N0=200910 N1=0
file=199107 N0=199107 N1=1
anon=1803 N0=1803 N1=2
unevictable=0 N0=0 N1=3
hierarchical_total=3596692 N0=3596692 N1=4
hierarchical_file=1383803 N0=1383803 N1=5
hierarchical_anon=2209488 N0=2209492 N1=6
hierarchical_unevictable=3419 N0=3419 N1=7
";

        let numa_stat = parse_numa_stat(content.as_bytes())?;

        assert_eq!(
            numa_stat,
            NumaStat {
                total: (200910, vec![200910, 0]),
                file: (199107, vec![199107, 1]),
                anon: (1803, vec![1803, 2]),
                unevictable: (0, vec![0, 3]),
                hierarchical_total: (3596692, vec![3596692, 4]),
                hierarchical_file: (1383803, vec![1383803, 5]),
                hierarchical_anon: (2209488, vec![2209492, 6]),
                hierarchical_unevictable: (3419, vec![3419, 7]),
            }
        );

        assert_eq!(
            parse_numa_stat(&b""[..]).unwrap_err().kind(),
            ErrorKind::Parse
        );

        Ok(())
    }

    #[test]
    fn test_parse_oom_control() -> Result<()> {
        let content = "\
oom_kill_disable 1
under_oom 1
oom_kill 42
";

        let oom_control = parse_oom_control(content.as_bytes())?;

        assert_eq!(
            oom_control,
            OomControl {
                oom_kill_disable: true,
                under_oom: true,
                oom_kill: Some(42),
            }
        );

        assert_eq!(
            parse_oom_control(&b""[..]).unwrap_err().kind(),
            ErrorKind::Parse
        );

        Ok(())
    }
}
