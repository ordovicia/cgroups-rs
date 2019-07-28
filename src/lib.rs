use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub mod cgroup;
pub mod cpu;
pub mod error;
pub mod hierarchies;

pub use crate::cgroup::Cgroup;
pub use crate::error::{Error, ErrorKind, Result};

#[rustfmt::skip]
use crate::cpu::CpuController;

/// Contains all the subsystems that are available in this crate.
#[derive(Debug)]
pub enum Subsystem {
    /// Controller for the `Cpu` subsystem, see `CpuController` for more information.
    Cpu(CpuController),
}

#[doc(hidden)]
#[derive(Eq, PartialEq, Debug)]
pub enum Controllers {
    Cpu,
}

impl Controllers {
    pub fn to_string(&self) -> String {
        match self {
            Controllers::Cpu => return "cpu".to_string(),
        }
    }
}

mod sealed {
    use super::*;

    pub trait ControllerInternal {
        fn apply(&self, res: &Resources) -> Result<()>;

        // meta stuff
        fn control_type(&self) -> Controllers;
        fn get_path(&self) -> &PathBuf;
        fn get_path_mut(&mut self) -> &mut PathBuf;
        fn get_base(&self) -> &PathBuf;

        fn verify_path(&self) -> Result<()> {
            if self.get_path().starts_with(self.get_base()) {
                Ok(())
            } else {
                Err(Error::new(ErrorKind::InvalidPath))
            }
        }

        fn open_path(&self, p: &str, w: bool) -> Result<File> {
            let mut path = self.get_path().clone();
            path.push(p);

            self.verify_path()?;

            if w {
                match File::create(&path) {
                    Err(e) => return Err(Error::with_source(ErrorKind::WriteFailed, e)),
                    Ok(file) => return Ok(file),
                }
            } else {
                match File::open(&path) {
                    Err(e) => return Err(Error::with_source(ErrorKind::ReadFailed, e)),
                    Ok(file) => return Ok(file),
                }
            }
        }

        #[doc(hidden)]
        fn path_exists(&self, p: &str) -> bool {
            if let Err(_) = self.verify_path() {
                return false;
            }

            std::path::Path::new(p).exists()
        }
    }
}

pub(crate) use crate::sealed::ControllerInternal;

/// A Controller is a subsystem attached to the control group.
///
/// Implementors are able to control certain aspects of a control group.
pub trait Controller {
    #[doc(hidden)]
    fn control_type(&self) -> Controllers;

    /// The file system path to the controller.
    fn path(&self) -> &Path;

    /// Apply a set of resources to the Controller, invoking its internal functions to pass the
    /// kernel the information.
    fn apply(&self, res: &Resources) -> Result<()>;

    /// Create this controller
    fn create(&self);

    /// Does this controller already exist?
    fn exists(&self) -> bool;

    /// Delete the controller.
    fn delete(&self);

    /// Attach a task to this controller.
    fn add_task(&self, pid: &CgroupPid) -> Result<()>;

    /// Get the list of tasks that this controller has.
    fn tasks(&self) -> Vec<CgroupPid>;
}

impl<T> Controller for T
where
    T: ControllerInternal,
{
    fn control_type(&self) -> Controllers {
        ControllerInternal::control_type(self)
    }

    fn path(&self) -> &Path {
        self.get_path()
    }

    /// Apply a set of resources to the Controller, invoking its internal functions to pass the
    /// kernel the information.
    fn apply(&self, res: &Resources) -> Result<()> {
        ControllerInternal::apply(self, res)
    }

    /// Create this controller
    fn create(&self) {
        self.verify_path().expect("path should be valid");

        match fs::create_dir(self.get_path()) {
            Ok(_) => (),
            Err(e) => log::warn!("error create_dir {:?}", e),
        }
    }

    /// Does this controller already exist?
    fn exists(&self) -> bool {
        self.get_path().exists()
    }

    /// Delete the controller.
    fn delete(&self) {
        if self.get_path().exists() {
            let _ = fs::remove_dir(self.get_path());
        }
    }

    /// Attach a task to this controller.
    fn add_task(&self, pid: &CgroupPid) -> Result<()> {
        self.open_path("tasks", true).and_then(|mut file| {
            file.write_all(pid.pid.to_string().as_ref())
                .map_err(|e| Error::with_source(ErrorKind::WriteFailed, e))
        })
    }

    /// Get the list of tasks that this controller has.
    fn tasks(&self) -> Vec<CgroupPid> {
        self.open_path("tasks", false)
            .and_then(|file| {
                let bf = BufReader::new(file);
                let mut v = Vec::new();
                for line in bf.lines() {
                    if let Ok(line) = line {
                        let n = line.trim().parse().unwrap_or(0u64);
                        v.push(n);
                    }
                }
                Ok(v.into_iter().map(CgroupPid::from).collect())
            })
            .unwrap_or(vec![])
    }
}

#[doc(hidden)]
pub trait ControllIdentifier {
    fn controller_type() -> Controllers;
}

/// Control group hierarchy (right now, only V1 is supported, but in the future Unified will be
/// implemented as well).
pub trait Hierarchy {
    /// Returns what subsystems are supported by the hierarchy.
    fn subsystems(&self) -> Vec<Subsystem>;

    /// Returns the root directory of the hierarchy.
    fn root(&self) -> PathBuf;

    /// Return a handle to the root control group in the hierarchy.
    fn root_control_group(&self) -> Cgroup<'_>;

    /// Checks whether a certain subsystem is supported in the hierarchy.
    ///
    /// This is an internal function and should not be used.
    #[doc(hidden)]
    fn check_support(&self, sub: Controllers) -> bool;
}

/// Resources limits about how the tasks can use the CPU.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct CpuResources {
    /// Whether values should be applied to the controller.
    pub update_values: bool,
    // cpuset
    /// A comma-separated list of CPU IDs where the task in the control group can run. Dashes
    /// between numbers indicate ranges.
    pub cpus: String,
    /// Same syntax as the `cpus` field of this structure, but applies to memory nodes instead of
    /// processors.
    pub mems: String,
    // cpu
    /// Weight of how much of the total CPU time should this control group get. Note that this is
    /// hierarchical, so this is weighted against the siblings of this control group.
    pub shares: u64,
    /// In one `period`, how much can the tasks run in nanoseconds.
    pub quota: i64,
    /// Period of time in nanoseconds.
    pub period: u64,
    /// This is currently a no-operation.
    pub realtime_runtime: i64,
    /// This is currently a no-operation.
    pub realtime_period: u64,
}

/// The resource limits and constraints that will be set on the control group.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct Resources {
    /// CPU related limits.
    pub cpu: CpuResources,
}

/// A structure representing a `pid`. Currently implementations exist for `u64` and
/// `std::process::Child`.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CgroupPid {
    /// The process identifier
    pub pid: u64,
}

impl From<u64> for CgroupPid {
    fn from(u: u64) -> CgroupPid {
        CgroupPid { pid: u }
    }
}

impl<'a> From<&'a std::process::Child> for CgroupPid {
    fn from(u: &std::process::Child) -> CgroupPid {
        CgroupPid { pid: u.id() as u64 }
    }
}

impl Subsystem {
    fn enter(self, path: &Path) -> Self {
        match self {
            Subsystem::Cpu(cont) => Subsystem::Cpu({
                let mut c = cont.clone();
                c.get_path_mut().push(path);
                c
            }),
        }
    }

    fn to_controller(&self) -> &dyn Controller {
        match self {
            Subsystem::Cpu(cont) => cont,
        }
    }
}
