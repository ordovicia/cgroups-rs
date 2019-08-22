use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

use crate::{
    util::parse_01_bool,
    v1::{self, Resources, SubsystemKind},
    Error, ErrorKind, Pid, Result,
};

const TASKS: &str = "tasks";
const PROCS: &str = "cgroup.procs";

const NOTIFY_ON_RELEASE: &str = "notify_on_release";
const RELEASE_AGENT: &str = "release_agent";

// NOTE: Keep the example below in sync with README.md and lib.rs

/// Common operations on a cgroup. Each subsystem handler implements this trait.
///
/// # Examples
///
/// ```no_run
/// # fn main() -> cgroups::Result<()> {
/// use std::path::PathBuf;
/// use cgroups::{Pid, v1::{cpu, Cgroup, CgroupPath, SubsystemKind, Resources}};
///
/// let pid = Pid::from(std::process::id());
///
/// // Define and create a new cgroup controlled by the CPU subsystem.
/// let name = PathBuf::from("students/charlie");
/// let mut cgroup = cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, name));
/// cgroup.create()?;
///
/// // Attach the self process to the cgroup.
/// cgroup.add_task(pid)?;
///
/// // Define resource limits and constraints for this cgroup.
/// // Here we just use the default for an example.
/// let resources = Resources::default();
///
/// // Apply the resource limits.
/// cgroup.apply(&resources)?;
///
/// // Low-level file operations are also supported.
/// let stat_file = cgroup.open_file_read("cpu.stat")?;
///
/// // Do something ...
///
/// // Now, remove self process from the cgroup.
/// cgroup.remove_task(pid)?;
///
/// // And delete the cgroup.
/// cgroup.delete()?;
///
/// // Note that cgroup handlers does not implement `Drop` and therefore when the
/// // handler is dropped, the cgroup will stay around.
/// # Ok(())
/// # }
/// ```
pub trait Cgroup {
    /// Defines a new cgroup with a path.
    ///
    /// Note that this method does not create a new cgroup. `create` method creates the new
    /// directory for the defined cgroup.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    /// ```
    fn new(path: CgroupPath) -> Self;

    /// Returns the subsystem kind of this cgroup.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// assert_eq!(cgroup.subsystem_kind(), SubsystemKind::Cpu);
    /// ```
    fn subsystem_kind(&self) -> SubsystemKind;

    /// Returns the absolute path to this cgroup.
    ///
    /// The resulting path is a concatenation of 1) the cgroup mount point `sys/fs/cgroup`, 2) the
    /// directory name for the subsystem of this cgroup, and 3) the cgroup name (e.g.
    /// `students/charlie`).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// assert_eq!(cgroup.path(), PathBuf::from("/sys/fs/cgroup/cpu/students/charlie"));
    /// ```
    fn path(&self) -> PathBuf;

    /// Returns whether this cgroup is a root cgroup of a subsystem.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let root = cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, PathBuf::new()));
    /// assert!(root.is_root());
    ///
    /// let cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    /// assert!(!cgroup.is_root());
    /// ```
    fn is_root(&self) -> bool;

    /// Returns the definition of the root cgroup for the subsystem of this cgroup.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// let root = cgroup.root_cgroup();
    /// assert_eq!(root.path(), PathBuf::from("/sys/fs/cgroup/cpu"));
    /// ```
    fn root_cgroup(&self) -> Box<Self>;

    /// Creates a new directory for this cgroup.
    ///
    /// This method does not create directories recursively; If a parent of the path does not
    /// exist, an error will be returned. All parent directories must be created before you call
    /// this method.
    ///
    /// This method does not verify that the subsystem directory (e.g. `/sys/fs/cgroup/cpu`) is a
    /// mount point of a cgroup file system. No error is returned in this case.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to create the directory, with kind [`ErrorKind::Io`].
    ///
    /// [`ErrorKind::Io`]: ../enum.ErrorKind.html#variant.Io
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let mut cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// cgroup.create()?;
    /// # Ok(())
    /// # }
    /// ```
    fn create(&mut self) -> Result<()> {
        fs::create_dir(self.path()).map_err(Into::into)
    }

    /// Applies a set of resource limits and constraints to this cgroup.
    ///
    /// See also implementors' documentations for their specific behavior.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to apply the resource configuration. The kind and lower-level
    /// source of the error can be obtained with [`Error::kind`] and [`Error::source`] methods.
    ///
    /// See also implementors' documentation for their specific behavior.
    ///
    /// [`Error::kind`]: ../enum.ErrorKind.html#method.kind
    /// [`Error::source`]: ../enum.ErrorKind.html#method.source
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, Resources, SubsystemKind};
    ///
    /// let mut cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// let resources = Resources {
    ///         cpu: cpu::Resources {
    ///             shares: Some(1024),
    ///             cfs_quota_us: Some(500_000),
    ///             cfs_period_us: Some(1_000_000),
    ///         },
    ///         ..Resources::default()
    ///     };
    /// cgroup.apply(&resources)?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn apply(&mut self, resources: &Resources) -> Result<()>;

    /// Deletes a directory of this cgroup.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to delete the directory, with kind [`ErrorKind::Io`].
    ///
    /// Deleting the directory will fail if this cgroup is in use (e.g. a task is still attached).
    ///
    /// [`ErrorKind::Io`]: ../enum.ErrorKind.html#variant.Io
    ///
    /// # Examples
    ///
    /// ```no_use
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let mut cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// cgroup.create()?;
    ///
    /// cgroup.delete()?;
    /// # Ok(())
    /// # }
    /// ```
    fn delete(&mut self) -> Result<()> {
        fs::remove_dir(self.path()).map_err(Into::into)
    }

    /// Reads a list of tasks attached to this cgroup from `tasks` file. The resulting tasks are
    /// represented by their thread IDs.
    ///
    /// See the kernel's documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to read and parse `tasks` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// println!("{:?}", cgroup.tasks()?);
    /// # Ok(())
    /// # }
    /// ```
    fn tasks(&self) -> Result<Vec<Pid>> {
        self.open_file_read(TASKS).and_then(parse_tasks_procs)
    }

    /// Attaches a task to this cgroup by writing a thread ID to `tasks` file.
    ///
    /// See the kernel's documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to write to `tasks` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::{Pid, v1::{cpu, Cgroup, CgroupPath, SubsystemKind}};
    ///
    /// let mut cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// cgroup.add_task(Pid::from(std::process::id()));
    /// # Ok(())
    /// # }
    /// ```
    fn add_task(&mut self, pid: Pid) -> Result<()> {
        fs::write(self.path().join(TASKS), format!("{}", pid)).map_err(Into::into)
    }

    /// Removes a task from this cgroup. The task is represented by its thread ID.
    /// The removed task is moved to the root cgroup of the same subsystem.
    ///
    /// See the kernel's documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to write to `tasks` file of the root cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::{Pid, v1::{cpu, Cgroup, CgroupPath, SubsystemKind}};
    ///
    /// let mut cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// let pid = Pid::from(std::process::id());
    /// cgroup.add_task(pid)?;
    ///
    /// cgroup.remove_task(pid)?;
    /// # Ok(())
    /// # }
    /// ```
    fn remove_task(&mut self, pid: Pid) -> Result<()> {
        self.root_cgroup().add_task(pid)
    }

    /// Reads a list of processes attached to this cgroup from `cgroup.procs` file. The resulting
    /// processes are represented by their PIDs.
    ///
    /// See the kernel's documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to read and parse `cgroup.procs` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// println!("{:?}", cgroup.procs()?);
    /// # Ok(())
    /// # }
    /// ```
    fn procs(&self) -> Result<Vec<Pid>> {
        self.open_file_read(PROCS).and_then(parse_tasks_procs)
    }

    /// Attaches a process to this cgroup by writing a PID to `cgroup.procs` file.
    ///
    /// See the kernel's documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to write to `cgroup.procs` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::{Pid, v1::{cpu, Cgroup, CgroupPath, SubsystemKind}};
    ///
    /// let mut cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// cgroup.add_proc(Pid::from(std::process::id()));
    /// # Ok(())
    /// # }
    /// ```
    fn add_proc(&mut self, pid: Pid) -> Result<()> {
        fs::write(self.path().join(PROCS), format!("{}", pid)).map_err(Into::into)
    }

    /// Removes a process from this cgroup, with all threads in the same thread group at once. The
    /// process is represented by its PID.
    /// The removed process is moved to the root cgroup of the same subsystem.
    ///
    /// See the kernel's documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to write to `cgroup.procs` file of the root cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::{Pid, v1::{cpu, Cgroup, CgroupPath, SubsystemKind}};
    ///
    /// let mut cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// let pid = Pid::from(std::process::id());
    /// cgroup.add_proc(pid)?;
    ///
    /// cgroup.remove_proc(pid)?;
    /// # Ok(())
    /// # }
    /// ```
    fn remove_proc(&mut self, pid: Pid) -> Result<()> {
        self.root_cgroup().add_proc(pid)
    }

    /// Reads whether the system executes the executable written in `release_agent` file when a
    /// cgroup no longer has any task, from `notify_on_release` file.
    ///
    /// See the kernel's documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to read and parse `notify_on_release` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::{v1::{cpu, Cgroup, CgroupPath, SubsystemKind}};
    ///
    /// let cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// let notify_on_release = cgroup.notify_on_release()?;
    /// # Ok(())
    /// # }
    /// ```
    fn notify_on_release(&self) -> Result<bool> {
        self.open_file_read(NOTIFY_ON_RELEASE)
            .and_then(parse_01_bool)
    }

    /// Sets whether the system executes the executable written in `release_agent` file when a
    /// cgroup no longer has any task, from `notify_on_release` file.
    ///
    /// See the kernel's documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to write to `notify_on_release` file of this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::{v1::{cpu, Cgroup, CgroupPath, SubsystemKind}};
    ///
    /// let mut cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// cgroup.set_notify_on_release(true)?;
    /// # Ok(())
    /// # }
    /// ```
    fn set_notify_on_release(&mut self, enable: bool) -> Result<()> {
        fs::write(
            self.path().join(NOTIFY_ON_RELEASE),
            format!("{}", enable as i32),
        )
        .map_err(Into::into)
    }

    /// Reads the command to be executed when "notify on release" is triggered, i.e. this cgroup is
    /// emptied of all tasks, from `release_agent` file.
    ///
    /// See the kernel's documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// This file is present only in the root cgroup. If you call this method on a non-root cgroup,
    /// an error is returned with kind [`ErrorKind::InvalidOperation`].
    ///
    /// On the root cgroup, returns an error if failed to read `release_agent` file.
    ///
    /// [`ErrorKind::InvalidOperation`]: ../enum.ErrorKind.html#variant.InvalidOperation
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::{v1::{cpu, Cgroup, CgroupPath, SubsystemKind}};
    ///
    /// let cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// cgroup.release_agent()?;
    /// # Ok(())
    /// # }
    /// ```
    fn release_agent(&self) -> Result<String> {
        use std::io::Read;

        if !self.is_root() {
            return Err(Error::new(ErrorKind::InvalidOperation));
        }

        let mut buf = String::new();
        self.open_file_read(RELEASE_AGENT)?
            .read_to_string(&mut buf)?;

        Ok(buf)
    }

    /// Sets a path of executable to be executed when "notify on release" is triggered, i.e. this
    /// cgroup is emptied of all tasks, by writing to `release_agent` file.
    ///
    /// See the kernel's documentation for more information about this field.
    ///
    /// # Errors
    ///
    /// This file is present only in the root cgroup. If you call this method on a non-root cgroup,
    /// an error is returned with kind [`ErrorKind::InvalidOperation`].
    ///
    /// On the root cgroup, returns an error if failed to write to `release_agent` file.
    ///
    /// [`ErrorKind::InvalidOperation`]: ../enum.ErrorKind.html#variant.InvalidOperation
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::{v1::{cpu, Cgroup, CgroupPath, SubsystemKind}};
    ///
    /// let mut cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// cgroup.set_release_agent(b"/usr/local/bin/foo.sh")?;
    /// # Ok(())
    /// # }
    /// ```
    fn set_release_agent(&mut self, agent_path: impl AsRef<[u8]>) -> Result<()> {
        if !self.is_root() {
            return Err(Error::new(ErrorKind::InvalidOperation));
        }
        fs::write(self.path().join(RELEASE_AGENT), agent_path.as_ref()).map_err(Into::into)
    }

    /// Returns whether a file with the given name exists in this cgroup.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// let cpu_stat_exists = cgroup.file_exists("cpu.stat");
    /// # Ok(())
    /// # }
    /// ```
    fn file_exists(&self, name: &str) -> bool {
        self.path().join(name).exists()
    }

    /// Low-level API that opens a file with read access.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to open the file, with kind [`ErrorKind::Io`].
    ///
    /// [`ErrorKind::Io`]: ../enum.ErrorKind.html#variant.Io
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// let cpu_stat_file = cgroup.open_file_read("cpu.stat")?;
    /// # Ok(())
    /// # }
    /// ```
    fn open_file_read(&self, name: &str) -> Result<File> {
        File::open(self.path().join(name)).map_err(Into::into)
    }

    /// Low-level API that opens a file with write access.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to open the file, with kind [`ErrorKind::Io`].
    ///
    /// [`ErrorKind::Io`]: ../enum.ErrorKind.html#variant.Io
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> cgroups::Result<()> {
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let mut cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    ///
    /// let cpu_shares_file = cgroup.open_file_write("cpu.shares")?;
    /// # Ok(())
    /// # }
    /// ```
    fn open_file_write(&mut self, name: &str) -> Result<File> {
        fs::OpenOptions::new()
            .write(true)
            // .create(true)
            .open(self.path().join(name))
            .map_err(Into::into)
    }
}

/// Path to a cgroup in a cgroup file system.
#[derive(Debug, PartialEq, Eq)]
pub struct CgroupPath {
    subsystem_root: PathBuf, // e.g. /sys/fs/cgroup/cpu
    name: Option<PathBuf>,   // e.g. students/charlie
}

impl CgroupPath {
    /// Create a new `CgroupPath` with a subsystem kind and a cgroup name.
    ///
    /// The resulting path is the concatenation of 1) the cgroup mount point `/sys/fs/cgroup`, 2)
    /// the standard directory name for the subsystem (e.g. `SubsystemKind::Cpu` => `cpu`), and 3)
    /// the cgroup name (e.g. `students/charlie`).
    ///
    /// If the name is empty, the resulting path points to the root cgroup of the subsystem.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use cgroups::v1::{CgroupPath, SubsystemKind};
    ///
    /// let path = CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie"));
    /// ```
    pub fn new(kind: SubsystemKind, name: PathBuf) -> Self {
        Self::with_subsystem_name(kind.to_string(), name)
    }

    /// Create a new `CgroupPath` with a custom subsystem directory name and a cgroup name.
    ///
    /// The resulting path is the concatenation of 1) the cgroup mount point `/sys/fs/cgroup`, 2)
    /// the given custom directory name, and 3) the cgroup name (e.g. `students/charlie`).
    ///
    /// If the name is empty, the resulting path points to the root cgroup of the subsystem.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use cgroups::v1::CgroupPath;
    ///
    /// let path = CgroupPath::with_subsystem_name(
    ///     String::from("cpu_memory"),
    ///     PathBuf::from("students/charlie"),
    /// );
    /// ```
    pub fn with_subsystem_name(subsystem_name: String, name: PathBuf) -> Self {
        Self {
            subsystem_root: Path::new(v1::CGROUPFS_MOUNT_POINT).join(subsystem_name),
            name: if name.as_os_str().is_empty() {
                None
            } else {
                Some(name)
            },
        }
    }

    pub(crate) fn to_path_buf(&self) -> PathBuf {
        if let Some(ref name) = self.name {
            self.subsystem_root.join(name)
        } else {
            self.subsystem_root.clone()
        }
    }

    pub(crate) fn is_subsystem_root(&self) -> bool {
        self.name.is_none()
    }

    pub(crate) fn subsystem_root(&self) -> Self {
        Self {
            subsystem_root: self.subsystem_root.clone(),
            name: None,
        }
    }
}

macro_rules! impl_cgroup {
    ($subsystem: ident, $($tt: tt)*) => {
        impl Cgroup for Subsystem {
            fn new(path: CgroupPath) -> Self {
                Self { path }
            }

            fn subsystem_kind(&self) -> SubsystemKind {
                SubsystemKind::$subsystem
            }

            fn path(&self) -> PathBuf {
                self.path.to_path_buf()
            }

            fn is_root(&self) -> bool {
                self.path.is_subsystem_root()
            }

            fn root_cgroup(&self) -> Box<Self> {
                Box::new(Self::new(self.path.subsystem_root()))
            }

            $($tt)*
        }
    };
}

pub(crate) trait CgroupHelper: Cgroup {
    fn write_file(&mut self, name: &str, val: impl std::fmt::Display) -> Result<()> {
        let _ = fs::write(self.path().join(name), format!("{}", val))?;
        Ok(())
    }
}

impl<T: Cgroup> CgroupHelper for T {}

fn parse_tasks_procs(file: File) -> Result<Vec<Pid>> {
    use std::io::{BufRead, BufReader};

    let mut ids = vec![];
    for line in BufReader::new(file).lines() {
        let id = line?.trim().parse::<u32>()?;
        ids.push(Pid::from(id))
    }

    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::cpu;

    #[test]
    fn test_cgroup_path() {
        let name = gen_cgroup_name!();
        let cgroup = cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, name.clone()));
        assert_eq!(
            cgroup.path(),
            PathBuf::from("/sys/fs/cgroup/cpu").join(name)
        );
    }

    #[test]
    fn test_cgroup_root_cgroup() {
        let cgroup = cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, gen_cgroup_name!()));
        assert_eq!(
            cgroup.root_cgroup().path(),
            PathBuf::from("/sys/fs/cgroup/cpu")
        );
    }

    #[test]
    fn test_cgroup_subsystem_kind() {
        macro_rules! t {
            ( $( ($subsystem: ident, $kind: ident) ),* ) => {{ $(
                let cgroup = crate::v1::$subsystem::Subsystem::new(CgroupPath::new(SubsystemKind::$kind, gen_cgroup_name!()));
                assert_eq!(cgroup.subsystem_kind(), SubsystemKind::$kind);
            )* }};
        }

        t! {
            (cpu, Cpu),
            (cpuset, Cpuset),
            (cpuacct, Cpuacct),
            (pids, Pids),
            (hugetlb, HugeTlb),
            (net_cls, NetCls),
            (net_prio, NetPrio),
            (rdma, Rdma),
            (freezer, Freezer),
            (perf_event, PerfEvent)
        }
    }

    #[test]
    fn test_cgroup_create_delete() -> Result<()> {
        let mut cgroup =
            cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, gen_cgroup_name!()));
        assert!(!cgroup.path().exists());

        cgroup.create()?;
        assert!(cgroup.path().exists());

        cgroup.delete()?;
        assert!(!cgroup.path().exists());

        Ok(())
    }

    #[test]
    #[ignore] // `cargo test` must not be executed in parallel for this test
    fn test_cgroup_add_get_remove_tasks() -> Result<()> {
        use std::process::{self, Command};

        let mut cgroup =
            cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, gen_cgroup_name!()));
        cgroup.create()?;

        let pid = Pid::from(process::id());
        cgroup.add_task(pid)?;
        assert_eq!(cgroup.tasks()?, vec![pid]);

        let child = Command::new("sleep").arg("1").spawn().unwrap();
        let child_pid = Pid::from(&child);
        cgroup.add_task(child_pid)?;
        assert!(cgroup.tasks()? == vec![pid, child_pid] || cgroup.tasks()? == vec![child_pid, pid]);

        cgroup.remove_task(child_pid)?;
        assert!(cgroup.tasks()? == vec![pid]);

        cgroup.remove_task(pid)?;
        assert!(cgroup.tasks()?.is_empty());

        cgroup.delete()
    }

    #[test]
    fn test_cgroup_add_get_remove_procs() -> Result<()> {
        use crate::util::sleep;
        use std::process::{self, Command};

        let mut cgroup =
            cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, gen_cgroup_name!()));
        cgroup.create()?;

        let pid = Pid::from(process::id());
        cgroup.add_proc(pid)?;
        assert_eq!(cgroup.procs()?, vec![pid]);

        let child = Command::new("sleep").arg("1").spawn().unwrap();
        let child_pid = Pid::from(&child);
        cgroup.add_proc(child_pid)?;
        assert!(cgroup.procs()? == vec![pid, child_pid] || cgroup.procs()? == vec![child_pid, pid]);

        cgroup.remove_proc(child_pid)?;
        sleep(100);
        assert!(cgroup.procs()? == vec![pid]);

        cgroup.remove_proc(pid)?;
        sleep(100);
        assert!(cgroup.procs()?.is_empty());

        cgroup.delete()
    }

    #[test]
    fn test_cgroup_notify_on_release() -> Result<()> {
        let mut cgroup =
            cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, gen_cgroup_name!()));
        cgroup.create()?;
        assert_eq!(cgroup.notify_on_release()?, false);

        cgroup.set_notify_on_release(true)?;
        assert_eq!(cgroup.notify_on_release()?, true);

        cgroup.delete()
    }

    #[test]
    #[ignore] // (temporarily) overrides the root cgroup
    fn test_cgroup_release_agent() -> Result<()> {
        let mut root = cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, PathBuf::new()));
        let agent = root.release_agent()?;

        root.set_release_agent(b"foo")?;
        assert_eq!(root.release_agent()?, "foo\n".to_string());

        root.set_release_agent(&agent)?;
        assert_eq!(root.release_agent()?, agent);

        Ok(())
    }

    #[test]
    fn err_cgroup_release_agent() -> Result<()> {
        let mut cgroup =
            cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, gen_cgroup_name!()));
        cgroup.create()?;

        assert_eq!(
            cgroup.release_agent().unwrap_err().kind(),
            ErrorKind::InvalidOperation
        );
        assert_eq!(
            cgroup.set_release_agent(b"foo").unwrap_err().kind(),
            ErrorKind::InvalidOperation
        );

        cgroup.delete()
    }

    #[test]
    fn test_cgroup_file_exists() -> Result<()> {
        let mut cgroup =
            cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, gen_cgroup_name!()));
        cgroup.create()?;

        assert!(cgroup.file_exists("tasks"));
        assert!(!cgroup.file_exists("does_not_exist"));

        cgroup.delete()
    }

    #[test]
    fn test_cgroup_open_file_read_write() -> Result<()> {
        use std::io::{Read, Write};

        let mut cgroup =
            cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, gen_cgroup_name!()));
        cgroup.create()?;

        // read
        let mut buf = String::new();
        cgroup
            .open_file_read(NOTIFY_ON_RELEASE)?
            .read_to_string(&mut buf)
            .unwrap();
        assert_eq!(buf, "0\n");

        // write
        let mut file = cgroup.open_file_write(NOTIFY_ON_RELEASE)?;
        write!(file, "1").unwrap();

        // read
        buf.clear();
        cgroup
            .open_file_read(NOTIFY_ON_RELEASE)?
            .read_to_string(&mut buf)
            .unwrap();
        assert_eq!(buf, "1\n");

        cgroup.delete()
    }

    #[test]
    fn test_cgroup_path_new() {
        let path = CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie"));
        assert_eq!(
            path.to_path_buf(),
            PathBuf::from("/sys/fs/cgroup/cpu/students/charlie")
        );
    }

    #[test]
    fn test_cgroup_path_with_subsystem_name() {
        let path = CgroupPath::with_subsystem_name(
            String::from("cpu_memory"),
            PathBuf::from("students/charlie"),
        );
        assert_eq!(
            path.to_path_buf(),
            PathBuf::from("/sys/fs/cgroup/cpu_memory/students/charlie")
        );
    }

    #[test]
    fn test_cgroup_path_subsystem_root() {
        let path = CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie"));
        let root = path.subsystem_root();

        assert_eq!(root.to_path_buf(), PathBuf::from("/sys/fs/cgroup/cpu"),);
    }
}
