use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

use crate::{
    v1::{self, Resources, SubsystemKind},
    Error, Pid, Result,
};

const TASKS_FILE_NAME: &str = "tasks";
const PROCS_FILE_NAME: &str = "cgroup.procs";

// Keep the example below in sync with README.md and lib.rs

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
/// let name = PathBuf::from("my_cgroup");
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
/// cgroup.apply(&resources, true)?;
///
/// // Low-level file operations are also supported.
/// let stat_file = cgroup.open_file_read("cpu.stat")?;
///
/// // do something ...
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
    /// Note that this method does not create a new cgroup. [`Cgroup::create`] creates the new directory for
    /// the defined cgroup.
    ///
    /// [`Cgroup::create`]: #method.create
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
    /// assert_eq!(cgroup.subsystem_kind(), SubsystemKind::Cpu);
    /// ```
    fn subsystem_kind(&self) -> SubsystemKind;

    /// Returns the absolute path to this cgroup.
    ///
    /// The resulting path is a concatanation of 1) the cgroup mount point `sys/fs/cgroup`, 2) the
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
    /// assert_eq!(cgroup.path(), PathBuf::from("/sys/fs/cgroup/cpu/students/charlie"));
    /// ```
    fn path(&self) -> PathBuf;

    /// Returns whether the directory already exists for this cgroup.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("does/not/exist")));
    /// assert!(!cgroup.exists());
    /// ```
    fn exists(&self) -> bool {
        self.path().exists()
    }

    /// Returns the definition of the root cgroup for the subsystem of this cgroup..
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use cgroups::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
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
    /// Returns an error if failed to create the directory, with kind [`ErrorKind::Io`]. The
    /// lower-level source can be obtained by using [`Error::source()`] method.
    ///
    /// [`ErrorKind::Io`]: ../enum.ErrorKind.html#variant.Io
    /// [`Error::source()`]: ../struct.Error.thml#method.source
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
    /// cgroup.create()?;
    /// # Ok(())
    /// # }
    /// ```
    fn create(&mut self) -> Result<()> {
        fs::create_dir(self.path()).map_err(Error::io)
    }

    /// Applies a set of resource limits and constraints to this cgroup.
    ///
    /// If `validate` is `true`, this method validates that the resource limits are correctly set,
    /// and returns an error if the validation failed.
    ///
    /// See also implementors' documentations for their specific behavior.
    ///
    /// # Errors
    ///
    /// Returns an error with kind [`ErrorKind::Apply`] if `validate` is `true` and the validation
    /// failed.
    ///
    /// See also implementors' documentation for their specific behavior.
    ///
    /// [`ErrorKind::Apply`]: ../enum.ErrorKind.html#variant.Apply
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
    ///             shares: Some(1000),
    ///             cfs_quota: Some(500 * 1000),
    ///             cfs_period: Some(1000 * 1000),
    ///         },
    ///         ..Resources::default()
    ///     };
    /// cgroup.apply(&resources, true)?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn apply(&mut self, resources: &Resources, validate: bool) -> Result<()>;

    /// Deletes a directory of this cgroup.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to delete the directory, with kind [`ErrorKind::Io`]. The
    /// lower-level source can be obtained by using [`Error::source()`] method.
    ///
    /// Deleting the directory will fail if this cgroup is in use (e.g. a task is still attached).
    ///
    /// [`ErrorKind::Io`]: ../enum.ErrorKind.html#variant.Io
    /// [`Error::source()`]: ../struct.Error.thml#method.source
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
    /// cgroup.create()?;
    ///
    /// cgroup.delete()?;
    /// # Ok(())
    /// # }
    /// ```
    fn delete(&mut self) -> Result<()> {
        fs::remove_dir(self.path()).map_err(Error::io)
    }

    /// Reads a list of tasks attached to this cgroup from `tasks` file. The resulting tasks are
    /// represented by their thread IDs.
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
    /// println!("{:?}", cgroup.tasks()?);
    /// # Ok(())
    /// # }
    /// ```
    fn tasks(&self) -> Result<Vec<Pid>> {
        self.open_file_read(TASKS_FILE_NAME)
            .and_then(read_tasks_procs)
    }

    /// Attaches a task to this cgroup by writing a thread ID to `tasks` file.
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
    /// cgroup.add_task(Pid::from(std::process::id()));
    /// # Ok(())
    /// # }
    /// ```
    fn add_task(&mut self, pid: Pid) -> Result<()> {
        self.open_file_write(TASKS_FILE_NAME, true)
            .and_then(|f| add_tasks_procs(f, pid))
    }

    /// Removes a task from this cgroup. The task is represented by its thread ID.
    ///
    /// The removed task is moved to the root cgroup of the same subsystem.
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
    /// let pid = Pid::from(std::process::id());
    ///
    /// let mut cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    /// cgroup.add_task(pid)?;
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
    /// println!("{:?}", cgroup.procs()?);
    /// # Ok(())
    /// # }
    /// ```
    fn procs(&self) -> Result<Vec<Pid>> {
        self.open_file_read(PROCS_FILE_NAME)
            .and_then(read_tasks_procs)
    }

    /// Attaches a process to this cgroup by writing a PID to `cgroup.procs` file.
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
    /// cgroup.add_proc(Pid::from(std::process::id()));
    /// # Ok(())
    /// # }
    /// ```
    fn add_proc(&mut self, pid: Pid) -> Result<()> {
        self.open_file_write(PROCS_FILE_NAME, true)
            .and_then(|f| add_tasks_procs(f, pid))
    }

    /// Removes a process from this cgroup, with all threads in the same thread group at once. The
    /// process is represented by its PID.
    ///
    /// The removed process is moved to the root cgroup of the same subsystem.
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
    /// let pid = Pid::from(std::process::id());
    ///
    /// let mut cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    /// cgroup.add_proc(pid)?;
    /// cgroup.remove_proc(pid)?;
    /// # Ok(())
    /// # }
    /// ```
    fn remove_proc(&mut self, pid: Pid) -> Result<()> {
        self.root_cgroup().add_proc(pid)
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
    /// let _ = cgroup.file_exists("cpu.stat");
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
    /// let cpu_stat = cgroup.open_file_read("cpu.stat")?;
    /// # Ok(())
    /// # }
    /// ```
    fn open_file_read(&self, name: &str) -> Result<File> {
        fs::OpenOptions::new()
            .read(true)
            .open(self.path().join(name))
            .map_err(Error::io)
    }

    /// Low-level API that opens a file with write access.
    ///
    /// If `append` is `true`, the file is opend in append mode. Otherwise, if the file already
    /// exists, writing to the file will overwrite its contents.
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
    /// let cpu_shares = cgroup.open_file_write("cpu.shares", false)?;
    /// # Ok(())
    /// # }
    /// ```
    fn open_file_write(&mut self, name: &str, append: bool) -> Result<File> {
        let mut open_options = fs::OpenOptions::new();
        if append {
            open_options.append(true);
        } else {
            open_options.write(true).create(true);
        }
        open_options.open(self.path().join(name)).map_err(Error::io)
    }
}

/// Path to a cgroup on the cgroup file system.
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
            name: Some(name),
        }
    }

    pub(crate) fn to_path_buf(&self) -> PathBuf {
        if let Some(ref name) = self.name {
            self.subsystem_root.join(name)
        } else {
            self.subsystem_root.clone()
        }
    }

    pub(crate) fn subsystem_root(&self) -> Self {
        Self {
            subsystem_root: self.subsystem_root.clone(),
            name: None,
        }
    }
}

pub(crate) trait CgroupHelper: Cgroup {
    fn write_file(&mut self, name: &str, val: impl std::fmt::Display) -> Result<()> {
        use std::io::Write;
        self.open_file_write(name, false)
            .and_then(|mut f| write!(f, "{}", val).map_err(Error::io))
    }
}

impl<T: Cgroup> CgroupHelper for T {}

fn read_tasks_procs(file: File) -> Result<Vec<Pid>> {
    use std::io::{BufRead, BufReader};

    let mut ids = vec![];
    for line in BufReader::new(file).lines() {
        let line = line.map_err(Error::io)?;
        let id = line.trim().parse::<u32>().map_err(Error::parse)?;
        ids.push(Pid::from(id))
    }

    Ok(ids)
}

fn add_tasks_procs(mut file: File, id: Pid) -> Result<()> {
    use std::io::Write;
    write!(file, "{}", id.to_inner()).map_err(Error::io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::cpu;

    #[test]
    fn test_cgroup_exists_create_delete() -> Result<()> {
        let mut cgroup =
            cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, make_cgroup_name!()));
        assert!(!cgroup.exists());

        cgroup.create()?;
        assert!(cgroup.exists());

        cgroup.delete()?;
        assert!(!cgroup.exists());

        Ok(())
    }

    #[test]
    #[ignore] // `cargo test` must not be executed in parallel for this test
    fn test_cgroup_add_get_remove_tasks() -> Result<()> {
        let mut cgroup =
            cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, make_cgroup_name!()));
        cgroup.create()?;

        let pid = Pid::from(std::process::id());

        // Add self to the cgroup
        cgroup.add_task(pid)?;
        // Verify that self is indeed in the cgroup
        assert_eq!(cgroup.tasks()?, vec![pid]);

        // Now, try removing self
        cgroup.remove_task(pid)?;
        // Verify that it was indeed removed
        assert!(cgroup.tasks()?.is_empty());

        cgroup.delete()
    }

    #[test]
    fn test_cgroup_add_get_remove_procs() -> Result<()> {
        let pid = Pid::from(std::process::id());

        let mut cgroup =
            cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, make_cgroup_name!()));
        cgroup.create()?;

        cgroup.add_proc(pid)?;
        assert_eq!(cgroup.procs()?, vec![pid]);

        cgroup.remove_proc(pid)?;
        assert!(cgroup.procs()?.is_empty());

        cgroup.delete()
    }

    #[test]
    fn test_cgroup_file_exists() -> Result<()> {
        let mut cgroup =
            cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, make_cgroup_name!()));
        cgroup.create()?;

        assert!(cgroup.file_exists("cpu.stat"));
        assert!(!cgroup.file_exists("does_not_exist"));

        cgroup.delete()
    }

    // TODO
    // #[test]
    // fn test_cgroup_open_file_read() -> Result<()> {
    //     Ok(())
    // }

    // TODO
    // #[test]
    // fn test_cgroup_open_file_write() -> Result<()> {
    //     Ok(())
    // }

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
