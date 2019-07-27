use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

use crate::{
    v1::{self, Resources, SubsystemKind},
    Error, Pid, Result,
};

const TASKS_FILE_NAME: &str = "tasks";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupPath {
    subsystem_root: PathBuf, // e.g. /sys/fs/cgroup/cpu
    name: PathBuf,
}

pub trait Cgroup {
    fn new(path: CgroupPath) -> Self;

    // fn subsystem_kind(&self) -> SubsystemKind;

    fn path(&self) -> PathBuf;

    fn exists(&self) -> bool {
        self.path().exists()
    }

    // TODO: avoid heap allocation
    fn root_cgroup(&self) -> Box<Self>;

    fn create(&mut self) -> Result<()> {
        fs::create_dir(self.path()).map_err(Error::io)
    }

    fn apply(&mut self, resources: &Resources) -> Result<()>;

    fn apply(&mut self, resources: &Resources, validate: bool) -> Result<()>;

    fn delete(&mut self) -> Result<()> {
        // more grace error handling in crate level?
        fs::remove_dir(self.path()).map_err(Error::io)
    }

    fn tasks(&self) -> Result<Vec<Pid>> {
        use std::io::{BufRead, BufReader};

        let mut tasks = vec![];
        let file = self.open_file_read(TASKS_FILE_NAME)?;

        for line in BufReader::new(file).lines() {
            let line = line.map_err(Error::io)?;
            let pid = line.trim().parse::<u32>().map_err(Error::parse)?;
            tasks.push(Pid::from(pid))
        }

        Ok(tasks)
    }

    fn add_task(&mut self, pid: Pid) -> Result<()> {
        use std::io::Write;

        self.open_file_write(TASKS_FILE_NAME, true)
            .and_then(|mut f| write!(f, "{}", pid.to_string()).map_err(Error::io))
    }

    fn remove_task(&mut self, pid: Pid) -> Result<()> {
        self.root_cgroup().add_task(pid)
    }

    fn open_file_read(&self, file_name: &str) -> Result<File> {
        fs::OpenOptions::new()
            .read(true)
            .open(self.path().join(file_name))
            .map_err(Error::io)
    }

    fn open_file_write(&mut self, file_name: &str, append: bool) -> Result<File> {
        let mut open_options = fs::OpenOptions::new();
        if append {
            open_options.append(true);
        } else {
            open_options.write(true).create(true);
        }
        open_options
            .open(self.path().join(file_name))
            .map_err(Error::io)
    }
}

impl CgroupPath {
    pub fn new(kind: SubsystemKind, name: PathBuf) -> Self {
        Self::with_subsystem_name(kind.to_string(), name)
    }

    pub fn with_subsystem_name(subsystem_name: String, name: PathBuf) -> Self {
        Self {
            subsystem_root: Path::new(v1::CGROUPFS_MOUNT_POINT).join(subsystem_name),
            name,
        }
    }

    pub(crate) fn to_path_buf(&self) -> PathBuf {
        self.subsystem_root.join(&self.name)
    }

    pub(crate) fn subsystem_root(&self) -> Self {
        Self {
            subsystem_root: self.subsystem_root.clone(),
            name: PathBuf::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_exists_create_delete() -> Result<()> {
        use crate::v1::cpu;

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
        use crate::v1::cpu;

        let pid = Pid::from(std::process::id());

        let mut cgroup =
            cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, make_cgroup_name!()));
        cgroup.create()?;

        // Add self to the cgroup
        cgroup.add_task(pid)?;

        // Verify that self is indeed in the cgroup
        let tasks = cgroup.tasks()?;
        assert_eq!(tasks, vec![pid]);

        // Now, try removing self
        cgroup.remove_task(pid)?;
        // Verify that it was indeed removed
        let tasks = cgroup.tasks()?;
        assert!(tasks.is_empty());

        cgroup.delete()?;

        Ok(())
    }
}
