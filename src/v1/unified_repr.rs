use std::path::PathBuf;

use crate::{
    v1::{self, cpu, Cgroup, CgroupPath, SubsystemKind},
    Pid, Result,
};

#[derive(Debug)]
pub struct UnifiedRepr {
    cpu: Option<cpu::Subsystem>,
}

impl UnifiedRepr {
    pub fn new(name: PathBuf) -> Self {
        use SubsystemKind::*;
        Self::with_subsystems(name, &[Cpu])
    }

    pub fn with_subsystems(name: PathBuf, subsystem_kinds: &[SubsystemKind]) -> Self {
        use SubsystemKind::*;

        let mut cpu = None;
        for kind in subsystem_kinds {
            let path = CgroupPath::new(*kind, name.clone());
            match kind {
                Cpu => {
                    cpu = Some(cpu::Subsystem::new(path));
                }
            }
        }

        Self { cpu }
    }

    pub fn supports(&self, subsystem_kind: SubsystemKind) -> bool {
        use SubsystemKind::*;

        match subsystem_kind {
            Cpu => self.cpu().is_some(),
        }
    }

    pub fn cpu(&self) -> Option<&cpu::Subsystem> {
        self.cpu.as_ref()
    }

    pub fn create(&mut self) -> Result<()> {
        if let Some(ref mut cpu) = self.cpu {
            cpu.create()?;
        }

        Ok(())
    }

    pub fn apply(&mut self, resources: &v1::Resources, validate: bool) -> Result<()> {
        if let Some(ref mut cpu) = self.cpu {
            cpu.apply(&resources, validate)?;
        }

        Ok(())
    }

    pub fn delete(&mut self) -> Result<()> {
        if let Some(ref mut cpu) = self.cpu {
            cpu.delete()?;
        }

        Ok(())
    }

    pub fn add_task(&mut self, pid: Pid) -> Result<()> {
        if let Some(ref mut cpu) = self.cpu {
            cpu.add_task(pid)?;
        }

        Ok(())
    }

    pub fn remove_task(&mut self, pid: Pid) -> Result<()> {
        if let Some(ref mut cpu) = self.cpu {
            cpu.remove_task(pid)?;
        }

        Ok(())
    }

    pub fn add_proc(&mut self, pid: Pid) -> Result<()> {
        if let Some(ref mut cpu) = self.cpu {
            cpu.add_proc(pid)?;
        }

        Ok(())
    }

    pub fn remove_proc(&mut self, pid: Pid) -> Result<()> {
        if let Some(ref mut cpu) = self.cpu {
            cpu.remove_proc(pid)?;
        }

        Ok(())
    }
}
