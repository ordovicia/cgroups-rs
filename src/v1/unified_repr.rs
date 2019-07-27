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
        let cpu = cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, name));

        Self {
            cpu: if cpu.exists() { Some(cpu) } else { None },
        }
    }

    pub fn supports(&self, subsystem_kind: SubsystemKind) -> bool {
        use SubsystemKind::*;

        match subsystem_kind {
            Cpu => self.cpu().is_some(),
        }
    }

    pub fn cpu(&self) -> &Option<cpu::Subsystem> {
        &self.cpu
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
}
