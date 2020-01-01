use std::{fs, os::unix::process::CommandExt as _};

use crate::v1::{Cgroup, UnifiedRepr};

/// Extension to the [`std::process::Command`] builder for attaching a command process to one or
/// more cgroups on start.
///
/// [`std::process::Command`]: https://doc.rust-lang.org/std/process/struct.Command.html
pub trait CommandExt {
    /// Attaches a command process to a cgroup on start.
    fn cgroup<C: Cgroup>(&mut self, cgroup: &mut C) -> &mut Self;

    /// Attaches a command process to each subsystem supported by a [`UnifiedRepr`] on start.
    ///
    /// [`UnifiedRepr`]: struct.UnifiedRepr.html
    fn cgroups_unified_repr(&mut self, cgroups: &mut UnifiedRepr) -> &mut Self;
}

impl CommandExt for std::process::Command {
    // NOTE: Keep the example below in sync with `README.md` and `lib.rs`

    /// Attaches this command process to a cgroup on start.
    ///
    /// The process will run within the cgroup from the beginning of its execution.
    ///
    /// Multiple cgroups can be registered for the process attachment. The process will be attached
    /// to the cgroups in order of their registration.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> controlgroup::Result<()> {
    /// use std::path::PathBuf;
    /// use controlgroup::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
    /// // Import extension trait
    /// use controlgroup::v1::CommandExt as _;
    ///
    /// let mut cgroup = cpu::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
    /// cgroup.create()?;
    ///
    /// let mut child = std::process::Command::new("sleep")
    ///     .arg("1")
    ///     // Attach this command process to a cgroup on start
    ///     .cgroup(&mut cgroup)
    ///     // This process will run within the cgroup
    ///     .spawn()
    ///     .unwrap();
    ///
    /// println!("{:?}", cgroup.stat()?);
    ///
    /// child.wait().unwrap();
    /// cgroup.delete()?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn cgroup<C: Cgroup>(&mut self, cgroup: &mut C) -> &mut Self {
        let path = cgroup.path().join(subsys_file!(cgroup, procs));
        unsafe { self.pre_exec(move || fs::write(&path, std::process::id().to_string())) }
    }

    /// Attaches this command process to each subsystem supported by a [`UnifiedRepr`] on start.
    ///
    /// See [`cgroup`] for more information.
    ///
    /// [`UnifiedRepr`]: struct.UnifiedRepr.html
    /// [`cgroup`]: #method.cgroup
    fn cgroups_unified_repr(&mut self, cgroups: &mut UnifiedRepr) -> &mut Self {
        macro_rules! a {
            ( $($subsystem: ident),* $(, )? ) => { $(
                if let Some(subsys) = cgroups.$subsystem() {
                    self.cgroup(subsys);
                }
            )* };
        }

        a! {
            cpu_mut,
            cpuset_mut,
            cpuacct_mut,
            memory_mut,
            hugetlb_mut,
            devices_mut,
            blkio_mut,
            rdma_mut,
            net_prio_mut,
            net_cls_mut,
            pids_mut,
            freezer_mut,
            perf_event_mut,
        }

        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        v1::{cpu, CgroupPath, SubsystemKind},
        Pid, Result,
    };

    #[test]
    fn test_command_ext_cgroup() -> Result<()> {
        let mut cgroup =
            cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, gen_cgroup_name!()));
        cgroup.create()?;

        let mut child = std::process::Command::new("sleep")
            .arg("1")
            .cgroup(&mut cgroup)
            .spawn()
            .unwrap();

        let pid = child.id();
        assert_eq!(cgroup.procs().unwrap(), vec![Pid::from(pid)]);

        child.wait()?;
        cgroup.delete()
    }

    #[test]
    fn test_command_ext_unified() -> Result<()> {
        use crate::v1::cpuset;

        let mut cgroups = UnifiedRepr::new(gen_cgroup_name!());
        cgroups.skip_create(&[SubsystemKind::Cpuacct, SubsystemKind::NetCls]);
        cgroups.create()?;

        cgroups.cpuset_mut().unwrap().apply({
            let id_set = [0].iter().copied().collect::<cpuset::IdSet>();
            &cpuset::Resources {
                cpus: Some(id_set.clone()),
                mems: Some(id_set.clone()),
                ..cpuset::Resources::default()
            }
            .into()
        })?;

        let mut child = std::process::Command::new("sleep")
            .arg("1")
            .cgroups_unified_repr(&mut cgroups)
            .spawn()
            .unwrap();

        let pid = Pid::from(child.id());
        assert_eq!(
            cgroups.procs().unwrap(),
            hashmap! {
                (SubsystemKind::BlkIo, vec![pid]),
                (SubsystemKind::Cpu, vec![pid]),
                (SubsystemKind::Cpuacct, vec![pid]),
                (SubsystemKind::Cpuset, vec![pid]),
                (SubsystemKind::Devices, vec![pid]),
                (SubsystemKind::Freezer, vec![pid]),
                (SubsystemKind::HugeTlb, vec![pid]),
                (SubsystemKind::Memory, vec![pid]),
                (SubsystemKind::NetCls, vec![pid]),
                (SubsystemKind::NetPrio, vec![pid]),
                (SubsystemKind::PerfEvent, vec![pid]),
                (SubsystemKind::Pids, vec![pid]),
                (SubsystemKind::Rdma, vec![pid]),
            }
        );

        child.wait()?;
        cgroups.delete()
    }
}
