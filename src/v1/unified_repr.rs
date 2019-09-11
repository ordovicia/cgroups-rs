use std::{collections::HashMap, path::PathBuf};

use crate::{
    v1::{self, Cgroup, CgroupPath, SubsystemKind},
    Pid, Result,
};

macro_rules! gen_unified_repr {
    ( $( ($subsystem: ident, $subsystem_mut: ident, $kind: ident, $name: literal) ),* $(, )? ) => {

use v1::{$( $subsystem ),*};

/// Unified representation of a set of cgroups sharing the same name.
///
/// In cgroup v1, a system has multiple directory hierarchies for different sets of subsystems
/// (typically one subsystem). Each cgroup belongs to a hierarchy, and subsystems attached to that
/// hierarchy control the resources of that cgroup.
///
/// In cgroup v2 (not yet fully implemented in the Linux kernel), on the other hand, a system has
/// only a single unified hierarchy, and subsystems are differently enabled for each cgroup. This
/// design is suitable for cases such as containers, where each cgroup should be controlled by
/// multiple subsystems simultaneously.
///
/// `UnifiedRepr` provides an access to a set of cgroups in the v1 hierarchies as if it is in the v2
/// hierarchy. A unified representation of a set of cgroups appears to have multiple subsystems,
/// and the set is controlled by the subsystems simultaneously by calling a single method of
/// `UnifiedRepr`.
///
/// For more information about cgroup v2, see the kernel's documentation
/// [Documentation/cgroup-v2.txt](https://www.kernel.org/doc/Documentation/cgroup-v2.txt).
///
/// # Examples
///
/// ```no_run
/// # fn main() -> controlgroup::Result<()> {
/// use std::path::PathBuf;
/// use controlgroup::{Pid, v1::{Resources, UnifiedRepr}};
///
/// // Define and create a new unified representation of a set of cgroups.
/// let mut cgroups = UnifiedRepr::new(PathBuf::from("students/charlie"));
/// cgroups.create()?;
///
/// // Attach the self process to the cgroup set.
/// let pid = Pid::from(std::process::id());
/// cgroups.add_task(pid)?;
///
/// // Define resource limits and constraints for this cgroup set.
/// // Here we just use the default for an example.
/// let resources = Resources::default();
///
/// // Apply the resource limits.
/// cgroups.apply(&resources)?;
///
/// // Do something ...
///
/// // Now, remove self from the cgroup set.
/// cgroups.remove_task(pid)?;
///
/// // ... and delete the cgroup set.
/// cgroups.delete()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct UnifiedRepr {
    $( $subsystem: Option<Subsys<$subsystem::Subsystem>> ),*
}

#[derive(Debug)]
struct Subsys<T> {
    subsystem: T,
    create: bool,
}

impl UnifiedRepr {
    /// Defines a new unified representation of a set of cgroups with all subsystems available in
    /// this crate.
    ///
    /// For the directory name of the each subsystem, the standard name (e.g. `SubsystemKind::Cpu`
    /// => `cpu`) are used.
    ///
    /// See [`SubsystemKind`] for the available subsystems.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use controlgroup::v1::UnifiedRepr;
    ///
    /// let cgroups = UnifiedRepr::new(PathBuf::from("students/charlie"));
    /// ```
    ///
    /// [`SubsystemKind`]: enum.SubsystemKind.html
    pub fn new(name: PathBuf) -> Self {
        Self::with_subsystems(name, &[$(SubsystemKind::$kind),*])
    }

    /// Defines a new unified representation of a set of cgroups with the given subsystem kinds.
    ///
    /// For the directory name of the each subsystem, the standard name (e.g. `SubsystemKind::Cpu`
    /// => `cpu`) are used.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use controlgroup::v1::{SubsystemKind, UnifiedRepr};
    ///
    /// let cgroups = UnifiedRepr::with_subsystems(
    ///     PathBuf::from("students/charlie"), &[SubsystemKind::Cpu]);
    /// ```
    pub fn with_subsystems(name: PathBuf, subsystems: &[SubsystemKind]) -> Self {
        Self::with_custom_name_subsystems(
            subsystems.iter().map(|k| (*k, CgroupPath::new(*k, name.clone())))
        )
    }

    /// Defines a new unified representation of a set of cgroups with the given subsystem kinds and
    /// their paths.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use controlgroup::v1::{CgroupPath, SubsystemKind, UnifiedRepr};
    ///
    /// let name = PathBuf::from("students/charlie");
    /// let cgroups = UnifiedRepr::with_custom_name_subsystems(
    ///         [
    ///             (SubsystemKind::Cpu, CgroupPath::new(SubsystemKind::Cpu, name.clone())),
    ///             (SubsystemKind::Cpuset, CgroupPath::with_subsystem_name("custom", name)),
    ///         ].iter().cloned()
    ///     );
    /// ```
    pub fn with_custom_name_subsystems(
        subsystems: impl IntoIterator<Item = (SubsystemKind, CgroupPath)>,
    ) -> Self {
        $( let mut $subsystem = None; )*
        for (kind, path) in subsystems {
            match kind {
                $(
                    SubsystemKind::$kind => {
                        $subsystem = Some(Subsys {
                            subsystem: $subsystem::Subsystem::new(path),
                            create: true,
                        });
                    }
                )*
            }
        }
        Self { $( $subsystem ),* }
    }

    /// Returns whether a subsystem is supported by this unified representation, i.e. included in
    /// this set of cgroups.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use controlgroup::v1::{SubsystemKind, UnifiedRepr};
    ///
    /// let cgroups = UnifiedRepr::with_subsystems(
    ///     PathBuf::from("students/charlie"), &[SubsystemKind::Cpu]);
    ///
    /// assert!(cgroups.supports(SubsystemKind::Cpu));
    /// assert!(!cgroups.supports(SubsystemKind::Cpuset));
    /// ```
    pub fn supports(&self, subsystem_kind: SubsystemKind) -> bool {
        match subsystem_kind {
            $(SubsystemKind::$kind => self.$subsystem.is_some()),*
        }
    }

    /// Skips creating and deleting the directories for some subsystems.
    ///
    /// This method is useful when multiple subsystems share the same hierarchy (including via
    /// symbolic links), and thus [`create`]/[`delete`] method tries to create/delete the same
    /// directory multiple times.
    ///
    /// [`create`]: #method.create
    /// [`delete`]: #method.delete
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> controlgroup::Result<()> {
    /// use std::path::PathBuf;
    /// use controlgroup::v1::{CgroupPath, SubsystemKind, UnifiedRepr};
    ///
    /// let mut cgroups = UnifiedRepr::with_subsystems(
    ///     PathBuf::from("students/charlie"), &[SubsystemKind::Cpu, SubsystemKind::Cpuset]);
    ///
    /// cgroups.skip_create(&[SubsystemKind::Cpuset]);
    ///
    /// cgroups.create()?;  // Creates only a directory for the CPU subsystem
    /// # Ok(())
    /// # }
    /// ```
    pub fn skip_create(&mut self, skip_subsystems: &[SubsystemKind]) {
        for kind in skip_subsystems {
            match kind {
                $(
                    SubsystemKind::$kind => {
                        if let Some(ref mut s) = self.$subsystem {
                            s.create = false;
                        }
                    }
                )*
            }
        }
    }

    /// Creates new directories for each cgroup of the all supported subsystems except for ones that
    /// was skipped by [`skip_create`] method.
    ///
    /// See [`Cgroup::create`] for more information.
    ///
    /// [`skip_create`]: #method.skip_create
    /// [`Cgroup::create`]: trait.Cgroup.html#method.create
    pub fn create(&mut self) -> Result<()> {
        $(
            if let Some(ref mut s) = self.$subsystem {
                if s.create {
                    s.subsystem.create()?;
                }
            }
        )*
        Ok(())
    }

    /// Applies resource limits and constraints to each cgroup of the all supported subsystems.
    pub fn apply(&mut self, resources: &v1::Resources) -> Result<()> {
        $(
            if let Some(ref mut s) = self.$subsystem {
                s.subsystem.apply(&resources)?;
            }
        )*
        Ok(())
    }

    /// Deletes directories for each cgroup of the all supported subsystems except for ones that
    /// was skipped by [`skip_create`] method.
    ///
    /// See [`Cgroup::delete`] for more information.
    ///
    /// [`skip_create`]: #method.skip_create
    /// [`Cgroup::delete`]: trait.Cgroup.html#method.delete
    pub fn delete(&mut self) -> Result<()> {
        $(
            if let Some(ref mut s) = self.$subsystem {
                if s.create {
                    s.subsystem.delete()?;
                }
            }
        )*
        Ok(())
    }

    /// Reads a list of tasks attached to each cgroup of the all supported subsystems.
    ///
    /// See [`Cgroup::tasks`] for more information.
    ///
    /// [`Cgroup::tasks`]: trait.Cgroup.html#method.tasks
    pub fn tasks(&self) -> Result<HashMap<SubsystemKind, Vec<Pid>>> {
        let mut tasks = HashMap::new();
        $(
            if let Some(ref s) = self.$subsystem {
                tasks.insert(SubsystemKind::$kind, s.subsystem.tasks()?);
            }
        )*
        Ok(tasks)
    }

    /// Attaches a task to each cgroup of the all supported subsystems.
    ///
    /// See [`Cgroup::add_task`] for more information.
    ///
    /// [`Cgroup::add_task`]: trait.Cgroup.html#method.add_task
    pub fn add_task(&mut self, pid: Pid) -> Result<()> {
        $(
            if let Some(ref mut s) = self.$subsystem {
                s.subsystem.add_task(pid)?;
            }
        )*
        Ok(())
    }

    /// Removes a task from each cgroup of the all supported subsystems.
    ///
    /// See [`Cgroup::remove_task`] for more information.
    ///
    /// [`Cgroup::remove_task`]: trait.Cgroup.html#method.remove_task
    pub fn remove_task(&mut self, pid: Pid) -> Result<()> {
        $(
            if let Some(ref mut s) = self.$subsystem {
                s.subsystem.remove_task(pid)?;
            }
        )*
        Ok(())
    }

    /// Reads a list of processes attached to each cgroup of the all supported subsystems.
    ///
    /// See [`Cgroup::procs`] for more information.
    ///
    /// [`Cgroup::procs`]: trait.Cgroup.html#method.procs
    pub fn procs(&self) -> Result<HashMap<SubsystemKind, Vec<Pid>>> {
        let mut procs = HashMap::new();
        $(
            if let Some(ref s) = self.$subsystem {
                procs.insert(SubsystemKind::$kind, s.subsystem.procs()?);
            }
        )*
        Ok(procs)
    }

    /// Attaches a process to each cgroup of the all supported subsystems.
    ///
    /// See [`Cgroup::add_proc`] for more information.
    ///
    /// [`Cgroup::add_proc`]: trait.Cgroup.html#method.add_proc
    pub fn add_proc(&mut self, pid: Pid) -> Result<()> {
        $(
            if let Some(ref mut s) = self.$subsystem {
                s.subsystem.add_proc(pid)?;
            }
        )*
        Ok(())
    }

    /// Removes a process from each cgroup of the all supported subsystems.
    ///
    /// See [`Cgroup::remove_proc`] for more information.
    ///
    /// [`Cgroup::remove_proc`]: trait.Cgroup.html#method.remove_proc
    pub fn remove_proc(&mut self, pid: Pid) -> Result<()> {
        $(
            if let Some(ref mut s) = self.$subsystem {
                s.subsystem.remove_proc(pid)?;
            }
        )*
        Ok(())
    }

    $(
        with_doc!(
            concat!("Returns a reference to the ", $name, " subsystem."),
            pub fn $subsystem(&self) -> Option<&$subsystem::Subsystem> {
                self.$subsystem.as_ref().map(|s| &s.subsystem)
            }
        );

        with_doc!(
            concat!("Returns a mutable reference to the ", $name, " subsystem."),
            pub fn $subsystem_mut(&mut self) -> Option<&mut $subsystem::Subsystem> {
                self.$subsystem.as_mut().map(|s| &mut s.subsystem)
            }
        );
    )*
}
    };
}

gen_unified_repr! {
    (cpu, cpu_mut, Cpu, "CPU"),
    (cpuset, cpuset_mut, Cpuset, "cpuset"),
    (cpuacct, cpuacct_mut, Cpuacct, "cpuacct"),
    (memory, memory_mut, Memory, "memory"),
    (hugetlb, hugetlb_mut, HugeTlb, "hugetlb"),
    (devices, devices_mut, Devices, "devices"),
    (blkio, blkio_mut, BlkIo, "blkio"),
    (rdma, rdma_mut, Rdma, "RDMA"),
    (net_prio, net_prio_mut, NetPrio, "net_prio"),
    (net_cls, net_cls_mut, NetCls, "net_cls"),
    (pids, pids_mut, Pids, "pids"),
    (freezer, freezer_mut, Freezer, "freezer"),
    (perf_event, perf_event_mut, PerfEvent, "perf_event"),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_repr_subsystems() {
        // with all subsystems
        let cgroups = UnifiedRepr::new(gen_cgroup_name!());

        assert!(cgroups.supports(SubsystemKind::Cpu));
        assert!(cgroups.cpu().is_some());

        assert!(cgroups.supports(SubsystemKind::Cpuset));
        assert!(cgroups.cpuset().is_some());

        // without any subsystems
        let cgroups = UnifiedRepr::with_subsystems(gen_cgroup_name!(), &[]);

        assert!(!cgroups.supports(SubsystemKind::Cpu));
        assert!(cgroups.cpu().is_none());

        assert!(!cgroups.supports(SubsystemKind::Cpuset));
        assert!(cgroups.cpuset().is_none());

        // with only CPU subsystem
        let cgroups = UnifiedRepr::with_subsystems(gen_cgroup_name!(), &[SubsystemKind::Cpu]);

        assert!(cgroups.supports(SubsystemKind::Cpu));
        assert!(cgroups.cpu().is_some());

        assert!(!cgroups.supports(SubsystemKind::Cpuset));
        assert!(cgroups.cpuset().is_none());
    }

    #[test]
    fn test_unified_repr_create_delete() -> Result<()> {
        {
            // with CPU and Cpuset subsystems

            let mut cgroups = UnifiedRepr::with_subsystems(
                gen_cgroup_name!(),
                &[SubsystemKind::Cpu, SubsystemKind::Cpuset],
            );
            cgroups.create()?;

            assert!(cgroups.cpu().unwrap().path().exists());
            assert!(cgroups.cpuset().unwrap().path().exists());

            cgroups.delete()?;

            assert!(!cgroups.cpu().unwrap().path().exists());
            assert!(!cgroups.cpuset().unwrap().path().exists());
        }

        {
            // without any subsystems

            let name = gen_cgroup_name!();
            let mut cgroups = UnifiedRepr::with_subsystems(name.clone(), &[]);
            cgroups.create()?;

            let cpu = cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, name.clone()));
            assert!(!cpu.path().exists());

            let cpuset = cpuset::Subsystem::new(CgroupPath::new(SubsystemKind::Cpuset, name));
            assert!(!cpuset.path().exists());

            cgroups.delete()?;
        }

        {
            // with only CPU subsystem

            let name = gen_cgroup_name!();
            let mut cgroups = UnifiedRepr::with_subsystems(name.clone(), &[SubsystemKind::Cpu]);
            cgroups.create()?;

            let cpu = cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, name.clone()));
            assert!(cpu.path().exists());

            let cpuset = cpuset::Subsystem::new(CgroupPath::new(SubsystemKind::Cpuset, name));
            assert!(!cpuset.path().exists());

            cgroups.delete()?;

            assert!(!cpu.path().exists());
            assert!(!cpuset.path().exists());
        }

        Ok(())
    }

    #[test]
    fn test_unified_repr_skip_create() -> Result<()> {
        let mut cgroups = UnifiedRepr::with_subsystems(
            gen_cgroup_name!(),
            &[SubsystemKind::Cpu, SubsystemKind::Cpuset],
        );

        cgroups.skip_create(&[SubsystemKind::Cpuset]);
        cgroups.create()?;

        assert!(cgroups.cpu().unwrap().path().exists());
        assert!(!cgroups.cpuset().unwrap().path().exists());

        cgroups.delete()?;

        assert!(!cgroups.cpu().unwrap().path().exists());
        assert!(!cgroups.cpuset().unwrap().path().exists());

        Ok(())
    }

    #[test]
    #[ignore] // must not be executed in parallel
    fn test_unified_repr_add_get_remove_tasks() -> Result<()> {
        let mut cgroups = UnifiedRepr::with_subsystems(gen_cgroup_name!(), &[SubsystemKind::Cpu]);
        cgroups.create()?;

        let pid = Pid::from(std::process::id());

        cgroups.add_task(pid)?;
        assert_eq!(cgroups.cpu().unwrap().tasks()?, vec![pid]);
        assert_eq!(
            cgroups.tasks()?,
            hashmap! { (SubsystemKind::Cpu, vec![pid]) }
        );

        cgroups.remove_task(pid)?;
        assert!(cgroups.cpu().unwrap().tasks()?.is_empty());
        assert!(cgroups.tasks()?[&SubsystemKind::Cpu].is_empty());

        cgroups.delete()
    }

    #[test]
    #[ignore] // must not be executed in parallel
    fn test_unified_repr_add_get_remove_procs() -> Result<()> {
        use std::process::{self, Command};

        let mut cgroups = UnifiedRepr::with_subsystems(gen_cgroup_name!(), &[SubsystemKind::Cpu]);
        cgroups.create()?;

        let pid = Pid::from(process::id());

        cgroups.add_proc(pid)?;
        assert_eq!(cgroups.cpu().unwrap().procs()?, vec![pid]);
        assert_eq!(
            cgroups.procs()?,
            hashmap! { (SubsystemKind::Cpu, vec![pid]) }
        );

        // automatically added to the cgroup
        let mut child = Command::new("sleep").arg("1").spawn().unwrap();
        let child_pid = Pid::from(&child);
        assert!(
            cgroups.cpu().unwrap().procs()? == vec![pid, child_pid]
                || cgroups.cpu().unwrap().procs()? == vec![child_pid, pid]
        );
        assert!(
            cgroups.procs()? == hashmap! { (SubsystemKind::Cpu, vec![pid, child_pid]) }
                || cgroups.procs()? == hashmap! { (SubsystemKind::Cpu, vec![child_pid, pid]) }
        );

        child.wait()?;
        assert!(cgroups.cpu().unwrap().procs()? == vec![pid]);
        assert!(cgroups.procs()? == hashmap! { (SubsystemKind::Cpu, vec![pid]) });

        cgroups.remove_proc(pid)?;
        assert!(cgroups.cpu().unwrap().procs()?.is_empty());
        assert!(cgroups.procs()?[&SubsystemKind::Cpu].is_empty());

        cgroups.delete()
    }

    #[test]
    fn test_unified_repr_apply() -> Result<()> {
        #![allow(clippy::identity_op)]

        const GB: u64 = 1 << 30;

        let mut cgroups = UnifiedRepr::new(gen_cgroup_name!());
        cgroups.skip_create(&[SubsystemKind::Cpuacct, SubsystemKind::NetCls]);
        cgroups.create()?;

        let id_set = [0].iter().copied().collect::<cpuset::IdSet>();
        let class_id = [0x10, 0x1].into();
        let pids_max = crate::Max::Limit(42);

        let mut resources = v1::Resources::default();
        resources.cpu.shares = Some(1000);
        resources.cpuset.cpus = Some(id_set.clone());
        resources.memory.limit_in_bytes = Some(1 * GB as i64);
        resources.hugetlb.limit_2mb = Some(hugetlb::Limit::Pages(1));
        resources.devices.deny = vec!["a".parse::<devices::Access>().unwrap()];
        resources.blkio.weight = Some(1000);
        // resources.rdma.max =
        resources.net_prio.ifpriomap = hashmap! { ("lo".to_string(), 1)};
        resources.net_cls.classid = Some(class_id);
        resources.pids.max = Some(pids_max);
        resources.freezer.state = Some(freezer::State::Frozen);

        cgroups.apply(&resources)?;

        assert_eq!(cgroups.cpu().unwrap().shares()?, 1000);
        assert_eq!(cgroups.cpuset().unwrap().cpus()?, id_set);
        assert_eq!(cgroups.memory().unwrap().limit_in_bytes()?, 1 * GB);
        assert_eq!(
            cgroups
                .hugetlb()
                .unwrap()
                .limit_in_pages(hugetlb::HugepageSize::Mb2)?,
            1
        );
        assert!(cgroups.devices().unwrap().list()?.is_empty());
        assert_eq!(cgroups.blkio().unwrap().weight()?, 1000);
        assert_eq!(cgroups.net_prio().unwrap().ifpriomap()?["lo"], 1);
        assert_eq!(cgroups.net_cls().unwrap().classid()?, class_id);
        assert_eq!(cgroups.pids().unwrap().max()?, pids_max);
        assert_eq!(cgroups.freezer().unwrap().state()?, freezer::State::Frozen);

        cgroups.delete()
    }
}
