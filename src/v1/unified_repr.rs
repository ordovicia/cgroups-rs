use std::{collections::HashMap, path::PathBuf};

use crate::{
    v1::{self, Cgroup, CgroupPath, SubsystemKind},
    Pid, Result,
};

macro_rules! gen_unified_repr {
    ( $( ($subsystem: ident, $subsystem_mut: ident, $kind: ident, $name: literal) ),* ) => {

use crate::v1::{$($subsystem),*};

/// Unified representation of a set of cgroups sharing a same name.
///
/// In cgroup v1, a system has multiple directory hierarchies for different sets of subsystems
/// (typically one subsystem). Each cgroup belongs to a hierarchy, and subsystems attached to that
/// hierarchy cotrol the resource of that cgroup.
///
/// In cgroup v2 (not yet fully implemented in the Linux kernel), on the other hand, a system has
/// only a single unified hierarchy, and subsystems are differently enabled for each cgroup. This
/// design is suitable for cases such as containers, where each cgroup should be controlled by
/// multiple subsystems simultaneously.
///
/// `UnifiedRepr` provides an access to a set of cgroups in the v1 hierarchies as if it is in the v2
/// hierarchy. A unified representation of a set of cgroups appears to have multiple subsystems,
/// and the set is controlled by the subsystems simultaneously by calling a single method.
///
/// For more information about cgroup v2, see the kernel's documentation
/// [Documentation/cgroup-v2.txt](https://www.kernel.org/doc/Documentation/cgroup-v2.txt).
///
/// # Examples
///
/// ```no_run
/// # fn main() -> cgroups::Result<()> {
/// use std::path::PathBuf;
/// use cgroups::{Pid, v1::{Resources, UnifiedRepr}};
///
/// let pid = Pid::from(std::process::id());
///
/// // Define and create a new unified representation of a set of cgroup.
/// let mut cgroups = UnifiedRepr::new(PathBuf::from("my_cgroups"));
/// cgroups.create()?;
///
/// // Attach the self process to the cgroup set.
/// cgroups.add_task(pid)?;
///
/// // Define resource limits and constraints for this cgroup set.
/// // Here we just use the default for an example.
/// let resources = Resources::default();
///
/// // Apply the resource limits.
/// cgroups.apply(&resources, true)?;
///
/// // Do something ...
///
/// // Now, remove self from the cgroup set.
/// cgroups.remove_task(pid)?;
///
/// // And delete the cgroup set.
/// cgroups.delete()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct UnifiedRepr {
    $($subsystem: Option<$subsystem::Subsystem>),*
}

impl UnifiedRepr {
    /// Creates a new unified representation of a set of cgroups with all subsystems available in
    /// this crate.
    ///
    /// See [`SubsystemKind`](enum.SubsystemKind.html) for the available subsystems.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use cgroups::v1::UnifiedRepr;
    ///
    /// let cgroups = UnifiedRepr::new(PathBuf::from("students/charlie"));
    /// ```
    pub fn new(name: PathBuf) -> Self {
        Self::with_subsystems(name, &[$(SubsystemKind::$kind),*])
    }

    /// Creates a new unified representation of a set of cgroups with the given subsystem kinds.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use cgroups::v1::{SubsystemKind, UnifiedRepr};
    ///
    /// let cgroups = UnifiedRepr::with_subsystems(
    ///     PathBuf::from("students/charlie"), &[SubsystemKind::Cpu]);
    /// ```
    pub fn with_subsystems(name: PathBuf, subsystem_kinds: &[SubsystemKind]) -> Self {
        $( let mut $subsystem = None; )*
        for kind in subsystem_kinds {
            let path = CgroupPath::new(*kind, name.clone());
            match kind {
                $( SubsystemKind::$kind => { $subsystem = Some($subsystem::Subsystem::new(path)); } )*
            }
        }

        Self { $($subsystem),* }
    }

    /// Returns whether a subsystem is supported by this unified representation, i.e. included in
    /// this set of cgroups.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use cgroups::v1::{SubsystemKind, UnifiedRepr};
    ///
    /// let name = PathBuf::from("students/charlie");
    /// let cgroups = UnifiedRepr::with_subsystems(name, &[SubsystemKind::Cpu]);
    /// assert!(cgroups.supports(SubsystemKind::Cpu));
    /// assert!(!cgroups.supports(SubsystemKind::Cpuset));
    /// ```
    pub fn supports(&self, subsystem_kind: SubsystemKind) -> bool {
        match subsystem_kind {
            $(SubsystemKind::$kind => self.$subsystem.is_some()),*
        }
    }

    $(
        with_doc!(
            concat!("Returns a reference to the ", $name, " subsystem."),
            pub fn $subsystem(&self) -> Option<&$subsystem::Subsystem> {
                self.$subsystem.as_ref()
            }
        );

        with_doc!(
            concat!("Returns a mutable reference to the ", $name, " subsystem."),
            pub fn $subsystem_mut(&mut self) -> Option<&mut $subsystem::Subsystem> {
                self.$subsystem.as_mut()
            }
        );
    )*

    /// Creates new directories for each cgroup of the all supported subsystems.
    ///
    /// See [`Cgroup::create()`](trait.Cgroup.html#method.create) for more information.
    pub fn create(&mut self) -> Result<()> {
        $(
            if let Some(ref mut s) = self.$subsystem {
                s.create()?;
            }
        )*
        Ok(())
    }

    /// Applies resource limits and constraints to each cgroup of the all supported subsystems.
    ///
    /// See [`Cgroup::apply()`](trait.Cgroup.html#method.apply) for more information.
    pub fn apply(&mut self, resources: &v1::Resources, validate: bool) -> Result<()> {
        $(
            if let Some(ref mut s) = self.$subsystem {
                s.apply(&resources, validate)?;
            }
        )*
        Ok(())
    }

    /// Deletes directories for each cgroup of the all supported subsystems.
    ///
    /// See [`Cgroup::delete()`](trait.Cgroup.html#method.delete) for more information.
    pub fn delete(&mut self) -> Result<()> {
        $(
            if let Some(ref mut s) = self.$subsystem {
                s.delete()?;
            }
        )*
        Ok(())
    }

    /// Gets a list of tasks attached to each cgroup of the all supported subsystems.
    ///
    /// See [`Cgroup::tasks()`](trait.Cgroup.html#method.tasks) for more information.
    pub fn tasks(&self) -> Result<HashMap<SubsystemKind, Vec<Pid>>> {
        let mut tasks = HashMap::new();
        $(
            if let Some(ref s) = self.$subsystem {
                tasks.insert(SubsystemKind::$kind, s.tasks()?);
            }
        )*
        Ok(tasks)
    }

    /// Attaches a task to each cgroup of the all supported subsystems.
    ///
    /// See [`Cgroup::add_task()`](trait.Cgroup.html#method.add_task) for more information.
    pub fn add_task(&mut self, pid: Pid) -> Result<()> {
        $(
            if let Some(ref mut s) = self.$subsystem {
                s.add_task(pid)?;
            }
        )*
        Ok(())
    }

    /// Removes a task from each cgroup of the all supported subsystems.
    ///
    /// See [`Cgroup::remove_task()`](trait.Cgroup.html#method.remove_task) for more information.
    pub fn remove_task(&mut self, pid: Pid) -> Result<()> {
        $(
            if let Some(ref mut s) = self.$subsystem {
                s.remove_task(pid)?;
            }
        )*
        Ok(())
    }

    /// Gets a list of processes attached to each cgroup of the all supported subsystems.
    ///
    /// See [`Cgroup::procs()`](trait.Cgroup.html#method.tasks) for more information.
    pub fn procs(&self) -> Result<HashMap<SubsystemKind, Vec<Pid>>> {
        let mut procs = HashMap::new();
        $(
            if let Some(ref s) = self.$subsystem {
                procs.insert(SubsystemKind::$kind, s.procs()?);
            }
        )*
        Ok(procs)
    }

    /// Attaches a process to each cgroup of the all supported subsystems.
    ///
    /// See [`Cgroup::add_proc()`](trait.Cgroup.html#method.add_proc) for more information.
    pub fn add_proc(&mut self, pid: Pid) -> Result<()> {
        $(
            if let Some(ref mut s) = self.$subsystem {
                s.add_proc(pid)?;
            }
        )*
        Ok(())
    }

    /// Removes a process from each cgroup of the all supported subsystems.
    ///
    /// See [`Cgroup::remove_proc()`](trait.Cgroup.html#method.remove_proc) for more information.
    pub fn remove_proc(&mut self, pid: Pid) -> Result<()> {
        $(
            if let Some(ref mut s) = self.$subsystem {
                s.remove_proc(pid)?;
            }
        )*
        Ok(())
    }
}

    };
}

gen_unified_repr! {
    (cpu, cpu_mut, Cpu, "CPU"),
    (cpuset, cpuset_mut, Cpuset, "cpuset"),
    (cpuacct, cpuacct_mut, Cpuacct, "cpuacct"),
    (pids, pids_mut, Pids, "pids"),
    (freezer, freezer_mut, Freezer, "freezer"),
    (perf_event, perf_event_mut, PerfEvent, "perf_event")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_repr_subsystems() {
        let cgroups = UnifiedRepr::new(PathBuf::from(gen_cgroup_name!()));

        assert!(cgroups.supports(SubsystemKind::Cpu));
        assert!(cgroups.cpu().is_some());

        assert!(cgroups.supports(SubsystemKind::Cpuset));
        assert!(cgroups.cpuset().is_some());

        let cgroups = UnifiedRepr::with_subsystems(PathBuf::from(gen_cgroup_name!()), &[]);

        assert!(!cgroups.supports(SubsystemKind::Cpu));
        assert!(cgroups.cpu().is_none());

        assert!(!cgroups.supports(SubsystemKind::Cpuset));
        assert!(cgroups.cpuset().is_none());

        let cgroups =
            UnifiedRepr::with_subsystems(PathBuf::from(gen_cgroup_name!()), &[SubsystemKind::Cpu]);
        assert!(cgroups.supports(SubsystemKind::Cpu));
        assert!(cgroups.cpu().is_some());

        assert!(!cgroups.supports(SubsystemKind::Cpuset));
        assert!(cgroups.cpuset().is_none());
    }

    #[test]
    #[ignore] // `cargo test` must not be executed in parallel for this test
    fn test_unified_repr_add_get_remove_tasks() -> Result<()> {
        let mut cgroups =
            UnifiedRepr::with_subsystems(PathBuf::from(gen_cgroup_name!()), &[SubsystemKind::Cpu]);
        cgroups.create()?;

        let pid = Pid::from(std::process::id());

        // Add self to the cgroup
        cgroups.add_task(pid)?;
        // Verify that self is indeed in the cgroup
        assert_eq!(cgroups.cpu().unwrap().tasks()?, vec![pid]);
        assert_eq!(
            cgroups.tasks()?,
            [(SubsystemKind::Cpu, vec![pid])]
                .iter()
                .cloned()
                .collect::<HashMap<_, _>>()
        );

        // Now, try removing self
        cgroups.remove_task(pid)?;
        // Verify that it was indeed removed
        assert!(cgroups.cpu().unwrap().tasks()?.is_empty());
        assert!(cgroups.tasks()?[&SubsystemKind::Cpu].is_empty());

        cgroups.delete()
    }

    #[test]
    fn test_unified_repr_add_get_remove_procs() -> Result<()> {
        let mut cgroups =
            UnifiedRepr::with_subsystems(PathBuf::from(gen_cgroup_name!()), &[SubsystemKind::Cpu]);
        cgroups.create()?;

        let pid = Pid::from(std::process::id());

        cgroups.add_proc(pid)?;
        assert_eq!(cgroups.cpu().unwrap().procs()?, vec![pid]);
        assert_eq!(
            cgroups.procs()?,
            [(SubsystemKind::Cpu, vec![pid])]
                .iter()
                .cloned()
                .collect::<HashMap<_, _>>()
        );

        cgroups.remove_proc(pid)?;
        assert!(cgroups.cpu().unwrap().procs()?.is_empty());
        assert!(cgroups.procs()?[&SubsystemKind::Cpu].is_empty());

        cgroups.delete()
    }
}
