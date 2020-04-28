#![cfg(target_os = "linux")]
#![warn(
    future_incompatible,
    missing_docs,
    missing_debug_implementations,
    nonstandard_style,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused
)]
// Clippy's suggestion causes many compile error
#![allow(clippy::string_lit_as_bytes)]
#![doc(html_root_url = "https://docs.rs/controlgroup/0.3.0")]

//! Native Rust crate for cgroup operations.
//!
//! Currently this crate supports only cgroup v1 hierarchy, implemented in [`v1`] module.
//!
//! ## Examples for v1 hierarchy
//!
//! ### Create a cgroup controlled by the CPU subsystem
//!
//! ```no_run
//! # fn main() -> controlgroup::Result<()> {
//! use std::path::PathBuf;
//! use controlgroup::{Pid, v1::{cpu, Cgroup, CgroupPath, SubsystemKind, Resources}};
//!
//! // Define and create a new cgroup controlled by the CPU subsystem.
//! let mut cgroup = cpu::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
//! cgroup.create()?;
//!
//! // Attach the self process to the cgroup.
//! let pid = Pid::from(std::process::id());
//! cgroup.add_task(pid)?;
//!
//! // Define resource limits and constraints for this cgroup.
//! // Here we just use the default for an example.
//! let resources = Resources::default();
//!
//! // Apply the resource limits.
//! cgroup.apply(&resources)?;
//!
//! // Low-level file operations are also supported.
//! let stat_file = cgroup.open_file_read("cpu.stat")?;
//!
//! // Do something ...
//!
//! // Now, remove self process from the cgroup.
//! cgroup.remove_task(pid)?;
//!
//! // ... and delete the cgroup.
//! cgroup.delete()?;
//!
//! // Note that subsystem handlers does not implement `Drop` and therefore when the
//! // handler is dropped, the cgroup will stay around.
//! # Ok(())
//! # }
//! ```
//!
//! ### Create a set of cgroups controlled by multiple subsystems
//!
//! [`v1::Builder`] provides a way to configure cgroups in the builder pattern.
//!
//! ```no_run
//! # fn main() -> controlgroup::Result<()> {
//! use std::path::PathBuf;
//! use controlgroup::{
//!     Max,
//!     v1::{devices, hugetlb::{self, HugepageSize}, net_cls, rdma, Builder, SubsystemKind},
//! };
//!
//! let mut cgroups =
//!     // Start building a (set of) cgroup(s).
//!     Builder::new(PathBuf::from("students/charlie"))
//!     // Start configuring the CPU resource limits.
//!     .cpu()
//!         .shares(1000)
//!         .cfs_quota_us(500 * 1000)
//!         .cfs_period_us(1000 * 1000)
//!         // Finish configuring the CPU resource limits.
//!         .done()
//!     // Start configuring the cpuset resource limits.
//!     .cpuset()
//!         .cpus([0].iter().copied().collect())
//!         .mems([0].iter().copied().collect())
//!         .memory_migrate(true)
//!         .done()
//!     .memory()
//!         .limit_in_bytes(4 * (1 << 30))
//!         .soft_limit_in_bytes(3 * (1 << 30))
//!         .use_hierarchy(true)
//!         .done()
//!     .hugetlb()
//!         .limits(
//!             [
//!                 (HugepageSize::Mb2, hugetlb::Limit::Pages(4)),
//!                 (HugepageSize::Gb1, hugetlb::Limit::Pages(2)),
//!             ].iter().copied()
//!         )
//!         .done()
//!     .devices()
//!         .deny(vec!["a *:* rwm".parse::<devices::Access>().unwrap()])
//!         .allow(vec!["c 1:3 mr".parse::<devices::Access>().unwrap()])
//!         .done()
//!     .blkio()
//!         .weight(1000)
//!         .weight_device([([8, 0].into(), 100)].iter().copied())
//!         .read_bps_device([([8, 0].into(), 10 * (1 << 20))].iter().copied())
//!         .write_iops_device([([8, 0].into(), 100)].iter().copied())
//!         .done()
//!     .rdma()
//!         .max(
//!             [(
//!                 "mlx4_0".to_string(),
//!                 rdma::Limit {
//!                     hca_handle: 2.into(),
//!                     hca_object: Max::Max,
//!                 },
//!             )].iter().cloned(),
//!         )
//!         .done()
//!     .net_prio()
//!         .ifpriomap(
//!             [("lo".to_string(), 0), ("wlp1s0".to_string(), 1)].iter().cloned(),
//!         )
//!         .done()
//!     .net_cls()
//!         .classid([0x10, 0x1].into())
//!         .done()
//!     .pids()
//!         .max(42.into())
//!         .done()
//!     .freezer()
//!         // Tasks in this cgroup will be frozen.
//!         .freeze()
//!         .done()
//!     // Enable CPU accounting for this cgroup.
//!     // Cpuacct subsystem has no parameter, so this method does not return a subsystem builder,
//!     // just enables the accounting.
//!     .cpuacct()
//!     // Enable monitoring this cgroup via `perf` tool.
//!     // Like `cpuacct()` method, this method does not return a subsystem builder.
//!     .perf_event()
//!     // Skip creating directories for Cpuacct subsystem and net_cls subsystem.
//!     // This is useful when some subsystems share hierarchy with others.
//!     .skip_create(vec![SubsystemKind::Cpuacct, SubsystemKind::NetCls])
//!     // Actually build cgroups with the configuration.
//!     .build()?;
//!
//! let pid = std::process::id().into();
//! cgroups.add_task(pid)?;
//!
//! // Do something ...
//!
//! cgroups.remove_task(pid)?;
//! cgroups.delete()?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Spawn a process within one or more cgroups
//!
//! [`v1::CommandExt`] extends the [`std::process::Command`] builder to attach a command process to
//! one or more cgroups on start.
//!
//! ```no_run
//! # fn main() -> controlgroup::Result<()> {
//! use std::path::PathBuf;
//! use controlgroup::v1::{cpu, Cgroup, CgroupPath, SubsystemKind};
//! // Import extension trait
//! use controlgroup::v1::CommandExt as _;
//!
//! let mut cgroup = cpu::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
//! cgroup.create()?;
//!
//! let mut child = std::process::Command::new("sleep")
//!     .arg("1")
//!     // Attach this command process to a cgroup on start
//!     .cgroup(&mut cgroup)
//!     // This process will run within the cgroup
//!     .spawn()
//!     .unwrap();
//!
//! println!("{:?}", cgroup.stat()?);
//!
//! child.wait().unwrap();
//! cgroup.delete()?;
//! # Ok(())
//! # }
//! ```
//!
//! [`v1`]: v1/index.html
//! [`v1::Builder`]: v1/builder/struct.Builder.html
//! [`v1::CommandExt`]: v1/trait.CommandExt.html
//! [`std::process::Command`]: https://doc.rust-lang.org/std/process/struct.Command.html

#[macro_use]
mod macros;
mod error;
mod parse;
mod types;
pub mod v1;

pub use error::{Error, ErrorKind, Result};
pub use types::{Device, DeviceNumber, Max, Pid, RefKv};

// Consume CPU time on the all logical cores until a condition holds. Panics if the condition does
// not hold in the given timeout.
//
// FIXME: consume system time
#[cfg(test)]
pub(crate) fn consume_cpu_until(condition: impl Fn() -> bool, timeout_sec: u64) {
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread, time,
    };

    let finished = Arc::new(AtomicBool::new(false));

    let handlers = (0..(num_cpus::get() - 1))
        .map(|_| {
            let fin = finished.clone();
            thread::spawn(move || {
                while !fin.load(Ordering::Relaxed) {
                    // spin
                }
            })
        })
        .collect::<Vec<_>>();

    let start = time::Instant::now();
    while start.elapsed() < time::Duration::from_secs(timeout_sec) {
        if condition() {
            finished.store(true, Ordering::Relaxed);
            for handler in handlers {
                handler.join().expect("Failed to join a thread");
            }

            return;
        }

        // spin
    }

    panic!("consume_cpu_until timeout")
}
