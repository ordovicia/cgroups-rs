# cgroups-rs ![Build](https://travis-ci.org/levex/cgroups-rs.svg?branch=master)

Native Rust library for operating on cgroups.

Currently this crate supports only cgroup v1 hierarchy, implementes in `v1` module.

## Examples

### Create a cgroup controlled by the CPU subsystem

```rust
use std::path::PathBuf;
use cgroups::{Pid, v1::{cpu, Cgroup, CgroupPath, SubsystemKind, Resources}};

// Define and create a new cgroup controlled by the CPU subsystem.
let name = PathBuf::from("my_cgroup");
let mut cgroup = cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, name));
cgroup.create()?;

// Attach the self process to the cgroup.
let pid = Pid::from(std::process::id());
cgroup.add_task(pid)?;

// Define resource limits and constraints for this cgroup.
// Here we just use the default (no limits and constraints) for an example.
let resources = Resources::default();

// Apply the resource limits.
cgroup.apply(&resources, true)?;

// Low-level file operations are also supported.
let stat_file = cgroup.open_file_read("cpu.stat")?;

// do something ...

// Now, remove self process from the cgroup.
cgroup.remove_task(pid)?;

// And delete the cgroup.
cgroup.delete()?;

// Note that cgroup handlers does not implement `Drop` and therefore when the
// handler is dropped, the cgroup will stay around.
```

### Create a set of cgroups controlled by multiple subsystems

`v1::Builder` provides a way to configure cgroups in the builder pattern.

```rust
use std::path::PathBuf;
use cgroups::v1::{cpuset::IdSet, Builder};

let mut cgroups =
    // Start building a (set of) cgroup(s).
    Builder::new(PathBuf::from("students/charlie"))
    // Start configurating the CPU resource limits.
    .cpu()
        .shares(1000)
        .cfs_quota_us(500 * 1000)
        .cfs_period_us(1000 * 1000)
        // Finish configurating the CPU resource limits.
        .done()
    // Start configurating the cpuset resource limits.
    .cpuset()
        .cpus([0].iter().copied().collect::<IdSet>())
        .mems([0].iter().copied().collect::<IdSet>())
        .done()
    // Actually build cgroups with the configuration.
    // Only create a directory for the CPU subsystem.
    .build(true)?;

// Attach the self process to the cgroups.
let pid = std::process::id().into();
cgroups.add_task(pid)?;

// do something ...

// Remove self process from the cgroups.
cgroups.remove_task(pid)?;

// And delete the cgroups.
cgroups.delete()?;

// Note that cgroup handlers does not implement `Drop` and therefore when the
// handler is dropped, the cgroup will stay around.
```

## Disclaimer

This crate is licensed under:

- MIT License (see LICENSE-MIT); or
- Apache 2.0 License (see LICENSE-Apache-2.0),

at your option.

Please note that this crate is under heavy development.
We use sematic versioning; during the `0.*` phase, no guarantees are made about
backwards compatibility.

Regardless, check back often and thanks for taking a look!
