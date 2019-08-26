# cgroups-rs ![Build](https://travis-ci.org/levex/cgroups-rs.svg?branch=master)

Native Rust library for operating on cgroups.

Currently this crate supports only cgroup v1 hierarchy, implemented in `v1` module.

## Examples

### Create a cgroup controlled by the CPU subsystem

```rust
use std::path::PathBuf;
use cgroups::{Pid, Max, v1::{cpu, Cgroup, CgroupPath, SubsystemKind, Resources}};

// Define and create a new cgroup controlled by the CPU subsystem.
let name = PathBuf::from("students/charlie");
let mut cgroup = cpu::Subsystem::new(CgroupPath::new(SubsystemKind::Cpu, name));
cgroup.create()?;

// Attach the self process to the cgroup.
let pid = Pid::from(std::process::id());
cgroup.add_task(pid)?;

// Define resource limits and constraints for this cgroup.
// Here we just use the default (no limits and constraints) for an example.
let resources = Resources::default();

// Apply the resource limits.
cgroup.apply(&resources)?;

// Low-level file operations are also supported.
let stat_file = cgroup.open_file_read("cpu.stat")?;

// Do something ...

// Now, remove self process from the cgroup.
cgroup.remove_task(pid)?;

// ... and delete the cgroup.
cgroup.delete()?;

// Note that cgroup handlers does not implement `Drop` and therefore when the
// handler is dropped, the cgroup will stay around.
```

### Create a set of cgroups controlled by multiple subsystems

`v1::Builder` provides a way to configure cgroups in the builder pattern.

```rust
use std::{collections::HashMap, path::PathBuf};
use cgroups::{Device, Max, v1::{devices, hugetlb, net_cls, rdma, Builder}};

let mut cgroups =
    // Start building a (set of) cgroup(s).
    Builder::new(PathBuf::from("students/charlie"))
    // Start configuring the CPU resource limits.
    .cpu()
        .shares(1000)
        .cfs_quota_us(500 * 1000)
        .cfs_period_us(1000 * 1000)
        // Finish configuring the CPU resource limits.
        .done()
    // Start configuring the cpuset resource limits.
    .cpuset()
        .cpus([0].iter().copied().collect())
        .mems([0].iter().copied().collect())
        .memory_migrate(true)
        .done()
    .memory()
        .limit_in_bytes(4 * (1 << 30))
        .soft_limit_in_bytes(3 * (1 << 30))
        .use_hierarchy(true)
        .done()
    .pids()
        .max(Max::<u32>::Limit(42))
        .done()
    .devices()
        .deny(vec!["a *:* rwm".parse::<devices::Access>().unwrap()])
        .allow(vec!["c 1:3 mr".parse::<devices::Access>().unwrap()])
        .done()
    .hugetlb()
        .limit_2mb(hugetlb::Limit::Pages(4))
        .limit_1gb(hugetlb::Limit::Pages(2))
        .done()
    .net_cls()
        .classid(net_cls::ClassId { major: 0x10, minor: 0x1 })
        .done()
    .net_prio()
        .ifpriomap(
            [("lo".to_string(), 0), ("wlp1s0".to_string(), 1)]
                .iter()
                .cloned()
                .collect(),
        )
        .done()
    .blkio()
        .weight(1000)
        .weight_device([([8, 0].into(), 100)].iter().copied().collect())
        .read_bps_device([([8, 0].into(), 10 * (1 << 20))].iter().copied().collect())
        .write_iops_device([([8, 0].into(), 100)].iter().copied().collect())
        .done()
    .rdma()
        .max(
            [(
                "mlx4_0".to_string(),
                rdma::Limit {
                    hca_handle: Max::<u32>::Limit(2),
                    hca_object: Max::<u32>::Max,
                },
            )]
                .iter()
                .cloned()
                .collect(),
        )
        .done()
    // Enable monitoring this cgroup via `perf` tool.
    .perf_event()
        // perf_event subsystem has no parameter, so this method does not
        // return a subsystem builder, just enables the monitoring.
    // Actually build cgroups with the configuration.
    .build()?;

let pid = std::process::id().into();
cgroups.add_task(pid)?;

// Do something ...

cgroups.remove_task(pid)?;
cgroups.delete()?;
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
