# controlgroup-rs [![Build Status](https://travis-ci.com/ordovicia/controlgroup-rs.svg?branch=master)](https://travis-ci.com/ordovicia/controlgroup-rs)

Native Rust crate for operating on cgroups.

Currently this crate supports only cgroup v1 hierarchy, implemented in `v1` module.

## Support

### Not implemented features

* CPU subsystem: Realtime thread support
* Memory subsystem: Operation on `memory.kmem.slabinfo` file

### Tested distributions

This crate is tested on

* Ubuntu 16.04 (Xenial)
* Ubuntu 18.04 (Bionic)

on Travis-CI.

### Not tested features

* Cpuset subsystem: Getting memory pressure faced by a cgroup
* Memory subsystem: Getting per-NUMA-node statistics on NUMA systems
* HugeTLB subsystem: Monitoring hugepage TLB usage by a cgroup
* BlkIO subsystem:
    * Setting weights for devices
    * Monitoring blkio throughput consumed by a cgroup
* RDMA subsystem

## Examples for v1 hierarchy

### Create a cgroup controlled by the CPU subsystem

```rust
use std::path::PathBuf;
use controlgroup::{Pid, v1::{cpu, Cgroup, CgroupPath, SubsystemKind, Resources}};

// Define and create a new cgroup controlled by the CPU subsystem.
let mut cgroup = cpu::Subsystem::new(
    CgroupPath::new(SubsystemKind::Cpu, PathBuf::from("students/charlie")));
cgroup.create()?;

// Attach the self process to the cgroup.
let pid = Pid::from(std::process::id());
cgroup.add_task(pid)?;

// Define resource limits and constraints for this cgroup.
// Here we just use the default for an example.
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

// Note that subsystem handlers does not implement `Drop` and therefore when the
// handler is dropped, the cgroup will stay around.
```

### Create a set of cgroups controlled by multiple subsystems

`v1::Builder` provides a way to configure cgroups in the builder pattern.

```rust
use std::path::PathBuf;
use controlgroup::{Max, v1::{devices, hugetlb, net_cls, rdma, Builder, SubsystemKind}};

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
    .hugetlb()
        .limit_2mb(hugetlb::Limit::Pages(4))
        .limit_1gb(hugetlb::Limit::Pages(2))
        .done()
    .devices()
        .deny(vec!["a *:* rwm".parse::<devices::Access>().unwrap()])
        .allow(vec!["c 1:3 mr".parse::<devices::Access>().unwrap()])
        .done()
    .blkio()
        .weight(1000)
        .weight_device([([8, 0].into(), 100)].iter().copied())
        .read_bps_device([([8, 0].into(), 10 * (1 << 20))].iter().copied())
        .write_iops_device([([8, 0].into(), 100)].iter().copied())
        .done()
    .rdma()
        .max(
            [(
                "mlx4_0".to_string(),
                rdma::Limit {
                    hca_handle: 2.into(),
                    hca_object: Max::Max,
                },
            )].iter().cloned(),
        )
        .done()
    .net_prio()
        .ifpriomap(
            [("lo".to_string(), 0), ("wlp1s0".to_string(), 1)].iter().cloned(),
        )
        .done()
    .net_cls()
        .classid([0x10, 0x1].into())
        .done()
    .pids()
        .max(42.into())
        .done()
    .freezer()
        // Tasks in this cgroup will be frozen.
        .freeze()
        .done()
    // Enable CPU accounting for this cgroup.
    // Cpuacct subsystem has no parameter, so this method does not return a subsystem builder,
    // just enables the accounting.
    .cpuacct()
    // Enable monitoring this cgroup via `perf` tool.
    // Like `cpuacct()` method, this method does not return a subsystem builder.
    .perf_event()
    // Skip creating directories for Cpuacct subsystem and net_cls subsystem.
    // This is useful when some subsystems share hierarchy with others.
    .skip_create(vec![SubsystemKind::Cpuacct, SubsystemKind::NetCls])
    // Actually build cgroups with the configuration.
    .build()?;

let pid = std::process::id().into();
cgroups.add_task(pid)?;

// Do something ...

cgroups.remove_task(pid)?;
cgroups.delete()?;
```

## MSRV (Minimum Supported Rust Version)

```
rustc 1.37.0 (eae3437df 2019-08-13)
```

If you want to use this crate with older Rust, please leave a comment on [issue #1].

[issue #1]: https://github.com/ordovicia/controlgroup-rs/issues/1

## Disclaimer

This project was started as a fork of [levex/cgroups-rs], and developed by
redesigning and reimplementing the whole project.

[levex/cgroups-rs] was licensed under MIT OR Apache-2.0.

See [LICENSE](LICENSE) for detail.

[levex/cgroups-rs]: https://github.com/levex/cgroups-rs

## License

Copyright 2019 Hidehito Yabuuchi \<hdht.ybuc@gmail.com\>

Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>, or the Apache
License, Version 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> at your option.
All files in the project carrying such notice may not be copied, modified, or distributed except
according to those terms.


Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
