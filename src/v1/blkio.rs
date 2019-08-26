//! Operations on a blkio subsystem.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/blkio-controller.txt](https://www.kernel.org/doc/Documentation/cgroup-v1/blkio-controller.txt).
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> cgroups::Result<()> {
//! use std::path::PathBuf;
//! use cgroups::{Device, Pid, v1::{self, blkio, Cgroup, CgroupPath, SubsystemKind}};
//!
//! let mut blkio_cgroup = blkio::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::BlkIo, PathBuf::from("students/charlie")));
//! blkio_cgroup.create()?;
//!
//! // Define how to throttle bandwidth of block I/O by a cgroup.
//! let resources = blkio::Resources {
//!     weight: Some(1000),
//!     weight_device: [([8, 0].into(), 100)].iter().copied().collect(),
//!     read_bps_device: [([8, 0].into(), 10 * (1 << 20))].iter().copied().collect(),
//!     write_iops_device: [([8, 0].into(), 100)].iter().copied().collect(),
//!     ..blkio::Resources::default()
//! };
//!
//! // Apply the resource limit to this cgroup.
//! blkio_cgroup.apply(&resources.into())?;
//!
//! // Add tasks to this cgroup.
//! let pid = Pid::from(std::process::id());
//! blkio_cgroup.add_task(pid)?;
//!
//! // Do something ...
//!
//! // Get the I/O service transferred by this cgroup in operation counts.
//! println!("{:?}", blkio_cgroup.io_serviced()?);
//!
//! blkio_cgroup.remove_task(pid)?;
//! blkio_cgroup.delete()?;
//! # Ok(())
//! # }
//! ```

use std::{
    collections::HashMap,
    error::Error as StdErr,
    io::{self, BufRead},
    path::PathBuf,
    str::FromStr,
};

use crate::{
    parse::{parse, parse_option},
    v1::{self, cgroup::CgroupHelper, Cgroup, CgroupPath, SubsystemKind},
    Device, Error, ErrorKind, Result,
};

/// Handler of a blkio subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Throttle bandwidth of block I/O by a cgroup.
///
/// See the kernel's documentation for more information about the fields.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// Relative weight of block I/O by this cgroup.
    ///
    /// The value must be between 10 and 1000 (inclusive).
    pub weight: Option<u16>,
    /// Override `weight` for specific devices.
    ///
    /// The value must be between 10 and 1000 (inclusive).
    pub weight_device: HashMap<Device, u16>,

    /// How much weight this cgroup has while competing against descendant cgroups.
    pub leaf_weight: Option<u16>,
    /// Override `leaf_weight` for specific devices.
    ///
    /// The value must be between 10 and 1000 (inclusive).
    pub leaf_weight_device: HashMap<Device, u16>,

    /// Throttle bytes/s of read access for each device.
    pub read_bps_device: HashMap<Device, u64>,
    /// Throttle bytes/s of write access for each device.
    pub write_bps_device: HashMap<Device, u64>,
    /// Throttle ops/s of read access for each device.
    pub read_iops_device: HashMap<Device, u64>,
    /// Throttle ops/s of write access for each device.
    pub write_iops_device: HashMap<Device, u64>,
}

/// How much I/O service a cgroup has transferred for each device and in total.
///
/// The unit of I/O service can be either bytes/s, ops/s, or nanosecond, depending on the
/// source from which the value is obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoService {
    /// How much I/O service this cgroup has transferred for each device.
    devices: HashMap<Device, Operations>,
    /// Total value.
    total: u64,
}

/// How much I/O service a cgroup has transferred for a specific device, for each type of operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operations {
    /// Value for read access.
    pub read: u64,
    /// Value for write access.
    pub write: u64,
    /// Value for synchronous operation.
    pub sync: u64,
    /// Value for asynchronous operation.
    pub async_: u64,
    /// Total value.
    pub total: u64,
}

impl_cgroup! {
    BlkIo,

    /// Applies `resources.blkio`.
    ///
    /// See [`Cgroup::apply`] for general information.
    ///
    /// [`Cgroup::apply`]: ../trait.Cgroup.html#tymethod.apply
    fn apply(&mut self, resources: &v1::Resources) -> Result<()> {
        let res = &resources.blkio;

        macro_rules! a {
            ($resource: ident, $setter: ident) => {
                for (device, x) in &res.$resource {
                    self.$setter(device, *x)?;
                }
            };
        }

        if let Some(weight) = res.weight {
            self.set_weight(weight)?;
        }
        a!(weight_device, set_weight_device);

        if let Some(leaf_weight) = res.leaf_weight {
            self.set_weight(leaf_weight)?;
        }
        a!(leaf_weight_device, set_leaf_weight_device);

        a!(read_bps_device, throttle_read_bps_device);
        a!(write_bps_device, throttle_write_bps_device);
        a!(read_iops_device, throttle_read_iops_device);
        a!(write_iops_device, throttle_write_iops_device);

        Ok(())
    }
}

macro_rules! gen_read {
    ($desc: literal, $field: ident, $ty: ty, $parser: ident) => {
        _gen_read!(blkio, BlkIo, $desc, $field, $ty, $parser);
    };

    (map; $desc: literal, $field: ident, $ty: ty $(, $recursive: ident )?) => {
        _gen_read!(blkio, BlkIo, $desc, $field, HashMap<Device, $ty>, parse_map);
        $( gen_read!(_recursive; $recursive, $field, HashMap<Device, $ty>, parse_map); )?
    };

    (map_no_ref; $desc: literal, $field: ident, $ty: ty $(, $recursive: ident )?) => {
        _gen_read!(no_ref; blkio, BlkIo, $desc, $field, HashMap<Device, $ty>, parse_map);
        $( gen_read!(_recursive; $recursive, $field, HashMap<Device, $ty>, parse_map); )?
    };

    (io_service; $desc: literal, $field: ident, $recursive: ident) => {
        _gen_read!(no_ref; blkio, BlkIo, $desc, $field, IoService, parse_io_service);
        gen_read!(_recursive; $recursive, $field, IoService, parse_io_service);
    };

    (_recursive; $recursive: ident, $field: ident, $ty: ty, $parser: ident) => {
        with_doc! { concat!(
            "Reads from `blkio.", stringify!($recursive), "` file.",
            " See `", stringify!($field), "` for more information."),
            pub fn $recursive(&self) -> Result<$ty> {
                self.open_file_read(concat!("blkio.", stringify!($recursive)))
                    .and_then($parser)
            }
        }
    }
}

macro_rules! gen_write {
    (weight; $desc: literal, $field: ident, $setter: ident) => { with_doc! { concat!(
        _gen_doc!(sets; $desc, blkio, $field, "The value must be between 10 and 1000 (inclusive)."),
        _gen_doc!(see; $field),
        gen_write!(_err_weight; $field),
        _gen_doc!(eg_write; blkio, BlkIo, $setter, 1000)),
        pub fn $setter(&mut self, weight: u16) -> Result<()> {
            if weight < 10 || weight > 1000 {
                return Err(Error::new(ErrorKind::InvalidArgument));
            }
            self.write_file(concat!("blkio.", stringify!($field)), weight)
        }
    } };

    (weight_map; $desc: literal, $field: ident, $setter: ident) => { with_doc!{ concat!(
        _gen_doc!(sets; $desc, blkio, $field, "The value must be between 10 and 1000 (inclusive)."),
        _gen_doc!(see; $field),
        gen_write!(_err_weight; $field),
        _gen_doc!(eg_write; blkio, BlkIo, $setter, &[8, 0].into(), 1000)),
        pub fn $setter(&mut self, device: &Device, weight: u16) -> Result<()> {
            use std::io::Write;

            if weight < 10 || weight > 1000 {
                return Err(Error::new(ErrorKind::InvalidArgument));
            }

            let mut file = self.open_file_write(concat!("blkio.", stringify!($field)))?;
            write!(file, "{} {}", device, weight).map_err(Into::into)
        }
    } };

    (throttle; $desc: literal, $field: ident, $setter: ident, $arg: ident, $ty: ty) => { with_doc! {
        concat!(
            "Throttles ", $desc, " for a device, by writing to `blkio.throttle.",
            stringify!($field), "` file.",
            _gen_doc!(see; $field),
            _gen_doc!(err_write; blkio, $field),
            _gen_doc!(eg_write; blkio, BlkIo, $setter, &[8, 0].into(), 100),
        ),
        pub fn $setter(&mut self, device: &Device, $arg: $ty) -> Result<()> {
            use std::io::Write;

            let mut file = self.open_file_write(concat!("blkio.throttle.", stringify!($field)))?;
            // write!(file, "{} {}", device, $arg).map_err(Into::into) // not work
            file.write_all(format!("{} {}", device, $arg).as_bytes()).map_err(Into::into)
        }
    } };

    (_err_weight; $field: ident) => { concat!(
"# Errors

Returns an error with kind [`ErrorKind::InvalidArgument`] if the weight is out-of-range. Returns an
error if failed to write to `blkio.", stringify!($field), "` file of this cgroup.

[`ErrorKind::InvalidArgument`]: ../../enum.ErrorKind.html#variant.InvalidArgument\n\n",
    ) };
}

impl Subsystem {
    gen_read!(
        "the relative weight of block I/O by this cgroup",
        weight,
        u16,
        parse
    );
    gen_write!(weight; "a relative weight of block I/O by this cgroup", weight, set_weight);

    gen_read!(map; "the overriding weight for devices", weight_device, u16);
    gen_write!(weight_map; "the overriding weight for a device", weight_device, set_weight_device);

    gen_read!(
        "the weight this cgroup has while competing against descendant cgroups,",
        leaf_weight,
        u16,
        parse
    );
    gen_write!(
        weight;
        "a weight this cgroup has while competing against descendant cgroups,",
        leaf_weight,
        set_leaf_weight
    );

    gen_read!(map; "the overriding leaf weight for devices", leaf_weight_device, u16);
    gen_write!(
        weight_map;
        "the overriding leaf weight for a device",
        leaf_weight_device,
        set_leaf_weight_device
    );

    gen_read!(
        map_no_ref;
        "the I/O time allocated to this cgroup per device (in milliseconds)",
        time,
        u64,
        time_recursive
    );

    gen_read!(
        map_no_ref;
        "the number of sectors transferred by this cgroup,",
        sectors,
        u64,
        sectors_recursive
    );

    gen_read!(
        io_service;
        "the I/O service transferred by this cgroup (in bytes)",
        io_service_bytes,
        io_service_bytes_recursive
    );
    gen_read!(
        io_service;
        "the I/O service transferred by this cgroup (in operation counts)",
        io_serviced,
        io_serviced_recursive
    );
    gen_read!(
        io_service;
        "the I/O service transferred by this cgroup (in nanoseconds)",
        io_service_time,
        io_service_time_recursive
    );

    gen_read!(
        io_service;
        "the total time the I/O for this cgroup spent waiting for service,",
        io_wait_time,
        io_wait_time_recursive
    );

    gen_read!(
        io_service;
        "the number of BIOS requests merged into I/O requests belonging to this cgroup,",
        io_merged,
        io_merged_recursive
    );

    gen_read!(
        io_service;
        "the number of I/O operations queued by this cgroup,",
        io_queued,
        io_queued_recursive
    );

    gen_write!(
        throttle;
        "bandwidth of read access in terms of bytes/s",
        read_bps_device,
        throttle_read_bps_device,
        bps,
        u64
    );
    gen_write!(
        throttle;
        "bandwidth of write access in terms of bytes/s",
        write_bps_device,
        throttle_write_bps_device,
        bps,
        u64
    );

    gen_write!(
        throttle;
        "bandwidth of read access in terms of ops/s",
        read_iops_device,
        throttle_read_iops_device,
        iops,
        u64
    );
    gen_write!(
        throttle;
        "bandwidth of write access in terms of ops/s",
        write_iops_device,
        throttle_write_iops_device,
        iops,
        u64
    );

    with_doc! { concat!(
        "Resets all statistics about block I/O for this cgroup, by writing to `blkio.reset_stats` file.\n\n",
        _gen_doc!(see),
        _gen_doc!(err_write; blkio, reset_stats),
        _gen_doc!(eg_write; blkio, BlkIo, reset_stats)),
        pub fn reset_stats(&mut self) -> Result<()> {
            self.write_file("blkio.reset_stats", 0)
        }
    }
}

impl Into<v1::Resources> for Resources {
    fn into(self) -> v1::Resources {
        v1::Resources {
            blkio: self,
            ..v1::Resources::default()
        }
    }
}

fn parse_map<T>(reader: impl io::Read) -> Result<HashMap<Device, T>>
where
    T: FromStr,
    <T as FromStr>::Err: StdErr + Sync + Send + 'static,
    Error: From<<T as FromStr>::Err>,
{
    let mut result = HashMap::new();

    for line in io::BufReader::new(reader).lines() {
        let line = line?;
        let mut entry = line.split_whitespace();

        result.insert(parse_option(entry.next())?, parse_option(entry.next())?);
    }

    Ok(result)
}

fn parse_io_service(reader: impl io::Read) -> Result<IoService> {
    let mut devices: HashMap<Device, Operations> = HashMap::new();
    let mut total = None;

    let lines = io::BufReader::new(reader)
        .lines()
        .collect::<std::result::Result<Vec<_>, std::io::Error>>()?;

    for lines5 in lines.chunks(5) {
        match &lines5 {
            // FIXME: order is guaranteed?
            // FIXME: 5 data of the same device are guaranteed to be contiguous?
            [read, write, sync, async_, total] => {
                let mut e = read.split_whitespace();
                let device = parse_option(e.next())?;

                let read = parse_option(e.nth(1))?;
                let write = parse_option({
                    let mut e = write.split_whitespace();
                    e.nth(2)
                })?;
                let sync = parse_option({
                    let mut e = sync.split_whitespace();
                    e.nth(2)
                })?;
                let async_ = parse_option({
                    let mut e = async_.split_whitespace();
                    e.nth(2)
                })?;
                let total = parse_option({
                    let mut e = total.split_whitespace();
                    e.nth(2)
                })?;

                devices.insert(
                    device,
                    Operations {
                        read,
                        write,
                        sync,
                        async_,
                        total,
                    },
                );
            }
            [tot] => {
                let mut e = tot.split_whitespace();
                if e.next() != Some("Total") {
                    return Err(Error::new(ErrorKind::Parse));
                }

                total = Some(parse_option(e.next())?);
                break;
            }
            _ => {
                return Err(Error::new(ErrorKind::Parse));
            }
        }
    }

    if let Some(total) = total {
        Ok(IoService { devices, total })
    } else {
        Err(Error::new(ErrorKind::Parse))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subsystem_create_file_exists() -> Result<()> {
        let mut files = [
            "weight",
            "weight_device",
            "leaf_weight",
            "leaf_weight_device",
            "throttle.io_service_bytes",
            "throttle.io_serviced",
            "throttle.read_bps_device",
            "throttle.read_iops_device",
            "throttle.write_bps_device",
            "throttle.write_iops_device",
            "reset_stats",
        ]
        .iter()
        .map(|f| format!("blkio.{}", f))
        .collect::<Vec<_>>();

        let files_rec = vec![
            "time",
            "sectors",
            "io_service_bytes",
            "io_service_time",
            "io_serviced",
            "io_merged",
            "io_queued",
            "io_wait_time",
        ];

        files.extend(files_rec.iter().map(|f| format!("blkio.{}", f)));
        files.extend(files_rec.iter().map(|f| format!("blkio.{}_recursive", f)));

        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::BlkIo, gen_cgroup_name!()));
        cgroup.create()?;

        assert!(files.iter().all(|f| cgroup.file_exists(f)));
        assert!(!cgroup.file_exists("does_not_exist"));

        cgroup.delete()?;
        assert!(!files.iter().all(|f| cgroup.file_exists(f)));

        Ok(())
    }

    #[test]
    fn test_subsystem_weight() -> Result<()> {
        gen_subsystem_test!(BlkIo; weight, 500, set_weight, 1000)?;
        gen_subsystem_test!(BlkIo; leaf_weight, 500, set_leaf_weight, 1000)
    }

    #[test]
    fn err_subsystem_weight() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::BlkIo, gen_cgroup_name!()));
        cgroup.create()?;

        assert_eq!(
            cgroup.set_weight(9).unwrap_err().kind(),
            ErrorKind::InvalidArgument
        );
        assert_eq!(
            cgroup.set_weight(1001).unwrap_err().kind(),
            ErrorKind::InvalidArgument
        );

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_weight_device() -> Result<()> {
        // TODO: test setting weights
        gen_subsystem_test!(BlkIo; weight_device, hashmap![])?;
        gen_subsystem_test!(BlkIo; leaf_weight_device, hashmap![])
    }

    // TODO: test adding tasks

    #[test]
    fn test_subsystem_time() -> Result<()> {
        gen_subsystem_test!(BlkIo; time, hashmap![])?;
        gen_subsystem_test!(BlkIo; time_recursive, hashmap![])
    }

    #[test]
    fn test_subsystem_sectors() -> Result<()> {
        gen_subsystem_test!(BlkIo; sectors, hashmap![])?;
        gen_subsystem_test!(BlkIo; sectors_recursive, hashmap![])
    }

    #[test]
    fn test_subsystem_io_service() -> Result<()> {
        let io_service = IoService {
            devices: HashMap::new(),
            total: 0,
        };

        gen_subsystem_test!(BlkIo; io_serviced, io_service)?;
        gen_subsystem_test!(BlkIo; io_serviced_recursive, io_service)?;

        gen_subsystem_test!(BlkIo; io_service_bytes, io_service)?;
        gen_subsystem_test!(BlkIo; io_service_bytes_recursive, io_service)?;

        gen_subsystem_test!(BlkIo; io_service_time, io_service)?;
        gen_subsystem_test!(BlkIo; io_service_time_recursive, io_service)
    }

    #[test]
    fn test_subsystem_io_wait_time() -> Result<()> {
        let io_service = IoService {
            devices: HashMap::new(),
            total: 0,
        };

        gen_subsystem_test!(BlkIo; io_wait_time, io_service)?;
        gen_subsystem_test!(BlkIo; io_wait_time_recursive, io_service)
    }

    #[test]
    fn test_subsystem_io_merged() -> Result<()> {
        let io_service = IoService {
            devices: HashMap::new(),
            total: 0,
        };

        gen_subsystem_test!(BlkIo; io_merged, io_service)?;
        gen_subsystem_test!(BlkIo; io_merged_recursive, io_service)
    }

    #[test]
    fn test_subsystem_io_queued() -> Result<()> {
        let io_service = IoService {
            devices: HashMap::new(),
            total: 0,
        };

        gen_subsystem_test!(BlkIo; io_queued, io_service)?;
        gen_subsystem_test!(BlkIo; io_queued_recursive, io_service)
    }

    #[test]
    fn test_subsystem_throttle() -> Result<()> {
        let device = lsblk();

        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::BlkIo, gen_cgroup_name!()));
        cgroup.create()?;

        cgroup.throttle_read_bps_device(&device, 42)?;
        cgroup.throttle_write_bps_device(&device, 42)?;
        cgroup.throttle_read_iops_device(&device, 42)?;
        cgroup.throttle_write_iops_device(&device, 42)?;

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_reset_stats() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::BlkIo, gen_cgroup_name!()));
        cgroup.create()?;

        cgroup.reset_stats()?;

        cgroup.delete()
    }

    #[test]
    fn test_parse_map() -> Result<()> {
        const CONTENT: &str = "\
7:26 256
259:0 65536
";

        let actual = parse_map(CONTENT.as_bytes())?;
        assert_eq!(
            actual,
            hashmap![([7, 26].into(), 256), ([259, 0].into(), 65536),]
        );

        assert_eq!(parse_map(&b""[..])?, HashMap::<Device, u32>::new());

        Ok(())
    }

    #[test]
    fn test_parse_io_service() -> Result<()> {
        const CONTENT_0: &str = "\
259:0 Read 5941
259:0 Write 10350930
259:0 Sync 6786851
259:0 Async 3570020
259:0 Total 10356871
7:26 Read 0
7:26 Write 0
7:26 Sync 0
7:26 Async 0
7:26 Total 0
Total 29281497
";

        let actual = parse_io_service(CONTENT_0.as_bytes())?;
        let expected = IoService {
            devices: hashmap![
                (
                    [259, 0].into(),
                    Operations {
                        read: 5941,
                        write: 10350930,
                        sync: 6786851,
                        async_: 3570020,
                        total: 10356871,
                    },
                ),
                (
                    [7, 26].into(),
                    Operations {
                        read: 0,
                        write: 0,
                        sync: 0,
                        async_: 0,
                        total: 0,
                    },
                ),
            ],
            total: 29281497,
        };

        assert_eq!(actual, expected);

        const CONTENT_1: &str = "\
Total 0
";

        let actual = parse_io_service(CONTENT_1.as_bytes())?;
        assert_eq!(
            actual,
            IoService {
                devices: HashMap::new(),
                total: 0
            }
        );

        Ok(())
    }

    fn lsblk() -> Device {
        let lsblk = std::process::Command::new("lsblk")
            .output()
            .expect("Failed to execute lsblk");

        String::from_utf8(lsblk.stdout)
            .expect("Output is not UTF-8")
            .lines()
            .nth(1)
            .expect("No device found")
            .split_whitespace()
            .nth(1)
            .expect("Invalid output")
            .parse::<Device>()
            .expect("Failed to parse")
    }
}
