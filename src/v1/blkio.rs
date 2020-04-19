//! Operations on a BlkIO subsystem.
//!
//! [`Subsystem`] implements [`Cgroup`] trait and subsystem-specific operations.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/blkio-controller.txt].
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> controlgroup::Result<()> {
//! use std::path::PathBuf;
//! use controlgroup::{Pid, v1::{self, blkio, Cgroup, CgroupPath, SubsystemKind}};
//!
//! let mut blkio_cgroup = blkio::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::BlkIo, PathBuf::from("students/charlie")));
//! blkio_cgroup.create()?;
//!
//! // Define how to throttle bandwidth of block I/O performed by a cgroup.
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
//! // Get the operation count of block I/O service transferred by this cgroup.
//! println!("{:?}", blkio_cgroup.io_serviced()?);
//!
//! blkio_cgroup.remove_task(pid)?;
//! blkio_cgroup.delete()?;
//! # Ok(())
//! # }
//! ```
//!
//! [`Subsystem`]: struct.Subsystem.html
//! [`Cgroup`]: ../trait.Cgroup.html
//! [Documentation/cgroup-v1/blkio-controller.txt]: https://www.kernel.org/doc/Documentation/cgroup-v1/blkio-controller.txt

use std::{
    collections::HashMap,
    io::{self, BufRead},
    path::PathBuf,
    str::FromStr,
};

use crate::{
    parse::{parse, parse_next},
    v1::{self, cgroup::CgroupHelper, Cgroup, CgroupPath},
    Device, Error, ErrorKind, Result,
};

/// Handler of a BlkIO subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Throttle bandwidth of block I/O performed by a cgroup.
///
/// See the kernel's documentation for more information about the fields.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// Relative weight of block I/O performed by this cgroup.
    ///
    /// The value must be between 10 and 1,000 (inclusive).
    pub weight: Option<u16>,
    /// Override `weight` for specific devices.
    ///
    /// The value must be between 10 and 1,000 (inclusive).
    pub weight_device: HashMap<Device, u16>,

    /// How much weight this cgroup has while competing against descendant cgroups.
    pub leaf_weight: Option<u16>,
    /// Override `leaf_weight` for specific devices.
    ///
    /// The value must be between 10 and 1,000 (inclusive).
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
/// The unit can be either bytes/s, ops/s, or nanosecond, depending on the source from which the
/// value is obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoService {
    /// How much I/O service this cgroup has transferred for each device.
    pub devices: HashMap<Device, Operations>,
    /// Total value.
    pub total: u64,
}

/// How much I/O service a cgroup has transferred for each type of operation.
///
/// The unit can be either bytes/s, ops/s, or nanosecond, depending on the source from which the
/// value is obtained.
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
    Subsystem, BlkIo,

    /// Applies `resources.blkio`.
    fn apply(&mut self, resources: &v1::Resources) -> Result<()> {
        let res = &resources.blkio;

        macro_rules! a {
            ($resource: ident, $setter: ident) => {
                for (&device, &x) in &res.$resource {
                    self.$setter(device, x)?;
                }
            };
        }

        if let Some(w) = res.weight {
            self.set_weight(w)?;
        }
        a!(weight_device, set_weight_device);

        if let Some(w) = res.leaf_weight {
            self.set_leaf_weight(w)?;
        }
        a!(leaf_weight_device, set_leaf_weight_device);

        a!(read_bps_device, throttle_read_bps_device);
        a!(write_bps_device, throttle_write_bps_device);
        a!(read_iops_device, throttle_read_iops_device);
        a!(write_iops_device, throttle_write_iops_device);

        Ok(())
    }
}

const WEIGHT_MIN: u16 = 10;
const WEIGHT_MAX: u16 = 1000;

impl Subsystem {
    /// Reads the relative weight of block I/O performed by this cgroup, from `blkio.weight` file.
    pub fn weight(&self) -> Result<u16> {
        self.open_file_read("blkio.weight").and_then(parse)
    }

    /// Sets the relative weight of block I/O performed by this cgroup, by writing to `blkio.weight` file.
    ///
    /// The weight must be between 10 and 1,000 (inclusive). If the weight is out-of-range, this
    /// method returns an error with kind [`ErrorKind::InvalidArgument`].
    ///
    /// [`ErrorKind::InvalidArgument`]: ../../enum.ErrorKind.html#variant.InvalidArgument\n\n",
    pub fn set_weight(&mut self, weight: u16) -> Result<()> {
        validate_weight(weight)?;
        self.write_file("blkio.weight", weight)
    }

    /// Reads an overriding weight for devices from `blkio.weight_device` file.
    pub fn weight_device(&self) -> Result<HashMap<Device, u16>> {
        self.open_file_read("blkio.weight_device")
            .and_then(parse_map)
    }

    /// Sets an overriding wright for a device by writing to `blkio.weight_device` file.
    ///
    /// The weight must be between 10 and 1,000 (inclusive). If the weight is out-of-range, this
    /// method returns an error with kind [`ErrorKind::InvalidArgument`].
    ///
    /// [`ErrorKind::InvalidArgument`]: ../../enum.ErrorKind.html#variant.InvalidArgument\n\n",
    fn set_weight_device(&mut self, device: Device, weight: u16) -> Result<()> {
        use io::Write;

        validate_weight(weight)?;

        let mut file = self.open_file_write("blkio.weight_device")?;
        write!(file, "{} {}", device, weight).map_err(Into::into)
    }

    /// Reads the weight this cgroup has while competing against descendant cgroups, from
    /// `blkio.leaf_weight` file.
    pub fn leaf_weight(&self) -> Result<u16> {
        self.open_file_read("blkio.leaf_weight").and_then(parse)
    }

    /// Sets the weight this cgroup has while competing against descendant cgroups, by writing to
    /// `blkio.leaf_weight` file.
    ///
    /// The weight must be between 10 and 1,000 (inclusive). If the weight is out-of-range, this
    /// method returns an error with kind [`ErrorKind::InvalidArgument`].
    ///
    /// [`ErrorKind::InvalidArgument`]: ../../enum.ErrorKind.html#variant.InvalidArgument\n\n",
    pub fn set_leaf_weight(&mut self, leaf_weight: u16) -> Result<()> {
        validate_weight(leaf_weight)?;
        self.write_file("blkio.leaf_weight", leaf_weight)
    }

    /// Reads the overriding leaf wright for devices from `blkio.leaf_weight_device` file.
    pub fn leaf_weight_device(&self) -> Result<HashMap<Device, u16>> {
        self.open_file_read("blkio.leaf_weight_device")
            .and_then(parse_map)
    }

    /// Sets an overriding leaf weight for a device by writing to `blkio.leaf_weight_device` file.
    ///
    /// The weight must be between 10 and 1,000 (inclusive). If the weight is out-of-range, this
    /// method returns an error with kind [`ErrorKind::InvalidArgument`].
    ///
    /// [`ErrorKind::InvalidArgument`]: ../../enum.ErrorKind.html#variant.InvalidArgument\n\n",
    pub fn set_leaf_weight_device(&mut self, device: Device, weight: u16) -> Result<()> {
        use io::Write;

        validate_weight(weight)?;

        let mut file = self.open_file_write("blkio.leaf_weight_device")?;
        write!(file, "{} {}", device, weight).map_err(Into::into)
    }

    /// Reads the I/O time allocated to this cgroup per device (in milliseconds) from `blkio.time`
    /// file.
    pub fn time(&self) -> Result<HashMap<Device, u64>> {
        self.open_file_read("blkio.time").and_then(parse_map)
    }

    /// Reads `blkio.time_recursive` file. See [`time`] method for more information.
    ///
    /// [`time`]: #method.time
    pub fn time_recursive(&self) -> Result<HashMap<Device, u64>> {
        self.open_file_read("blkio.time_recursive")
            .and_then(parse_map)
    }

    /// Reads the number of sectors transferred by this cgroup, from `blkio.sectors` file.
    pub fn sectors(&self) -> Result<HashMap<Device, u64>> {
        self.open_file_read("blkio.sectors").and_then(parse_map)
    }

    /// Reads `blkio.sectors_recursive` file. See [`sectors`] method for more information.
    ///
    /// [`sectors`]: #method.sectors
    pub fn sectors_recursive(&self) -> Result<HashMap<Device, u64>> {
        self.open_file_read("blkio.sectors_recursive")
            .and_then(parse_map)
    }

    /// Reads the I/O service transferred by this cgroup (in bytes), from `blkio.io_service_bytes`
    /// file.
    pub fn io_service_bytes(&self) -> Result<IoService> {
        self.open_file_read("blkio.io_service_bytes")
            .and_then(parse_io_service)
    }

    /// Reads `blkio.io_service_bytes_recursive` file. See [`io_service_bytes`] method for more
    /// information.
    ///
    /// [`io_service_bytes`]: #method.io_service_bytes
    pub fn io_service_bytes_recursive(&self) -> Result<IoService> {
        self.open_file_read("blkio.io_service_bytes_recursive")
            .and_then(parse_io_service)
    }

    /// Reads the I/O service transferred by this cgroup (in operation count), from
    /// `blkio.io_serviced` file.
    pub fn io_serviced(&self) -> Result<IoService> {
        self.open_file_read("blkio.io_serviced")
            .and_then(parse_io_service)
    }

    /// Reads `blkio.io_serviced_recursive` file. See [`io_serviced`] method for more
    /// information.
    ///
    /// [`io_serviced`]: #method.io_serviced
    pub fn io_serviced_recursive(&self) -> Result<IoService> {
        self.open_file_read("blkio.io_serviced_recursive")
            .and_then(parse_io_service)
    }

    /// Reads the I/O service transferred by this cgroup (in nanoseconds), from
    /// `blkio.io_service_time` file.
    pub fn io_service_time(&self) -> Result<IoService> {
        self.open_file_read("blkio.io_service_time")
            .and_then(parse_io_service)
    }

    /// Reads `blkio.io_service_time_recursive` file. See [`io_service_time`] method for more
    /// information.
    ///
    /// [`io_service_time`]: #method.io_service_time
    pub fn io_service_time_recursive(&self) -> Result<IoService> {
        self.open_file_read("blkio.io_service_time_recursive")
            .and_then(parse_io_service)
    }

    /// Reads the total time the I/O for this cgroup spent waiting for services, from
    /// `blkio.io_wait_time` file.
    pub fn io_wait_time(&self) -> Result<IoService> {
        self.open_file_read("blkio.io_wait_time")
            .and_then(parse_io_service)
    }

    /// Reads `blkio.io_wait_time_recursive` file. See [`io_wait_time`] method for more
    /// information.
    ///
    /// [`io_wait_time`]: #method.io_wait_time
    pub fn io_wait_time_recursive(&self) -> Result<IoService> {
        self.open_file_read("blkio.io_wait_time_recursive")
            .and_then(parse_io_service)
    }

    /// Reads the number of BIOS requests merged into I/O requests belonging to this cgroup, from
    /// `blkio.io_merged` file.
    pub fn io_merged(&self) -> Result<IoService> {
        self.open_file_read("blkio.io_merged")
            .and_then(parse_io_service)
    }

    /// Reads `blkio.io_merged_recursive` file. See [`io_merged`] method for more information.
    ///
    /// [`io_merged`]: #method.io_merged
    pub fn io_merged_recursive(&self) -> Result<IoService> {
        self.open_file_read("blkio.io_merged_recursive")
            .and_then(parse_io_service)
    }

    /// Reads the number of I/O operations queued by this cgroup, from `blkio.io_queued` file.
    pub fn io_queued(&self) -> Result<IoService> {
        self.open_file_read("blkio.io_queued")
            .and_then(parse_io_service)
    }

    /// Reads `blkio.io_queued_recursive` file. See [`io_queued`] method for more information.
    ///
    /// [`io_queued`]: #method.io_queued
    pub fn io_queued_recursive(&self) -> Result<IoService> {
        self.open_file_read("blkio.io_queued_recursive")
            .and_then(parse_io_service)
    }

    /// Reads the throttle on bandwidth of read access in terms of bytes/s, from
    /// `blkio.throttle.read_bps_device` file.
    pub fn read_bps_device(&self) -> Result<HashMap<Device, u64>> {
        self.open_file_read("blkio.throttle.read_bps_device")
            .and_then(parse_map)
    }

    /// Reads the throttle on bandwidth of write access in terms of bytes/s, from
    /// `blkio.throttle.write_bps_device` file.
    pub fn write_bps_device(&self) -> Result<HashMap<Device, u64>> {
        self.open_file_read("blkio.throttle.write_bps_device")
            .and_then(parse_map)
    }

    /// Reads the throttle on bandwidth of read access in terms of ops/s, from
    /// `blkio.throttle.read_iops_device` file.
    pub fn read_iops_device(&self) -> Result<HashMap<Device, u64>> {
        self.open_file_read("blkio.throttle.read_iops_device")
            .and_then(parse_map)
    }

    /// Reads the throttle on bandwidth of write access in terms of ops/s, from
    /// `blkio.throttle.write_iops_device` file.
    pub fn write_iops_device(&self) -> Result<HashMap<Device, u64>> {
        self.open_file_read("blkio.throttle.write_iops_device")
            .and_then(parse_map)
    }

    /// Sets a throttle on bandwidth of read access in terms of bytes/s, by writing to
    /// `blkio.throttle.read_bps_device` file.
    pub fn throttle_read_bps_device(&mut self, device: Device, bps: u64) -> Result<()> {
        use io::Write;

        let mut file = self.open_file_write("blkio.throttle.read_bps_device")?;
        // write!(file, "{} {}", device, $arg).map_err(Into::into) // not work
        file.write_all(format!("{} {}", device, bps).as_bytes())
            .map_err(Into::into)
    }

    /// Sets a throttle on bandwidth of write access in terms of bytes/s, by writing to
    /// `blkio.throttle.write_bps_device` file.
    pub fn throttle_write_bps_device(&mut self, device: Device, bps: u64) -> Result<()> {
        use io::Write;

        let mut file = self.open_file_write("blkio.throttle.write_bps_device")?;
        file.write_all(format!("{} {}", device, bps).as_bytes())
            .map_err(Into::into)
    }

    /// Sets a throttle on bandwidth of read access in terms of ops/s, by writing to
    /// `blkio.throttle.read_iops_device` file.
    pub fn throttle_read_iops_device(&mut self, device: Device, iops: u64) -> Result<()> {
        use io::Write;

        let mut file = self.open_file_write("blkio.throttle.read_iops_device")?;
        file.write_all(format!("{} {}", device, iops).as_bytes())
            .map_err(Into::into)
    }

    /// Sets a throttle on bandwidth of write access in terms of ops/s, by writing to
    /// `blkio.throttle.write_iops_device` file.
    pub fn throttle_write_iops_device(&mut self, device: Device, iops: u64) -> Result<()> {
        use io::Write;

        let mut file = self.open_file_write("blkio.throttle.write_iops_device")?;
        file.write_all(format!("{} {}", device, iops).as_bytes())
            .map_err(Into::into)
    }

    /// Resets all statistics about block I/O performed by this cgroup, by writing to
    /// `blkio.reset_stats` file.
    pub fn reset_stats(&mut self) -> Result<()> {
        self.write_file("blkio.reset_stats", 0)
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

fn validate_weight(weight: u16) -> Result<()> {
    if weight < WEIGHT_MIN || weight > WEIGHT_MAX {
        Err(Error::new(ErrorKind::InvalidArgument))
    } else {
        Ok(())
    }
}

fn parse_map<T, R>(reader: R) -> Result<HashMap<Device, T>>
where
    T: FromStr,
    <T as FromStr>::Err: std::error::Error + Sync + Send + 'static,
    Error: From<<T as FromStr>::Err>,
    R: io::Read,
{
    let mut result = HashMap::new();

    for line in io::BufReader::new(reader).lines() {
        let line = line?;
        let mut entry = line.split_whitespace();

        let device = parse_next(&mut entry)?;
        let val = parse_next(&mut entry)?;

        if entry.next().is_some() {
            bail_parse!();
        }

        result.insert(device, val);
    }

    Ok(result)
}

fn parse_io_service(reader: impl io::Read) -> Result<IoService> {
    let mut devices = HashMap::new();
    let mut total = None;

    // FIXME: avoid memory allocation
    let lines = io::BufReader::new(reader)
        .lines()
        .collect::<std::result::Result<Vec<_>, std::io::Error>>()?;

    for lines5 in lines.chunks(5) {
        match &lines5 {
            // FIXME: order is guaranteed?
            // FIXME: 5 lines of the same device are guaranteed to be contiguous?
            [read, write, sync, async_, total] => {
                let mut e = read.split_whitespace();
                let device = parse_next(&mut e)?;

                let read = parse_next(e.skip(1))?;
                let write = parse_next({
                    let e = write.split_whitespace();
                    e.skip(2)
                })?;
                let sync = parse_next({
                    let e = sync.split_whitespace();
                    e.skip(2)
                })?;
                let async_ = parse_next({
                    let e = async_.split_whitespace();
                    e.skip(2)
                })?;
                let total = parse_next({
                    let e = total.split_whitespace();
                    e.skip(2)
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
                let mut entry = tot.split_whitespace();
                if entry.next() != Some("Total") {
                    bail_parse!();
                }

                total = Some(parse_next(&mut entry)?);

                if entry.next().is_some() {
                    bail_parse!();
                }

                break;
            }
            _ => {
                bail_parse!();
            }
        }
    }

    if let Some(total) = total {
        Ok(IoService { devices, total })
    } else {
        bail_parse!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use v1::SubsystemKind;

    #[test]
    #[rustfmt::skip]
    fn test_subsystem_create_file_exists() -> Result<()> {
        gen_subsystem_test!(
            BlkIo,
            [
                "weight", "weight_device", "leaf_weight", "leaf_weight_device",
                "throttle.io_service_bytes", "throttle.io_serviced",
                "throttle.read_bps_device", "throttle.read_iops_device",
                "throttle.write_bps_device", "throttle.write_iops_device",
                "reset_stats",

                "time", "sectors",
                "io_service_bytes", "io_service_time", "io_serviced",
                "io_merged", "io_queued", "io_wait_time",

                "time_recursive", "sectors_recursive",
                "io_service_bytes_recursive", "io_service_time_recursive", "io_serviced_recursive",
                "io_merged_recursive", "io_queued_recursive", "io_wait_time_recursive",
            ]
        )
    }

    #[test]
    fn test_subsystem_apply() -> Result<()> {
        gen_subsystem_test!(
            BlkIo,
            Resources {
                weight: Some(1000),
                weight_device: hashmap! {},
                leaf_weight: Some(1000),
                leaf_weight_device: hashmap! {},
                read_bps_device: hashmap! {},
                write_bps_device: hashmap! {},
                read_iops_device: hashmap! {},
                write_iops_device: hashmap! {},
            },
            (weight, 1000),
            (leaf_weight, 1000),
        )
    }

    #[test]
    fn test_subsystem_weight() -> Result<()> {
        const WEIGHT_DEFAULT: u16 = 500;

        gen_subsystem_test!(
            BlkIo,
            weight,
            WEIGHT_DEFAULT,
            set_weight,
            WEIGHT_MIN,
            WEIGHT_MAX,
        )?;
        gen_subsystem_test!(
            BlkIo,
            leaf_weight,
            WEIGHT_DEFAULT,
            set_leaf_weight,
            WEIGHT_MIN,
            WEIGHT_MAX,
        )
    }

    #[test]
    fn err_subsystem_weight() -> Result<()> {
        gen_subsystem_test!(
            BlkIo,
            set_weight,
            (InvalidArgument, WEIGHT_MIN - 1),
            (InvalidArgument, WEIGHT_MAX + 1),
        )?;
        gen_subsystem_test!(
            BlkIo,
            set_leaf_weight,
            (InvalidArgument, WEIGHT_MIN - 1),
            (InvalidArgument, WEIGHT_MAX + 1),
        )
    }

    #[test]
    fn test_subsystem_weight_device() -> Result<()> {
        gen_subsystem_test!(BlkIo, weight_device, hashmap! {})?;
        gen_subsystem_test!(BlkIo, leaf_weight_device, hashmap! {})
    }

    #[test]
    fn err_subsystem_weight_device() -> Result<()> {
        let device = lsblk();

        gen_subsystem_test!(
            BlkIo,
            set_weight_device,
            (InvalidArgument, device, WEIGHT_MIN - 1),
            (InvalidArgument, device, WEIGHT_MAX + 1),
        )?;
        gen_subsystem_test!(
            BlkIo,
            set_leaf_weight_device,
            (InvalidArgument, device, WEIGHT_MIN - 1),
            (InvalidArgument, device, WEIGHT_MAX + 1),
        )
    }

    #[test]
    fn test_subsystem_time() -> Result<()> {
        gen_subsystem_test!(BlkIo, time, hashmap! {})?;
        gen_subsystem_test!(BlkIo, time_recursive, hashmap! {})
    }

    #[test]
    fn test_subsystem_sectors() -> Result<()> {
        gen_subsystem_test!(BlkIo, sectors, hashmap! {})?;
        gen_subsystem_test!(BlkIo, sectors_recursive, hashmap! {})
    }

    #[test]
    fn test_subsystem_io_service() -> Result<()> {
        let io_service = IoService {
            devices: HashMap::new(),
            total: 0,
        };

        gen_subsystem_test!(BlkIo, io_service_bytes, io_service)?;
        gen_subsystem_test!(BlkIo, io_service_bytes_recursive, io_service)?;

        gen_subsystem_test!(BlkIo, io_serviced, io_service)?;
        gen_subsystem_test!(BlkIo, io_serviced_recursive, io_service)?;

        gen_subsystem_test!(BlkIo, io_service_time, io_service)?;
        gen_subsystem_test!(BlkIo, io_service_time_recursive, io_service)
    }

    #[test]
    fn test_subsystem_io_wait_time() -> Result<()> {
        let io_service = IoService {
            devices: HashMap::new(),
            total: 0,
        };

        gen_subsystem_test!(BlkIo, io_wait_time, io_service)?;
        gen_subsystem_test!(BlkIo, io_wait_time_recursive, io_service)
    }

    #[test]
    fn test_subsystem_io_merged() -> Result<()> {
        let io_service = IoService {
            devices: HashMap::new(),
            total: 0,
        };

        gen_subsystem_test!(BlkIo, io_merged, io_service)?;
        gen_subsystem_test!(BlkIo, io_merged_recursive, io_service)
    }

    #[test]
    fn test_subsystem_io_queued() -> Result<()> {
        let io_service = IoService {
            devices: HashMap::new(),
            total: 0,
        };

        gen_subsystem_test!(BlkIo, io_queued, io_service)?;
        gen_subsystem_test!(BlkIo, io_queued_recursive, io_service)
    }

    #[test]
    fn test_subsystem_throttle() -> Result<()> {
        let device = lsblk();

        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::BlkIo, gen_cgroup_name!()));
        cgroup.create()?;

        assert!(cgroup.read_bps_device()?.is_empty());
        assert!(cgroup.write_bps_device()?.is_empty());
        assert!(cgroup.read_iops_device()?.is_empty());
        assert!(cgroup.write_iops_device()?.is_empty());

        cgroup.throttle_read_bps_device(device, 42)?;
        cgroup.throttle_write_bps_device(device, 42)?;
        cgroup.throttle_read_iops_device(device, 42)?;
        cgroup.throttle_write_iops_device(device, 42)?;

        assert_eq!(cgroup.read_bps_device()?, hashmap! {(device, 42)});
        assert_eq!(cgroup.write_bps_device()?, hashmap! {(device, 42)});
        assert_eq!(cgroup.read_iops_device()?, hashmap! {(device, 42)});
        assert_eq!(cgroup.write_iops_device()?, hashmap! {(device, 42)});

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
        const CONTENT_OK: &str = "\
7:26 256
259:0 65536
";

        let actual = parse_map(CONTENT_OK.as_bytes())?;
        assert_eq!(
            actual,
            hashmap! {([7, 26].into(), 256), ([259, 0].into(), 65536)}
        );

        assert_eq!(parse_map::<u32, _>("".as_bytes())?, hashmap! {});

        const CONTENT_NG_NOT_INT: &str = "\
7:26 invalid
259:0 65536
";
        const CONTENT_NG_NOT_DEVICE: &str = "\
7:26 256
invalid:0 65536
";

        const CONTENT_NG_MISSING_DATA: &str = "\
7:26
259:0 65536
";

        const CONTENT_NG_EXTRA_DATA: &str = "\
7:26 256 256
259:0 65536
";

        for case in &[
            CONTENT_NG_NOT_INT,
            CONTENT_NG_NOT_DEVICE,
            CONTENT_NG_MISSING_DATA,
            CONTENT_NG_EXTRA_DATA,
        ] {
            assert_eq!(
                parse_map::<u32, _>(case.as_bytes()).unwrap_err().kind(),
                ErrorKind::Parse
            );
        }

        Ok(())
    }

    #[test]
    fn test_parse_io_service() -> Result<()> {
        #![allow(clippy::unreadable_literal)]

        const CONTENT_OK: &str = "\
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

        let actual = parse_io_service(CONTENT_OK.as_bytes())?;
        let expected = IoService {
            devices: hashmap! {
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
            },
            total: 29281497,
        };

        assert_eq!(actual, expected);

        const CONTENT_OK_EMPTY: &str = "\
Total 0
";

        let actual = parse_io_service(CONTENT_OK_EMPTY.as_bytes())?;
        assert_eq!(
            actual,
            IoService {
                devices: HashMap::new(),
                total: 0
            }
        );

        const CONTENT_NG_MISSING_DATA: &str = "\
259:0 Read 5941
259:0 Write 10350930
259:0 Sync 6786851
259:0 Total 10356871
Total 29281497
        ";

        const CONTENT_NG_EXTRA_DATA: &str = "\
259:0 Read 5941
259:0 Write 10350930
259:0 Sync 6786851
259:0 Async 3570020
259:0 Total 10356871
Total 29281497
259:0 Read 5941
        ";

        const CONTENT_NG_MISSING_TOTAL: &str = "\
259:0 Read 5941
259:0 Write 10350930
259:0 Sync 6786851
259:0 Async 3570020
259:0 Total 10356871
        ";

        const CONTENT_NG_TOTAL_ORDER: &str = "\
259:0 Read 5941
259:0 Write 10350930
259:0 Sync 6786851
259:0 Async 3570020
259:0 Total 10356871
Total 29281497
7:26 Read 0
7:26 Write 0
7:26 Sync 0
7:26 Async 0
7:26 Total 0
        ";

        for case in &[
            CONTENT_NG_MISSING_DATA,
            CONTENT_NG_EXTRA_DATA,
            CONTENT_NG_MISSING_TOTAL,
            CONTENT_NG_TOTAL_ORDER,
        ] {
            assert_eq!(
                parse_io_service(case.as_bytes()).unwrap_err().kind(),
                ErrorKind::Parse
            );
        }

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
