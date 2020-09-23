//! Operations on a HugeTLB subsystem.
//!
//! [`Subsystem`] implements [`Cgroup`] trait and subsystem-specific operations.
//!
//! For more information about this subsystem, see the kernel's documentation
//! [Documentation/cgroup-v1/hugetlb.txt].
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> controlgroup::Result<()> {
//! use std::path::PathBuf;
//! use controlgroup::{
//!     Pid,
//!     v1::{self, hugetlb::{self, HugepageSize, Limit}, Cgroup, CgroupPath, SubsystemKind},
//! };
//!
//! let mut hugetlb_cgroup = hugetlb::Subsystem::new(
//!     CgroupPath::new(SubsystemKind::HugeTlb, PathBuf::from("students/charlie")));
//! hugetlb_cgroup.create()?;
//!
//! // Define a resource limit about how many hugepage TLB a cgroup can use.
//! let resources = hugetlb::Resources {
//!     limits: [
//!         (hugetlb::HugepageSize::Mb2, Limit::Pages(1)),
//!         (hugetlb::HugepageSize::Gb1, Limit::Pages(1)),
//!     ].iter().copied().collect(),
//! };
//!
//! // Apply the resource limit.
//! hugetlb_cgroup.apply(&resources.into())?;
//!
//! // Add tasks to this cgroup.
//! let pid = Pid::from(std::process::id());
//! hugetlb_cgroup.add_task(pid)?;
//!
//! // Do something ...
//!
//! hugetlb_cgroup.remove_task(pid)?;
//! hugetlb_cgroup.delete()?;
//! # Ok(())
//! # }
//! ```
//!
//! [`Subsystem`]: struct.Subsystem.html
//! [`Cgroup`]: ../trait.Cgroup.html
//!
//! [Documentation/cgroup-v1/hugetlb.txt]: https://www.kernel.org/doc/Documentation/cgroup-v1/hugetlb.txt

use std::{collections::HashMap, fmt, path::PathBuf};

use crate::{
    parse::parse,
    v1::{self, cgroup::CgroupHelper, Cgroup, CgroupPath},
    Result,
};

/// Handler of a HugeTLB subsystem.
#[derive(Debug)]
pub struct Subsystem {
    path: CgroupPath,
}

/// Resource limit no how many hugepage TLBs a cgroup can use.
///
/// See the kernel's documentation for more information about the fields.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resources {
    /// How many hugepage TLBs this cgroup can use for each hugepage size.
    pub limits: HashMap<HugepageSize, Limit>,
}

/// Limit on hugepage TLB usage in different units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// Limit hugepage TLB usage in bytes.
    Bytes(u64),
    /// Limit hugepage TLB usage in pages.
    Pages(u64),
}

/// Hugepage sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HugepageSize {
    /// 8 KB hugepage.
    Kb8,
    /// 64 KB hugepage.
    Kb64,
    /// 256 KB hugepage.
    Kb256,
    /// 1 MB hugepage.
    Mb1,
    /// 2 MB hugepage.
    Mb2,
    /// 4 MB hugepage.
    Mb4,
    /// 16 MB hugepage.
    Mb16,
    /// 256 MB hugepage.
    Mb256,
    /// 1 GB hugepage.
    Gb1,
}

impl_cgroup! {
    Subsystem, HugeTlb,

    /// Applies `resources.hugetlb.limits` if it is not empty.
    fn apply(&mut self, resources: &v1::Resources) -> Result<()> {
        for (&size, &limit) in &resources.hugetlb.limits {
            self.set_limit(size, limit)?;
        }

        Ok(())
    }
}

const LIMIT_IN_BYTES: &str = "limit_in_bytes";
const LIMIT_IN_PAGES: &str = "limit_in_pages";

const USAGE_IN_BYTES: &str = "usage_in_bytes";
const USAGE_IN_PAGES: &str = "usage_in_pages";

const MAX_USAGE_IN_BYTES: &str = "max_usage_in_bytes";
const MAX_USAGE_IN_PAGES: &str = "max_usage_in_pages";

const FAILCNT: &str = "failcnt";

impl Subsystem {
    /// Returns whether the system supports hugepage in `size`.
    ///
    /// Note that this method returns `false` if the directory of this cgroup is not created yet.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn main() -> controlgroup::Result<()> {
    /// use std::path::PathBuf;
    /// use controlgroup::v1::{hugetlb::{self, HugepageSize}, Cgroup, CgroupPath, SubsystemKind};
    ///
    /// let mut cgroup = hugetlb::Subsystem::new(
    ///     CgroupPath::new(SubsystemKind::HugeTlb, PathBuf::from("students/charlie")));
    /// cgroup.create()?;
    ///
    /// let support_2mb = cgroup.size_supported(HugepageSize::Mb2);
    /// let support_1gb = cgroup.size_supported(HugepageSize::Gb1);
    /// # Ok(())
    /// # }
    /// ```
    pub fn size_supported(&self, size: HugepageSize) -> bool {
        self.file_exists(&format!("hugetlb.{}.{}", size, LIMIT_IN_BYTES))
            && self.file_exists(&format!("hugetlb.{}.{}", size, USAGE_IN_BYTES))
            && self.file_exists(&format!("hugetlb.{}.{}", size, MAX_USAGE_IN_BYTES))
            && self.file_exists(&format!("hugetlb.{}.{}", size, FAILCNT))
    }

    /// Reads the limit of hugepage TLB usage in bytes from `hugetlb.<hugepage size>.limit_in_bytes`
    /// file.
    pub fn limit_in_bytes(&self, size: HugepageSize) -> Result<u64> {
        self.open_file_read(&format!("hugetlb.{}.{}", size, LIMIT_IN_BYTES))
            .and_then(parse)
    }

    /// Reads the limit of hugepage TLB usage in pages from `hugetlb.<hugepage size>.limit_in_pages`
    /// file.
    pub fn limit_in_pages(&self, size: HugepageSize) -> Result<u64> {
        self.open_file_read(&format!("hugetlb.{}.{}", size, LIMIT_IN_PAGES))
            .and_then(parse)
    }

    /// Sets a limit of hugepage TLB usage by writing to `hugetlb.<hugepage size>.limit_in_bytes`
    /// file.
    pub fn set_limit(&mut self, size: HugepageSize, limit: Limit) -> Result<()> {
        match limit {
            Limit::Bytes(bytes) => self.set_limit_in_bytes(size, bytes),
            Limit::Pages(pages) => self.set_limit_in_pages(size, pages),
        }
    }

    /// Sets a limit of hugepage TLB usage in bytes. See [`set_limit`] method for more information.
    ///
    /// [`set_limit`]: #method.set_limit
    pub fn set_limit_in_bytes(&mut self, size: HugepageSize, bytes: u64) -> Result<()> {
        self.write_file(&format!("hugetlb.{}.{}", size, LIMIT_IN_BYTES), bytes)
    }

    /// Sets a limit of hugepage TLB usage in pages. See [`set_limit`] method for more information.
    ///
    /// [`set_limit`]: #method.set_limit
    pub fn set_limit_in_pages(&mut self, size: HugepageSize, pages: u64) -> Result<()> {
        self.set_limit_in_bytes(size, size.pages_to_bytes(pages))
    }

    /// Reads the current usage of hugepage TLB in bytes from
    /// `hugetlb.<hugepage size>.usage_in_bytes` file.
    pub fn usage_in_bytes(&self, size: HugepageSize) -> Result<u64> {
        self.open_file_read(&format!("hugetlb.{}.{}", size, USAGE_IN_BYTES))
            .and_then(parse)
    }

    /// Reads the current usage of hugepage TLB in pages from
    /// `hugetlb.<hugepage size>.usage_in_pages` file.
    pub fn usage_in_pages(&self, size: HugepageSize) -> Result<u64> {
        self.open_file_read(&format!("hugetlb.{}.{}", size, USAGE_IN_PAGES))
            .and_then(parse)
    }

    /// Reads the maximum recorded usage of hugepage TLB in bytes from
    /// `hugetlb.<hugepage size>.max_usage_in_bytes` file.
    pub fn max_usage_in_bytes(&self, size: HugepageSize) -> Result<u64> {
        self.open_file_read(&format!("hugetlb.{}.{}", size, MAX_USAGE_IN_BYTES))
            .and_then(parse)
    }

    /// Reads the maximum recorded usage of hugepage TLB in pages from
    /// `hugetlb.<hugepage size>.max_usage_in_pages` file.
    pub fn max_usage_in_pages(&self, size: HugepageSize) -> Result<u64> {
        self.open_file_read(&format!("hugetlb.{}.{}", size, MAX_USAGE_IN_PAGES))
            .and_then(parse)
    }

    /// Reads the number of allocation failure due to the limit, from
    /// `hugetlb.<hugepage size>.failcnt` file.
    pub fn failcnt(&self, size: HugepageSize) -> Result<u64> {
        self.open_file_read(&format!("hugetlb.{}.{}", size, FAILCNT))
            .and_then(parse)
    }
}

impl Into<v1::Resources> for Resources {
    fn into(self) -> v1::Resources {
        v1::Resources {
            hugetlb: self,
            ..v1::Resources::default()
        }
    }
}

impl HugepageSize {
    fn pages_to_bytes(self, pages: u64) -> u64 {
        match self {
            Self::Kb8 => pages * (8 << 10),
            Self::Kb64 => pages * (64 << 10),
            Self::Kb256 => pages * (256 << 10),

            Self::Mb1 => pages * (1 << 20),
            Self::Mb2 => pages * (2 << 20),
            Self::Mb4 => pages * (4 << 20),
            Self::Mb16 => pages * (16 << 20),
            Self::Mb256 => pages * (256 << 20),

            Self::Gb1 => pages * (1 << 30),
        }
    }
}

impl fmt::Display for HugepageSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Kb8 => "8KB",
                Self::Kb64 => "64KB",
                Self::Kb256 => "256KB",
                Self::Mb1 => "1MB",
                Self::Mb2 => "2MB",
                Self::Mb4 => "4MB",
                Self::Mb16 => "16MB",
                Self::Mb256 => "256MB",
                Self::Gb1 => "1GB",
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use v1::SubsystemKind;
    use HugepageSize::*;

    const LIMIT_2MB_BYTES_DEFAULT: u64 = 0x7FFF_FFFF_FFE0_0000;
    const LIMIT_1GB_BYTES_DEFAULT: u64 = 0x7FFF_FFFF_C000_0000;

    #[test]
    fn test_subsystem_create_file_exists_delete() -> Result<()> {
        gen_test_subsystem_create_delete!(
            HugeTlb,
            "2MB.limit_in_bytes",
            "2MB.usage_in_bytes",
            "2MB.max_usage_in_bytes",
            "2MB.failcnt",
            "1GB.limit_in_bytes",
            "1GB.usage_in_bytes",
            "1GB.max_usage_in_bytes",
            "1GB.failcnt",
        )
    }

    #[test]
    fn test_subsystem_apply() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(
            v1::SubsystemKind::HugeTlb,
            gen_cgroup_name!(),
        ));
        cgroup.create()?;

        cgroup.apply(
            &Resources {
                limits: [(Mb2, Limit::Pages(4)), (Gb1, Limit::Pages(2))]
                    .iter()
                    .copied()
                    .collect(),
            }
            .into(),
        )?;

        assert_eq!(cgroup.limit_in_pages(HugepageSize::Mb2)?, 4);
        assert_eq!(cgroup.limit_in_pages(HugepageSize::Gb1)?, 2);

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_size_supported() -> Result<()> {
        let mut cgroup =
            Subsystem::new(CgroupPath::new(SubsystemKind::HugeTlb, gen_cgroup_name!()));

        assert!(!cgroup.size_supported(Mb2));
        assert!(!cgroup.size_supported(Gb1));

        cgroup.create()?;

        assert!(cgroup.size_supported(Mb2));
        assert!(cgroup.size_supported(Gb1));

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_limit_in_bytes() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(
            v1::SubsystemKind::HugeTlb,
            gen_cgroup_name!(),
        ));

        cgroup.create()?;
        assert_eq!(cgroup.limit_in_bytes(Mb2)?, LIMIT_2MB_BYTES_DEFAULT);
        assert_eq!(cgroup.limit_in_bytes(Gb1)?, LIMIT_1GB_BYTES_DEFAULT);

        cgroup.set_limit_in_bytes(Mb2, 4 * (1 << 21))?;
        cgroup.set_limit_in_bytes(Gb1, 2 * (1 << 30))?;

        assert_eq!(cgroup.limit_in_bytes(Mb2)?, 4 * (1 << 21));
        assert_eq!(cgroup.limit_in_bytes(Gb1)?, 2 * (1 << 30));

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_limit_in_pages() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(
            v1::SubsystemKind::HugeTlb,
            gen_cgroup_name!(),
        ));

        cgroup.create()?;
        assert_eq!(cgroup.limit_in_pages(Mb2)?, LIMIT_2MB_BYTES_DEFAULT >> 21);
        assert_eq!(cgroup.limit_in_pages(Gb1)?, LIMIT_1GB_BYTES_DEFAULT >> 30);

        cgroup.set_limit_in_pages(Mb2, 4)?;
        cgroup.set_limit_in_pages(Gb1, 2)?;

        assert_eq!(cgroup.limit_in_pages(Mb2)?, 4);
        assert_eq!(cgroup.limit_in_pages(Gb1)?, 2);

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_set_limit() -> Result<()> {
        let mut cgroup =
            Subsystem::new(CgroupPath::new(SubsystemKind::HugeTlb, gen_cgroup_name!()));
        cgroup.create()?;

        cgroup.set_limit(Mb2, Limit::Bytes(4 * (1 << 21)))?;
        assert_eq!(cgroup.limit_in_bytes(Mb2)?, 4 * (1 << 21));

        cgroup.set_limit(Mb2, Limit::Pages(4))?;
        assert_eq!(cgroup.limit_in_pages(Mb2)?, 4);

        cgroup.set_limit(Gb1, Limit::Bytes(4 * (1 << 30)))?;
        assert_eq!(cgroup.limit_in_bytes(Gb1)?, 4 * (1 << 30));

        cgroup.set_limit(Gb1, Limit::Pages(4))?;
        assert_eq!(cgroup.limit_in_pages(Gb1)?, 4);

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_usage_in_bytes() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(
            SubsystemKind::HugeTlb,
            gen_cgroup_name!(),
        ));

        cgroup.create()?;
        assert_eq!(cgroup.usage_in_bytes(Mb2)?, 0);
        assert_eq!(cgroup.usage_in_bytes(Gb1)?, 0);

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_usage_in_pages() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(
            SubsystemKind::HugeTlb,
            gen_cgroup_name!(),
        ));

        cgroup.create()?;
        assert_eq!(cgroup.usage_in_pages(Mb2)?, 0);
        assert_eq!(cgroup.usage_in_pages(Gb1)?, 0);

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_max_usage_in_bytes() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(
            SubsystemKind::HugeTlb,
            gen_cgroup_name!(),
        ));

        cgroup.create()?;
        assert_eq!(cgroup.max_usage_in_bytes(Mb2)?, 0);
        assert_eq!(cgroup.max_usage_in_bytes(Gb1)?, 0);

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_max_usage_in_pages() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(
            SubsystemKind::HugeTlb,
            gen_cgroup_name!(),
        ));

        cgroup.create()?;
        assert_eq!(cgroup.max_usage_in_pages(Mb2)?, 0);
        assert_eq!(cgroup.max_usage_in_pages(Gb1)?, 0);

        cgroup.delete()
    }

    #[test]
    fn test_subsystem_failcnt() -> Result<()> {
        let mut cgroup = Subsystem::new(CgroupPath::new(
            SubsystemKind::HugeTlb,
            gen_cgroup_name!(),
        ));

        cgroup.create()?;
        assert_eq!(cgroup.failcnt(Mb2)?, 0);
        assert_eq!(cgroup.failcnt(Gb1)?, 0);

        cgroup.delete()
    }

    #[test]
    fn test_pages_to_bytes() {
        #![allow(clippy::identity_op)]

        assert_eq!(Mb2.pages_to_bytes(0), 0);
        assert_eq!(Mb2.pages_to_bytes(1), 1 * (1 << 21));
        assert_eq!(Mb2.pages_to_bytes(4), 4 * (1 << 21));

        assert_eq!(Gb1.pages_to_bytes(0), 0);
        assert_eq!(Gb1.pages_to_bytes(1), 1 * (1 << 30));
        assert_eq!(Gb1.pages_to_bytes(4), 4 * (1 << 30));
    }
}
