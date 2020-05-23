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

macro_rules! _gen_getter {
    ($desc: literal, $in_bytes: ident, $in_pages: ident) => {
        with_doc! { concat!(
            gen_doc!(reads; subsys_file!("hugetlb.<hugepage size>", $in_bytes), $desc),
            gen_doc!(see),
            gen_doc!(err_read; subsys_file!("hugetlb.<hugepage size>", $in_bytes)),
            gen_doc!(eg_read; hugetlb, $in_bytes, hugetlb::HugepageSize::Mb2)),
            pub fn $in_bytes(&self, size: HugepageSize) -> Result<u64> {
                self.open_file_read(&format!("hugetlb.{}.{}", size, stringify!($in_bytes)))
                    .and_then(parse)
            }
        }

        with_doc! { concat!(
            "Reads ", $desc, " in pages. See [`", stringify!($in_bytes), "`](#method.",
            stringify!($in_bytes), ") method for more information."),
            pub fn $in_pages(&self, size: HugepageSize) -> Result<u64> {
                self.$in_bytes(size).map(|b| size.bytes_to_pages(b))
            }
        }
    };
}

const LIMIT_IN_BYTES: &str = "limit_in_bytes";
const USAGE_IN_BYTES: &str = "usage_in_bytes";
const MAX_USAGE_IN_BYTES: &str = "max_usage_in_bytes";
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

    _gen_getter!(
        "the limit of hugepage TLB usage in bytes",
        limit_in_bytes,
        limit_in_pages
    );

    with_doc! { concat!(
        gen_doc!(
            sets;
            "hugetlb.<hugepage size>.limit_in_bytes",
            "a limit of hugepage TLB usage"
        ),
        gen_doc!(see),
        gen_doc!(err_write; "hugetlb.<hugepage size>.limit_in_bytes"),
        gen_doc!(
            eg_write; hugetlb,
            set_limit, hugetlb::HugepageSize::Mb2, hugetlb::Limit::Pages(4)
        )),
        pub fn set_limit(&mut self, size: HugepageSize, limit: Limit) -> Result<()> {
            match limit {
                Limit::Bytes(bytes) => self.set_limit_in_bytes(size, bytes),
                Limit::Pages(pages) => self.set_limit_in_pages(size, pages),
            }
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

    _gen_getter!(
        "the current usage of hugepage TLB in bytes",
        usage_in_bytes,
        usage_in_pages
    );

    _gen_getter!(
        "the maximum recorded usage of hugepage TLB in bytes",
        max_usage_in_bytes,
        max_usage_in_pages
    );

    with_doc! { concat!(
        gen_doc!(
            reads;
            "hugetlb.<hugepage size>.failcnt",
            "the number of allocation failure due to the limit,"
        ),
        gen_doc!(see),
        gen_doc!(err_read; "hugetlb.<hugepage size>.failcnt"),
        gen_doc!(eg_read; hugetlb, failcnt, hugetlb::HugepageSize::Mb2)),
        pub fn failcnt(&self, size: HugepageSize) -> Result<u64> {
            self.open_file_read(&format!("hugetlb.{}.{}", size, FAILCNT))
                .and_then(parse)
        }
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
    fn bytes_to_pages(self, bytes: u64) -> u64 {
        match self {
            Self::Kb8 => bytes / (8 << 10),
            Self::Kb64 => bytes / (64 << 10),
            Self::Kb256 => bytes / (256 << 10),

            Self::Mb1 => bytes / (1 << 20),
            Self::Mb2 => bytes / (2 << 20),
            Self::Mb4 => bytes / (4 << 20),
            Self::Mb16 => bytes / (16 << 20),
            Self::Mb256 => bytes / (256 << 20),

            Self::Gb1 => bytes / (1 << 30),
        }
    }

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
    #[rustfmt::skip]
    fn test_subsystem_create_file_exists_delete() -> Result<()> {
        gen_subsystem_test!(
            HugeTlb,
            [
                "2MB.limit_in_bytes", "2MB.usage_in_bytes", "2MB.max_usage_in_bytes", "2MB.failcnt",
                "1GB.limit_in_bytes", "1GB.usage_in_bytes", "1GB.max_usage_in_bytes", "1GB.failcnt"
            ]
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

    macro_rules! gen_test {
        ($field: ident, $mb2: expr, $gb1: expr) => {{
            let mut cgroup = Subsystem::new(CgroupPath::new(
                v1::SubsystemKind::HugeTlb,
                gen_cgroup_name!(),
            ));

            cgroup.create()?;
            assert_eq!(cgroup.$field(Mb2)?, $mb2);
            assert_eq!(cgroup.$field(Gb1)?, $gb1);

            cgroup.delete()
        }};

        (
            $field: ident,
            $setter: ident,
            $dfl_mb2: expr,
            $dfl_gb1: expr,
            $val_mb2: expr,
            $val_gb1: expr
        ) => {{
            let mut cgroup = Subsystem::new(CgroupPath::new(
                v1::SubsystemKind::HugeTlb,
                gen_cgroup_name!(),
            ));

            cgroup.create()?;
            assert_eq!(cgroup.$field(Mb2)?, $dfl_mb2);
            assert_eq!(cgroup.$field(Gb1)?, $dfl_gb1);

            cgroup.$setter(Mb2, $val_mb2)?;
            cgroup.$setter(Gb1, $val_gb1)?;

            assert_eq!(cgroup.$field(Mb2)?, $val_mb2);
            assert_eq!(cgroup.$field(Gb1)?, $val_gb1);

            cgroup.delete()
        }};
    }

    #[test]
    fn test_subsystem_limit_in_bytes() -> Result<()> {
        gen_test!(
            limit_in_bytes,
            set_limit_in_bytes,
            LIMIT_2MB_BYTES_DEFAULT,
            LIMIT_1GB_BYTES_DEFAULT,
            4 * (1 << 21),
            2 * (1 << 30)
        )
    }

    #[test]
    fn test_subsystem_limit_in_pages() -> Result<()> {
        gen_test!(
            limit_in_pages,
            set_limit_in_pages,
            LIMIT_2MB_BYTES_DEFAULT >> 21,
            LIMIT_1GB_BYTES_DEFAULT >> 30,
            4,
            2
        )
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
    fn test_subsystem_usage() -> Result<()> {
        gen_test!(usage_in_bytes, 0, 0)?;
        gen_test!(usage_in_pages, 0, 0)
    }

    #[test]
    fn test_subsystem_max_usage() -> Result<()> {
        gen_test!(max_usage_in_bytes, 0, 0)?;
        gen_test!(max_usage_in_pages, 0, 0)
    }

    #[test]
    fn test_subsystem_failcnt() -> Result<()> {
        gen_test!(failcnt, 0, 0)
    }

    #[test]
    fn test_bytes_to_pages() {
        #![allow(clippy::identity_op)]

        assert_eq!(Mb2.bytes_to_pages(1 * (1 << 20)), 0);
        assert_eq!(Mb2.bytes_to_pages(1 * (1 << 21)), 1);
        assert_eq!(Mb2.bytes_to_pages(4 * (1 << 21) - 1), 3);
        assert_eq!(Mb2.bytes_to_pages(4 * (1 << 21)), 4);
        assert_eq!(Mb2.bytes_to_pages(4 * (1 << 21) + 1), 4);

        assert_eq!(Gb1.bytes_to_pages(1 * (1 << 29)), 0);
        assert_eq!(Gb1.bytes_to_pages(1 * (1 << 30)), 1);
        assert_eq!(Gb1.bytes_to_pages(4 * (1 << 30) - 1), 3);
        assert_eq!(Gb1.bytes_to_pages(4 * (1 << 30)), 4);
        assert_eq!(Gb1.bytes_to_pages(4 * (1 << 30) + 1), 4);
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
