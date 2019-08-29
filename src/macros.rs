macro_rules! with_doc {
    ($doc: expr, $( $tt: tt )*) => {
        #[doc = $doc]
        $( $tt )*
    };
}

macro_rules! subsystem_file {
    ($subsystem: ident, $field: ident) => {
        concat!(stringify!($subsystem), ".", stringify!($field))
    };
}

macro_rules! gen_doc {
    (reads; $subsystem: ident, $desc: literal $( : $detail: literal )?, $field: ident) => { concat!(
        "Reads ", $desc, " from `", subsystem_file!($subsystem, $field), "` file.",
        $( " ", $detail, )? "\n\n",
     ) };

    (sets; $subsystem: ident, $desc: literal $( : $detail: literal )?, $field: ident) => { concat!(
        "Sets ", $desc, " by writing to `", subsystem_file!($subsystem, $field), "` file.",
        $( " ", $detail, )? "\n\n",
    ) };

    (see $(; $field: ident )?)  => { concat!(
        "See"
        $(, " [`Resources.", stringify!($field), "`]",
            "(struct.Resources.html#structfield.", stringify!($field), ") and" )?,
        " the kernel's documentation for more information about this field.\n\n"
    ) };

    (err_read; $subsystem: ident, $field: ident) => { concat!(
        "# Errors\n\n",
        "Returns an error if failed to read and parse `",
        subsystem_file!($subsystem, $field), "` file of this cgroup.\n\n"
    ) };

    (err_write; $subsystem: ident, $field: ident) => { concat!(
        "# Errors\n\n",
        "Returns an error if failed to write to `",
        subsystem_file!($subsystem, $field), "` file of this cgroup.\n\n"
    ) };

    (eg_read; $subsystem: ident, $kind: ident, $field: ident $(, $val: expr )*) => { concat!(
"# Examples

```no_run
# fn main() -> cgroups::Result<()> {
use std::path::PathBuf;
use cgroups::v1::{", stringify!($subsystem), ", Cgroup, CgroupPath, SubsystemKind};

let cgroup = ", stringify!($subsystem), "::Subsystem::new(
    CgroupPath::new(SubsystemKind::", stringify!($kind), ", PathBuf::from(\"students/charlie\")));

let ", stringify!($field), " = cgroup.", stringify!($field), "(", stringify!($( $val ),* ), ")?;
# Ok(())
# }
```") };

    (eg_write; $subsystem: ident, $kind: ident, $setter: ident $(, $val: expr )*) => { concat!(
"# Examples

```no_run
# fn main() -> cgroups::Result<()> {
use std::path::PathBuf;
use cgroups::v1::{", stringify!($subsystem), ", Cgroup, CgroupPath, SubsystemKind};

let mut cgroup = ", stringify!($subsystem), "::Subsystem::new(
    CgroupPath::new(SubsystemKind::", stringify!($kind), ", PathBuf::from(\"students/charlie\")));

cgroup.", stringify!($setter), "(", stringify!($( $val ),* ), ")?;
# Ok(())
# }
```") };
}

macro_rules! gen_getter {
    (
        $subsystem: ident,
        $kind: ident,
        $desc: literal $( : $detail: literal )?,
        $field: ident $( : $link : ident )?,
        $ty: ty,
        $parser: ident
    ) => { with_doc! { concat!(
        gen_doc!(reads; $subsystem, $desc $( : $detail )?, $field),
        _link!($field $( : $link )?),
        gen_doc!(err_read; $subsystem, $field),
        gen_doc!(eg_read; $subsystem, $kind, $field)),
        pub fn $field(&self) -> Result<$ty> {
            self.open_file_read(subsystem_file!($subsystem, $field)).and_then($parser)
        }
    } };
}

macro_rules! gen_setter {
    (
        $subsystem: ident,
        $kind: ident,
        $desc: literal $( : $detail: literal )?,
        $field: ident $( : $link: ident )?,
        $setter: ident,
        $ty: ty,
        $( $val: expr ),*
    ) => { with_doc! { concat!(
        gen_doc!(sets; $subsystem, $desc $( : $detail )?, $field),
        _link!($field $( : $link )?),
        gen_doc!(err_write; $subsystem, $field),
        gen_doc!(eg_write; $subsystem, $kind, $setter, $( $val ),*)),
        pub fn $setter(&mut self, $field: $ty) -> Result<()> {
            self.write_file(subsystem_file!($subsystem, $field), $field)
        }
    } };

    (
        $subsystem: ident,
        $kind: ident,
        $desc: literal $( : $detail: literal )?,
        $field: ident $( : $link : ident )?,
        $setter: ident,
        $arg: ident : $ty: ty $( as $as: ty )?,
        $( $val: expr ),*
    ) => { with_doc! { concat!(
        gen_doc!(sets; $subsystem, $desc $( : $detail )?, $field),
        _link!($field $( : $link )?),
        gen_doc!(err_write; $subsystem, $field),
        gen_doc!(eg_write; $subsystem, $kind, $setter, $( $val ),*)),
        pub fn $setter(&mut self, $arg: $ty) -> Result<()> {
            self.write_file(subsystem_file!($subsystem, $field), $arg $( as $as )?)
        }
    } };
}

macro_rules! _link {
    ($field: ident : link) => {
        gen_doc!(see; $field);
    };
    ($field: ident) => {
        gen_doc!(see);
    }
}

#[cfg(test)]
macro_rules! gen_cgroup_name {
    () => {
        std::path::PathBuf::from(format!(
            "cgroups_rs-{}-{}",
            std::path::Path::new(file!())
                .file_stem()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap(),
            line!()
        ))
    };
}

#[cfg(test)]
macro_rules! hashmap {
    ( $( ( $k: expr, $v: expr $(, )? ) ),* $(, )? ) => { {
        #[allow(unused_mut)]
        let mut hashmap = HashMap::new();
        $( hashmap.insert($k, $v); )*
        hashmap
    } };
}

#[cfg(test)]
macro_rules! gen_subsystem_test {
    // Test create, file_exists, and delete
    ($kind: ident; $subsystem: ident, [ $( $file: literal ),* ]) => { {
        let files = vec![$(
            format!("{}.{}", stringify!($subsystem), $file)
        ),+];

        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::$kind, gen_cgroup_name!()));
        cgroup.create()?;

        assert!(files.iter().all(|f| cgroup.file_exists(f)));
        assert!(!cgroup.file_exists("does_not_exist"));

        cgroup.delete()?;
        assert!(files.iter().all(|f| !cgroup.file_exists(f)));

        let ok: Result<()> = Ok(());
        ok
    } };

    // Test a read-only field
    ($kind: ident; $field: ident, $default: expr) => { {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::$kind, gen_cgroup_name!()));
        cgroup.create()?;
        assert_eq!(cgroup.$field()?, $default);

        cgroup.delete()
    } };

    // Test a read-write field
    ($kind: ident; $field: ident, $default: expr, $setter: ident, $val: expr) => { {
        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::$kind, gen_cgroup_name!()));
        cgroup.create()?;
        assert_eq!(cgroup.$field()?, $default);

        cgroup.$setter($val)?;
        assert_eq!(cgroup.$field()?, $val);

        cgroup.delete()
    } };
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_gen_cgroup_name() {
        assert_eq!(
            gen_cgroup_name!(),
            std::path::PathBuf::from("cgroups_rs-macros-215")
        );
    }
}
