#[cfg(test)]
macro_rules! gen_test_subsystem_create_delete {
    ($kind: ident, $( $file: expr ),* $(, )?) => { {
        use crate::v1::{Cgroup, CgroupPath, SubsystemKind};

        let mut cgroup = Subsystem::new(
            CgroupPath::new(SubsystemKind::$kind, gen_cgroup_name!()));
        $( assert!(!cgroup.file_exists($file)); )*

        cgroup.create()?;
        $( assert!(cgroup.file_exists($file)); )*
        assert!(!cgroup.file_exists("does_not_exist"));

        cgroup.delete()?;
        $( assert!(!cgroup.file_exists($file)); )*

        let ok: Result<()> = Ok(());
        ok
    } }
}

#[cfg(test)]
macro_rules! gen_test_subsystem_apply {
    ($kind: ident, $resources: expr, $( ($field: ident, $val: expr) ),* $(, )?) => { {
        use crate::v1::{Cgroup, CgroupPath, SubsystemKind};

        let mut cgroup = Subsystem::new(
            CgroupPath::new(SubsystemKind::$kind, gen_cgroup_name!()));
        cgroup.create()?;

        cgroup.apply(&$resources.into())?;
        $( assert_eq!(cgroup.$field()?, $val); )*

        cgroup.delete()
    } }
}

#[cfg(test)]
macro_rules! gen_test_subsystem_get {
    ($kind: ident, $getter: ident, $default: expr) => {{
        use crate::v1::{Cgroup, CgroupPath, SubsystemKind};

        let mut cgroup = Subsystem::new(CgroupPath::new(SubsystemKind::$kind, gen_cgroup_name!()));
        cgroup.create()?;
        assert_eq!(cgroup.$getter()?, $default);

        cgroup.delete()
    }};
}

#[cfg(test)]
macro_rules! gen_test_subsystem_get_set {
    ($kind: ident, $getter: ident, $default: expr, $setter: ident, $( $val: expr ),+ $(, )?) => { {
        use crate::v1::{Cgroup, CgroupPath, SubsystemKind};

        let mut cgroup = Subsystem::new(
            CgroupPath::new(SubsystemKind::$kind, gen_cgroup_name!()));
        cgroup.create()?;
        assert_eq!(cgroup.$getter()?, $default);

        $(
            cgroup.$setter($val)?;
            assert_eq!(cgroup.$getter()?, $val);
        )+

        cgroup.delete()
    } }
}

#[cfg(test)]
macro_rules! gen_test_subsystem_err {
    ($kind: ident, $getter: ident, $( ( $err: ident, $( $arg: expr ),* $(, )? ) ),* $(, )?) => { {
        use crate::{ErrorKind, v1::{CgroupPath, SubsystemKind}};

        let mut cgroup = Subsystem::new(
            CgroupPath::new(SubsystemKind::$kind, gen_cgroup_name!()));
        cgroup.create()?;

        $(
            assert_eq!(cgroup.$getter($( $arg ),*).unwrap_err().kind(), ErrorKind::$err);
        )*

        cgroup.delete()
    } }
}