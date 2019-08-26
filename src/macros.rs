macro_rules! with_doc {
    ($doc: expr, $($tt: tt)*) => {
        #[doc = $doc]
        $($tt)*
    };
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
macro_rules! gen_subsystem_test {
    // Test a read-only resource
    ($subsystem: ident; $resource: ident, $default: expr) => {{
        let mut cgroup = Subsystem::new(CgroupPath::new(
            SubsystemKind::$subsystem,
            gen_cgroup_name!(),
        ));
        cgroup.create()?;
        assert_eq!(cgroup.$resource()?, $default);

        cgroup.delete()
    }};

    // Test a read-write resource
    ($subsystem: ident; $resource: ident, $default: expr, $setter: ident, $val: expr) => {{
        let mut cgroup = Subsystem::new(CgroupPath::new(
            SubsystemKind::$subsystem,
            gen_cgroup_name!(),
        ));
        cgroup.create()?;
        assert_eq!(cgroup.$resource()?, $default);

        cgroup.$setter($val)?;
        assert_eq!(cgroup.$resource()?, $val);

        cgroup.delete()
    }};
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
mod tests {
    use super::*;

    #[test]
    fn test_gen_cgroup_name() {
        assert_eq!(
            gen_cgroup_name!(),
            std::path::PathBuf::from("cgroups_rs-macros-69")
        );
    }
}
