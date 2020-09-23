macro_rules! with_doc {
    ($doc: expr, $( $tt: tt )*) => {
        #[doc = $doc]
        $( $tt )*
    };
}

macro_rules! bail_parse {
    () => {
        return Err(crate::Error::new(crate::ErrorKind::Parse));
    };
}

#[cfg(test)]
macro_rules! gen_cgroup_name {
    () => {
        std::path::PathBuf::from(format!(
            "controlgroup_rs-{}-{}",
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
        #[allow(unused_mut, clippy::let_and_return)]

        let mut hashmap = std::collections::HashMap::new();
        $( hashmap.insert($k, $v); )*
        hashmap
    } };
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_gen_cgroup_name() {
        assert_eq!(
            gen_cgroup_name!(),
            std::path::PathBuf::from("controlgroup_rs-macros-58")
        );
    }

    #[test]
    fn test_hashmap() {
        assert_eq!(
            hashmap! { (0, "zero"), (1, "one") },
            [(0, "zero"), (1, "one")]
                .iter()
                .copied()
                .collect::<std::collections::HashMap<_, _>>()
        );
    }
}
