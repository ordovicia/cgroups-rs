use std::{error::Error as StdError, str::FromStr};

use crate::{Error, ErrorKind, Result};

macro_rules! with_doc {
    ($doc: expr, $($tt: tt)*) => {
        #[doc = $doc]
        $($tt)*
    };
}

#[cfg(test)]
macro_rules! make_cgroup_name {
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
macro_rules! gen_resource_test {
    // Test a read-only resource
    ($subsystem: ident; $resource: ident, $default: expr) => {{
        let mut cgroup = Subsystem::new(CgroupPath::new(
            SubsystemKind::$subsystem,
            make_cgroup_name!(),
        ));
        cgroup.create()?;
        assert_eq!(cgroup.$resource()?, $default);
        cgroup.delete()
    }};

    // Test a read-write resource
    ($subsystem: ident; $resource: ident, $default: expr, $setter: ident, $val: expr) => {{
        let mut cgroup = Subsystem::new(CgroupPath::new(
            SubsystemKind::$subsystem,
            make_cgroup_name!(),
        ));
        cgroup.create()?;
        assert_eq!(cgroup.$resource()?, $default);

        cgroup.$setter($val)?;
        assert_eq!(cgroup.$resource()?, $val);

        cgroup.delete()
    }};
}

pub(crate) fn parse<T, R>(mut reader: R) -> Result<T>
where
    T: FromStr,
    <T as FromStr>::Err: StdError + Sync + Send + 'static,
    R: std::io::Read,
{
    let mut buf = String::new();
    reader.read_to_string(&mut buf).map_err(Error::io)?;
    buf.trim().parse::<T>().map_err(Error::parse)
}

pub(crate) fn parse_option<T>(s: Option<&str>) -> Result<T>
where
    T: FromStr,
    <T as FromStr>::Err: StdError + Sync + Send + 'static,
{
    match s {
        Some(s) => s.parse::<T>().map_err(Error::parse),
        None => Err(Error::new(ErrorKind::Parse)),
    }
}

pub(crate) fn parse_01_bool<R: std::io::Read>(reader: R) -> Result<bool> {
    parse::<i32, _>(reader).and_then(|n| match n {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::new(ErrorKind::Parse)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_cgroup_name() {
        assert_eq!(
            make_cgroup_name!(),
            std::path::PathBuf::from("cgroups_rs-util-92")
        );
    }

    #[test]
    fn test_parse() {
        assert_eq!(parse::<i32, _>("42".as_bytes()).unwrap(), 42);
        assert_eq!(parse::<bool, _>("true".as_bytes()).unwrap(), true);
        assert_eq!(
            parse::<i32, _>("".as_bytes()).unwrap_err().kind(),
            ErrorKind::Parse
        );
    }

    #[test]
    fn test_parse_option() {
        assert_eq!(parse_option::<i32>(Some("42")).unwrap(), 42);
        assert_eq!(parse_option::<bool>(Some("true")).unwrap(), true);
        assert_eq!(
            parse_option::<i32>(None).unwrap_err().kind(),
            ErrorKind::Parse
        );
    }

    #[test]
    fn test_parse_01_bool() {
        assert_eq!(parse_01_bool("0".as_bytes()).unwrap(), false);
        assert_eq!(parse_01_bool("1".as_bytes()).unwrap(), true);
        assert_eq!(
            parse_01_bool("2".as_bytes()).unwrap_err().kind(),
            ErrorKind::Parse
        );
        assert_eq!(
            parse_01_bool("invalid".as_bytes()).unwrap_err().kind(),
            ErrorKind::Parse
        );
    }
}
