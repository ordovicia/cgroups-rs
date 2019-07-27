use std::{error::Error as StdError, fs::File, str::FromStr};

use crate::{Error, ErrorKind, Result};

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

pub(crate) fn parse_file<T>(mut file: File) -> Result<T>
where
    T: FromStr,
    <T as FromStr>::Err: StdError + Send + 'static,
{
    use std::io::Read;

    let mut buf = String::new();
    file.read_to_string(&mut buf).map_err(Error::io)?;
    buf.trim().parse::<T>().map_err(Error::parse)
}

pub(crate) fn parse_option<T>(s: Option<&str>) -> Result<T>
where
    T: FromStr,
    <T as FromStr>::Err: StdError + Send + 'static,
{
    match s {
        Some(s) => s.parse::<T>().map_err(Error::parse),
        None => Err(Error::new(ErrorKind::Parse)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_cgroup_name() {
        assert_eq!(
            make_cgroup_name!(),
            std::path::PathBuf::from("cgroups_rs-util-49")
        );
    }

    #[test]
    fn test_parse_option() {
        assert_eq!(parse_option::<i32>(Some("42")).unwrap(), 42);
        assert_eq!(
            parse_option::<i32>(None).unwrap_err().kind(),
            ErrorKind::Parse
        );
    }
}
