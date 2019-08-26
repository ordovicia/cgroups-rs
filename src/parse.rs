use std::{error::Error as StdErr, str::FromStr};

use crate::{Error, ErrorKind, Result};

pub fn parse<T, R>(mut reader: R) -> Result<T>
where
    T: FromStr,
    <T as FromStr>::Err: StdErr + Sync + Send + 'static,
    R: std::io::Read,
{
    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;
    buf.trim().parse::<T>().map_err(Error::parse)
}

pub fn parse_option<T>(s: Option<&str>) -> Result<T>
where
    T: FromStr,
    <T as FromStr>::Err: StdErr + Sync + Send + 'static,
{
    match s {
        Some(s) => s.parse::<T>().map_err(Error::parse),
        None => Err(Error::new(ErrorKind::Parse)),
    }
}

pub fn parse_vec<T, R>(mut reader: R) -> Result<Vec<T>>
where
    T: FromStr,
    <T as FromStr>::Err: StdErr + Sync + Send + 'static,
    R: std::io::Read,
{
    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;

    buf.split_whitespace()
        .map(|e| e.parse::<T>().map_err(Error::parse))
        .collect()
}

pub fn parse_01_bool<R: std::io::Read>(reader: R) -> Result<bool> {
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
    fn test_parse_vec() {
        assert_eq!(parse_vec::<i32, _>("".as_bytes()).unwrap(), vec![]);
        assert_eq!(
            parse_vec::<i32, _>("0 1 2 3".as_bytes()).unwrap(),
            vec![0, 1, 2, 3]
        );
        assert_eq!(
            parse_vec::<bool, _>("true false true".as_bytes()).unwrap(),
            vec![true, false, true]
        );
        assert_eq!(
            parse_vec::<i32, _>("foo bar".as_bytes())
                .unwrap_err()
                .kind(),
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