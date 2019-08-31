use std::{error::Error as StdErr, io, str::FromStr};

use crate::{Error, Result};

pub fn parse<T, R>(mut reader: R) -> Result<T>
where
    T: FromStr,
    <T as FromStr>::Err: StdErr + Sync + Send + 'static,
    R: io::Read,
{
    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;
    buf.trim().parse::<T>().map_err(Error::parse)
}

pub fn parse_next<T, I, S>(iter: I) -> Result<T>
where
    T: FromStr,
    <T as FromStr>::Err: StdErr + Sync + Send + 'static,
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    match iter.into_iter().next() {
        Some(s) => s.as_ref().parse::<T>().map_err(Error::parse),
        None => {
            bail_parse!();
        }
    }
}

pub fn parse_vec<T, R>(mut reader: R) -> Result<Vec<T>>
where
    T: FromStr,
    <T as FromStr>::Err: StdErr + Sync + Send + 'static,
    R: io::Read,
{
    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;

    buf.split_whitespace()
        .map(|e| e.parse::<T>().map_err(Error::parse))
        .collect()
}

pub fn parse_01_bool<R: io::Read>(reader: R) -> Result<bool> {
    parse::<i32, _>(reader).and_then(|n| match n {
        0 => Ok(false),
        1 => Ok(true),
        _ => {
            bail_parse!();
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;

    #[test]
    fn test_parse() {
        assert_eq!(parse::<i32, _>("42".as_bytes()).unwrap(), 42);
        assert_eq!(parse::<bool, _>("true".as_bytes()).unwrap(), true);

        assert_eq!(
            parse::<i32, _>("invalid".as_bytes()).unwrap_err().kind(),
            ErrorKind::Parse
        );
    }

    #[test]
    fn test_parse_next() {
        use std::iter;

        assert_eq!(parse_next::<i32, _, _>(Some("42")).unwrap(), 42);
        assert_eq!(parse_next::<bool, _, _>(iter::once("true")).unwrap(), true);

        assert_eq!(
            parse_next::<i32, _, _>(Some("invalid")).unwrap_err().kind(),
            ErrorKind::Parse
        );
        assert_eq!(
            parse_next::<i32, _, &str>(None).unwrap_err().kind(),
            ErrorKind::Parse
        );
        assert_eq!(
            parse_next::<i32, _, &str>(iter::empty())
                .unwrap_err()
                .kind(),
            ErrorKind::Parse
        );
    }

    #[test]
    fn test_parse_vec() {
        assert_eq!(parse_vec::<i32, _>("".as_bytes()).unwrap(), vec![]);

        assert_eq!(parse_vec::<i32, _>("0".as_bytes()).unwrap(), vec![0]);

        assert_eq!(
            parse_vec::<i32, _>("0 1 2 3".as_bytes()).unwrap(),
            vec![0, 1, 2, 3]
        );

        assert_eq!(
            parse_vec::<bool, _>("true false true".as_bytes()).unwrap(),
            vec![true, false, true]
        );

        assert_eq!(
            parse_vec::<i32, _>("0 invalid".as_bytes())
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
