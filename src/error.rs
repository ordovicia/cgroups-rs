use std::{error::Error as StdError, fmt};

/// Result type returned from this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type that can be returned from this crate, in the `Result::Err` variant. The lower-level
/// source of this error can be obtained by using `source` method.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    source: Option<Box<dyn StdError + Sync + Send + 'static>>,
}

/// Kinds of errors that can occur while operating on cgroups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Failed to do an I/O operation on a cgroup file system.
    Io,

    /// Failed to parse contents in a cgroup file into a value.
    ///
    /// In the future, there will be some information attached to this variant.
    Parse,

    /// Failed to apply a value to a cgruop.
    Apply,

    /// You tried to do something invalid.
    InvalidOperation,
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self.source {
            Some(ref x) => Some(&**x),
            None => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self.kind {
                ErrorKind::Io => "unable to do an I/O operation on a cgroup file system",
                ErrorKind::Parse => "unable to parse contents in a cgroup file",
                ErrorKind::Apply => "unable to apply a value to a cgroup",
                ErrorKind::InvalidOperation => "the requested operation is invalid",
            }
        )?;

        if let Some(ref source) = self.source {
            write!(f, ": {}", source)?;
        }

        Ok(())
    }
}

impl Error {
    pub(crate) fn new(kind: ErrorKind) -> Self {
        Self { kind, source: None }
    }

    pub(crate) fn with_source<E>(kind: ErrorKind, source: E) -> Self
    where
        E: StdError + Sync + Send + 'static,
    {
        Self {
            kind,
            source: Some(Box::new(source)),
        }
    }

    /// Returns the kind of this error.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub(crate) fn io<E>(source: E) -> Self
    where
        E: StdError + Sync + Send + 'static,
    {
        Self::with_source(ErrorKind::Io, source)
    }

    pub(crate) fn parse<E>(source: E) -> Self
    where
        E: StdError + Sync + Send + 'static,
    {
        Self::with_source(ErrorKind::Parse, source)
    }
}
