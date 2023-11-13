use std::array;
use std::fmt;
use std::io;

#[derive(Debug)]
pub enum DnsError {
  Io(io::Error),
  Convert(array::TryFromSliceError),
  Regular(ErrorKind),
  Other(String),
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorKind {
  ParseError { field: String },
  ConfigError { field: String },
  Other,
}

impl From<&str> for DnsError {
  fn from(incoming: &str) -> DnsError {
    DnsError::Other(incoming.to_string())
  }
}

impl From<io::Error> for DnsError {
  fn from(err: io::Error) -> DnsError {
    DnsError::Io(err)
  }
}

impl From<array::TryFromSliceError> for DnsError {
  fn from(err: array::TryFromSliceError) -> DnsError {
    DnsError::Regular(ErrorKind::ConfigError {
      field: "tx_id".to_string(),
    })
  }
}

/*
impl From<Deserializer::Error> for DnsError {
  fn from(err: Deserializer::Error) -> DnsError {
    DnsError::Other(err)
  }
}
*/

impl ErrorKind {
  fn as_str(&self) -> &str {
    match *self {
      ErrorKind::ConfigError { field: _ } => "configuration error",
      ErrorKind::ParseError { field: _ } => "parse error",
      ErrorKind::Other => "other error",
    }
  }
}

impl fmt::Display for DnsError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      DnsError::Regular(ref err) => write!(f, "{:?}", err),
      DnsError::Other(ref err) => write!(f, "{:?}", err),
      DnsError::Io(ref err) => err.fmt(f),
      DnsError::Convert(ref err) => err.fmt(f),
    }
  }
}

/// Easy formatting for errors as they come in.
///
/// example:
///
/// ```
/// use hm::hmerror;
/// let _a = "src/config.toml";
/// let _e = "my_dummy_error";
/// hmerror::error(
///  format!("Couldn't open specified config file `{}`", _a).as_str(),
///  _e,
/// );
/// ```

pub type Result<T> = std::result::Result<T, DnsError>;
