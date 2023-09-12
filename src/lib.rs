//! Serialization and parsing for the Common Log Format.
//!
//! See [clf] for more information about the format.
//!
//! [clf]: https://en.wikipedia.org/wiki/Common_Log_Format

use std::{
    error::Error,
    fmt::Display,
    net::{AddrParseError, IpAddr},
    num::ParseIntError,
    str::FromStr,
};

use chrono::{DateTime, ParseError, Utc};
use http::{status::InvalidStatusCode, StatusCode};

/// A single line in Common Log Format.
///
/// Any field could be missing, which is indicated with a dash (`-`). This struct implements
/// [`FromStr`], which is the intended way of constructing instances.
///
/// # Example
/// ```
/// use common_log_format::LogEntry;
/// let line = "127.0.0.1 user-identifier frank [1996-12-19T16:39:57-08:00] \"GET /apache_pb.gif HTTP/1.0\" 200 2326";
/// let entry: LogEntry = line.parse().unwrap();
/// ```
/// Dashes represent missing fields:
/// ```
/// use common_log_format::LogEntry;
/// let line = "127.0.0.1 - - [1996-12-19T16:39:57-08:00] \"GET /apache_pb.gif HTTP/1.0\" 200 2326";
/// let entry: LogEntry = line.parse().unwrap();
/// ```
/// `LogEntry` implements `serde::Serialize` and `serde::Deserialize`:
/// ```
/// use common_log_format::LogEntry;
/// let line = "127.0.0.1 - - [1996-12-19T16:39:57-08:00] \"GET /apache_pb.gif HTTP/1.0\" 200 2326";
/// let entry: LogEntry = line.parse().unwrap();
/// let s = serde_json::to_string(&entry).unwrap();
/// let de_entry: LogEntry = serde_json::from_str(&s).unwrap();
/// assert_eq!(de_entry, entry);
/// ```
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LogEntry {
    pub host: Option<IpAddr>,
    pub ident: Option<String>,
    pub authuser: Option<String>,
    pub time: Option<chrono::DateTime<Utc>>,
    pub request_line: Option<String>,
    #[serde(
        serialize_with = "serialize_status_code",
        deserialize_with = "deserialize_status_code"
    )]
    pub status_code: Option<StatusCode>,
    pub object_size: Option<usize>,
}

fn serialize_status_code<S>(sc: &Option<StatusCode>, ser: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::Serialize;
    sc.map(|s| s.as_u16()).serialize(ser)
}

fn deserialize_status_code<'de, D>(de: D) -> Result<Option<StatusCode>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match <Option<u16> as serde::Deserialize<'de>>::deserialize(de)? {
        Some(sc) => match StatusCode::from_u16(sc) {
            Ok(s) => Ok(Some(s)),
            Err(_) => Ok(None),
        },
        None => Ok(None),
    }
}

/// An error parsing a [`LogEntry`].
#[derive(Debug)]
pub enum LogEntryParseError {
    FieldNotFound,
    IpAddrParse(AddrParseError),
    DateTimeParse(ParseError),
    StatusCodeParse(InvalidStatusCode),
    SizeParse(ParseIntError),
}

impl Display for LogEntryParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error parsing log entry")
    }
}

impl Error for LogEntryParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::FieldNotFound => None,
            Self::IpAddrParse(ref e) => Some(e),
            Self::DateTimeParse(ref e) => Some(e),
            Self::StatusCodeParse(ref e) => Some(e),
            Self::SizeParse(ref e) => Some(e),
        }
    }
}

impl FromStr for LogEntry {
    type Err = LogEntryParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, remaining) = peel_ip(s)?;
        let (ident, remaining) = peel_string(remaining)?;
        let (authuser, remaining) = peel_string(remaining)?;
        let (time, remaining) = peel_timestamp(remaining)?;
        let (request_line, remaining) = peel_quoted_string(remaining)?;
        let (status_code, remaining) = peel_status_code(remaining)?;
        let (object_size, _remaining) = peel_usize(remaining)?;

        Ok(LogEntry {
            host,
            ident: ident.map(str::to_owned),
            authuser: authuser.map(str::to_owned),
            time,
            request_line: request_line.map(str::to_owned),
            status_code,
            object_size,
        })
    }
}

/// Take an [`IpAddr`] from the start of `line`.
///
/// Return None (and the remainder) if the string starts with `-`
pub fn peel_ip(line: &str) -> Result<(Option<IpAddr>, &str), LogEntryParseError> {
    let first_space_idx = line.find(' ').unwrap_or(line.len());
    let rem = line[first_space_idx..].trim_start();
    match line.chars().next() {
        None => unreachable!(),
        Some(x) if x == '-' => return Ok((None, rem)),
        Some(_) => (),
    }
    let ip_addr = line[..first_space_idx]
        .parse()
        .map_err(LogEntryParseError::IpAddrParse)?;
    Ok((Some(ip_addr), rem))
}

/// Take a [`usize`] from the start of `line` until the first whitespace.
///
/// Return None (and the remainder) if the string starts with `-`
pub fn peel_usize(line: &str) -> Result<(Option<usize>, &str), LogEntryParseError> {
    let first_space_idx = line.find(' ').unwrap_or(line.len());
    let rem = line[first_space_idx..].trim_start();
    match line.chars().next() {
        None => unreachable!(),
        Some(x) if x == '-' => return Ok((None, rem)),
        Some(_) => (),
    }
    Ok((
        Some(
            line[..first_space_idx]
                .parse()
                .map_err(LogEntryParseError::SizeParse)?,
        ),
        rem,
    ))
}

/// Take a [`str`] from the start of `line` until the first whitespace.
///
/// Return None (and the remainder) if the string starts with `-`
pub fn peel_string(line: &str) -> Result<(Option<&str>, &str), LogEntryParseError> {
    let first_space_idx = line.find(' ').unwrap_or(line.len());
    let rem = line[first_space_idx..].trim_start();
    match line.chars().next() {
        None => unreachable!(),
        Some(x) if x == '-' => return Ok((None, rem)),
        Some(_) => (),
    }
    Ok((Some(&line[..first_space_idx]), rem))
}

/// Take a [`str`] from the start of `line` delimited by quotation marks (`"`).
///
/// Return None (and the remainder) if the string starts with `-`
pub fn peel_quoted_string(line: &str) -> Result<(Option<&str>, &str), LogEntryParseError> {
    match line.chars().next() {
        Some(x) if x == '-' => {
            return Ok((None, line[1..].trim_start()));
        }
        Some(x) if x == '"' => (),
        None | Some(_) => return Err(LogEntryParseError::FieldNotFound),
    }
    let rest = &line[1..];
    let string_end_idx = rest.find('"').ok_or(LogEntryParseError::FieldNotFound)?;
    Ok((
        Some(&rest[..string_end_idx]),
        rest[string_end_idx + 1..].trim_start(),
    ))
}

/// Take a [`DateTime`] from the start of `line` until the first whitespace.
///
/// Use the strftime format "%d/%b/%Y:%H:%M:%S %z". Return None (and the remainder) if the string
/// starts with `-`
pub fn peel_timestamp(line: &str) -> Result<(Option<DateTime<Utc>>, &str), LogEntryParseError> {
    match line.chars().next() {
        Some(x) if x == '-' => {
            return Ok((None, line[1..].trim_start()));
        }
        Some(x) if x == '[' => (),
        None | Some(_) => return Err(LogEntryParseError::FieldNotFound),
    }

    let time_end_idx = line.find(']').ok_or(LogEntryParseError::FieldNotFound)?;
    let dt = DateTime::parse_from_rfc3339(&line[1..time_end_idx])
        .map_err(LogEntryParseError::DateTimeParse)?;
    Ok((Some(dt.into()), line[time_end_idx + 1..].trim_start()))
}

/// Take a [`StatusCode`] from the start of `line` until the first whitespace.
///
/// Return None (and the remainder) if the string starts with `-`
///
/// # Example
/// ```rust
/// use http::StatusCode;
/// let remainder = "200 2326";
/// let (sc, rem) = common_log_format::peel_status_code(remainder).unwrap();
/// assert_eq!(sc.unwrap(), StatusCode::from_u16(200).unwrap());
/// assert_eq!(rem, "2326");
/// ```
pub fn peel_status_code(line: &str) -> Result<(Option<StatusCode>, &str), LogEntryParseError> {
    let first_space_idx = line.find(' ').unwrap_or(line.len());
    let rem = line[first_space_idx..].trim_start();
    match line.chars().next() {
        None => unreachable!(),
        Some(x) if x == '-' => return Ok((None, rem)),
        Some(_) => (),
    }
    Ok((
        Some(
            line[..first_space_idx]
                .parse()
                .map_err(LogEntryParseError::StatusCodeParse)?,
        ),
        rem,
    ))
}
