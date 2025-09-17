use std::fmt;
use std::io;
use std::net::AddrParseError;

#[derive(Debug)]
pub enum ScanError {
    ConnectionRefused,
    TimedOut,
    HostUnreachable,
    NetworkUnreachable,
    PermissionDenied,
    InvalidAddress,
    TooManyOpenFiles,
    NetworkError(io::Error),
    ParseError(AddrParseError),
    RateLimitExceeded,
    SemaphoreError,
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ScanError::ConnectionRefused => write!(f, "Connection refused (port likely closed)"),
            ScanError::TimedOut => write!(f, "Connection timed out (port filtered or host down)"),
            ScanError::HostUnreachable => write!(f, "Host unreachable (routing issue)"),
            ScanError::NetworkUnreachable => write!(f, "Network unreachable (routing issue)"),
            ScanError::PermissionDenied => write!(f, "Permission denied (firewall or privileges)"),
            ScanError::InvalidAddress => write!(f, "Invalid IP address format"),
            ScanError::TooManyOpenFiles => write!(f, "Too many open files (reduce concurrency)"),
            ScanError::NetworkError(e) => write!(f, "Network error: {}", e),
            ScanError::ParseError(e) => write!(f, "Address parsing error: {}", e),
            ScanError::RateLimitExceeded => write!(f, "Rate limit exceeded"),
            ScanError::SemaphoreError => write!(f, "Concurrency control error"),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<io::Error> for ScanError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::ConnectionRefused => ScanError::ConnectionRefused,
            io::ErrorKind::TimedOut => ScanError::TimedOut,
            io::ErrorKind::PermissionDenied => ScanError::PermissionDenied,
            io::ErrorKind::InvalidInput => ScanError::InvalidAddress,
            _ => ScanError::NetworkError(error),
        }
    }
}

impl From<AddrParseError> for ScanError {
    fn from(error: AddrParseError) -> Self {
        ScanError::ParseError(error)
    }
}

/// Helper function to classify network errors into meaningful categories
pub fn classify_network_error(error: &io::Error) -> ScanError {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => ScanError::ConnectionRefused,
        io::ErrorKind::TimedOut => ScanError::TimedOut,
        io::ErrorKind::PermissionDenied => ScanError::PermissionDenied,
        io::ErrorKind::InvalidInput => ScanError::InvalidAddress,
        io::ErrorKind::NotFound => ScanError::HostUnreachable,
        io::ErrorKind::AddrNotAvailable => ScanError::NetworkUnreachable,
        _ => ScanError::NetworkError(error.kind().into()),
    }
}

/// Convert scan error to appropriate port status for reporting
pub fn error_to_port_status(error: &ScanError) -> crate::scanner::structure::PortStatus {
    use crate::scanner::structure::PortStatus;

    match error {
        ScanError::ConnectionRefused => PortStatus::Closed,
        ScanError::TimedOut => PortStatus::Filtered,
        ScanError::HostUnreachable => PortStatus::Filtered,
        ScanError::NetworkUnreachable => PortStatus::Filtered,
        ScanError::PermissionDenied => PortStatus::Filtered,
        _ => PortStatus::Filtered,
    }
}
