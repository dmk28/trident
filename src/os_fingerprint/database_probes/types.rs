use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct DatabaseInfo {
    pub service_type: String,
    pub version: Option<String>,
    pub authentication_required: bool,
    pub anonymous_access_possible: bool,
    pub case_sensitive: Option<bool>,
    pub handshake_steps: u8,
    pub additional_info: HashMap<String, String>,
    pub raw_banner: Option<String>,
}

#[derive(Debug)]
pub enum DatabaseProbeError {
    ConnectionFailed(std::io::Error),
    Timeout,
    ProtocolError(String),
    InvalidResponse,
}

impl From<std::io::Error> for DatabaseProbeError {
    fn from(error: std::io::Error) -> Self {
        DatabaseProbeError::ConnectionFailed(error)
    }
}

impl std::fmt::Display for DatabaseProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseProbeError::ConnectionFailed(e) => write!(f, "Connection failed: {}", e),
            DatabaseProbeError::Timeout => write!(f, "Operation timed out"),
            DatabaseProbeError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            DatabaseProbeError::InvalidResponse => write!(f, "Invalid response received"),
        }
    }
}

impl std::error::Error for DatabaseProbeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DatabaseProbeError::ConnectionFailed(e) => Some(e),
            _ => None,
        }
    }
}
