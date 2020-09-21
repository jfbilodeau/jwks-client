#[derive(Debug)]
pub struct Error {
    /// Debug message associated with error
    pub msg: &'static str,
    pub kind: ErrorKind,
}

/// Type of error encountered
#[derive(Debug)]
pub enum ErrorKind {
    /// An error decoding or validating a token
    JwtDecodeError(Box<jsonwebtoken::errors::ErrorKind>),
    /// Problem with key
    Key,
    /// Could not download key set
    Connection,
    /// Unsupported key type, only RSA is currently supported
    UnsupportedKeyType(String),
    /// Algorithm mismatch - algorithm of token doesn't match intended algorithm of key
    AlgorithmMismatch,
    /// Internal problem (Signals a serious bug or fatal error)
    Internal,
}

pub(crate) fn err(msg: &'static str, kind: ErrorKind) -> Error {
    Error { msg, kind }
}

pub(crate) fn err_key(msg: &'static str) -> Error {
    err(msg, ErrorKind::Key)
}

pub(crate) fn err_con(msg: &'static str) -> Error {
    err(msg, ErrorKind::Connection)
}

pub(crate) fn err_int(msg: &'static str) -> Error {
    err(msg, ErrorKind::Internal)
}

pub(crate) fn err_jwt(error: jsonwebtoken::errors::Error) -> Error {
    err("", ErrorKind::JwtDecodeError(Box::new(error.into_kind())))
}

#[cfg(test)]
mod tests {}
