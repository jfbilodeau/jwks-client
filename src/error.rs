#[derive(Debug)]
pub struct Error {
    msg: &'static str,
    typ: ErrorType,
}

#[derive(Debug)]
pub enum ErrorType {
    Invalid,
    Expired,
    Certificate,
    Key,
    Connection,
    // Could not decode payload
    Header,
    Signature,
    Payload,
    Internal,
}

pub fn err(msg: &'static str, typ: ErrorType) -> Error {
    Error {
        msg,
        typ
    }
}

pub fn err_inv(msg: &'static str) -> Error {
    err(msg, ErrorType::Invalid)
}

pub fn err_exp(msg: &'static str) -> Error {
    err(msg, ErrorType::Expired)
}

pub fn err_cer(msg: &'static str) -> Error {
    err(msg, ErrorType::Certificate)
}

pub fn err_key(msg: &'static str) -> Error {
    err(msg, ErrorType::Key)
}

pub fn err_con(msg: &'static str) -> Error {
    err(msg, ErrorType::Connection)
}

pub fn err_hea(msg: &'static str) -> Error {
    err(msg, ErrorType::Header)
}

pub fn err_pay(msg: &'static str) -> Error {
    err(msg, ErrorType::Payload)
}

pub fn err_sig(msg: &'static str) -> Error {
    err(msg, ErrorType::Signature)
}

pub fn err_int(msg: &'static str) -> Error {
    err(msg, ErrorType::Internal)
}

#[cfg(test)]
mod tests {

}
