use jwks_client::error::{Error, Type};
use jwks_client::keyset::KeyStore;

#[rustfmt::skip]
#[tokio::main]
async fn main() {
    let url = "https://raw.githubusercontent.com/jfbilodeau/jwks-client/0.1.3/test/test-jwks.json";
    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.eTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";

    let key_set = KeyStore::new_from(url).await.unwrap();

    match key_set.verify(token) {
        Ok(jwt) => {
            println!("name={}", jwt.payload().get_str("name").unwrap());
        }
        Err(Error {
            msg,
            typ: Type::Header,
        }) => {
            eprintln!("Problem with header. Message: {}", msg);
        }
        Err(Error {
            msg,
            typ: Type::Payload,
        }) => {
            eprintln!("Problem with payload. Message: {}", msg);
        }
        Err(Error {
            msg,
            typ: Type::Signature,
        }) => {
            eprintln!("Problem with signature. Message: {}", msg);
        }
        Err(Error {
            msg: _,
            typ: Type::Expired,
        }) => {
            eprintln!("Token is expired.");
        }
        Err(Error {
            msg: _,
            typ: Type::Early,
        }) => {
            eprintln!("Too early to use token.");
        }
        Err(e) => {
            eprintln!("Something else went wrong. Message {:?}", e);
        }
    }
}
