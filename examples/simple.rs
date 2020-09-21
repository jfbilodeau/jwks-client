use jwks_client::Error;
use jwks_client::KeyStore;
use serde::Deserialize;

#[tokio::main]
async fn main() {
    let jkws_url = "https://raw.githubusercontent.com/jfbilodeau/jwks-client/0.1.8/test/test-jwks.json";

    let key_set = KeyStore::new_from(jkws_url.to_owned()).await.unwrap();

    // ...

    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.eTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";

    #[derive(Deserialize)]
    struct Claims {
        iss: String,
        name: String,
    }

    let validation = jsonwebtoken::Validation {
        validate_nbf: true,
        validate_exp: true,
        algorithms: vec![jsonwebtoken::Algorithm::RS256], // only the RSA keytype is currently supported
        leeway: 0,
        sub: None,
        aud: None,
        iss: Some("https://chronogears.com/test".to_owned()),
    };

    match key_set.verify(token, &validation) {
        Ok(jsonwebtoken::TokenData { header: _, claims: Claims { iss, name } }) => {
            println!("iss={}", iss);
            println!("name={}", name);
        }
        Err(Error { msg, kind }) => {
            eprintln!("Could not verify token. Reason: {} {:?}", msg, kind);
        }
    }
}
