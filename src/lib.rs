pub mod error;
pub mod jwt;
pub mod jwks;

#[cfg(test)]
mod tests {
    use serde_derive::{Deserialize, Serialize};

    use crate::jwks::{JwtKey, KeyStore};
    use std::time::{SystemTime, Duration};

//    const IAT: u64 = 200;
    const NBF: u64 = 300;
    const EXP: u64 = 500;

//    static HEADER: Value = json!({
//        "alg": "RS256",
//        "typ": "JWT",
//        "kid": "1"
//    });
//
//    static PAYLOAD: Value = json!({
//        "name": "Ada Lovelace",
//        "iss": "https://chronogears.com/test",
//        "aud": "test",
//        "auth_time": 100,
//        "user_id": "uid123",
//        "sub": "sbu123",
//        "iat": IAT,
//        "exp": EXP,
//        "nbf": NBF,
//        "email": "alovelace@chronogears.com"
//    });

    const E: &str = "AQAB";
    const N: &str = "t5N44H1mpb5Wlx_0e7CdoKTY8xt-3yMby8BgNdagVNkeCkZ4pRbmQXRWNC7qn__Zaxx9dnzHbzGCul5W0RLfd3oB3PESwsrQh-oiXVEPTYhvUPQkX0vBfCXJtg_zY2mY1DxKOIiXnZ8PaK_7Sx0aMmvR__0Yy2a5dIAWCmjPsxn-PcGZOkVUm-D5bH1-ZStcA_68r4ZSPix7Szhgl1RoHb9Q6JSekyZqM0Qfwhgb7srZVXC_9_m5PEx9wMVNYpYJBrXhD5IQm9RzE9oJS8T-Ai-4_5mNTNXI8f1rrYgffWS4wf9cvsEihrvEg9867B2f98L7ux9Llle7jsHCtwgV1w";
    const N_INVALID: &str = "xt5N44H1mpb5Wlx_0e7CdoKTY8xt-3yMby8BgNdagVNkeCkZ4pRbmQXRWNC7qn__Zaxx9dnzHbzGCul5W0RLfd3oB3PESwsrQh-oiXVEPTYhvUPQkX0vBfCXJtg_zY2mY1DxKOIiXnZ8PaK_7Sx0aMmvR__0Yy2a5dIAWCmjPsxn-PcGZOkVUm-D5bH1-ZStcA_68r4ZSPix7Szhgl1RoHb9Q6JSekyZqM0Qfwhgb7srZVXC_9_m5PEx9wMVNYpYJBrXhD5IQm9RzE9oJS8T-Ai-4_5mNTNXI8f1rrYgffWS4wf9cvsEihrvEg9867B2f98L7ux9Llle7jsHCtwgV1w==";
    const TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.eTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";
    const TOKEN_INV_CERT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.XXXeTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";

    #[derive(Debug, Serialize, Deserialize)]
    pub struct TestPayload {
        pub iss: String,
        pub name: String,
        pub email: String,
    }

    #[test]
    fn test_new_with_url() {
        let validator = KeyStore::new_with_url("test_url");

        assert_eq!("test_url", validator.jkws_url())
    }

    #[test]
    fn test_refresh_keys() {
        const URL: &str = "https://raw.githubusercontent.com/jfbilodeau/jwks-client/master/test/test-jwks.json";

        let mut validator = KeyStore::new_with_url(URL);

        let result = validator.refresh_keys();

        assert!(result.is_ok());
        assert_eq!(URL, validator.jkws_url());
        assert!(validator.keys_len() > 0);
    }

    #[test]
    fn test_add_key() {
        let key = JwtKey::new("1", N, E);

        let mut validator = KeyStore::new();

        assert_eq!(0usize, validator.keys_len());

        validator.add_key(&key);

        assert_eq!(1usize, validator.keys_len());

        let result = validator.key_by_id("1");

        assert!(result.is_some());

        let key = result.unwrap();

        assert_eq!(N, key.n);
        assert_eq!(E, key.e);
        assert_eq!("1", key.kid);
    }

    #[test]
    fn test_get_key() {
        let key = JwtKey::new("1", N, E);

        let mut validator = KeyStore::new();

        assert_eq!(0usize, validator.keys_len());

        validator.add_key(&key);

        assert_eq!(1usize, validator.keys_len());

        let result = validator.key_by_id("1");

        assert!(result.is_some());

        let result = validator.key_by_id("2");

        assert!(result.is_none());
    }

    #[test]
    fn test_decode_custom_payload() {
        let key = JwtKey::new("1", N, E);

        let mut validator = KeyStore::new();

        validator.add_key(&key);

        let result = validator.decode(TOKEN);

        assert!(result.is_ok());

        let jwt = result.unwrap();

        let payload = jwt.payload().load_into::<TestPayload>().unwrap();

        assert_eq!("https://chronogears.com/test", payload.iss);
        assert_eq!("Ada Lovelace", payload.name);
        assert_eq!("alovelace@chronogears.com", payload.email);
    }

    #[test]
    fn test_decode_json_payload() {
        let key = JwtKey::new("1", N, E);

        let mut validator = KeyStore::new();

        validator.add_key(&key);

        let result = validator.decode(TOKEN);

        assert!(result.is_ok());

        let jwt = result.unwrap();

        assert_eq!("https://chronogears.com/test", jwt.payload().iss().unwrap());
        assert_eq!("Ada Lovelace", jwt.payload().get_str("name").unwrap());
        assert_eq!("alovelace@chronogears.com", jwt.payload().get_str("email").unwrap());
    }

    #[test]
    fn test_verify_certificate() {
        let key = JwtKey::new("1", N, E);

        let mut validator = KeyStore::new();

        validator.add_key(&key);

        let result = validator.verify(TOKEN);

        assert!(result.is_ok());

        let jwt = result.unwrap();

        assert_eq!("https://chronogears.com/test", jwt.payload().iss().unwrap());
        assert_eq!("Ada Lovelace", jwt.payload().get_str("name").unwrap());
        assert_eq!("alovelace@chronogears.com", jwt.payload().get_str("email").unwrap());
    }

    #[test]
    fn test_verify_invalid_certificate() {
        let key = JwtKey::new("1", N_INVALID, E);

        let mut validator = KeyStore::new();

        validator.add_key(&key);

        let result = validator.verify(TOKEN);

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let key = JwtKey::new("1", N, E);

        let mut validator = KeyStore::new();

        validator.add_key(&key);

        let result = validator.verify(TOKEN_INV_CERT);

        assert!(result.is_err());
    }

    #[test]
    fn test_expired() {
        let key_store = KeyStore::new();

        let jwk = key_store.decode(TOKEN).unwrap();

        let time = SystemTime::UNIX_EPOCH + Duration::new(EXP+1, 0);

        assert!(jwk.expired_time(time).unwrap());
    }

    #[test]
    fn test_not_expired() {
        let key_store = KeyStore::new();

        let jwk = key_store.decode(TOKEN).unwrap();

        let time = SystemTime::UNIX_EPOCH + Duration::new(EXP-1, 0);

        assert!(!jwk.expired_time(time).unwrap());
    }

    #[test]
    fn test_nbf() {
        let validator = KeyStore::new();

        let jwk = validator.decode(TOKEN).unwrap();

        let time = SystemTime::UNIX_EPOCH + Duration::new(NBF-1, 0);

        assert!(jwk.early_time(time).unwrap());
    }

    #[test]
    fn test_not_nbf() {
        let validator = KeyStore::new();

        let jwk = validator.decode(TOKEN).unwrap();

        let time = SystemTime::UNIX_EPOCH + Duration::new(NBF+1, 0);

        assert!(!jwk.early_time(time).unwrap());
    }

    #[test]
    fn test_valid_exp() {
        let validator = KeyStore::new();

        let jwk = validator.decode(TOKEN).unwrap();

        let time = SystemTime::UNIX_EPOCH + Duration::new(NBF-1, 0);

        assert!(jwk.early_time(time).unwrap());
    }
}
