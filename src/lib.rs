pub mod error;
pub mod jwt;
pub mod keyset;

///JWKS client library [![Build Status](https://travis-ci.com/jfbilodeau/jwks-client.svg?branch=master)](https://travis-ci.com/jfbilodeau/jwks-client) [![License:MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
///===
///JWKS-Client is a library written in Rust to decode and validate JWT tokens using a JSON Web Key Store.
///
///I created this library specifically to decode GCP/Firebase JWT but should be useable with little to no modification. Contact me to propose support for different JWKS key store.
///
///TODO:
///* More documentation :P
///* Extract expiration time of keys from HTTP request
///* Automatically refresh keys in background
#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use serde_derive::{Deserialize, Serialize};

    use crate::error::{Error, Type};
    use crate::keyset::{JwtKey, KeyStore};

    //    const IAT: u64 = 200;
    const TIME_NBF: u64 = 300;
    const TIME_SAFE: u64 = 400;
    const TIME_EXP: u64 = 500;

    fn time_nbf() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::new(TIME_NBF - 1, 0)
    }

    fn time_safe() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::new(TIME_SAFE, 0)
    }

    fn time_exp() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::new(TIME_EXP + 1, 0)
    }

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

    pub const KEY_URL: &str = "https://raw.githubusercontent.com/jfbilodeau/jwks-client/master/test/test-jwks.json";
    pub const E: &str = "AQAB";
    pub const N: &str = "t5N44H1mpb5Wlx_0e7CdoKTY8xt-3yMby8BgNdagVNkeCkZ4pRbmQXRWNC7qn__Zaxx9dnzHbzGCul5W0RLfd3oB3PESwsrQh-oiXVEPTYhvUPQkX0vBfCXJtg_zY2mY1DxKOIiXnZ8PaK_7Sx0aMmvR__0Yy2a5dIAWCmjPsxn-PcGZOkVUm-D5bH1-ZStcA_68r4ZSPix7Szhgl1RoHb9Q6JSekyZqM0Qfwhgb7srZVXC_9_m5PEx9wMVNYpYJBrXhD5IQm9RzE9oJS8T-Ai-4_5mNTNXI8f1rrYgffWS4wf9cvsEihrvEg9867B2f98L7ux9Llle7jsHCtwgV1w";
    pub const N_INVALID: &str = "xt5N44H1mpb5Wlx_0e7CdoKTY8xt-3yMby8BgNdagVNkeCkZ4pRbmQXRWNC7qn__Zaxx9dnzHbzGCul5W0RLfd3oB3PESwsrQh-oiXVEPTYhvUPQkX0vBfCXJtg_zY2mY1DxKOIiXnZ8PaK_7Sx0aMmvR__0Yy2a5dIAWCmjPsxn-PcGZOkVUm-D5bH1-ZStcA_68r4ZSPix7Szhgl1RoHb9Q6JSekyZqM0Qfwhgb7srZVXC_9_m5PEx9wMVNYpYJBrXhD5IQm9RzE9oJS8T-Ai-4_5mNTNXI8f1rrYgffWS4wf9cvsEihrvEg9867B2f98L7ux9Llle7jsHCtwgV1w==";
    pub const TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.eTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";
    pub const TOKEN_INV_CERT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.XXXeTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";

    #[derive(Debug, Serialize, Deserialize)]
    pub struct TestPayload {
        pub iss: String,
        pub name: String,
        pub email: String,
    }

    #[test]
    fn test_new_with_url() {
        let url = KEY_URL;

        let key_set = KeyStore::new_from(url).unwrap();

        assert_eq!(url, key_set.key_set_url());
    }

    #[test]
    fn test_refresh_keys() {
        let key_set = KeyStore::new_from(KEY_URL).unwrap();

        assert_eq!(KEY_URL, key_set.key_set_url());
        assert!(key_set.keys_len() > 0);

        assert!(key_set.key_by_id("1").is_some());
        assert!(key_set.key_by_id("2").is_none());

        let result = key_set.verify_time(TOKEN, time_safe());

        let jwt = result.unwrap();

        assert_eq!("https://chronogears.com/test", jwt.payload().iss().unwrap());
        assert_eq!("Ada Lovelace", jwt.payload().get_str("name").unwrap());
        assert_eq!("alovelace@chronogears.com", jwt.payload().get_str("email").unwrap());
    }

    #[test]
    fn test_add_key() {
        let key = JwtKey::new("1", N, E);

        let mut key_set = KeyStore::new();

        assert_eq!(0usize, key_set.keys_len());

        key_set.add_key(&key);

        assert_eq!(1usize, key_set.keys_len());

        let result = key_set.key_by_id("1");

        assert!(result.is_some());

        let key = result.unwrap();

        assert_eq!(N, key.n);
        assert_eq!(E, key.e);
        assert_eq!("1", key.kid);
    }

    #[test]
    fn test_get_key() {
        let key = JwtKey::new("1", N, E);

        let mut key_set = KeyStore::new();

        assert_eq!(0usize, key_set.keys_len());

        key_set.add_key(&key);

        assert_eq!(1usize, key_set.keys_len());

        let result = key_set.key_by_id("1");

        assert!(result.is_some());

        let result = key_set.key_by_id("2");

        assert!(result.is_none());
    }

    #[test]
    fn test_decode_custom_payload() {
        let key = JwtKey::new("1", N, E);

        let mut key_set = KeyStore::new();

        key_set.add_key(&key);

        let result = key_set.decode(TOKEN);

        assert!(result.is_ok());

        let jwt = result.unwrap();

        let payload = jwt.payload().into::<TestPayload>().unwrap();

        assert_eq!("https://chronogears.com/test", payload.iss);
        assert_eq!("Ada Lovelace", payload.name);
        assert_eq!("alovelace@chronogears.com", payload.email);
    }

    #[test]
    fn test_decode_json_payload() {
        let key = JwtKey::new("1", N, E);

        let mut key_set = KeyStore::new();

        key_set.add_key(&key);

        let result = key_set.decode(TOKEN);

        assert!(result.is_ok());

        let jwt = result.unwrap();

        assert_eq!("https://chronogears.com/test", jwt.payload().iss().unwrap());
        assert_eq!("Ada Lovelace", jwt.payload().get_str("name").unwrap());
        assert_eq!("alovelace@chronogears.com", jwt.payload().get_str("email").unwrap());
    }

    #[test]
    fn test_verify() {
        let key = JwtKey::new("1", N, E);

        let mut key_set = KeyStore::new();

        key_set.add_key(&key);

        let result = key_set.verify_time(TOKEN, time_safe());

        assert!(result.is_ok());

        let jwt = result.unwrap();

        assert_eq!("https://chronogears.com/test", jwt.payload().iss().unwrap());
        assert_eq!("Ada Lovelace", jwt.payload().get_str("name").unwrap());
        assert_eq!("alovelace@chronogears.com", jwt.payload().get_str("email").unwrap());

        let result = key_set.verify_time(TOKEN, time_nbf());

        match result {
            Ok(_) => panic!(),
            Err(Error { msg: _, typ }) => {
                assert_eq!(Type::Early, typ);
            }
        }

        let result = key_set.verify_time(TOKEN, time_exp());

        match result {
            Ok(_) => panic!(),
            Err(Error { msg: _, typ }) => {
                assert_eq!(Type::Expired, typ);
            }
        }
    }

    #[test]
    fn test_verify_invalid_certificate() {
        let key = JwtKey::new("1", N_INVALID, E);

        let mut key_set = KeyStore::new();

        key_set.add_key(&key);

        let result = key_set.verify(TOKEN);

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let key = JwtKey::new("1", N, E);

        let mut key_set = KeyStore::new();

        key_set.add_key(&key);

        let result = key_set.verify(TOKEN_INV_CERT);

        assert!(result.is_err());

        // Should still be able to decode:
        let result = key_set.decode(TOKEN_INV_CERT);

        let jwt = result.unwrap();

        assert_eq!("https://chronogears.com/test", jwt.payload().iss().unwrap());
        assert_eq!("Ada Lovelace", jwt.payload().get_str("name").unwrap());
        assert_eq!("alovelace@chronogears.com", jwt.payload().get_str("email").unwrap());
    }

    #[test]
    fn test_expired() {
        let key_set = KeyStore::new();

        let jwk = key_set.decode(TOKEN).unwrap();

        let time = SystemTime::UNIX_EPOCH + Duration::new(TIME_EXP + 1, 0);

        assert!(jwk.expired_time(time).unwrap());
    }

    #[test]
    fn test_not_expired() {
        let key_set = KeyStore::new();

        let jwk = key_set.decode(TOKEN).unwrap();

        let time = SystemTime::UNIX_EPOCH + Duration::new(TIME_EXP - 1, 0);

        assert!(!jwk.expired_time(time).unwrap());
    }

    #[test]
    fn test_nbf() {
        let key_set = KeyStore::new();

        let jwk = key_set.decode(TOKEN).unwrap();

        let time = SystemTime::UNIX_EPOCH + Duration::new(TIME_NBF - 1, 0);

        assert!(jwk.early_time(time).unwrap());
    }

    #[test]
    fn test_not_nbf() {
        let key_set = KeyStore::new();

        let jwk = key_set.decode(TOKEN).unwrap();

        let time = SystemTime::UNIX_EPOCH + Duration::new(TIME_NBF + 1, 0);

        assert!(!jwk.early_time(time).unwrap());
    }

    #[test]
    fn test_valid_exp() {
        let key_set = KeyStore::new();

        let jwk = key_set.decode(TOKEN).unwrap();

        let time = SystemTime::UNIX_EPOCH + Duration::new(TIME_NBF - 1, 0);

        assert!(jwk.early_time(time).unwrap());
    }

    #[test]
    fn test_keys_expired() {
        let key_store = KeyStore::new();

        assert_eq!(None, key_store.last_refresh_time());
        assert_eq!(None, key_store.keys_expired());

        let key_store = KeyStore::new_from(KEY_URL).unwrap();

        assert!(key_store.last_refresh_time().is_some());
        assert!(key_store.keys_expired().is_some());
        assert_eq!(false, key_store.keys_expired().unwrap());
    }
}
