pub mod error;
pub mod jwt;
pub mod jwks;

#[cfg(test)]
mod tests {
    use serde_derive::{Deserialize, Serialize};
    use serde_json::Value;

    use crate::jwks::{JwtKey, KeyStore};

    use super::*;

    const E: &str = "AQAB";
    const N: &str = "t5N44H1mpb5Wlx_0e7CdoKTY8xt-3yMby8BgNdagVNkeCkZ4pRbmQXRWNC7qn__Zaxx9dnzHbzGCul5W0RLfd3oB3PESwsrQh-oiXVEPTYhvUPQkX0vBfCXJtg_zY2mY1DxKOIiXnZ8PaK_7Sx0aMmvR__0Yy2a5dIAWCmjPsxn-PcGZOkVUm-D5bH1-ZStcA_68r4ZSPix7Szhgl1RoHb9Q6JSekyZqM0Qfwhgb7srZVXC_9_m5PEx9wMVNYpYJBrXhD5IQm9RzE9oJS8T-Ai-4_5mNTNXI8f1rrYgffWS4wf9cvsEihrvEg9867B2f98L7ux9Llle7jsHCtwgV1w==";
    const TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjcsInVzZXJfaWQiOiJ1aWQxMjMiLCJzdWIiOiJzYnUxMjMiLCJpYXQiOjMsImV4cCI6MTMsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.bWT4zM_wlhv8LnRrFkeTMOGgCQnvnKSBOhiQmAzttlVmcyRacHHXzusjlxGJQh8H0orQfW8Vr8Ct_9IwSC-n9CTAxIc-wKMGuYlAfsTS6Xcxho9e9koigxdkT8cQqeK2EXjLEVmAG5dapKurcMfdruZPawhCySJnUUfvpnZRBCFVJvOAr-9hHl7PvqamfMgO2iF_DZI9_w4j2fzfb6H8Qn-zqbFPs7k2EiBT6OsBlaV8XeX8HpFRTIOeREulmY-t4FAsTVfMUQEZZBcmKg_afpRGzp23zctIsPdCO6ZxDVIAUlpimb5d0hk2A4eSddBzZ3bSChw-b3SMGFwGqZA8bw";

    #[derive(Debug, Serialize, Deserialize)]
    pub struct TestPayload {
        pub exp: f64,
        pub iat: f64,
        pub aud: String,
        pub iss: String,
        pub sub: String,
        pub auth_time: f64,
        pub user_id: String,
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
        const URL: &str = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

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

        assert_eq!("https://chronogears.com/test", jwt.payload().iss().unwrap());
        assert_eq!("Ada Lovelace", jwt.payload().get_str("name").unwrap());
        assert_eq!("alovelace@chronogears.com", jwt.payload().get_str("email").unwrap());
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
    fn test_validate() {
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
}
