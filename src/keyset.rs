use std::time::{Duration, SystemTime};
use std::{convert::TryFrom, convert::TryInto};

use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation};
use regex::Regex;
use reqwest::Response;
use serde::{de::DeserializeOwned, Deserialize};

use crate::error::*;

#[derive(Debug, Deserialize)]
pub struct JWK {
    pub alg: jsonwebtoken::Algorithm,
    pub kid: String,
    pub kty: String,
    pub e: Option<String>,
    pub n: Option<String>,
}

#[derive(Debug)]
pub struct JwtKey {
    pub alg: jsonwebtoken::Algorithm,
    pub kid: String,
    pub kind: JwtKeyKind,
}

#[derive(Debug)]
pub enum JwtKeyKind {
    RSA(DecodingKey<'static>),
    UnsupportedKty(String),
}

impl JwtKey {
    pub fn new(kid: &str, alg: Algorithm, key: DecodingKey<'static>) -> JwtKey {
        JwtKey {
            alg,
            kid: kid.to_owned(),
            kind: JwtKeyKind::RSA(key),
        }
    }

    pub fn new_rsa256(kid: &str, n: &str, e: &str) -> JwtKey {
        JwtKey {
            alg: Algorithm::RS256,
            kid: kid.to_owned(),
            kind: JwtKeyKind::RSA(DecodingKey::from_rsa_components(n, e).into_static()),
        }
    }

    pub fn decoding_key(&self) -> Result<&DecodingKey, Error> {
        match &self.kind {
            JwtKeyKind::RSA(key) => Ok(key),
            JwtKeyKind::UnsupportedKty(kty) => Err(err("Unsupported key type", ErrorKind::UnsupportedKeyType(kty.to_owned()))),
        }
    }
}

impl TryFrom<JWK> for JwtKey {
    type Error = Error;

    fn try_from(JWK { kid, alg, kty, n, e }: JWK) -> Result<Self, Error> {
        let kind = match (kty.as_ref(), n, e) {
            ("RSA", Some(n), Some(e)) => JwtKeyKind::RSA(DecodingKey::from_rsa_components(&n, &e).into_static()),
            ("RSA", _, _) => return Err(err("RSA key misses parameters", ErrorKind::Key)),
            (_, _, _) => JwtKeyKind::UnsupportedKty(kty),
        };
        Ok(JwtKey { kid, alg, kind })
    }
}

pub struct KeyStore {
    key_url: String,
    keys: Vec<JwtKey>,
    refresh_interval: f64,
    load_time: Option<SystemTime>,
    expire_time: Option<SystemTime>,
    refresh_time: Option<SystemTime>,
}

impl KeyStore {
    pub fn new() -> KeyStore {
        KeyStore {
            key_url: "".to_owned(),
            keys: Vec::new(),
            refresh_interval: 0.5,
            load_time: None,
            expire_time: None,
            refresh_time: None,
        }
    }

    pub async fn new_from(jkws_url: String) -> Result<KeyStore, Error> {
        let mut key_store = KeyStore::new();

        key_store.key_url = jkws_url;

        key_store.load_keys().await?;

        Ok(key_store)
    }

    pub fn clear_keys(&mut self) {
        self.keys.clear();
    }

    pub fn key_set_url(&self) -> &str {
        &self.key_url
    }

    pub async fn load_keys_from(&mut self, url: String) -> Result<(), Error> {
        self.key_url = url;

        self.load_keys().await?;

        Ok(())
    }

    pub async fn load_keys(&mut self) -> Result<(), Error> {
        #[derive(Deserialize)]
        pub struct JwtKeys {
            pub keys: Vec<JWK>,
        }

        let mut response = reqwest::get(&self.key_url).await.map_err(|_| err_con("Could not download JWKS"))?;

        let load_time = SystemTime::now();
        self.load_time = Some(load_time);

        let result = KeyStore::cache_max_age(&mut response);

        if let Ok(value) = result {
            let expire = load_time + Duration::new(value, 0);
            self.expire_time = Some(expire);
            let refresh_time = (value as f64 * self.refresh_interval) as u64;
            let refresh = load_time + Duration::new(refresh_time, 0);
            self.refresh_time = Some(refresh);
        }

        let jwks = response.json::<JwtKeys>().await.map_err(|_| err_int("Failed to parse keys"))?;

        for jwk in jwks.keys {
            self.add_key(jwk.try_into()?);
        }

        Ok(())
    }

    fn cache_max_age(response: &mut Response) -> Result<u64, ()> {
        let header = response.headers().get("cache-control").ok_or(())?;

        let header_text = header.to_str().map_err(|_| ())?;

        let re = Regex::new("max-age\\s*=\\s*(\\d+)").map_err(|_| ())?;

        let captures = re.captures(header_text).ok_or(())?;

        let capture = captures.get(1).ok_or(())?;

        let text = capture.as_str();

        let value = text.parse::<u64>().map_err(|_| ())?;

        Ok(value)
    }

    /// Fetch a key by key id (KID)
    pub fn key_by_id(&self, kid: &str) -> Option<&JwtKey> {
        self.keys.iter().find(|key| key.kid == kid)
    }

    /// Number of keys in keystore
    pub fn keys_len(&self) -> usize {
        self.keys.len()
    }

    /// Manually add a key to the keystore
    pub fn add_key(&mut self, key: JwtKey) {
        self.keys.push(key);
    }

    /// Verify a JWT token.
    /// If the token is valid, it is returned.
    ///
    /// A token is considered valid if:
    /// * Is well formed
    /// * Has a `kid` field that matches a public signature `kid
    /// * Signature matches public key
    /// * It is not expired
    /// * The `nbf` is not set to before now
    pub fn verify<T: DeserializeOwned>(&self, token: &str, validation: &Validation) -> Result<TokenData<T>, Error> {
        let header = jsonwebtoken::decode_header(token).map_err(err_jwt)?;

        let kid = header.kid.ok_or_else(|| err_key("No key id"))?;

        let key = self.key_by_id(&kid).ok_or_else(|| err_key("JWT key does not exists"))?;

        if key.alg != header.alg {
            return Err(err("Token and its key have non-matching algorithms", ErrorKind::AlgorithmMismatch));
        }

        let data = jsonwebtoken::decode(token, key.decoding_key()?, &validation).map_err(err_jwt)?;

        Ok(data)
    }

    /// Time at which the keys were last refreshed
    pub fn last_load_time(&self) -> Option<SystemTime> {
        self.load_time
    }

    /// True if the keys are expired and should be refreshed
    ///
    /// None if keys do not have an expiration time
    pub fn keys_expired(&self) -> Option<bool> {
        match self.expire_time {
            Some(expire) => Some(expire <= SystemTime::now()),
            None => None,
        }
    }

    /// Specifies the interval (as a fraction) when the key store should refresh it's key.
    ///
    /// The default is 0.5, meaning that keys should be refreshed when we are halfway through the expiration time (similar to DHCP).
    ///
    /// This method does _not_ update the refresh time. Call `load_keys` to force an update on the refresh time property.
    pub fn set_refresh_interval(&mut self, interval: f64) {
        self.refresh_interval = interval;
    }

    /// Get the current fraction time to check for token refresh time.
    pub fn refresh_interval(&self) -> f64 {
        self.refresh_interval
    }

    /// The time at which the keys were loaded
    /// None if the keys were never loaded via `load_keys` or `load_keys_from`.
    pub fn load_time(&self) -> Option<SystemTime> {
        self.load_time
    }

    /// Get the time at which the keys are considered expired
    pub fn expire_time(&self) -> Option<SystemTime> {
        self.expire_time
    }

    /// time at which keys should be refreshed.
    pub fn refresh_time(&self) -> Option<SystemTime> {
        self.refresh_time
    }

    /// Returns `Option<true>` if keys should be refreshed based on the given `current_time`.
    ///
    /// None is returned if the key store does not have a refresh time available. For example, the
    /// `load_keys` function was not called or the HTTP server did not provide a  
    pub fn should_refresh_time(&self, current_time: SystemTime) -> Option<bool> {
        if let Some(refresh_time) = self.refresh_time {
            return Some(refresh_time <= current_time);
        }

        None
    }

    /// Returns `Option<true>` if keys should be refreshed based on the system time.
    ///
    /// None is returned if the key store does not have a refresh time available. For example, the
    /// `load_keys` function was not called or the HTTP server did not provide a  
    pub fn should_refresh(&self) -> Option<bool> {
        self.should_refresh_time(SystemTime::now())
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}
