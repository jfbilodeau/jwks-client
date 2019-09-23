use std::time::{Duration, SystemTime};

use base64::{decode_config, URL_SAFE_NO_PAD};
use regex::Regex;
use reqwest;
use reqwest::Response;
use ring::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};
use serde::de::DeserializeOwned;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::*;
use crate::jwt::*;

type HeaderBody = String;
pub type Signature = String;

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtKey {
    pub e: String,
    pub kty: String,
    pub alg: String,
    pub n: String,
    pub kid: String,
}

impl JwtKey {
    pub fn new(kid: &str, n: &str, e: &str) -> JwtKey {
        JwtKey {
            e: e.to_owned(),
            kty: "JTW".to_string(),
            alg: "RS256".to_string(),
            n: n.to_owned(),
            kid: kid.to_owned(),
        }
    }
}

impl Clone for JwtKey {
    fn clone(&self) -> Self {
        JwtKey {
            e: self.e.clone(),
            kty: self.kty.clone(),
            alg: self.alg.clone(),
            n: self.n.clone(),
            kid: self.kid.clone(),
        }
    }
}

pub struct KeyStore {
    key_url: String,
    keys: Vec<JwtKey>,
    check: Option<SystemTime>,
    expire: Option<SystemTime>,
}

impl KeyStore {
    pub fn new() -> KeyStore {
        let validator = KeyStore {
            key_url: "".to_owned(),
            keys: vec![],
            check: None,
            expire: None,
        };

        validator
    }

    pub fn new_from(jkws_url: &str) -> Result<KeyStore, Error> {
        let mut key_store = KeyStore {
            key_url: jkws_url.to_owned(),
            keys: vec![],
            check: None,
            expire: None,
        };

        key_store.load_keys()?;

        Ok(key_store)
    }

    pub fn clear_keys(&mut self) {
        self.keys.clear();
    }

    pub fn key_set_url(&self) -> &str {
        &self.key_url
    }

    pub fn load_keys_from(&mut self, url: &str) -> Result<(), Error> {
        self.key_url = url.to_owned();

        self.load_keys()?;

        Ok(())
    }

    pub fn load_keys(&mut self) -> Result<(), Error> {
        #[derive(Deserialize)]
        pub struct JwtKeys {
            pub keys: Vec<JwtKey>,
        }

        let mut response = reqwest::get(&self.key_url).or(Err(err_con("Could not download JWKS")))?;

        let result = KeyStore::cache_max_age(&mut response);

        if let Ok(value) = result {
            let expire = SystemTime::now() + Duration::new(value, 0);
            self.expire = Some(expire);
        }

        let result = response.json::<JwtKeys>();

        let jwks = result.or(Err(err_int("Failed to parse keys")))?;

        jwks.keys.iter().for_each(|k| self.add_key(k));

        self.check = Some(SystemTime::now());

        Ok(())
    }

    fn cache_max_age(response: &mut Response) -> Result<u64, ()> {
        let header = response.headers().get("cache-control").ok_or(())?;

        let header_text = header.to_str().map_err(|_| ())?;

        let re = Regex::new("max-age\\w*=\\w*(\\d)+").map_err(|_| ())?;

        let captures = re.captures(header_text).ok_or(())?;

        let capture = captures.get(1).ok_or(())?;

        let text = capture.as_str();

        let value = text.parse::<u64>().map_err(|_| ())?;

        Ok(value)
    }

    pub fn key_by_id(&self, kid: &str) -> Option<&JwtKey> {
        self.keys.iter().find(|k| k.kid == kid)
    }

    pub fn keys_len(&self) -> usize {
        self.keys.len()
    }

    pub fn add_key(&mut self, key: &JwtKey) {
        self.keys.push(key.clone());
    }

    fn decode_segments(&self, token: &str) -> Result<(Header, Payload, Signature, HeaderBody), Error> {
        let raw_segments: Vec<&str> = token.split(".").collect();
        if raw_segments.len() != 3 {
            return Err(err_inv("JWT does not have 3 segments"));
        }

        let header_segment = raw_segments[0];
        let payload_segment = raw_segments[1];
        let signature_segment = raw_segments[2].to_string();

        let header = Header::new(decode_segment::<Value>(header_segment).or(Err(err_hea("Failed to decode header")))?);
        let payload = Payload::new(decode_segment::<Value>(payload_segment).or(Err(err_pay("Failed to decode payload")))?);

        let body = format!("{}.{}", header_segment, payload_segment);

        Ok((header, payload, signature_segment, body))
    }

    pub fn decode(&self, token: &str) -> Result<Jwt, Error> {
        let (header, payload, signature, _) = self.decode_segments(token)?;

        Ok(Jwt::new(header, payload, signature))
    }

    pub fn verify_time(&self, token: &str, time: SystemTime) -> Result<Jwt, Error> {
        let (header, payload, signature, body) = self.decode_segments(token)?;

        if header.alg() != Some("RS256") {
            return Err(err_inv("Unsupported algorithm"));
        }

        let kid = header.kid().ok_or(err_key("No key id"))?;

        let key = self.key_by_id(kid).ok_or(err_key("JWT key does not exists"))?;

        let e = decode_config(&key.e, URL_SAFE_NO_PAD).or(Err(err_cer("Failed to decode exponent")))?;
        let n = decode_config(&key.n, URL_SAFE_NO_PAD).or(Err(err_cer("Failed to decode modulus")))?;

        verify_signature(&e, &n, &body, &signature)?;

        let jwt = Jwt::new(header, payload, signature);

        if jwt.expired_time(time).unwrap_or(false) {
            return Err(err_exp("Token expired"));
        }
        if jwt.early_time(time).unwrap_or(false) {
            return Err(err_nbf("Too early to use token (nbf)"));
        }

        Ok(jwt)
    }

    pub fn verify(&self, token: &str) -> Result<Jwt, Error> {
        self.verify_time(token, SystemTime::now())
    }

    pub fn last_refresh_time(&self) -> Option<SystemTime> {
        self.check
    }

    pub fn keys_expired(&self) -> Option<bool> {
        match self.expire {
            Some(expire) => Some(expire > SystemTime::now()),
            None => None,
        }
    }
}

fn verify_signature(e: &Vec<u8>, n: &Vec<u8>, message: &str, signature: &str) -> Result<(), Error> {
    let pkc = RsaPublicKeyComponents { e, n };

    let message_bytes = &message.as_bytes().to_vec();
    let signature_bytes = decode_config(&signature, URL_SAFE_NO_PAD).or(Err(err_sig("Could not base64 decode signature")))?;

    let result = pkc.verify(&RSA_PKCS1_2048_8192_SHA256, &message_bytes, &signature_bytes);

    result.or(Err(err_cer("Signature does not match certificate")))
}

fn decode_segment<T: DeserializeOwned>(segment: &str) -> Result<T, Error> {
    let raw = decode_config(segment, base64::URL_SAFE_NO_PAD).or(Err(err_inv("Failed to decode segment")))?;
    let slice = String::from_utf8_lossy(&raw);
    let decoded: T = serde_json::from_str(&slice).or(Err(err_inv("Failed to decode segment")))?;

    Ok(decoded)
}

#[cfg(test)]
mod tests {}
