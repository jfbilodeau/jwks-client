use base64::decode_config;
use reqwest;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde::de::DeserializeOwned;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::*;
use crate::jwt::*;

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
}

impl KeyStore {
    pub fn new() -> KeyStore {
        let validator = KeyStore {
            key_url: "".to_owned(),
            keys: vec![],
        };

        validator
    }

    pub fn new_with_url(jkws_url: &str) -> KeyStore {
        let validator = KeyStore {
            key_url: jkws_url.to_owned(),
            keys: vec![],
        };

        validator
    }

    pub fn clear_keys(&mut self) -> &mut KeyStore {
        self.keys.clear();

        self
    }

    pub fn jkws_url(&self) -> &str {
        &self.key_url
    }

    pub fn refresh_keys_url(&mut self, url: &str) -> Result<&mut KeyStore, Error> {
        self.key_url = url.to_owned();

        self.refresh_keys()
    }

    pub fn refresh_keys(&mut self) -> Result<&mut KeyStore, Error> {
        use serde_derive::Deserialize;
        #[derive(Deserialize)]
        pub struct JwtKeys {
            pub keys: Vec<JwtKey>,
        }

        let mut response = reqwest::get(&self.key_url).or(Err(err_con("Could not download JWKS")))?;

        let result = response.json::<JwtKeys>();

        let jwks = result.or(Err(err_int("Failed to decode keys")))?;

        jwks.keys.iter().for_each(|k| self.add_key(k));

        Ok(self)
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

    pub fn decode_segments(&self, token: &str) -> Result<(Header, Payload, HeaderBodyRaw, Signature), Error> {
        let raw_segments: Vec<&str> = token.split(".").collect();
        if raw_segments.len() != 3 {
            return Err(err_inv("JWT does not have 3 segments"));
        }

        let header_segment = raw_segments[0];
        let payload_segment = raw_segments[1];
        let crypto_segment = raw_segments[2];

        let header = Header::new(decode_segment::<Value>(header_segment).or(Err(err_hea("Failed to decode header")))?);
        let payload = Payload::new(decode_segment::<Value>(payload_segment).or(Err(err_pay("Failed to decode payload")))?);

        let signature = decode_config(crypto_segment.as_bytes(), base64::URL_SAFE_NO_PAD)
            .or(Err(err_sig("Failed to decode signature")))?;

        let body = format!("{}.{}", header_segment, payload_segment)
            .as_bytes()
            .to_vec();

        Ok((header, payload, body, signature))
    }

    pub fn decode(&self, token: &str) -> Result<Jwt, Error> {
        let (header, payload, _, _) = self.decode_segments(token)?;

        Ok(Jwt::new(header, payload))
    }

    pub fn verify(&self, token: &str) -> Result<Jwt, Error> {
        let (header, payload, body, signature) = self.decode_segments(token)?;

        if header.alg() != Some("RS256") {
            return Err(err_inv("Unsupported algorithm"))
        }

        let kid = header.kid().ok_or(err_key("No key id"))?;

        let key = self.key_by_id(kid).ok_or(err_key("JWT key does not exists"))?;

        let n = decode_config(&key.n, base64::URL_SAFE_NO_PAD).or(Err(err_cer("Failed to decode modulus")))?;
        let e = decode_config(&key.e, base64::URL_SAFE_NO_PAD).or(Err(err_cer("Failed to decode exponent")))?;

        let pkc = RsaPublicKeyComponents {
            e,
            n,
        };

        let result = pkc.verify(&RSA_PKCS1_2048_8192_SHA256, &body, &signature);

        result.or(Err(err_cer("Signature does not match certificate")))?;

        Ok(Jwt::new(header, payload))
    }
}

fn decode_segment<T: DeserializeOwned>(segment: &str) -> Result<T, Error> {
    let raw = decode_config(segment, base64::URL_SAFE_NO_PAD).or(Err(err_inv("Failed to decode segment")))?;
    let slice = String::from_utf8_lossy(&raw);
    let decoded: T = serde_json::from_str(&slice).or(Err(err_inv("Failed to decode segment")))?;

    Ok(decoded)
}

#[cfg(test)]
mod tests {
}
