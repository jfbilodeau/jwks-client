#[allow(unused_variables)]
#[cfg(test)]
mod demo {
    use crate::tests::{E, KEY_URL, N, TOKEN};

    //----------------------------------------------------------------------------------------------
    // Demos
    //----------------------------------------------------------------------------------------------
    #[test]
    fn demo_simple() {
        use crate::keyset::KeyStore;

        let jkws_url = KEY_URL;
        let key_set = KeyStore::new_from(jkws_url).unwrap();

        // ...

        let token = TOKEN;

        match key_set.verify(token) {
            Ok(jwt) => {
                println!("name={}", jwt.payload().get_str("name").unwrap());
            }
            Err(_) => {
                eprintln!("Could not verify token");
            }
        }
    }

    #[test]
    fn demo_into() {
        use serde_derive::Deserialize;

        use crate::jwt::Jwt;
        use crate::keyset::{JwtKey, KeyStore};

        #[derive(Deserialize)]
        pub struct MyClaims {
            pub iss: String,
            pub name: String,
            pub email: String,
        }

        let key = JwtKey::new("1", N, E);

        let mut key_set = KeyStore::new();

        key_set.add_key(&key);

        let jwt = key_set.decode(TOKEN).unwrap();

        let claims = jwt.payload().into::<MyClaims>().unwrap();

        assert_eq!("https://chronogears.com/test", claims.iss);
        assert_eq!("Ada Lovelace", claims.name);
        assert_eq!("alovelace@chronogears.com", claims.email);
    }

    #[test]
    fn demo_error() {
        use crate::error::{Error, Type};
        use crate::keyset::KeyStore;

        let jwks_url = KEY_URL;
        let token = TOKEN;

        let key_set = KeyStore::new_from(jwks_url).unwrap();

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

    #[test]
    fn demo_decode() {
        use crate::keyset::KeyStore;

        let key_set = KeyStore::new();

        let token = TOKEN;

        let jwt = key_set.decode(token).unwrap();

        if jwt.expired().unwrap_or(false) {
            println!("Sorry, token expired")
        } else {
            let result = jwt.payload().get_str("name");

            match result {
                Some(name) => {
                    println!("Welcome, {}!", name);
                }
                None => {
                    println!("Welcome, anonymous");
                }
            }
        }
    }

    #[test]
    fn demo_keystore() {
        let jwks_url = KEY_URL;

        use crate::keyset::{JwtKey, KeyStore};

        let my_key = JwtKey::new("my_key_id", "--modulus--", "--exponent--");

        let url = KEY_URL;

        // Create blank key store
        let mut key_set = KeyStore::new();
        // Add a custom key to the store
        key_set.add_key(&my_key);
        // Number of keys in store
        let _ = key_set.keys_len();
        // Clear all keys
        key_set.clear_keys();
        // Set the URL for the JWKS
        key_set.load_keys_from(jwks_url).unwrap();
    }
}
