#[allow(unused_variables)]
#[cfg(test)]
mod demo {
    use crate::tests::{E, KEY_URL, N, TOKEN};

    //----------------------------------------------------------------------------------------------
    // Demos
    //----------------------------------------------------------------------------------------------
    #[test]
    fn demo_simple() {
        use crate::jwks::KeySet;

        let jkws_url = KEY_URL;
        let key_set = KeySet::new_from(jkws_url).unwrap();

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

    fn demo_error() {
        use crate::jwks::KeySet;
        use crate::error::{Error, Type};

        let jwks_url = KEY_URL;
        let token = TOKEN;

        let key_set = KeySet::new_from(jwks_url).unwrap();

        match key_set.verify(token) {
            Ok(jwt) => {
                println!("name={}", jwt.payload().get_str("name").unwrap());
            }
            Err(Error { msg, typ: Type::Header }) => {
                eprintln!("Problem with header. Message: {}", msg);
            }
            Err(Error { msg, typ: Type::Payload }) => {
                eprintln!("Problem with payload. Message: {}", msg);
            }
            Err(Error { msg, typ: Type::Signature }) => {
                eprintln!("Problem with signature. Message: {}", msg);
            }
            Err(Error { msg: _, typ: Type::Expired }) => {
                eprintln!("Token is expired.");
            }
            Err(Error { msg: _, typ: Type::Early }) => {
                eprintln!("Too early to use token.");
            }
            Err(e) => {
                eprintln!("Something else went wrong. Message {:?}", e);
            }
        }
    }

    #[test]
    fn demo_decode() {
        use crate::jwks::KeySet;

        let key_set = KeySet::new();

        let token = TOKEN;

        let jwt = key_set.decode(token).unwrap();

        if jwt.expired().unwrap_or(false) {
            println!("Sorry, token expired")
        } else {
            let result = jwt.payload().get_str("name");

            match result {
                Some(name) => { println!("Welcome, {}!", name); }
                None => { println!("Welcome, anonymous"); }
            }
        }
    }

    #[test]
    fn demo_keystore() {
        let jwks_url = KEY_URL;

        use crate::jwks::{KeySet, JwtKey};

        let my_key = JwtKey::new("my_key_id", "--modulus--", "--exponent--");

        let url = KEY_URL;

        // Create blank key store
        let mut key_set = KeySet::new();
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
