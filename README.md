[![Build Status](https://travis-ci.com/jfbilodeau/jwks-client.svg?branch=master)](https://travis-ci.com/jfbilodeau/jwks-client) [![License:MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![License:Apache](https://img.shields.io/badge/License-Apache-yellow.svg)](https://opensource.org/licenses/Apache-2.0) ![Minimum rustc version](https://img.shields.io/badge/rustc-stable-success.svg)

JWKS-Client is a library written in Rust to decode and validate JWT tokens using a JSON Web Key Store.

** IMPORTANT **
---
JWKS-Client was designed to work with a project that uses [Rocket](https://crates.io/crates/rocket). Unfortunately, the version of Rocket in [crates.io](https://crates.io) is not compatible with the version of [Ring](https://crates.io/crates/ring) required for JWKS-Client.

To use JWKS-Client with Rocket, use the following dependency in `Cargo.toml`:

```toml
rocket = { git = "https://github.com/SergioBenitez/Rocket" }
``` 

Furthermore, be aware that JWKS-Client is still being developed. Some (hopefully minor) breaking changes may happen. Sorry about that!

Features
---
* No panic!
* Download key set from HTTP address
* Decode JWT tokens into header, payload and signature
* Verify token signature, expiry and not-before 
* Can transfer header and payload in user-defined struct. See the example below 
* Consise results (see [error::Type](https://docs.rs/shared_jwt/latest/shared_jwt/error/enum.Type.html) for example)
* Designed for a production system (not an academic project)
* Build with Rust stable

I created this library specifically to decode GCP/Firebase JWT but should be useable with little to no modification. Contact me to propose support for different JWKS key store. Feedback, suggestions, complaints and critisism is appreaciate.

Basic Usage
---

The following demonstrates how to load a set of keys from an HTTP address and verify a JWT token using those keys:

```rust
use keyset::KeyStore;

<<<<<<< HEAD
let key_store = KeyStore::new_from("http://mykeyset.com/").unwrap();
=======
let jkws_url = "https://...";
let key_set = KeySet::new_from(jkws_url).unwrap();
>>>>>>> fade3478dc6e28ac80b39ddccb3bbe315b87e8ab

// ...

let my_token = "...";  // JWT

match key_store.verify(my_token) {
    Ok(jwt) => {
        println!("name={}", jwt.payload().get_str("name").unwrap());
    }
    Err(_) => {
        eprintln!("Could not verify token");
    }
}
```

JWKS-Client offers descriptive error results:

```rust
use keyset::KeyStore;
use error::{Error, Type};

let key_store = KeyStore::new_from("http://mykeyset.com/").unwrap();

<<<<<<< HEAD
match key_store.verify(my_token) {
=======
let key_set = KeySet::new_from(jwks_url).unwrap();

match key_set.verify(token) {
>>>>>>> fade3478dc6e28ac80b39ddccb3bbe315b87e8ab
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
```

JWKS-Client can decode a JWT payload (claims) into a struct:

```rust
use serde_derive::Deserialize;

#[derive(Deserialize)]
pub struct MyClaims {
    pub iss: String,
    pub name: String,
    pub email: String,
}

let mut key_store = KeyStore::new_from("http://mykeys.com");

let jwt = key_store.decode(my_token).unwrap();

let claims = jwt.payload().into::<MyClaims>().unwrap();

assert_eq!("https://chronogears.com/test", claims.iss);
assert_eq!("Ada Lovelace", claims.name);
assert_eq!("alovelace@chronogears.com", claims.email);
```

History
--- 
* 0.1.3:
  * Change the license to be MIT/Apache
  * Moved demoes into `./example`
  * Added the ability to verify if keys need to be refreshed in the keystore based on the cache-control header
  
* 0.1.2: (Sorry for the breaking changes)
  * Rename module `jwks` to `keyset`
  * Renamed struct `Jwks` to `KeyStore`
  * Expanded documentation a bit
  * Fixed some demos
* 0.1.1: Original version

TODO:
---
* Lots More documentation :P
* Automatically refresh keys

(Made with ❤️ with Rust)
