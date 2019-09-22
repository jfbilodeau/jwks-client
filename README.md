JWKS client library [![Build Status](https://travis-ci.com/jfbilodeau/jwks-client.svg?branch=master)](https://travis-ci.com/jfbilodeau/jwks-client) [![License:MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
===
JWKS-Client is a library written in Rust to decode and validate JWT tokens using a JSON Web Key Store.

I created this library specifically to decode GCP/Firebase JWT but should be useable with little to no modification. Contact me to propose support for different JWKS key store.

Basic Usage
---

The following demonstrates how to load a set of keys from an HTTP address and verify a JWT token using those keys:

```rust
use jwks::KeyStore;

let jkws_url = "https://...";
let key_store = KeyStore::new_from(jkws_url).unwrap();

// ...

let token = "...";

match key_store.verify(token) {
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
use jwks::KeyStore;
use error::{Error, Type};

let jwks_url = "http://...";
let token = "...";

let key_store = KeyStore::new_from(jwks_url).unwrap();

match key_store.verify(token) {
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

JWKS-Client can decode a JWT payload into a struct:

```rust
use jwks::KeyStore;

let key_store = KeyStore::new();

let token = TOKEN;

let jwt = key_store.decode(token).unwrap();

if jwt.expired().unwrap_or(false) {
    println!("Sorry, token expired")
} else {
    let result = jwt.payload().get_str("name");

    match result {
        Some(name) => { println!("Welcome, {}!", name); }
        None => { println!("Welcome, anonymous"); }
    }
}
```


TODO:
---
* More documentation :P
* Extract expiration time of keys from HTTP request
* Automatically refresh keys in background
