[![Build Status](https://travis-ci.com/jfbilodeau/jwks-client.svg?branch=master)](https://travis-ci.com/jfbilodeau/jwks-client) [![License:MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![License:Apache](https://img.shields.io/badge/License-Apache-yellow.svg)](https://opensource.org/licenses/Apache-2.0) ![Minimum rustc version](https://img.shields.io/badge/rustc-stable-success.svg)

JWKS-Client is a library written in Rust to decode and validate JWT tokens using a JSON Web Key Store.

## ** IMPORTANT **
JWKS-Client was designed to work with a project that uses [Rocket](https://crates.io/crates/rocket). Unfortunately, the version of Rocket in [crates.io](https://crates.io) is not compatible with the version of [Ring](https://crates.io/crates/ring) required for JWKS-Client. Until the next version of Rocket is published, consider using the following in your `Cargo.toml`:

```toml
[dependencies]
jwks-client = "0.1.4"
rocket = { git = "https://github.com/jfbilodeau/Rocket", version = "0.5.0-dev"}
# Other dependencies...

[dependencies.rocket_contrib]
version = "0.5.0-dev"
git = "https://github.com/jfbilodeau/Rocket"
# Other options...

``` 

Features
---

### Library wide:
* No panic!
* Build with Rust stable
* Designed for a production system (not an academic project)
* Consise results (see [error::Type](https://docs.rs/shared_jwt/latest/shared_jwt/error/enum.Type.html) for example)

### JWKS key store
* Download key set from HTTP address
* Decode JWT tokens into header, payload and signature
* Verify token signature, expiry and not-before
* Determine when keys should be refreshed
  
### JWT: 
* Transfer header and payload in user-defined struct. See the example below[^1]
* Accessor for standard header and payload fields


JWKS-Client was create specifically to decode GCP/Firebase JWT but should be useable with little to no modification. Contact me to propose support for different JWKS key store. Feedback, suggestions, complaints and critisism is appreciated.

Basic Usage
---

The following demonstrates how to load a set of keys from an HTTP address and verify a JWT token using those keys:

```rust
use jwks_client::error::Error;
use jwks_client::keyset::KeyStore;

fn main() {
    let jkws_url = "https://raw.githubusercontent.com/jfbilodeau/jwks-client/0.1.3/test/test-jwks.json";

    let key_set = KeyStore::new_from(jkws_url).unwrap();

    // ...

    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.eTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";

    match key_set.verify(token) {
        Ok(jwt) => {
            println!("name={}", jwt.payload().get_str("name").unwrap());
        }
        Err(Error { msg, typ: _ }) => {
            eprintln!("Could not verify token. Reason: {}", msg);
        }
    }
}
```

JWKS-Client can be use to simply decode a JWT token without validating the signature.

```rust
use jwks_client::keyset::KeyStore;

fn main() {
    let key_store = KeyStore::new();

    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.eTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";

    let jwt = key_store.decode(token).unwrap();

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
```


JWKS-Client offers descriptive error results:

```rust
use jwks_client::error::{Error, Type};
use jwks_client::keyset::KeyStore;

#[rustfmt::skip]
fn main() {
    let url = "https://raw.githubusercontent.com/jfbilodeau/jwks-client/0.1.3/test/test-jwks.json";
    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.eTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";

    let key_set = KeyStore::new_from(url).unwrap();

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
```

[^1] JWKS-Client can decode a JWT payload (claims) into a struct:

```rust
use serde_derive::Deserialize;

use jwks_client::keyset::KeyStore;

fn main() {
    #[derive(Deserialize)]
    pub struct MyClaims {
        pub iss: String,
        pub name: String,
        pub email: String,
    }

    let url = "https://raw.githubusercontent.com/jfbilodeau/jwks-client/0.1.3/test/test-jwks.json";

    let key_store = KeyStore::new_from(url).unwrap();

    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.eTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";

    let jwt = key_store.decode(token).unwrap();

    let claims = jwt.payload().into::<MyClaims>().unwrap();

    println!("Issuer: {}", claims.iss);
    println!("Name: {}", claims.name);
    println!("Email: {}", claims.email);
}
```

History
--- 
* 0.1.6
  * Added `key_set::KeyStore::should_refresh()` to test if keys should be refreshed
  * Added `key_set::KeyStore::refresh_interval` to determine how early keys should be refreshed before they expire
  * Some more documentation
* 0.1.5:
  * Added `readme = "README.md"` to `Cargo.toml`
* 0.1.4:
  * Updated documentation--specifically how to use JWKS-Client with Rocket
  * Added the ability to determine if keys should be refreshed from the `KeyStore`
  * Fixed example on this page--they are now directly from `./examples/*`
* 0.1.3:
  * Change the license to be MIT/Apache
  * Moved demos into `./example`
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
