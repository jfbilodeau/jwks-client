JWKS client library [![Build Status](https://travis-ci.com/jfbilodeau/jwks-client.svg?branch=master)](https://travis-ci.com/jfbilodeau/jwks-client) [![License:MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
===
JWKS-Client is a library written in Rust to decode and validate JWT tokens using a JSON Web Key Store.

I created this library specifically to decode GCP/Firebase JWT but should be useable with little to no modification. Contact me to propose support for different JWKS key store.

TODO:
* More documentation :P
* Extract expiration time of keys from HTTP request
* Automatically refresh keys in background
