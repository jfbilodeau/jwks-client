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
