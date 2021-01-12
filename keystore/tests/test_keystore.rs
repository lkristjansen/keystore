use keystore::{self, KeyDetails, KeyStore};

#[test]
fn use_keystore_to_encrypt_and_decrypt() {
    let mut keystore = KeyStore::new();
    let details = KeyDetails::new("keyname", None, 512);
    let generate_key_result = keystore.generate_key(details);
    assert!(generate_key_result.is_ok());

    let message = b"this is a secret message";
    let encrypted_message = keystore.encrypt("keyname", message).unwrap();

    let serialized_keystore = keystore.serialize().unwrap();
    let keystore = KeyStore::deserialize(&serialized_keystore).unwrap();
    let decrypted_message = keystore.decrypt("keyname", &encrypted_message).unwrap();
    assert_eq!(&message[..], &decrypted_message[..]);
}
