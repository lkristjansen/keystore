#![allow(dead_code)]

use rand::rngs::OsRng;
use rsa::{BigUint, PaddingScheme, PublicKey, PublicKeyParts, RSAPrivateKey, RSAPublicKey};
use serde::{Deserialize, Serialize};

use std::error;
use std::fmt;

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyStore {
    entries: Vec<KeyEntry>,
}

impl KeyStore {
    pub fn new() -> Self {
        KeyStore {
            entries: Vec::new(),
        }
    }

    fn find<T: AsRef<str>>(&self, key_name: T) -> Result<&KeyEntry, KeyStoreError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.name.eq(key_name.as_ref()));

        if entry.is_none() {
            return Err(KeyStoreError::new(&format!(
                "key: '{}' not found",
                key_name.as_ref()
            )));
        }

        Ok(entry.unwrap())
    }

    pub fn encrypt<T: AsRef<str>>(
        &self,
        key_name: T,
        data: &[u8],
    ) -> Result<Vec<u8>, KeyStoreError> {
        let key_entry = self.find(key_name)?;
        let private_key = key_entry.key.to_private_key();
        let public_key = RSAPublicKey::from(&private_key);
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let mut rng = OsRng;
        Ok(public_key.encrypt(&mut rng, padding, data)?)
    }

    pub fn decrypt<T: AsRef<str>>(
        &self,
        key_name: T,
        data: &[u8],
    ) -> Result<Vec<u8>, KeyStoreError> {
        let key_entry = self.find(key_name)?;
        let private_key = key_entry.key.to_private_key();
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        Ok(private_key.decrypt(padding, data)?)
    }

    pub fn generate_key(&mut self, details: KeyDetails) -> Result<(), KeyStoreError> {
        let mut rng = OsRng;
        let private_key = RSAPrivateKey::new(&mut rng, details.size)?;
        let entry = KeyEntry::new(&details.name, None, KeyComponents::from(private_key));
        self.entries.push(entry);
        Ok(())
    }

    pub fn serialize(&self) -> Result<String, KeyStoreError> {
        Ok(serde_json::to_string(&self)?)
    }

    pub fn deserialize<T: AsRef<str>>(data: T) -> Result<Self, KeyStoreError> {
        Ok(serde_json::from_str(data.as_ref())?)
    }
}

pub struct KeyDetails {
    name: String,
    description: Option<String>,
    size: usize,
}

impl KeyDetails {
    pub fn new<T: AsRef<str>>(name: T, _description: Option<T>, size: usize) -> Self {
        Self {
            name: String::from(name.as_ref()),
            description: None,
            size: size,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyEntry {
    name: String,
    description: Option<String>,
    key: KeyComponents,
}

impl KeyEntry {
    fn new<T: AsRef<str>>(name: T, _description: Option<T>, key: KeyComponents) -> Self {
        Self {
            name: String::from(name.as_ref()),
            description: None,
            key: key,
        }
    }
}

#[derive(Debug)]
pub struct KeyStoreError {
    message: String,
}

impl KeyStoreError {
    fn new<T: AsRef<str>>(message: T) -> Self {
        Self {
            message: String::from(message.as_ref()),
        }
    }
}

impl error::Error for KeyStoreError {}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<serde_json::Error> for KeyStoreError {
    fn from(error: serde_json::Error) -> Self {
        KeyStoreError::new(error.to_string())
    }
}

impl From<rsa::errors::Error> for KeyStoreError {
    fn from(error: rsa::errors::Error) -> Self {
        KeyStoreError::new(&format!("{}", error))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyComponents {
    primes: Vec<Vec<u8>>,
    n: Vec<u8>,
    e: Vec<u8>,
    d: Vec<u8>,
}

impl KeyComponents {
    fn to_private_key(&self) -> RSAPrivateKey {
        let primes = self
            .primes
            .iter()
            .map(|prime| BigUint::from_bytes_le(prime))
            .collect();

        RSAPrivateKey::from_components(
            BigUint::from_bytes_le(self.n.as_slice()),
            BigUint::from_bytes_le(self.e.as_slice()),
            BigUint::from_bytes_le(self.d.as_slice()),
            primes,
        )
    }
}

impl From<RSAPrivateKey> for KeyComponents {
    fn from(private_key: RSAPrivateKey) -> Self {
        let public_key = RSAPublicKey::from(&private_key);
        let primes = private_key
            .primes()
            .iter()
            .map(|prime| prime.to_bytes_le())
            .collect();

        Self {
            primes,
            n: public_key.n().to_bytes_le(),
            e: public_key.e().to_bytes_le(),
            d: private_key.d().to_bytes_le(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{KeyDetails, KeyStore};

    #[test]
    fn should_fail_to_find_unknown_key() {
        let keystore = KeyStore::new();
        let key_result = keystore.find("<not a key>");
        assert!(key_result.is_err());
    }

    #[test]
    fn find_key_in_keystore() {
        let mut keystore = KeyStore::new();
        let details = KeyDetails::new("keyname", Some(""), 512);
        let generate_key_result = keystore.generate_key(details);
        assert!(generate_key_result.is_ok());

        let key_result = keystore.find("keyname");
        assert!(key_result.is_ok());
    }
}
