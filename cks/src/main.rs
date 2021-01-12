use std::path::Path;

use keystore::{KeyDetails, KeyStore};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Commandline KeyStore",
    about = "A simple commandline application that allows users to create a keystore, add keys to the keystore and use the keys for encryption and decryption."
)]
enum KeyStoreOpt {
    GenerateKey {
        #[structopt(long)]
        key_store_path: String,

        #[structopt(long)]
        key_name: String,

        #[structopt(long)]
        key_strength: usize,
    },

    Encrypt {
        #[structopt(long)]
        key_store_path: String,

        #[structopt(long)]
        key_name: String,

        #[structopt(long)]
        input_file_path: String,

        #[structopt(long)]
        output_file_path: String,
    },

    Decrypt {
        #[structopt(long, short)]
        key_store_path: String,

        #[structopt(long)]
        key_name: String,

        #[structopt(long)]
        input_file_path: String,

        #[structopt(long)]
        output_file_path: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = KeyStoreOpt::from_args();

    match opt {
        KeyStoreOpt::GenerateKey {
            key_store_path,
            key_name,
            key_strength,
        } => {
            let mut ks = if Path::new(&key_store_path).exists() {
                let keystore_content = std::fs::read_to_string(&key_store_path)?;
                KeyStore::deserialize(&keystore_content)?
            } else {
                KeyStore::new()
            };

            let details = KeyDetails::new(&key_name, None, key_strength);

            ks.generate_key(details)?;

            let key_store_content = ks.serialize()?;
            std::fs::write(key_store_path, key_store_content)?;
        }
        KeyStoreOpt::Encrypt {
            key_store_path,
            key_name,
            input_file_path,
            output_file_path,
        } => {
            let keystore_content = std::fs::read_to_string(&key_store_path)?;
            let ks = KeyStore::deserialize(&keystore_content)?;
            let ciphertext = std::fs::read(input_file_path)?;
            let enc_text = ks.encrypt(key_name, &ciphertext)?;
            std::fs::write(output_file_path, &enc_text)?;
        }
        KeyStoreOpt::Decrypt {
            key_store_path,
            key_name,
            input_file_path,
            output_file_path,
        } => {
            let keystore_content = std::fs::read_to_string(&key_store_path)?;
            let ks = KeyStore::deserialize(&keystore_content)?;
            let ciphertext = std::fs::read(input_file_path)?;
            let enc_text = ks.decrypt(key_name, &ciphertext)?;
            std::fs::write(output_file_path, &enc_text)?;
        }
    }

    Ok(())
}
