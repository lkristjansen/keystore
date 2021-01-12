use assert_cmd::prelude::*;
use std::process::Command;

#[test]
fn generate_key_and_create_key_store() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("cks")?;

    cmd.args(&[
        "generate-key",
        "--key-store-path",
        "mystore.rs",
        "--key-name",
        "mykey",
        "--key-strength",
        "512",
    ])
    .assert()
    .success();

    Ok(())
}

#[test]
fn decrypt_when_keystore_does_not_exist() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("cks")?;

    cmd.args(&[
        "decrypt",
        "--key-store-path",
        "mystore.rs",
        "--key-name",
        "not_a_key",
        "--input_file_path",
        "input.dat",
        "--output_file_path",
        "output.dat",
    ])
    .assert()
    .failure();

    Ok(())
}
