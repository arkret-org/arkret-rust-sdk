use contrix_sdk::crypto;

fn main() -> contrix_sdk::Result<()> {
    let plaintext = br#"{"msgtype":"m.text","body":"hello"}"#;
    let key_material = b"example-device-key-material";
    let aad = b"cx:space:01JS0SP000000000000000000|cx.message.create";

    let envelope = crypto::seal(plaintext, key_material, aad)?;
    let opened = crypto::open(&envelope, key_material, aad)?;

    assert_eq!(opened, plaintext);
    Ok(())
}
