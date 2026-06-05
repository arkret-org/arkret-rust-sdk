use cokret::crypto;

fn main() -> cokret::Result<()> {
    let plaintext = br#"{"msgtype":"m.text","body":"hello"}"#;
    let key_material = b"example-device-key-material";
    let aad = b"ck:realm:01904100-0000-7000-8000-9b64700c6ee8|ck.message.create";

    let envelope = crypto::seal(plaintext, key_material, aad)?;
    let opened = crypto::open(&envelope, key_material, aad)?;

    assert_eq!(opened, plaintext);
    Ok(())
}
