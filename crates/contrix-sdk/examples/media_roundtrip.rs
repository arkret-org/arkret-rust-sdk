use contrix_sdk::{Did, MemoryBlobStore, safe_content_disposition, safe_content_type};

fn main() -> contrix_sdk::Result<()> {
    let mut blobs = MemoryBlobStore::new();
    let media_type =
        safe_content_type("IMAGE/PNG").unwrap_or_else(|| "application/octet-stream".to_owned());
    let disposition = safe_content_disposition("avatar.png");
    assert!(disposition.contains("avatar.png"));

    let metadata = blobs.upload(
        b"png-bytes",
        media_type,
        Some("avatar.png".to_owned()),
        Did::new("did:web:alice.example")?,
    )?;
    let bytes = blobs.download(&metadata.blob_ref).expect("uploaded bytes");

    assert_eq!(bytes, b"png-bytes");
    Ok(())
}
