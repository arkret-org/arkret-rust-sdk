use contrix::{AuthManager, BaseClient, DeviceId, Did, SessionMeta};

fn main() -> contrix::Result<()> {
    let user_id = Did::new("did:web:alice.example")?;
    let device_id = DeviceId::new("cx:device:01904100-0000-7000-8000-000000000009")?;

    let mut auth = AuthManager::default();
    auth.register_password_user("alice", "correct-horse-battery-staple", user_id)?;
    let session =
        auth.login_password("alice", "correct-horse-battery-staple", device_id.clone())?;

    let base = BaseClient::new();
    base.set_session_meta(SessionMeta::new(session.user_id, device_id))?;
    let _whoami = base.whoami()?;

    Ok(())
}
