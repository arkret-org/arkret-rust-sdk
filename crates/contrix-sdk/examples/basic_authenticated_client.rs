use contrix_sdk::{AuthManager, BaseClient, DeviceId, Did, SessionMeta};

fn main() -> contrix_sdk::Result<()> {
    let user_id = Did::new("did:web:alice.example")?;
    let device_id = DeviceId::new("dev_desktop")?;

    let mut auth = AuthManager::default();
    auth.register_password_user("alice", "correct-horse-battery-staple", user_id)?;
    let session =
        auth.login_password("alice", "correct-horse-battery-staple", device_id.clone())?;

    let base = BaseClient::new();
    base.set_session_meta(SessionMeta::new(session.user_id, device_id))?;
    let _whoami = base.whoami()?;

    Ok(())
}
