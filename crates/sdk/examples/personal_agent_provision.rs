//! End-to-end personal-agent provisioning demo against the soland agent-runtime
//! surface. Wires every operation from the `agent_runtime` group of
//! `operation-registry.json` (spec head 37ce729):
//!
//! 1. `ck.gate.account.agent_key_pair`        — mint a fresh agent keypair
//! 2. `ck.self.agent.provision`               — create the agent principal
//! 3. `ck.self.agent.list`                    — confirm registry membership
//! 4. `ck.self.agent.get`                     — fetch the principal record
//! 5. `ck.self.agent.pause`                   — quiesce the runtime
//! 6. `ck.self.agent.resume`                  — un-quiesce
//! 7. `ck.self.agent.rotate_key`              — roll the signing key
//! 8. `ck.self.agent.grant.attach`            — bind a delegation grant
//! 9. `ck.self.agent.grant.detach`            — release the grant
//! 10. `ck.self.agent.sidecar_thread.ensure`  — pin a sidecar thread for tool calls
//! 11. `ck.self.agent.deactivate`             — terminate the principal
//!
//! The example does NOT require a live soland deployment. The HTTP `Client` is
//! constructed against a stub URL; the per-step bodies and paths are stamped
//! out so a reader (or `cargo expand`) can audit the exact wire shape the SDK
//! emits. The `_send` closure is a single chokepoint a real integration would
//! replace with `client.post(...).await` / `client.get(...).await`.
//!
//! Build with the default feature set:
//!
//! ```sh
//! cargo run --example personal_agent_provision
//! ```

use cokret::{DeviceId, Did};
use serde_json::{Value, json};
use std::fmt::Write;

/// Stand-in for a wire send. Returns the mock response a real soland would
/// produce for each operation so the example stays self-contained.
fn mock_send(op_id: &str, method: &str, path: &str, body: &Value) -> Value {
    println!("→ {method} {path}  ({op_id})");
    println!("  request: {body}");
    match op_id {
        "ck.gate.account.agent_key_pair" => json!({
            "agent_key_id": "ck:agent_key:01964137-0000-7000-8000-000000000001",
            "public_key": "ed25519:base64-pub-key",
        }),
        "ck.self.agent.provision" => json!({
            "agent_principal_id": "did:web:agent.example",
            "status": "active",
        }),
        "ck.self.agent.list" => json!({ "agents": [], "next_cursor": null }),
        "ck.self.agent.get" => {
            json!({ "agent_principal_id": body["agent_principal_id"], "status": "active" })
        }
        "ck.self.agent.pause" => json!({ "status": "paused" }),
        "ck.self.agent.resume" => json!({ "status": "active" }),
        "ck.self.agent.rotate_key" => json!({
            "agent_key_id": "ck:agent_key:01964137-0000-7000-8000-000000000002",
            "status": "rotated",
        }),
        "ck.self.agent.grant.attach" => json!({
            "grant_id": "ck:grant:01964137-0000-7000-8000-000000000010",
            "status": "active",
        }),
        "ck.self.agent.grant.detach" => json!({ "status": "detached" }),
        "ck.self.agent.sidecar_thread.ensure" => json!({
            "sidecar_thread_id": "ck:thread:01964137-0000-7000-8000-000000000020",
            "created": true,
        }),
        "ck.self.agent.deactivate" => json!({ "status": "deactivated" }),
        _ => Value::Null,
    }
}

fn path_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(&mut encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn main() -> cokret::Result<()> {
    let controller: Did = Did::new("did:web:alice.example")?;
    let device_id: DeviceId = DeviceId::new("ck:device:01964137-0000-7000-8000-000000000009")?;

    // A real integration would construct a `cokret::Client` against the
    // home soland's base URL and replace `mock_send` with `client.post(...)`
    // / `client.get(...)` / `client.delete(...)`. The example skips the
    // live transport so it compiles without network access.

    // 1. ck.gate.account.agent_key_pair
    let key = mock_send(
        "ck.gate.account.agent_key_pair",
        "POST",
        "/_cokret/gate/account/agent-key-pair",
        &json!({ "controller": controller, "device_id": device_id }),
    );
    let agent_key_id = key["agent_key_id"].as_str().unwrap();

    // 2. ck.self.agent.provision
    let provisioned = mock_send(
        "ck.self.agent.provision",
        "POST",
        "/agents",
        &json!({
            "controller": controller,
            "display_name": "alice-personal-agent",
            "agent_key_id": agent_key_id,
        }),
    );
    let agent_principal_id = provisioned["agent_principal_id"].as_str().unwrap().to_owned();
    let agent_principal_path = path_component(&agent_principal_id);

    // 3. ck.self.agent.list
    let _list = mock_send(
        "ck.self.agent.list",
        "GET",
        "/agents?controller=did:web:alice.example",
        &Value::Null,
    );

    // 4. ck.self.agent.get
    let _get = mock_send(
        "ck.self.agent.get",
        "GET",
        &format!("/agents/{agent_principal_path}"),
        &json!({ "agent_principal_id": agent_principal_id }),
    );

    // 5-6. pause + resume
    let _paused = mock_send(
        "ck.self.agent.pause",
        "POST",
        &format!("/agents/{agent_principal_path}/pause"),
        &json!({ "reason": "user_requested" }),
    );
    let _resumed = mock_send(
        "ck.self.agent.resume",
        "POST",
        &format!("/agents/{agent_principal_path}/resume"),
        &Value::Null,
    );

    // 7. rotate-key
    let _rotated = mock_send(
        "ck.self.agent.rotate_key",
        "POST",
        &format!("/agents/{agent_principal_path}/rotate-key"),
        &json!({ "previous_key_id": agent_key_id }),
    );

    // 8. grant.attach
    let grant = mock_send(
        "ck.self.agent.grant.attach",
        "POST",
        &format!("/agents/{agent_principal_path}/grants"),
        &json!({
            "scope": ["ck:capability:send_message"],
            "ttl_secs": 3_600,
        }),
    );
    let grant_id = grant["grant_id"].as_str().unwrap().to_owned();
    let grant_path = path_component(&grant_id);

    // 9. grant.detach
    let _detached = mock_send(
        "ck.self.agent.grant.detach",
        "DELETE",
        &format!("/agents/{agent_principal_path}/grants/{grant_path}"),
        &Value::Null,
    );

    // 10. sidecar_thread.ensure
    let _sidecar = mock_send(
        "ck.self.agent.sidecar_thread.ensure",
        "POST",
        "/agent-sidecar-threads:ensure",
        &json!({
            "agent_principal_id": agent_principal_id,
            "space_id": "ck:space:01964137-0000-7000-8000-000000000030",
        }),
    );

    // 11. deactivate
    let _deactivated = mock_send(
        "ck.self.agent.deactivate",
        "POST",
        &format!("/agents/{agent_principal_path}/deactivate"),
        &json!({ "reason": "demo_complete" }),
    );

    println!("personal-agent provisioning demo complete");
    Ok(())
}
