//! End-to-end personal-agent provisioning demo against the soland agent-runtime
//! surface. Wires every operation from the `agent_runtime` group of
//! `operation-registry.json` (spec head 37ce729):
//!
//! 1. `cx.account.agent_key_pair`        — mint a fresh agent keypair
//! 2. `cx.agent.provision`               — create the agent principal
//! 3. `cx.agent.list`                    — confirm registry membership
//! 4. `cx.agent.get`                     — fetch the principal record
//! 5. `cx.agent.pause`                   — quiesce the runtime
//! 6. `cx.agent.resume`                  — un-quiesce
//! 7. `cx.agent.rotate_key`              — roll the signing key
//! 8. `cx.agent.grant.attach`            — bind a delegation grant
//! 9. `cx.agent.grant.detach`            — release the grant
//! 10. `cx.agent.sidecar_thread.ensure`  — pin a sidecar thread for tool calls
//! 11. `cx.agent.deactivate`             — terminate the principal
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

use contrix::{DeviceId, Did};
use serde_json::{Value, json};
use std::fmt::Write;

/// Stand-in for a wire send. Returns the mock response a real soland would
/// produce for each operation so the example stays self-contained.
fn mock_send(op_id: &str, method: &str, path: &str, body: &Value) -> Value {
    println!("→ {method} {path}  ({op_id})");
    println!("  request: {body}");
    match op_id {
        "cx.account.agent_key_pair" => json!({
            "agent_key_id": "cx:agent_key:01964137-0000-7000-8000-000000000001",
            "public_key": "ed25519:base64-pub-key",
        }),
        "cx.agent.provision" => json!({
            "agent_principal_id": "did:web:agent.example",
            "status": "active",
        }),
        "cx.agent.list" => json!({ "agents": [], "next_cursor": null }),
        "cx.agent.get" => {
            json!({ "agent_principal_id": body["agent_principal_id"], "status": "active" })
        }
        "cx.agent.pause" => json!({ "status": "paused" }),
        "cx.agent.resume" => json!({ "status": "active" }),
        "cx.agent.rotate_key" => json!({
            "agent_key_id": "cx:agent_key:01964137-0000-7000-8000-000000000002",
            "status": "rotated",
        }),
        "cx.agent.grant.attach" => json!({
            "grant_id": "cx:grant:01964137-0000-7000-8000-000000000010",
            "status": "active",
        }),
        "cx.agent.grant.detach" => json!({ "status": "detached" }),
        "cx.agent.sidecar_thread.ensure" => json!({
            "sidecar_thread_id": "cx:thread:01964137-0000-7000-8000-000000000020",
            "created": true,
        }),
        "cx.agent.deactivate" => json!({ "status": "deactivated" }),
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

fn main() -> contrix::Result<()> {
    let controller: Did = Did::new("did:web:alice.example")?;
    let device_id: DeviceId = DeviceId::new("cx:device:01964137-0000-7000-8000-000000000009")?;

    // A real integration would construct a `contrix::Client` against the
    // home soland's base URL and replace `mock_send` with `client.post(...)`
    // / `client.get(...)` / `client.delete(...)`. The example skips the
    // live transport so it compiles without network access.

    // 1. cx.account.agent_key_pair
    let key = mock_send(
        "cx.account.agent_key_pair",
        "POST",
        "/auth/account/agent-key-pair",
        &json!({ "controller": controller, "device_id": device_id }),
    );
    let agent_key_id = key["agent_key_id"].as_str().unwrap();

    // 2. cx.agent.provision
    let provisioned = mock_send(
        "cx.agent.provision",
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

    // 3. cx.agent.list
    let _list =
        mock_send("cx.agent.list", "GET", "/agents?controller=did:web:alice.example", &Value::Null);

    // 4. cx.agent.get
    let _get = mock_send(
        "cx.agent.get",
        "GET",
        &format!("/agents/{agent_principal_path}"),
        &json!({ "agent_principal_id": agent_principal_id }),
    );

    // 5-6. pause + resume
    let _paused = mock_send(
        "cx.agent.pause",
        "POST",
        &format!("/agents/{agent_principal_path}/pause"),
        &json!({ "reason": "user_requested" }),
    );
    let _resumed = mock_send(
        "cx.agent.resume",
        "POST",
        &format!("/agents/{agent_principal_path}/resume"),
        &Value::Null,
    );

    // 7. rotate-key
    let _rotated = mock_send(
        "cx.agent.rotate_key",
        "POST",
        &format!("/agents/{agent_principal_path}/rotate-key"),
        &json!({ "previous_key_id": agent_key_id }),
    );

    // 8. grant.attach
    let grant = mock_send(
        "cx.agent.grant.attach",
        "POST",
        &format!("/agents/{agent_principal_path}/grants"),
        &json!({
            "scope": ["cx:capability:send_message"],
            "ttl_secs": 3_600,
        }),
    );
    let grant_id = grant["grant_id"].as_str().unwrap().to_owned();
    let grant_path = path_component(&grant_id);

    // 9. grant.detach
    let _detached = mock_send(
        "cx.agent.grant.detach",
        "DELETE",
        &format!("/agents/{agent_principal_path}/grants/{grant_path}"),
        &Value::Null,
    );

    // 10. sidecar_thread.ensure
    let _sidecar = mock_send(
        "cx.agent.sidecar_thread.ensure",
        "POST",
        "/agent-sidecar-threads:ensure",
        &json!({
            "agent_principal_id": agent_principal_id,
            "space_id": "cx:space:01964137-0000-7000-8000-000000000030",
        }),
    );

    // 11. deactivate
    let _deactivated = mock_send(
        "cx.agent.deactivate",
        "POST",
        &format!("/agents/{agent_principal_path}/deactivate"),
        &json!({ "reason": "demo_complete" }),
    );

    println!("personal-agent provisioning demo complete");
    Ok(())
}
