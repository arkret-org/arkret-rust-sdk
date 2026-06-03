# Known SDK / Spec Drift

> S-12 (savfox SDK gap, 2026-05-27). One-page reference for downstream
> integrators (savfox, gateway-server bridges, agent runtimes) so the
> known shape mismatches between the in-tree types and the on-wire spec
> don't have to be discovered the hard way.

Last sync: spec head `37ce729`, SDK at commit produced alongside this
file.

## 1. `Event.applet_id` / `Event.external_ref` are first-class top-level fields

**Status:** **Resolved this release (S-7).**

`spec/v1/zh/applet-integration.md` §8 shows `ck.applet.bridge_event`
Envelopes carrying top-level `applet_id` and `external_ref`. Prior to
this release the SDK had no slot for either field; downstream
integrators (savfox `crates/channels/src/cokret/applet/outbound.rs`)
were stuffing them into `Event.unsigned` and tagging the line with
`TODO(cokret-spec-drift)`.

As of this commit:

- `cokret_core::Event::applet_id: Option<String>` is a first-class
  field.
- `cokret_core::Event::external_ref: Option<serde_json::Value>` is a
  first-class field.
- Both are folded into `Event::event_digest()` (canonical event bytes)
  whenever set — no special-cased signing transcript wiring is needed.
- Reducer `actor_kind` stamping is unchanged.

**Action for integrators:** drop the `unsigned`-hosted shims and
populate the top-level slots directly. Re-sign the Envelope via
`cokret_signatures::sign_event` (S-1) afterwards so the proof binds the
new bytes.

## 2. `SignedAppletRegistration` vs wire `ck.applet.registration`

**Status:** **Co-exists; new integrations MUST use `WireAppletRegistration` (S-4).**

The legacy `cokret::SignedAppletRegistration`
(`crates/sdk/src/applet.rs`) is an SDK-internal model whose field names
(`registration_id`, `schema`, `namespaces: Vec<…Declaration>`) do not
match the on-wire `ck.applet.registration` Event content shape spec'd
in `applet-schema.md` §1.

The wire shape — `kind / applet_id / service_did / controller_did /
base_url / bot_actor_id / protocols / namespaces { actors, realms,
handles } / receive_events / receive_ephemeral / rate_limited /
requested_scopes / webhook_auth / created_at / proof` — is now
available as `cokret::WireAppletRegistration`. Sign it with
`cokret::sign_registration(&mut reg, signer, vm_id)`.

`SignedAppletRegistration` is kept for in-process registry callers
(`AppletRegistry`); new external-facing code MUST use
`WireAppletRegistration` to avoid silent reducer rejection.

## 3. Other intentionally-deferred items

- `ck.principal.provision` / managed-account auto-creation lives in
  `cokret-spec` proposal review. Not in scope for the SDK until the
  spec lands.
- MLS / E2EE Ghost actor encryption path: spec §12 defines it but
  savfox Phase 6 explicitly defers.
- Federation anchor verification + cursor-revoke auto-recovery: tracked
  separately; not part of the S-1..S-11 deliverable.

---

If you are an integrator hitting drift not listed here, file an issue
referencing this file so we can either fix the SDK or document the
gap.
