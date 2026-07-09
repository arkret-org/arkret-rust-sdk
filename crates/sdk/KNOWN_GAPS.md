# Known SDK / Spec Drift

> S-12 (savfox SDK gap, 2026-05-27). One-page reference for downstream
> integrators (savfox, gateway-server bridges, agent runtimes) so the
> known shape mismatches between the in-tree types and the on-wire spec
> don't have to be discovered the hard way.

Last sync: spec head `653ffb2`, SDK at commit produced alongside this
file.

## 0. 2026-06-04 Applet protocol alignment (S-13)

Spec `653ffb2` landed the finalized Applet install model. The SDK was
brought into line:

- **`ak.applet.registration.registration_epoch` is now required.**
  `WireAppletRegistration` gained a non-optional
  `registration_epoch: Hash` (canonical security epoch hash). The SDK
  cannot synthesize the full evidence digest, so
  `WireAppletRegistration::new(..)` and `AppletPackage::new(..)` take it
  as the final argument. Registrations emitted before this release are
  non-conformant (missing the field) and MUST be re-issued.
- **Namespace entries are object-form.** `AppletWireNamespaces`
  `actors` / `realms` / `handles` changed from `Vec<String>` to
  `Vec<AppletNamespaceEntry>` (`{ exclusive, pattern }`) per
  `applet-schema.md` §2. **Breaking wire change**: a bare `["pattern"]`
  array no longer deserializes; use `[{ "exclusive": .., "pattern": .. }]`.
- **`AppletPackage` (`ak.schema.applet_package.v1`) added.** Controller-
  signed distribution object with `seal()` (stamp `package_digest`),
  `sign()` (controller proof) and `to_registration()` (spec §1a
  Package→registration derivation). A package is NOT a grant and NOT
  Realm history.
- **Install aggregate objects added.** `InstallPreviewRequest`,
  `InstallPlan` (with `seal()` / `compute_plan_digest()`),
  `InstallCommitRequest`, `InstallCommitResponse`, `EffectiveScope`
  (realm / circle), `ApprovalRequest`, `ApprovedScope`, `ActorPolicy`,
  `InstallE2eePolicy`, `WidgetPolicy`.
- **`ak.applet.bridge_error` reshaped.** `AppletBridgeErrorBuilder` now
  binds the spec §7 required fields (`realm_id`,
  `failed_transaction_ref`, `error_class`, `error_code`, `retriable`,
  `visibility_scope`). The old `severity` / `target_ref` slots and the
  `AppletBridgeErrorSeverity` enum were removed in favor of
  `AppletBridgeErrorVisibility`.
- **Namespace pattern grammar aligned to §2.** `namespace_pattern_matches`
  is now domain-aware — `namespace_pattern_matches(AppletNamespaceDomain,
  pattern, candidate)`. Separators depend on the bucket (actor: `:`;
  realm / handle: `:` and `/`), `**` crosses `/` but never `:` and never
  matches an empty segment, and a DID `#fragment` is ignored for actor
  matching. Exclusive-overlap detection moved onto
  `AppletWireNamespaces::conflicts_with`.
- **`applet` convenience feature added** (`applet-runtime` + `client` +
  `server` + `salvo`) so `cargo add arkret --features applet` is all an
  Applet service needs.
- **Parallel models removed** (compatibility intentionally
  dropped): `SignedAppletRegistration`, the pre-wire `AppletSchema` /
  `AppletPermission` / `OpenApiBinding` triple, and
  `AppletNamespaceDeclaration` / `AppletNamespaceKind` are gone.
  `WireAppletRegistration` + `AppletPackage` + `AppletNamespaceEntry`
  (with `AppletNamespaceDomain`) are the only registration / namespace
  surface.

## 1. `Event.applet_id` / `Event.external_ref` are first-class top-level fields

**Status:** **Resolved this release (S-7).**

`spec/v1/zh/applet-integration.md` §8 shows `ak.applet.bridge_event`
Envelopes carrying top-level `applet_id` and `external_ref`. Prior to
this release the SDK had no slot for either field; downstream
integrators (savfox `crates/channels/src/arkret/applet/outbound.rs`)
were stuffing them into `Event.unsigned` and tagging the line with
`TODO(arkret-spec-drift)`.

As of this commit:

- `arkret_core::Event::applet_id: Option<String>` is a first-class
  field.
- `arkret_core::Event::external_ref: Option<serde_json::Value>` is a
  first-class field.
- Both are folded into `Event::event_digest()` (canonical event bytes)
  whenever set — no special-cased signing transcript wiring is needed.
- Reducer `actor_kind` stamping is unchanged.

**Action for integrators:** drop the `unsigned`-hosted shims and
populate the top-level slots directly. Re-sign the Envelope via
`arkret_signatures::sign_event` (S-1) afterwards so the proof binds the
new bytes.

## 2. `SignedAppletRegistration` vs wire `ak.applet.registration`

**Status:** **Resolved (S-13): `SignedAppletRegistration` removed.**

The SDK-internal `SignedAppletRegistration` (plus its
`AppletSchema` / `AppletNamespaceDeclaration` dependencies and the
test-only `AppletRegistry`) has been deleted. `ak.applet.registration`
has exactly one representation:

`arkret::WireAppletRegistration` — wire shape `kind / applet_id /
service_did / controller_did / base_url / bot_actor_id / protocols /
namespaces { actors, realms, handles } / receive_events /
receive_ephemeral / rate_limited / requested_scopes / registration_epoch
/ webhook_auth / manifest? / proof / created_at`. Sign it with
`arkret::sign_registration(&mut reg, signer, vm_id)`, or derive it from
an `AppletPackage` via `package.to_registration()`.

## 3. Other intentionally-deferred items

- `ak.principal.provision` / managed-account auto-creation lives in
  `arkret-spec` proposal review. Not in scope for the SDK until the
  spec lands.
- MLS / E2EE Ghost actor encryption path: spec §12 defines it but
  savfox Phase 6 explicitly defers.
- Federation seal verification + cursor-revoke auto-recovery: tracked
  separately; not part of the S-1..S-11 deliverable.

---

If you are an integrator hitting drift not listed here, file an issue
referencing this file so we can either fix the SDK or document the
gap.
