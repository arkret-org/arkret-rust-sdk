# SDK spec coverage contract

Date: 2026-08-01

## Decision

The SDK covers every `active` row in `schema-registry.json` at the schema-artifact
layer. Coverage means all of the following are present and synchronized:

1. a generated `SchemaId` and `SchemaDescriptor`;
2. the referenced JSON Schema document in the embedded artifact bundle; and
3. runtime loading through `schema_registry_from_{spec,embedded}_artifacts`.

It does not mean that every registry row owns a standalone hand-written Rust DTO.
Some documents are aggregate definition libraries, binding frames, or validation-only
contracts. Typed DTO coverage is a separate property of the owning model crates and
must not be inferred from this gate.

`SpecArtifactBundle::drift_report` therefore compares active live rows with generated
`REGISTERED_SCHEMA_IDS` in both directions. The generated table replaces the former
hand-maintained `SUPPORTED_SCHEMA_IDS`. A live schema addition without regeneration is
reported as `unlisted_schemas`; a generated row removed from the live registry is
reported as `missing_schemas`.

## Classification of the reported rows

The live report contained 57 rows (the older task text said 58). All 57 are covered by
the contract above; none is classified outside the promise:

- `ak.schema.agent_sidecar.v1`
- `ak.schema.agent_sidecar_event_exchange_binding.v1`
- `ak.schema.agent_sidecar_exchange_control.v1`
- `ak.schema.agent_sidecar_exchange_projection.v1`
- `ak.schema.agent_sidecar_view_state.v1`
- `ak.schema.agent_signer_evidence.v1`
- `ak.schema.agent_signer_evidence_bundle.v1`
- `ak.schema.agent_signer_evidence_query_outcome.v1`
- `ak.schema.agent_signer_evidence_query_request.v1`
- `ak.schema.agent_signing_key_binding.v1`
- `ak.schema.authority_set_policy.v1`
- `ak.schema.backup_series_erase_confirmation.v1`
- `ak.schema.call_signal_plaintext.v1`
- `ak.schema.cba_proof_bundle.v1`
- `ak.schema.device_pairing_bootstrap.v1`
- `ak.schema.device_pairing_operations.v1`
- `ak.schema.did_binding_contracts.v1`
- `ak.schema.did_webvh_witness_receipt.v1`
- `ak.schema.events_subscribe_frame.v1`
- `ak.schema.extension_manifest.v1`
- `ak.schema.federated_device_signing_key_evidence.v1`
- `ak.schema.high_risk_authority_proof.v1`
- `ak.schema.object_addressing.v1`
- `ak.schema.offline_publication.v1`
- `ak.schema.public_key.v1`
- former recovery authority ticket schema (removed by the PCR-genesis clean cut)
- `ak.schema.recovery_completion_attestation.v1`
- `ak.schema.security_rotation_local_commit.v1`
- `ak.schema.security_transaction.v1`
- `ak.schema.signal_envelope.v1`
- `ak.schema.signal_message_stream.v1`
- `ak.schema.signal_presence.v1`
- `ak.schema.signal_relay.v1`
- `ak.schema.signal_stream_frame.v1`
- `ak.schema.signal_typing.v1`
- `ak.schema.string_profiles.v1`
- `ak.schema.time.v1`
- `ak.schema.transport_binding.v1`
- `ak.schema.websocket_authenticate_frame.v1`
- `ak.schema.websocket_challenge_frame.v1`
- `ak.schema.websocket_client_frame.v1`
- `ak.schema.websocket_close_frame.v1`
- `ak.schema.websocket_closed_frame.v1`
- `ak.schema.websocket_control_frame.v1`
- `ak.schema.websocket_data_frame.v1`
- `ak.schema.websocket_dpop_claims.v1`
- `ak.schema.websocket_dpop_proof.v1`
- `ak.schema.websocket_dpop_protected_header.v1`
- `ak.schema.websocket_error_frame.v1`
- `ak.schema.websocket_frame.v1`
- `ak.schema.websocket_open_frame.v1`
- `ak.schema.websocket_opened_frame.v1`
- `ak.schema.websocket_ping_frame.v1`
- `ak.schema.websocket_pong_frame.v1`
- `ak.schema.websocket_reauth_required_frame.v1`
- `ak.schema.websocket_server_frame.v1`
- `ak.schema.websocket_welcome_frame.v1`

The classification is machine-auditable: the generator selects active rows, and the
drift report compares that generated set against the independently loaded live
registry. The unit test injects an extra active row and proves that it is rejected.

## Follow-up adjudication

- Closed registries: generate `TrackName`, `BindingKind`,
  `AuthoritySetPolicyKind`, and `AuthoritySetSourceKind`. This closes the concrete
  `synthesis` track omission and removes manual authority/binding vocabularies.
  `ProtocolLayerKind` remains deliberately hand-written because Extension Manifest
  forbids `kernel`, while the protocol-layer registry correctly contains it.
  Runner kinds and string profiles have no duplicate SDK enum to replace; generating
  unused types would add no enforcement.
- Operation errors: generate one descriptor per `ServiceOperationId` from
  `operations-error-mapping.json`. Generation validates complete operation coverage,
  the HTTP alias cross-link, and every referenced error/reason code.
- HTTP client paths: retain endpoint-local path templates. Dynamic captures require
  endpoint-specific substitution, and replacing them with runtime descriptor scans
  would not improve correctness. `operation_path_coverage` already compares every
  source path with generated descriptors, checks its own source-file coverage, and
  rejects stale exemptions.
- Identifier fields: use `PlanId` and `ServiceRegistrationReceiptId`, and spell the
  receipt wire member `registration_receipt_id` exactly as the schema requires.
