# arkret-egress-reqwest

The composition layer over [`arkret-egress-policy`](../egress-policy).

`arkret-egress-policy` answers one question at a time: may this scheme be used,
may this host name be reached, may this address be connected to. Everything
above it — parse the URL, judge it, resolve it, judge every DNS answer, and bind
the surviving answers to the `reqwest` client that will dispatch the request so
a second lookup cannot rebind the host — is the same in every Arkret service.
This crate owns that sequence so no service has to reassemble it.

## Use

```rust,ignore
let guard = arkret_egress_reqwest::EgressGuard::public_https();
let target = guard.lock_str("https://relay.example/inbox", "federation outbox")?;
let client = target
    .apply_to_client_builder(guard.apply_to_client_builder(reqwest::Client::builder()))
    .build()?;
let response = client.get(target.url().clone()).send().await?;
```

`EgressGuard::apply_to_client_builder` installs the connect-time DNS resolver
and the scheme restriction; `LockedEgressUrl::apply_to_client_builder` pins the
already-validated answer set. Redirects must repeat the whole sequence, so
callers build with `redirect::Policy::none()`.

## Loopback host scope

Beyond the base `OutboundPolicy`, a deployment may name hosts that are allowed
to resolve *wholly* to loopback while everything else keeps the public-HTTPS
posture (`with_trusted_loopback_https_hosts`), or restrict a client to loopback
destinations only (`loopback_only`). Both default to off, and neither can admit
a private, link-local, or metadata destination.
