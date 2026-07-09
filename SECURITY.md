# Security Policy

## Supported versions

The Arkret Rust SDK is in its local `1.0.0` freeze line. Local fixes should
target the latest `1.0.x` branch; remote publication is outside this readiness
workflow.

| Version | Supported |
| ------- | --------- |
| `1.0.x` | Yes       |
| < `1.0` | No        |

After `1.0`, the support window will track the latest stable major plus one
prior minor; the table here will be updated to reflect that.

## Reporting a vulnerability

Please **do not** open public GitHub issues for suspected security
vulnerabilities. Instead, report privately via either channel:

- GitHub Security Advisories (preferred): use the *Report a vulnerability*
  button on the repository's Security tab. This creates a private advisory
  visible only to maintainers.
- Email: `chris@acroidea.com`. Use a subject line that starts with
  `[arkret-rust-sdk security]`.

Please include:

- Affected SDK version (`cargo pkgid arkret` output is fine).
- A minimal reproduction (a Rust snippet, an HTTP transcript, or a failing
  conformance vector).
- Your assessment of impact (information disclosure, signature forgery,
  denial of service, …).
- Whether you intend to disclose publicly, and any deadline you would like
  the project to honour.

## Response and disclosure timeline

- We aim to acknowledge new reports within **3 business days**.
- For confirmed issues we aim to ship a fix within **30 days** of the
  acknowledgement, or sooner for actively-exploited vulnerabilities. Complex
  protocol issues that require coordination with the Arkret specification
  may take longer; the reporter will be kept informed.
- Once a fix is ready locally, a private advisory record and a CHANGELOG entry
  will describe the issue, affected versions, and the fix.
  Reporter credit is given by default; ask in your report if you prefer
  anonymity.

## Scope

In scope:

- Anything in `crates/*` that ships in a local `arkret-*` package artifact.
- The default behaviour of `arkret-http-client` against an arbitrary Arkret
  service (URL handling, header construction, retry/backoff, error envelope
  parsing).
- Cryptographic primitives and AEAD/MLS bindings when their explicit SDK
  features are enabled.

Out of scope:

- Issues that require modifying the SDK source to introduce a vulnerability
  (e.g. disabling validation hooks, replacing trait implementations with
  insecure ones).
- Bugs reachable only when callers explicitly opt into clearly-named unsafe
  behaviour such as `ClientBuilder::allow_insecure_localhost`.
- Bugs in third-party `reqwest`, `openmls`, `salvo`, etc. — please report
  them upstream. Mention the affected version in your report so we can issue
  a coordinated advisory if the SDK exposes it.

## Cryptographic guarantees

The current `1.0.0` local freeze records a security-review packet in
`docs/security-review-1.0.0.md` and real-server interoperability evidence in
`docs/release-evidence-1.0.0.md`. Treat the cryptographic surface as locally
reviewed, with external audit claims still out-of-scope for this workflow.
Production deployments should:

- Back MLS state with a platform key store and durable `CryptoStore`
  implementation.
- Pin the SDK by minor version and enable `cargo audit` in CI.
- Keep `allow_insecure_localhost` off in production builds.
