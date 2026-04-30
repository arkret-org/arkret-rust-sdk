# Releasing

The release unit is the Contrix crate set: `contrix-core`, `contrix-client`,
`contrix-server` and the umbrella `contrix` crate.

## Checklist

1. Run verification:

   ```sh
   cargo fmt --check
   cargo check
   cargo test
   ```

2. Confirm the public protocol surface is compatible with the current Contrix
   specification.

3. Update crate and workspace versions in `Cargo.toml`.

4. Tag and publish:

   ```sh
   cargo publish -p contrix-core
   cargo publish -p contrix-client
   cargo publish -p contrix-server
   cargo publish -p contrix
   ```

Do not publish a release that changes canonical digest behavior without an
explicit compatibility note.
