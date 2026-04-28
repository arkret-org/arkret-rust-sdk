# Releasing

The release unit is the `contrix-sdk` crate.

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
   git tag contrix-sdk-vX.Y.Z
   cargo publish -p contrix-sdk
   git push origin contrix-sdk-vX.Y.Z
   ```

Do not publish a release that changes canonical digest behavior without an
explicit compatibility note.
