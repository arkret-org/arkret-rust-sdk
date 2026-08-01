# arkret-locale

The single UI-locale vocabulary and resolution order shared by Arkret services
and clients.

`UiLocale` is the closed set of languages the product ships. `resolve` applies
one precedence chain — account preference, explicit request, device cache,
platform default, English — so coauth and inkson cannot disagree about what
language a user is in.

Dependency-free and `wasm32`-safe: the same code runs in coauth's server, in
coauth's browser SPA and in inkson's cross-platform client.

```rust
use arkret_locale::{LocaleSources, UiLocale, resolve};

let locale = resolve(&LocaleSources {
    account: Some("zh"),
    platform: Some("en-US,en;q=0.9"),
    ..Default::default()
});
assert_eq!(locale, UiLocale::Zh);
```
