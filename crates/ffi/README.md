# contrix-ffi

FFI and WASM embedding contracts for Contrix.

This crate provides layout-stable handles, error payloads, callback results,
WASM HTTP/store/WebCrypto descriptors and API-freeze review artifacts that can
be shared by UniFFI, WASM and native host bindings.

## Binding examples

The three snippets below are illustrative — they show the *shape* of the
host-side calling convention against the C ABI exported by this crate. Real
bindings should be generated (UniFFI / wasm-bindgen / `cargo ndk`) rather than
hand-written, but these are useful when wiring a new host or auditing the
ABI surface.

### C header

```c
// contrix.h — minimal C ABI sketch (layout-stable handles + error payload).
#include <stdint.h>
#include <stddef.h>

typedef struct ContrixHandle ContrixHandle;

typedef struct {
    int32_t  code;          // 0 == ok; non-zero matches ErrorPayload.code
    const char *message;    // UTF-8, owned by SDK; valid until next call
} ContrixError;

ContrixHandle *contrix_client_new(const char *base_url, ContrixError *err);
int32_t        contrix_client_whoami(ContrixHandle *h, char **out_json,
                                     ContrixError *err);
void           contrix_string_free(char *s);
void           contrix_client_free(ContrixHandle *h);
```

### WASM glue (TypeScript host)

```ts
// contrix-wasm.ts — calling the Wasm export surface from a browser host.
import init, { ContrixClient } from "./contrix_ffi_wasm.js";

await init();                                  // load .wasm
const client = new ContrixClient("https://home.example");
client.setDidResolver(async (did: string) => {
    const res = await fetch(`/.well-known/did.json?did=${did}`);
    return new Uint8Array(await res.arrayBuffer());
});
const me = await client.whoami();              // returns JSON.parse'd object
console.log(me.user_id);
client.free();                                 // explicit drop — wasm has no GC
```

### JNI (Android / Kotlin host)

```kotlin
// ContrixClient.kt — UniFFI-style JNI bridge for Android.
class ContrixClient(baseUrl: String) : AutoCloseable {
    private val handle: Long = nativeNew(baseUrl)
    fun whoami(): String = nativeWhoami(handle)
    override fun close() { nativeFree(handle) }

    private external fun nativeNew(baseUrl: String): Long
    private external fun nativeWhoami(handle: Long): String
    private external fun nativeFree(handle: Long)

    companion object { init { System.loadLibrary("contrix_ffi") } }
}
```
