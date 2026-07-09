# arkret-ffi

FFI and WASM embedding contracts for Arkret.

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
// arkret.h — minimal C ABI sketch (layout-stable handles + error payload).
#include <stdint.h>
#include <stddef.h>

typedef struct CokretHandle CokretHandle;

typedef struct {
    int32_t  code;          // 0 == ok; non-zero matches ErrorPayload.code
    const char *message;    // UTF-8, owned by SDK; valid until next call
} CokretError;

CokretHandle *cokret_client_new(const char *base_url, CokretError *err);
int32_t        cokret_client_whoami(CokretHandle *h, char **out_json,
                                     CokretError *err);
void           cokret_string_free(char *s);
void           cokret_client_free(CokretHandle *h);
```

### WASM glue (TypeScript host)

```ts
// arkret-wasm.ts — calling the Wasm export surface from a browser host.
import init, { CokretClient } from "./cokret_ffi_wasm.js";

await init();                                  // load .wasm
const client = new CokretClient("https://home.example");
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
// CokretClient.kt — UniFFI-style JNI bridge for Android.
class CokretClient(baseUrl: String) : AutoCloseable {
    private val handle: Long = nativeNew(baseUrl)
    fun whoami(): String = nativeWhoami(handle)
    override fun close() { nativeFree(handle) }

    private external fun nativeNew(baseUrl: String): Long
    private external fun nativeWhoami(handle: Long): String
    private external fun nativeFree(handle: Long)

    companion object { init { System.loadLibrary("cokret_ffi") } }
}
```
