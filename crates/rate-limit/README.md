# arkret-rate-limit

Capacity-bounded, framework-independent in-memory token-bucket and fixed-window
rate-limit mechanisms shared by Arkret services.

This crate has no protocol-model, runtime, HTTP framework, or storage
dependencies. Services supply their own semantic keys, quotas, persistence,
and error mapping.
