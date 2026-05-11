# Sync Best Practices

Use `sync_client::SyncLoop` as the control-plane state for long-polling:

- Build each request with `next_request`.
- Execute transport outside the loop so native, mobile and WASM runtimes can
  provide their own HTTP/cancellation model.
- On failure, use the returned retry delay from exponential backoff.
- On success, pass updates into application managers or `BaseClient`.

Use `SyncResponseProcessor` when the application receives sync responses from a
custom transport. It updates caches for spaces, to-device messages, device list
changes, presence, account data and notifications.

Use `SlidingSync` to generate visible-window subscriptions. Keep the ordered
space list in the UI model, apply deltas, then build a `SubscriptionConfig` for
the next sync request.

Persist the latest sync token, event cache and verified state snapshot in your
application's durable storage before acknowledging a batch to the UI.
