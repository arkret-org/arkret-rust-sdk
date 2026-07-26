# Sync Best Practices

Use `sync_client::SyncLoop` as the control-plane state for long-polling:

- Build each request with `next_request`.
- Execute transport outside the loop so native, mobile and WASM runtimes can
  provide their own HTTP/cancellation model.
- On failure, use the returned retry delay from exponential backoff.
- On success, pass updates into Garth's `SyncResponseProcessor` or `ArkretClient`.

Use `SyncResponseProcessor` when the application receives sync responses from a
custom transport. It updates caches for spaces, to-device messages, device list
changes, presence, account data and notifications.

Use Garth's `SubscriptionEngine` for Realm event subscriptions; keep
presentation-specific ordering and visible-window state in the application.

Persist the latest sync token, event cache and verified state snapshot in your
application's durable storage before acknowledging a batch to the UI.
