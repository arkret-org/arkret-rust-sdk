# Migration From Matrix

Contrix maps several familiar Matrix SDK concepts to protocol-first SDK types:

| Matrix concept | Contrix SDK concept |
| --- | --- |
| Room | Space |
| Room state | `resolver::SpaceState` / `base::ClientSpace` |
| Timeline | `timeline::Timeline` |
| Sync token | `sync::SyncResponse.next_batch` / `BaseClient::sync_token` |
| Sliding Sync lists | `sync_client::SlidingSync` |
| Room membership | `membership::MembershipManager` |
| To-device events | `devices::DeviceManager` / `sync::ToDeviceMessage` |
| Receipts | `receipts::ReceiptManager` |
| Account data | `account::AccountDataManager` |
| Push rules | `push::PushGateway` |
| Event handlers | `event_handler::EventHandlerRegistry` |

Migration guidance:

- Preserve room IDs as external references; create Contrix `SpaceId` values for
  new native spaces.
- Migrate room events into Contrix `Event` values with canonical payloads.
- Convert membership state before timeline data so access checks can be applied.
- Rebuild read receipts and notification counts after timeline import.
- Keep Matrix device identities available until E2EE sessions are re-established
  through Contrix MLS/key-management flows.
