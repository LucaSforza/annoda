## Transactional notifications

```mermaid
classDiagram
    class PeerStorage {
        +ingest(parcel, checkpoint) IngestResult
        +pending_notifications(owner, limit) List
        +acknowledge_notification(owner, event_id) Result
    }
    class NotificationEvent {
        +bytes32 event_id
        +NotificationKind kind
    }
    class NotificationKind {
        <<enumeration>>
        NewLike
        NewMatch
    }
    class OutboxEntry {
        +NotificationEvent event
        +ProfileId owner
        +AckState state
    }
    class NotificationPreferences {
        +bool likes_enabled
        +bool matches_enabled
    }
    class SyncCheckpoint {
        +ProfileId owner
        +String peer
        +u64 expires_cursor
        +bytes16 parcel_cursor
    }
    class NativeNotificationAdapter {
        <<planned host>>
        +post(stable_id, kind) Result
        +acknowledge(event_id) void
    }
    PeerStorage "1" *-- "0..*" OutboxEntry
    PeerStorage "1" *-- "0..*" SyncCheckpoint
    PeerStorage "1" *-- "0..*" NotificationPreferences
    OutboxEntry "1" *-- "1" NotificationEvent
    NotificationEvent "1" --> "1" NotificationKind
    NativeNotificationAdapter ..> NotificationEvent
    NativeNotificationAdapter ..> PeerStorage : explicit ack
```

Mapping: additive core SQLite tables/types; UniFFI DTOs export only event id/kind. State/evidence/outbox/checkpoint commit atomically. Returning events leaves Pending unchanged. Native adapters may retry at least once and must use stable ids. [Notification authority](../../notifications.md).
