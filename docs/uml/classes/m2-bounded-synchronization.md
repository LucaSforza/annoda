## Bounded synchronization

```mermaid
classDiagram
    class SyncContext {
        +VerifiedCredential credential
        +TrustedIssuers issuers
        +List known_peers
        +Path state_path
        +Path transport_data_dir
        +ContributionInputs contribution
    }
    class SyncBudget {
        +Duration max_duration
        +u64 max_download_bytes
        +u64 max_upload_bytes
        +u16 max_peers
        +u16 max_mailbox_items
        +u16 max_concurrent_requests
        +u16 retries
        +Duration request_timeout
    }
    class SyncService {
        +sync_once(account, context, budget, cancellation) SyncReport
    }
    class AccountHandle {
        -UnlockedAccount account
        -LifecycleGate lifecycle
        +start_sync_session(request) SyncSession
        +lock() Result
    }
    class SyncSession {
        -CancellationToken cancellation
        -OptionalResult result
        +cancel() void
        +wait_result(timeout_ms) OptionalReport
        +is_finished() bool
    }
    class TransferMeter {
        -u64 downloaded
        -u64 uploaded
        +read_remaining() u64
        +write_remaining() u64
    }
    class CancellationToken {
        +cancel() void
        +is_cancelled() bool
    }
    class SyncReport {
        +SyncStatus status
        +u32 verified_items
        +u32 rejected_items
        +u64 downloaded_bytes
        +u64 uploaded_bytes
        +List new_events
    }
    class PeerContributionPolicy {
        +bool enabled
        +bool wifi_only
        +bool charging_only
        +u64 max_storage_bytes
        +u64 max_transfer_bytes
        +Duration max_duration
    }
    class SessionSwarm {
        +connect(allowed_peer) Result
        +poll_page() MailboxPage
        +shutdown() Result
    }
    SyncService ..> SyncContext
    SyncService ..> UnlockedAccount : borrows authorized keys
    SyncService ..> SyncBudget
    SyncService "1" *-- "1" SessionSwarm
    SessionSwarm "1" *-- "1" TransferMeter
    SyncService ..> CancellationToken : observes across awaits
    SyncContext "1" --> "1" PeerContributionPolicy
    SyncService ..> SyncReport : finite result
    AccountHandle "1" *-- "0..1" UnlockedAccount : released after drain
    AccountHandle "1" --> "0..1" SyncSession : active session
    SyncSession ..> SyncService : finite runtime task
```

Mapping: network::sync function/types (SyncService is the module-level operation), raw transport I/O wrapper/meter, existing PeerNode/SQLite; mobile-ffi AccountHandle and SyncSession own native lifecycle. Initial scheduling may be serial, always below requested concurrency ceiling. Invariants: global byte and peer ceilings, outbound-only Annoda RPC admission, no transaction across await, no optional transfers without policy, no swarm after result. Replica batches have distinct owners; a confirmation counts one peer's complete manifest, with Partial for incomplete requested contribution. Start and lock exclude each other; completion follows release of the worker's key reference. Host grant is external and can end at any time. [Lifecycle authority](../../background-sync.md).
