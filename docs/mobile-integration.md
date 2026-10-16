# Native integration contract

UniFFI exposes owned records, opaque account handles, typed errors and asynchronous lifecycle operations; never Swarm, PeerId or Multiaddr types. SwiftUI and Compose applications remain outside this milestone. Minimal generated Swift/Kotlin binding proves ABI generation, not native app runtime behavior.

M3 delivers the high-level account/profile/discovery/matching/contact workflow through ApplicationHandle. [Application API](application-api.md) owns domain behavior; [durable operations](durable-operations.md) owns retry and recovery. No native caller manipulates keys, SQLite or libp2p. Actual build/runtime evidence is in [progress](progress.md).

## M3 exported operation mapping

Rust export names below are converted to language-specific casing by UniFFI. Inputs and outputs are owned bounded records or opaque handles.

| Export | Native-facing result |
|---|---|
| `create_application(config, passphrase)` / `open_application(config, passphrase)` | Opaque ApplicationHandle; explicit encrypted-vault create/open |
| `identity_summary()` / `import_credential(bytes)` / `credential()` | Public keys for an authorized issuer adapter; verified signed credential import/inspection |
| `publish_profile(photos)` / `published_profile()` | Durable publication receipt; locally persisted verified own profile |
| `discover(query)` / `fetch_photo(owner, hash)` | Verified candidate page; validated display-ready photograph |
| `like(profile_id)` / `pass(profile_id)` | Durable positive-intent receipt; private local pass |
| `received_likes(page_size, cursor)` / `matches(page_size, cursor)` | Authenticated sender and match pages; no automatic contact exposure |
| `disclose_contacts(match_id, handles)` / `received_contacts(match_id)` | Explicit matched disclosure and private selected handles |
| `block(profile_id)` / `report_profile(...)` / `local_reports_page(...)` | Local terminal block; signed LocalOnly reports and bounded history |
| `rank_candidates(...)` / `record_feedback(...)` / `reset_learning()` | Local ranking, feedback and reset |
| `operations(limit)` / `operations_page(page_size, cursor)` / `recover_pending()` | Bounded operation receipts and finite retry |
| `start_sync_session()` | Shared foreground/background synchronization through cancellable SyncSession |
| `pending_notifications(limit)` / `acknowledge_notification(id)` | Durable notification recovery and explicit display acknowledgement |
| `cancel_current_operation()` / `close()` | Independent cancellation; drain and release account ownership |

Publication and delivery receipts report retention rather than guaranteed recipient processing. Cancellation preserves committed work and cannot retract content already delivered. Typed categories distinguish expected input, authorization, credential, safety, network, capacity, cancellation and internal failures; private payloads never enter error strings. The portable passphrase backend does not prescribe a future mobile authentication UX.

One process-owned Tokio runtime executes serialized application operations; libp2p uses its bounded actor queue. Network work has explicit budgets and cancellation. Continuous network-state subscriptions, automatic repair/renewal, platform keystore adapters, native image pickers and production inference remain planned. Native lifecycle behavior is specified below; future ABI/schema changes require an explicit compatibility decision.

Preserved M1 facade contract: `api_version() -> String`; `LocalPreferenceModel(dimensions: u32, encoder_version: u16)`; `score(version, values) -> FfiRankingScore`; `record_feedback(version, values, liked)`; `reset()`. M1 typed errors InvalidInput, IncompatibleModel and Internal remain available. Generated Swift and Kotlin bindings plus actual Python ctypes ABI smoke prove different levels of integration; see [evidence](progress.md).

## M2 background host boundary

M2 API contracts below use Rust names; generated Swift/Kotlin casing follows UniFFI. They add to the existing LocalPreferenceModel API. No raw private-key bytes enter the ABI.

| Export | Contract |
|---|---|
| `create_account(directory, passphrase)` | Explicit portable-vault creation, fails if an account exists |
| `open_account(directory, passphrase)` | Opens existing vault only; returns opaque AccountHandle or typed key error |
| `AccountHandle.profile_id()` | Public account identifier, unavailable after lock |
| `AccountHandle.start_sync_session(request)` | Accepts bounded credential/trust/revocation/peer/contribution inputs and starts the shared Rust operation; credential verification precedes network activity and failures surface through the session result |
| `SyncSession.cancel()` | Signals cancellation independently of the worker |
| `SyncSession.wait_result(timeout_ms)` / `is_finished()` | Bounded wait/poll for structured report; returning a report does not acknowledge notification display |
| `AccountHandle.pending_notifications(limit)` / `acknowledge_notification(event_id)` | Durable metadata-only recovery and explicit host acknowledgement |
| `AccountHandle.notification_preferences()` / `set_notification_preferences(...)` | Persist independent like/match settings |
| `AccountHandle.lock()` | Excludes concurrent start, cancels/drains active work and releases account key ownership, including after a failed session |

One process-owned Tokio runtime executes finite sessions. A handle permits at most one active session; start and lock serialize their lifecycle. Foreground/background hosts reuse that handle or defer when the portable vault is already held; Busy never triggers replacement. The worker releases its account-key reference before publishing completion. Native hosts must run vault KDF, lock/drain and blocking result waits off UI threads; they must not destroy a borrowed foreign object while its call is active. Host cancellation signals the session and drains completion within the available window. OS process termination can interrupt everything; transaction/outbox recovery handles the next launch. Passphrases are prototype-backend authorization, not a prescribed native UX; Rust zeroization cannot erase copies retained by a foreign caller.

Contribution requests carry bounded already-authorized public profile/photo/lease inputs and host conditions. Enabling a policy alone never invents content or acknowledgements. Examples must use actual generated names; generated source is not a native compilation claim. The complete profile/swipe/contact application API is delivered by M3 above; these preserved M2 exports remain available for existing integrations.

Host source examples: [Android worker](../crates/mobile-ffi/examples/android/AnnodaSyncWorker.kt) and [iOS background task](../crates/mobile-ffi/examples/ios/AnnodaBackgroundSync.swift). These show scheduling, authorization deferral, cancellation, remaining-window budgets and permission-aware local notification acknowledgement. They require host dependency injection, platform setup and generated binding packaging. They are not complete applications or tested native adapters; [progress](progress.md) lists available compiler/runtime evidence.

Android host: unique periodic WorkManager CoroutineWorker, ≥15-minute requested interval, appropriate network/battery/charging constraints, same Rust operation as foreground, propagate coroutine stop/cancellation and drain pending events with stable notification ids before explicit ack. Actual launch can be delayed by Doze/quotas/constraints. No continuously running foreground-service workaround. [Official WorkManager contract](https://developer.android.com/develop/background-work/background-tasks/persistent/getting-started/define-work).

iOS host: register permitted BGTaskScheduler identifiers, use BGAppRefreshTask for short work or BGProcessingTask only when eligible, expirationHandler cancels Rust session, complete system task and request next opportunity, respect local notification permission. Scheduling is not an execution guarantee, fixed periods are unavailable, and force-quit must not be assumed to preserve background launches. [Apple background strategy](https://developer.apple.com/documentation/backgroundtasks/choosing-background-strategies-for-your-app), [BGTaskScheduler](https://developer.apple.com/documentation/backgroundtasks/bgtaskscheduler).

OS-granted window and authorized key-store access are independent prerequisites. Keychain/Keystore wrapping adapters, entitlements/manifest identifiers, notification authorization UI and physical-device validation remain host work. Small adapters/examples may be provided, no SwiftUI/Compose applications.

The host's outer execution window includes authorization/KDF, synchronization and notification handling. Subtract monotonic elapsed key-access time before choosing the remaining SyncBudget and stop if the grant has expired. The examples use a conservative host-selected 20-second work ceiling; this is not an OS grant or timing guarantee. In particular, WorkManager's 15-minute scheduling minimum is unrelated to the available execution duration. A portable-vault KDF is synchronous and cannot be preempted by the network cancellation token; an unavailable authorization grant must defer work, not prompt from a background task or persist an unprotected passphrase.

## M3 complete application facade

The [application service contract](application-api.md) replaces native orchestration of primitives with one opaque application handle backed by `annoda_network::client::AnnodaClient`. It adds the full account/credential/profile/discovery/photo/intent/inbox/match/contact/block/report/ranking/operation workflow while preserving M2 exports. Creation and opening authorize the existing portable vault; no raw keys cross UniFFI. The new handle and legacy M2 handle share the same exclusive vault lease.

All collections use bounded DTO pages and validated opaque cursors. Native-facing peer configuration uses strings; no `PeerId`/`Multiaddr` object is exposed. A typed category distinguishes InvalidInput, Unauthorized, UntrustedIdentity, CredentialExpired, SafetyUnavailable, NetworkUnavailable, StorageFull, Cancelled, Pending, Unsupported and Internal. Operation receipts distinguish locally saved work, remote retention and unknown recipient processing. Returned notification events still require explicit host acknowledgement after display. DTO additions are additive; signed protocol version remains 1.

One owned runtime executes serialized client operations. Sync uses a cancellable session with independent cancellation access and bounded waiting. Lock/close cancels active work and releases key ownership only after it drains. Blocking calls/KDF and waiting must run off the UI thread. Existing Android/iOS scheduling limitations apply unchanged; foreground and background use the same service protocol. [Progress](progress.md) lists actual exports, ABI smoke evidence and unavailable native compilation. Development inference configuration is explicit and never an automatic production fallback.

Generated bindings are tied to the built library and its UniFFI checksums. Regenerate and ship them together after API additions; preserving M2 exported operations is not a claim that an arbitrary older binary binding can load every newer library. `ApplicationHandle.published_profile()` returns the owner’s locally verified persisted profile after reopen, without a network round trip.

`operations(limit)` is a bounded convenience preview. Native clients use `operations_page` to reach older Pending/Partial/Completed/Failed receipts beyond its first page; owner-bound cursors reuse the Rust service validation.
