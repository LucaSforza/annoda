# Native integration contract

UniFFI exposes owned records, opaque account handles, typed errors and asynchronous lifecycle operations; never Swarm, PeerId or Multiaddr types. SwiftUI and Compose applications remain outside this milestone. Minimal generated Swift/Kotlin binding proves ABI generation, not native app runtime behavior.

Target facade: create/open local account; import/verify credential; publish profile; query candidates; like/pass; read received likes and matches; explicitly disclose selected contacts; block/report; rank/reset preferences; observe bounded network events; cancel work and close account. Account opening must require encrypted secret access rather than plaintext key file defaults. Returned DTOs contain only fields caller is allowed to see. Stable error categories: InvalidInput, UntrustedIdentity, Expired, Unauthorized, SafetyUnavailable, NetworkUnavailable, StorageFull, Cancelled, Internal.

Initial surface may expose smaller verified operations (e.g. protocol version, credential validation, local ranking); list actual exports and generated-binding commands in [progress](progress.md). Unimplemented methods must not return invented success. Network facade delivery requires account persistence, runtime ownership and cancellation tests; [progress](progress.md) records M2 proof.

One Rust runtime owns network tasks; API requests use bounded queue, explicit deadline/cancellation and event subscription with bounded buffering. Mobile suspension stops active repair and renewal; reconnect reconciles persisted inbox and leases. Platform keystore, background tasks, image picker and actual model inference are future adapters. Schema/API changes require versioning and migration ADR.

## Target operation contracts (planned except minimal exports below)

| Operation | Input / output | Required effect |
|---|---|---|
| create_account | secure-store selector → opaque AccountHandle | OS RNG key generation; protected secret storage |
| open_account | account locator + unlock capability → AccountHandle | no raw secret returned |
| import_credential | signed bytes → VerifiedIdentitySummary | trust, key binding, age, time, revocation validated |
| publish_profile | photo inputs + public preference DTO → OperationId | normalize/classify, sign, replicate; receipt distinguishes partial replicas |
| candidate_profiles | explicit filter + cursor → bounded CandidatePage | verify records, exclude local blocks, no model sent |
| like / pass | candidate id → LocalIntentReceipt | persist before sending; pass remains local |
| received_likes | cursor → bounded ReceivedLikePage | decrypted authenticated sender visible before match |
| matches | cursor → bounded MatchPage | two authenticated intents; no implicit contact |
| disclose_contacts | match id + selected handles → OperationId | match gate and private encrypted delivery |
| block / report | profile id + optional bounded evidence → LocalReceipt | local immediate exclusion; remote report only explicit future policy |
| rank / feedback / reset | local embeddings and feedback → scores / receipt | no remote preference upload |
| observe_network | subscription → bounded events | Connecting, Online, Offline, Degraded, Error |
| cancel / close | OperationId / AccountHandle → receipt | stop future task effects where possible; preserve committed state |

Operation completion may report partial replication or queued offline retention rather than guaranteed delivery. Cancellation cannot retract content already delivered; operation ids distinguish those outcomes. Cursor/version and DTO additions require compatibility policy before full facade ships.

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

Contribution requests carry bounded already-authorized public profile/photo/lease inputs and host conditions. Enabling a policy alone never invents content or acknowledgements. Examples must use actual generated names; generated source is not a native compilation claim. Full profile/swipe/contact UI APIs in the target table remain outside M2 unless explicitly listed in progress.

Host source examples: [Android worker](../crates/mobile-ffi/examples/android/AnnodaSyncWorker.kt) and [iOS background task](../crates/mobile-ffi/examples/ios/AnnodaBackgroundSync.swift). These show scheduling, authorization deferral, cancellation, remaining-window budgets and permission-aware local notification acknowledgement. They require host dependency injection, platform setup and generated binding packaging. They are not complete applications or tested native adapters; [progress](progress.md) lists available compiler/runtime evidence.

Android host: unique periodic WorkManager CoroutineWorker, ≥15-minute requested interval, appropriate network/battery/charging constraints, same Rust operation as foreground, propagate coroutine stop/cancellation and drain pending events with stable notification ids before explicit ack. Actual launch can be delayed by Doze/quotas/constraints. No continuously running foreground-service workaround. [Official WorkManager contract](https://developer.android.com/develop/background-work/background-tasks/persistent/getting-started/define-work).

iOS host: register permitted BGTaskScheduler identifiers, use BGAppRefreshTask for short work or BGProcessingTask only when eligible, expirationHandler cancels Rust session, complete system task and request next opportunity, respect local notification permission. Scheduling is not an execution guarantee, fixed periods are unavailable, and force-quit must not be assumed to preserve background launches. [Apple background strategy](https://developer.apple.com/documentation/backgroundtasks/choosing-background-strategies-for-your-app), [BGTaskScheduler](https://developer.apple.com/documentation/backgroundtasks/bgtaskscheduler).

OS-granted window and authorized key-store access are independent prerequisites. Keychain/Keystore wrapping adapters, entitlements/manifest identifiers, notification authorization UI and physical-device validation remain host work. Small adapters/examples may be provided, no SwiftUI/Compose applications.

The host's outer execution window includes authorization/KDF, synchronization and notification handling. Subtract monotonic elapsed key-access time before choosing the remaining SyncBudget and stop if the grant has expired. The examples use a conservative host-selected 20-second work ceiling; this is not an OS grant or timing guarantee. In particular, WorkManager's 15-minute scheduling minimum is unrelated to the available execution duration. A portable-vault KDF is synchronous and cannot be preempted by the network cancellation token; an unavailable authorization grant must defer work, not prompt from a background task or persist an unprotected passphrase.
