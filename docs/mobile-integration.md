# Native integration contract

UniFFI exposes owned records, opaque account handles, typed errors and asynchronous lifecycle operations; never Swarm, PeerId or Multiaddr types. SwiftUI and Compose applications remain outside this milestone. Minimal generated Swift/Kotlin binding proves ABI generation, not native app runtime behavior.

Target facade: create/open local account; import/verify credential; publish profile; query candidates; like/pass; read received likes and matches; explicitly disclose selected contacts; block/report; rank/reset preferences; observe bounded network events; cancel work and close account. Account opening must require encrypted secret access rather than plaintext key file defaults. Returned DTOs contain only fields caller is allowed to see. Stable error categories: InvalidInput, UntrustedIdentity, Expired, Unauthorized, SafetyUnavailable, NetworkUnavailable, StorageFull, Cancelled, Internal.

Initial surface may expose smaller verified operations (e.g. protocol version, credential validation, local ranking); list actual exports and generated-binding commands in [progress](progress.md). Unimplemented methods must not return invented success. Network facade is planned until account persistence, runtime ownership and cancellation are tested.

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

Delivered minimal facade contract: `api_version() -> String`; `LocalPreferenceModel(dimensions: u32, encoder_version: u16)`; `score(version, values) -> FfiRankingScore`; `record_feedback(version, values, liked)`; `reset()`. Typed errors are InvalidInput, IncompatibleModel, Internal. This surface owns no network or account and claims no full client implementation. Generated Swift and Kotlin bindings plus actual Python ctypes ABI smoke prove different levels of integration; see [evidence](progress.md).
