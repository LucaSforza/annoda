# Application service and owned state

Status: M3 contract; delivery tracked in [progress](../../progress.md).

```mermaid
classDiagram
class AnnodaClient {
  -UnlockedAccount account
  -ClientConfig config
  +identity_summary() IdentitySummary
  +attach_credential(VerifiedCredential)
  +published_profile() PublicProfile optional
  +publish_profile(photos) PublicationReceipt
  +publish_profile_with_cancellation(photos, cancellation) PublicationReceipt
  +discover(DiscoveryQuery) Page
  +like(ProfileId) OperationReceipt
  +sync(cancellation) SyncReport
  +close()
}
class ClientConfig {
  +PathBuf data_dir
  +TrustedIssuers issuers
  +SyncPeerAddress[] peers
  +SyncBudget sync_budget
  +bool allow_development_safety_fixture
}
class IdentitySummary {
  +ProfileId profile_id
  +bytes signing_public_key
  +bytes encryption_public_key
}
class UnlockedAccount {
  +identity() DeviceKeyPair
  +lock()
}
class PeerStorage {
  +save_credential(credential)
  +create_local_like_operation(fields) OperationRecord
  +save_publication_bundle(fields) OperationRecord
  +match_records_after(owner, cursor, limit) MatchRecord[]
}
class PhotoSafetyClassifier {
  <<interface>>
  +classify_rgb(pixels) float
}
class PhotoEncoder {
  <<interface>>
  +encode(validated_photo_bytes) PhotoEmbedding
  +mode() EncoderMode
}
class PreferenceModel {
  +score(embedding) RankingScore
  +update(embedding, liked)
  +reset()
}
class ApplicationHandle {
  +start_sync_session() SyncSession
  +operations_page(size, cursor) FfiOperationPage
  +cancel_current_operation()
  +close()
}
AnnodaClient "1" *-- "1" UnlockedAccount : owns vault lease
AnnodaClient "1" *-- "1" ClientConfig
AnnodaClient ..> PeerStorage : short transactions
AnnodaClient "1" --> "0..1" PhotoSafetyClassifier : explicit injection
AnnodaClient "1" *-- "0..1" PreferenceModel : owns persisted local model
AnnodaClient "1" --> "0..1" PhotoEncoder : explicit injected backend
AnnodaClient ..> IdentitySummary : public keys only
ApplicationHandle "1" *-- "0..1" AnnodaClient : serialized access
```

Rust mapping: `annoda_network::client` owns AnnodaClient/config/DTOs; core key_store/storage remain the underlying owners; intelligence traits/model are reused. `annoda_mobile_ffi` owns its opaque adapter handle. Invariants: exclusive vault lease, no private key export, no SQL transaction across await, current issuer/key validation at trust boundaries.

Authority: [application API](../../application-api.md), [durable operations](../../durable-operations.md).

Application preferences and local reports are implemented in the private `client::ranking_reporting` child module while retaining AnnodaClient as their public owner. Core stores validated versioned opaque model bytes without an intelligence dependency.
