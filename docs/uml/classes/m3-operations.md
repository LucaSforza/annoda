# Durable operations and query DTOs

Status: M3 contract; delivery tracked in [progress](../../progress.md).

```mermaid
classDiagram
class OperationRecord {
  +bytes16 id
  +uint16 version
  +ProfileId owner
  +OutgoingOperationKind kind
  +OutgoingOperationStatus status
  +bytes exact_payload
  +String[] peer_targets
  +bytes32[] items
  +uint64 expires_at
}
class OutgoingOperationStatus {
  <<enumeration>>
  Pending
  Partial
  Completed
  Failed
}
class PeerItemAck {
  +String peer_id
  +bytes32 item
  +bool accepted
  +DeliveryFailureKind optional_failure
}
class DeliveryFailureKind {
  <<enumeration>>
  Unreachable
  Rejected
  Budget
  Cancelled
}
class DeliveryFailure {
  +String peer_id
  +bytes32 item_hash
  +DeliveryFailureReason reason
}
class OperationReceipt {
  +bytes16 operation_id
  +OutgoingOperationStatus status
  +uint32 acknowledged_peers
  +bytes32[] pending_items
  +DeliveryFailure[] failures
  +bool retry_recommended
}
class FfiOperationPage {
  +FfiOperationReceipt[] items
  +FfiPageCursor optional_next_cursor
}
class PublicationReceipt {
  +OperationReceipt operation
  +uint64 revision
  +uint32 replicated_peers
}
class CandidateProfile {
  +PublicProfile profile
  +float optional_score
}
class Page {
  +T[] items
  +PageCursor optional_next_cursor
}
class PageCursor {
  +bytes opaque_value
}
class IncomingLike {
  +ProfileId sender
  +MatchState state
  +VerifiedCredential credential
}
class MatchSummary {
  +ProfileId peer
  +bytes32 match_id
  +VerifiedCredential credential
}
class ProfileReport {
  +bytes16 report_id
  +bytes32 reporter
  +bytes32 subject
  +uint16 policy_reason
  +bytes32[] evidence_hashes
  +bytes signature
}
OperationRecord "1" *-- "1" OutgoingOperationStatus
OperationRecord "1" *-- "0..*" PeerItemAck : durable distinct peers
PublicationReceipt "1" *-- "1" OperationReceipt
OperationReceipt ..> OperationRecord : durable local view
OperationReceipt "1" *-- "0..*" DeliveryFailure
PeerItemAck ..> DeliveryFailureKind : safe diagnostic
Page "1" *-- "0..64" CandidateProfile : candidate specialization
Page "1" *-- "0..64" OperationReceipt : operation specialization
FfiOperationPage ..> Page : native projection
Page "1" *-- "0..1" PageCursor
IncomingLike ..> CandidateProfile : optional published profile
IncomingLike "1" *-- "1" VerifiedCredential : authenticated sender
MatchSummary "1" *-- "1" VerifiedCredential : revalidated peer
ProfileReport ..> CandidateProfile : local evidence
```

Rust mapping: `annoda_core::storage::{OperationRecord, OutgoingOperationStatus, PeerItemAck, DeliveryFailureKind}` own durable records and acknowledgement transactions. `annoda_network::client` owns OperationReceipt, DeliveryFailure, PublicationReceipt, CandidateProfile, Page<T>, PageCursor, IncomingLike and MatchSummary. DeliveryFailureReason projects the storage failure enum without exposing transport errors. `annoda_intelligence::safety::ProfileReport` is reused by the private client ranking_reporting module. UniFFI maps these into its Ffi-prefixed records.

Invariants: exact work survives retry; only peers accepting all required items count as full replicas; accepted acknowledgements cannot be downgraded; Incoming is visible before Matched; signed local reports imply no remote moderation acceptance. Page multiplicity is a return bound, not a collection truncation policy: validated cursors must reach subsequent eligible records. Contacts and private preferences never enter public profile records.

Authority: [application API](../../application-api.md), [durable operations](../../durable-operations.md).
