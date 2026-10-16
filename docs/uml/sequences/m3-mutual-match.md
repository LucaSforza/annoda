# Reciprocal positive intent

Status: M3 contract before implementation, [progress](../../progress.md) records actual proof.

```mermaid
sequenceDiagram
actor Alice
participant A as Alice client
participant DB as Alice database
participant V as Volunteer
participant B as Bob client
Alice->>A: like Bob while Incoming
A->>DB: existing FSM Incoming to Matched, durable parcel and NewMatch
A->>V: retain reciprocal encrypted like
V-->>A: retention acknowledgement
B->>V: bounded authenticated poll
V-->>B: reciprocal parcel
B->>B: verify and decrypt
B->>B: existing FSM Outgoing to Matched, persist notification
A-->>Alice: match with deterministic pair id
Note over A,B: Both derive same match id, acknowledgement alone never creates match
```

Participants map to `annoda_network::client::AnnodaClient`, core `PeerStorage`/`AccountKeyStore`, intelligence `PhotoProcessor` and existing finite libp2p volunteer RPCs. Native UI and real CIE adapters remain planned. [Application contract](../../application-api.md), [operation contract](../../durable-operations.md).
