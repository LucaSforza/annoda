# Incoming like before match

Status: M3 contract before implementation, [progress](../../progress.md) records actual proof.

```mermaid
sequenceDiagram
actor Alice
participant Client
participant Volunteer
participant DB
Alice->>Client: bounded sync
Client->>Volunteer: authenticated paged mailbox poll
Volunteer-->>Client: encrypted parcels
Client->>Client: decrypt, verify sender credential, signature, recipient, expiry and replay
alt new valid like
Client->>DB: atomic Incoming, sender credential, notification and checkpoint
else duplicate or invalid
Client->>DB: no duplicate intent/event, record appropriate checkpoint
end
Alice->>Client: received likes and matches
Client-->>Alice: verified sender Incoming, no match until local positive intent
```

Participants map to `annoda_network::client::AnnodaClient`, core `PeerStorage`/`AccountKeyStore`, intelligence `PhotoProcessor` and existing finite libp2p volunteer RPCs. Native UI and real CIE adapters remain planned. [Application contract](../../application-api.md), [operation contract](../../durable-operations.md).
