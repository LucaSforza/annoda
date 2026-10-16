# Explicit matched contact disclosure

Status: M3 contract before implementation, [progress](../../progress.md) records actual proof.

```mermaid
sequenceDiagram
actor Host
participant Client
participant DB
participant Volunteer
participant Match as Recipient client
Host->>Client: disclose selected handles(match id)
Client->>DB: load current matching state
alt Matched and not blocked
Client->>Client: validate bounded handles and encrypt match-bound disclosure
Client->>DB: commit exact outgoing operation
Client->>Volunteer: deposit saved parcel within budget
Match->>Volunteer: bounded mailbox sync
Volunteer-->>Match: encrypted parcel
Match->>Match: verify sender, match, recipient and signature
Match->>Match: persist private incoming contacts
else missing match or blocked
Client-->>Host: Unauthorized, no parcel
end
```

Participants map to `annoda_network::client::AnnodaClient`, core `PeerStorage`/`AccountKeyStore`, intelligence `PhotoProcessor` and existing finite libp2p volunteer RPCs. Native UI and real CIE adapters remain planned. [Application contract](../../application-api.md), [operation contract](../../durable-operations.md).
