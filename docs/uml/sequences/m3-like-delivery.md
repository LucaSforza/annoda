# Durable like and asynchronous delivery

Status: M3 contract before implementation, [progress](../../progress.md) records actual proof.

```mermaid
sequenceDiagram
actor Host
participant Client
participant DB
participant Volunteer
Host->>Client: like(candidate)
Client->>Client: validate credential and existing FSM
Client->>DB: atomic intent, exact encrypted parcel and Pending operation
DB-->>Client: stable operation id
Client-->>Host: locally saved, recipient receipt unknown
Host->>Client: bounded sync or retry
Client->>Volunteer: exact saved recipient-sealed parcel
alt retained
Volunteer-->>Client: retention acknowledgement
Client->>DB: checkpoint acknowledgement
else unreachable or cancelled
Client->>DB: retain pending work for next session
end
Client-->>Host: receipt distinguishes retention from recipient processing
```

Participants map to `annoda_network::client::AnnodaClient`, core `PeerStorage`/`AccountKeyStore`, intelligence `PhotoProcessor` and existing finite libp2p volunteer RPCs. Native UI and real CIE adapters remain planned. [Application contract](../../application-api.md), [operation contract](../../durable-operations.md).
