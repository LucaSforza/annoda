# Restart and operation recovery

Status: M3 contract before implementation, [progress](../../progress.md) records actual proof.

```mermaid
sequenceDiagram
actor Host
participant Old as Original client
participant DB
participant Vault
participant New as Reopened client
participant Peer
Old->>DB: commit Pending operation before network
Old->>Peer: send exact operation
Note over Old: Process may stop before acknowledgement checkpoint
Host->>Old: close or process termination
Old->>Vault: release private keys and lease
Host->>New: open existing account
New->>Vault: unlock exact keys, never create fallback
New->>DB: restore credential, matching, contacts and pending operations
alt vault inaccessible or corrupt
New-->>Host: explicit failure, identity unchanged
else restored
New->>Peer: bounded replay of exact saved work
Peer-->>New: idempotent acknowledgement
New->>DB: checkpoint without duplicate logical intent
New-->>Host: recovered receipts and unchanged ProfileId
end
```

Participants map to `annoda_network::client::AnnodaClient`, core `PeerStorage`/`AccountKeyStore`, intelligence `PhotoProcessor` and existing finite libp2p volunteer RPCs. Native UI and real CIE adapters remain planned. [Application contract](../../application-api.md), [operation contract](../../durable-operations.md).
