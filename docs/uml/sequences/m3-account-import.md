# Account creation and credential import

Status: M3 contract before implementation, [progress](../../progress.md) records actual proof.

```mermaid
sequenceDiagram
actor Host
participant Client as AnnodaClient
participant Vault as AccountKeyStore
participant Issuer as Authorized issuer adapter
participant DB as PeerStorage
Host->>Client: create(private directory, passphrase)
Client->>Vault: create encrypted exact signing and HPKE keys
Vault-->>Client: UnlockedAccount and exclusive lease
Client-->>Host: public identity summary
Host->>Issuer: authenticate and bind both public keys
Note over Issuer: Real CIE deferred, tests explicitly use DevelopmentIssuer
Issuer-->>Host: signed credential
Host->>Client: attach credential
Client->>Client: verify issuer, time, revocation and BOTH key bindings
alt valid
Client->>DB: transactionally save bound credential
Client-->>Host: verified identity summary
else invalid or foreign key
Client-->>Host: typed failure, account unchanged
end
```

Participants map to `annoda_network::client::AnnodaClient`, core `PeerStorage`/`AccountKeyStore`, intelligence `PhotoProcessor` and existing finite libp2p volunteer RPCs. Native UI and real CIE adapters remain planned. [Application contract](../../application-api.md), [operation contract](../../durable-operations.md).
