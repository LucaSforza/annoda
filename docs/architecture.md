# Architecture

Normative layers: protocol and domain core → network adapters and local intelligence → mobile facade, headless volunteer executable, simulator. Dependencies flow inward. No libp2p types cross the mobile boundary. The implementation may group related modules into a small number of crates; [contracts](contracts.md) fixes module ownership before implementation.

```mermaid
flowchart TD
    Mobile[Future SwiftUI and Compose] --> FFI[mobile-ffi]
    FFI --> Core[protocol identity matching storage]
    FFI --> Intelligence[ranking safety]
    FFI --> Network[Tokio libp2p adapter]
    Node[headless node] --> Network
    Sim[simulator integration harness] --> Network
    Sim --> Intelligence
    Network --> Core
    Intelligence --> Core
    Core --> DB[SQLite local persistence]
    Network --> Peers[Independent volunteer peers]
```

Accounts own application signing and recipient encryption keys. Node transport identities are separate. Issuers authenticate CIE attributes and sign minimized key-bound attestations. Storage peers retain signed public records and opaque private envelopes under finite leases. Client domain services verify all trust-bearing data, regardless of transport authentication.

The principal agent owns this KB and architecture. Delegated Rust agents own code and repository scaffolding only after contracts exist. No implementation may quietly redefine signed bytes, credential validity, matching transitions, or replica ownership. New tradeoffs require an [ADR](decisions/README.md).
