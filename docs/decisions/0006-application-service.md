# ADR 0006: application orchestration and durable delivery

Status: accepted before M3 implementation; evidence in progress.md.

Context: M2 exposes correct primitives but a native client would otherwise coordinate SQLite, cryptography, network sessions and safety itself. Multi-peer writes cannot be globally atomic and apps terminate between acknowledgements.

Decision: keep four crates. Put AnnodaClient in annoda-network's client module, with a normal dependency on annoda-intelligence. Core owns additive application persistence and existing FSM/cryptography. Intelligence owns reusable safety and ranking including validated persistent model representation. Mobile-ffi is a thin adapter to the high-level service and preserves M2 exports. Dependency DAG: mobile-ffi → network → intelligence → core, with direct core dependencies where needed; core never depends on network/intelligence.

Durable versioned operation records save exact publication bundles and encrypted parcels before network activity. Per-peer acknowledgements are local checkpoints; retries are idempotent, not exactly once. Foreground/background share finite metered network plumbing and M2 incoming verification. Account access is serialized; vault ownership prevents concurrent process access. A public-key summary permits synthetic issuance without exporting private material. Issuer trust and development inference opt-in remain explicit.

Alternatives: a fifth orchestration crate adds little boundary value here; putting application logic inside FFI binds Rust callers to native adapter types; generating a new encrypted message on retry breaks logical idempotency; treating volunteer retention as recipient delivery is false.

Migration: additive bounded SQLite tables and indexes, no changes to v1 signed/public records, wire discriminants or existing vault format. Existing M2 state remains readable and receives a bound application owner on first authorized open. Incompatible local operation formats fail explicitly. Legacy M2 and M3 account handles share the vault lease and cannot unlock the same account simultaneously.

Consequences: the network crate now also contains the client application service, but transport remains private at the mobile boundary. Private application DB contents are filesystem-protected plaintext; full database encryption remains deferred. No classifier/encoder model or platform UI is introduced. Distributed deletion, internet discovery and automatic repair remain separate milestones.

