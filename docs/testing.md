# Verification and acceptance

Workflow: relevant KB → contract/UML update → failing executable test → smallest implementation → checks → evidence in [progress](progress.md). Do not mark done from source existence.

Required commands: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo build --workspace`. CI runs these on stable Rust with locked dependencies. Dependency resolution and actual compiler output, not documentation alone, establish compatibility. Generated Swift and Kotlin bindings must be produced using built UniFFI library; compilation/calls on native runtimes are separate proof.

Core tests: invalid issuer/signature/key binding/version/time/adulthood/revocation, signature tampering, wrong HPKE recipient, envelope expiry, duplicate messages across database restart, missing/corrupt blobs, quotas and expired leases, state table transitions, blocked/delayed likes and denied contacts. Property tests cover canonical round trips/tampering or finite ranking behavior and state invariants with bounded generated inputs.

Real-network acceptance: isolated loopback libp2p nodes, trusted synthetic issuer, generated images only. Alice publishes three verified normalized photos and signed profile to multiple volunteers, stops her swarm, Bob bootstraps/discovers and fetches all images from volunteers, classifies with explicit deterministic fixture, sends signed encrypted like to offline Alice mailbox, Alice reconnects and decrypts, recipients see like before reciprocation, Alice sends positive intent, both match, each explicitly discloses contacts privately. Node restart must preserve retained records. Tests assert observable outcomes and bounded timeouts, not arbitrary sleeps.

Failure scenarios: stop one replica and fetch from another; unavailable provider error and repair; expired leases cease serving; corruption refused; duplicate offline delivery does not create duplicate inbox/matches. Simulator uses fixed seed and injected domain clocks, actual scheduling/network may vary. Report synthetic ranking metrics including cold start, coverage, mutual positives, exposure and runtime/memory estimates.

Documentation checks: links within KB resolve, all five class diagrams and twelve sequence diagrams present, Mermaid parses when tooling available. If parser unavailable record limitation. Skill validation checks frontmatter/name/references and actual workflow routing. No real CIE, cloud or real personal image dependency.
