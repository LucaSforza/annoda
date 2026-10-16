# Verification and acceptance

Workflow: relevant KB → contract/UML update → failing executable test → smallest implementation → checks → evidence in [progress](progress.md). Do not mark done from source existence.

Required commands: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo build --workspace`. CI runs these on stable Rust with locked dependencies. Dependency resolution and actual compiler output, not documentation alone, establish compatibility. Generated Swift and Kotlin bindings must be produced using built UniFFI library; compilation/calls on native runtimes are separate proof.

Core tests: invalid issuer/signature/key binding/version/time/adulthood/revocation, signature tampering, wrong HPKE recipient, envelope expiry, duplicate messages across database restart, missing/corrupt blobs, quotas and expired leases, state table transitions, blocked/delayed likes and denied contacts. Property tests cover canonical round trips/tampering or finite ranking behavior and state invariants with bounded generated inputs.

Real-network acceptance: isolated loopback libp2p nodes, trusted synthetic issuer, generated images only. Alice publishes three verified normalized photos and signed profile to multiple volunteers, stops her swarm, Bob bootstraps/discovers and fetches all images from volunteers, classifies with explicit deterministic fixture, sends signed encrypted like to offline Alice mailbox, Alice reconnects and decrypts, recipients see like before reciprocation, Alice sends positive intent, both match, each explicitly discloses contacts privately. Node restart must preserve retained records. Tests assert observable outcomes and bounded timeouts, not arbitrary sleeps.

Failure scenarios: stop one replica and fetch from another; unavailable provider error and repair; expired leases cease serving; corruption refused; duplicate offline delivery does not create duplicate inbox/matches. Simulator uses fixed seed and injected domain clocks, actual scheduling/network may vary. Report synthetic ranking metrics including cold start, coverage, mutual positives, exposure and runtime/memory estimates.

Documentation checks: links within KB resolve, all five class diagrams and twelve sequence diagrams present, Mermaid parses when tooling available. If parser unavailable record limitation. Skill validation checks frontmatter/name/references and actual workflow routing. No real CIE, cloud or real personal image dependency.

## M2 acceptance (before implementation)

Run existing 39-test baseline before changes. Write failing tests then minimal implementation. Key-persistence tests must pass before sync service implementation starts.

1. Account vault round-trip from fresh instance and actual child process termination/reopen: both public keys/ProfileId equal and an earlier sealed message decrypts; no passphrase on process command line.
2. Wrong passphrase, corrupt envelope, unsupported schema/KDF limits, missing/locked/insecure/symlink paths and simultaneous opens produce typed errors without replacement. Check private bytes absent on disk/debug output and Unix permissions. Atomic create race has one winner.
3. Real volunteer restart retains PeerId and serves original authorized photo/queued parcel. Existing M1 loopback scenario also uses stable identity after restart.
4. Fresh restored Alice session polls real TCP swarms for old offline Bob like and atomically persists Incoming plus new opaque notification. Repeated scans and ack never regenerate it; preferences and crash-before-ack pending recovery work.
5. Reciprocation yields identical match id on both sides and owner-scoped NewMatch events. Invalid/revoked/tampered/foreign recipient envelopes never mutate state/outbox. Contacts preserve match gate.
6. Cooperative session forwards a valid authorized replica to a real volunteer within allocation/time/transfer caps; disabled or unmet Wi-Fi/charging policy does no optional content operations and no invented acknowledgement.
7. Cancellation during blocked/partial transfer terminates within deadline/finalization tolerance, keeps earlier commits/pending events and next run continues. Tiny duration/bytes/peers/items/concurrency/storage/retry limits measured at actual transport/service boundary.
8. No reachable peers returns bounded Deferred/Partial, does not spin or clear pending state. Paging/cursors can reach items beyond first page over repeated small-budget runs.
9. UniFFI regenerate Swift/Kotlin/Python, extend actual Python ABI smoke for portable account restore, typed errors, sync cancellation/report and notifications. Native samples reference actual generated APIs; compile/device proof only if tools exist.

Run all four workspace gates and all real-network tests plus Python ABI smoke. Additive schema migration must open existing M1 SQLite fixtures/records. Record fail-before-fix commands/results, platform limits and actual delivered mechanisms in progress.md.

## M3 acceptance

Baseline on merged master: all 78 tests passed before implementation. Add failing tests before behavior, retaining extracted `src/tests/` convention. Mandatory public-API Alice/Bob test uses two real persistent TCP libp2p volunteers; only infrastructure/issuer fixtures use low-level APIs. Create/import, publish three photos each with two acknowledgements, discover without IDs, validate fetched photo, expose Incoming before reciprocation, recognize identical mutual match, explicitly exchange contacts, close/reopen exact account with credential/match/contacts, block, and recover persisted outgoing work after interruption. Assert via AnnodaClient only.

Focused acceptance covers key mismatch/expired/untrusted credentials, no classifier, invalid/corrupt photos and fallback, duplicate likes, private pass, unauthorized disclosure, stale revision, malformed/foreign cursor, bounded cancellation/unreachable peers/partial publication, operation recovery, exclusive account access and additive M2 DB migration. Extend real Python UniFFI smoke through the application facade; regenerate tracked bindings. Native compile/device proof must be recorded separately. All four workspace gates plus M1/M2 regression and real-network suites remain required.

M3 migration proof must start from the literal pre-M3 SQLite schema, rather than creating a fresh database using the new library and calling it M2. Verify real preexisting matched/blocked state, notification acknowledgements and checkpoints after opening.
