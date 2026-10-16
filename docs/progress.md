# M2 implementation progress

Branch `feat/m2-persistent-identities-sync`, base `976464d` on master (fetched origin/master, no divergence). Working tree initially clean. Existing AGPL license preserved. KB skill read; M2 contracts, ADRs and UML established before implementation. Baseline `CARGO_HOME=/tmp/annoda-cargo CCACHE_DISABLE=1 cargo test --locked --offline --workspace` passed all 39 tests, including real TCP loopback.

M2 delivers a verified Rust-only prototype: exact persistent account keys, stable volunteer PeerId, finite real-TCP synchronization, transactional notification outbox and opt-in authorized replica forwarding. No central application or push server is introduced. Principal authored documentation; GPT-6 Luna/high agents authored all Rust, bindings, host examples and root integration changes.

## Delivered components

| Component / affected files | Verified behavior | Boundary |
|---|---|---|
| core `identity.rs`, `key_store.rs` | AccountKeyStore separates create/unlock; PortableAccountVault restores exact Ed25519 seed and actual HPKE private bytes; UnlockedAccount owns exclusive lease | Portable passphrase backend, not native Keychain/Keystore |
| core `storage.rs`, `notifications.rs` | Additive M1-compatible SQLite tables; paged mailbox/cursors; atomic verified state/replay/event/checkpoint commits; prefs, bounded pending/history, explicit idempotent ack; private contact persistence | Client DB remains unencrypted; no exactly-once OS display claim |
| network `node_identity.rs`, `node.rs` | Filesystem-protected persistent node key, initialized PeerId marker, explicit replacement, corruption/missing/busy errors; lock held until actor/swarm ends | Transport key is deliberately plaintext under operator permissions, distinct from encrypted account vault |
| network `sync.rs`, `transfer.rs`, `wire.rs` | One `sync_once` service; finite temporary client swarm; allowlisted known peers, outbound-only RPC, bounded retries/paging/cancellation; raw TCP metering and optional combined-byte phase cap | No new bootstrap discovery, mobile inbound provider, parcel relay or indefinite daemon |
| mobile-ffi `src/lib.rs`, generated Swift/Kotlin/Python | Opaque account/session handles; start/cancel/wait/report; durable event read/ack/preferences; bounded signed replica DTOs; shared Tokio runtime and serialized lock/drain | Full account/profile/swipe/contact UI facade remains future work |
| mobile-ffi `examples/{android,ios}` | WorkManager unique periodic worker/factory and BGAppRefreshTask registration/expiration source examples; host authorization, 20-second chosen ceiling, permission-aware notifications | Native compilers/SDK/device tests unavailable; source examples only |
| root README, AGENTS, `.gitignore` | Exact demos, KB workflow, explicit node-key exception; Python caches ignored and old tracked bytecode removed | Existing CI automatically exercises expanded workspace and Python smoke; no hosted CI success claimed here |

Authoritative contracts: [key management](key-management.md), [sync](background-sync.md), [notifications](notifications.md), [contribution](peer-contribution.md), [mobile integration](mobile-integration.md). [ADRs 0004/0005](decisions/README.md), three M2 class diagrams and seven sequences in [M2 UML](uml/m2.md) preceded delegated implementation. Existing five domain class/twelve sequence diagrams remain intact.

## Persistence and end-to-end evidence

The seven serial vault tests passed before Phase C began. `persists_identity_and_reopens_in_a_fresh_process` creates and exits one child process, then another unlocks the vault, directly compares both public keys and credential subject/ProfileId, verifies the old credential under normal trust/time rules, and decrypts an earlier ciphertext. Another child holds the vault while its parent receives BusyLocked. Wrong authorization, tampering, unsupported costs, missing paths, mode checks, symlink target preservation and concurrent creation never generate replacement account keys.

Vault v1 uses Argon2id v19 (64 MiB, three iterations, one lane), XChaCha20-Poly1305, fresh OS-random salt/nonce, purpose/header AAD, zeroizing temporary secrets, 0700/0600 paths, advisory locks and fsynced atomic non-clobber publication. Cargo resolved Argon2 0.6.0 and chacha20poly1305 0.11.0. Native wrapping and password/key recovery are not implemented.

`sync_loopback` uses real TCP/Noise/Yamux and SQLite. Bob sends a signed recipient-sealed like through a real volunteer RPC while Alice's original vault is locked. A new restored Alice session polls it, persists Incoming and NewLike, then acknowledges the event. A second ordered sender exercises a one-item run and resumed paging; completed scans reset the cursor. Repeated scans do not recreate acknowledged events. Alice explicitly reciprocates through real RPC, both participants recognize the same match and owner-scoped NewMatch events, and a subsequent contact parcel persists through the match-gated checkpointed receive path without inventing another notification kind. This network test restores released keys in new account objects; the separate vault test proves complete process termination/restoration.

`node_identity_process` launches fresh child processes and proves stable PeerId. Existing M1 real-loopback acceptance also verifies same PeerId after node-instance restart while serving previously authorized photographs and retaining the offline parcel. Principal additionally launched the built `annoda-node` executable twice from a previously absent nested directory, using loopback/ephemeral TCP and the same data directory: both SIGINT shutdowns exited 0, PeerId matched, directory/key modes were 0700/0600. No private key was printed; temporary files were removed.

Eight `sync_limits` real-TCP tests cover unreachable peers, selected-peer/item limits, raw byte and short-deadline ceilings during a stalled Noise handshake, exactly one versus three requests for retry counts 0/2, cancellation after an earlier like/outbox commit and idempotent continuation, and cooperative disabled/tiny-storage/tiny-transfer/success paths. They also reject duplicate owners before optional transfer and report Partial when only some complete copies are acknowledged. Meter unit tests exercise concurrent connections and combined optional upload/download caps. RPC ingress regression proves a connected peer cannot make the sync client decode an unsolicited application request.

General core tests cover invalid issuers, revocation, expiry, signatures, recipient binding, replayed likes, denied contacts, transactional outbox/checkpoint rollback, preference re-enable behavior, expired rejection cleanup, M1 database preservation and a bounded SQLite lock wait. The cancellation acceptance blocks a real TCP/Noise handshake after an earlier commit; adversarial partial-RPC-body/fuzz/physical-device crash matrices remain additional hardening work.

## Commands and final results

Principal ran these serially after the final Rust changes, on Rust 1.99.0:

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --locked --offline --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --locked --offline --workspace` | PASS: 78 tests, none failed/ignored; four doctest suites passed |
| `cargo build --locked --offline --workspace` | PASS |
| `python3 crates/mobile-ffi/tests/python_ffi_smoke.py target/debug/libannoda_mobile_ffi.so` | PASS against final rebuilt library |
| Built `annoda-node` two-process loopback/SIGINT harness | PASS: fresh nested directory, stable PeerId, exit 0 and private modes |

Breakdown: core 28, intelligence 17, mobile FFI 5, network library 14, binary parsers 2, M1 loopback 1, node process harness 2, sync limits 8, M2 loopback 1. Final M2 loopback ran in 8.41 seconds; timing varies and is not a mobile benchmark. Reproduce specific networking with `cargo test --locked -p annoda-network --test sync_loopback --test sync_limits --test node_identity_process -- --nocapture` and vault proof with `cargo test --locked -p annoda-core key_store::tests -- --test-threads=1`.

Local sandbox required `CARGO_HOME=/tmp/annoda-cargo CCACHE_DISABLE=1`, reviewed loopback execution and an earlier reviewed dependency fetch. Python additionally used `PYTHONDONTWRITEBYTECODE=1 CARGO_NET_OFFLINE=true`. These environment workarounds do not change release behavior. Standard writable machines can use the README commands. CI already runs the required workspace checks and one-argument Python smoke; that smoke automatically creates a clearly synthetic encrypted-vault/public-credential fixture in a temporary directory.

Swift/Kotlin/Python bindings were generated from the built shared library with UniFFI, with trailing-whitespace normalization only. Python ABI checks exercise ranker compatibility, create/open/lock, exact ProfileId, wrong-passphrase typed errors, persisted preferences, nonempty verified NewLike metadata and explicit ack/idempotent ack, and a valid no-peer session/report with cancellation request. No-peer completion can win the cancellation race; blocked-network cancellation is proved separately by Rust TCP tests. `swiftc` and `kotlinc` are absent, so generated bindings and host samples have not been compiled or executed on their native platforms.

## Workflow evidence and remaining limits

KB contracts/security/UML were established before implementation, and account plus transport persistence gates passed before sync implementation started. Initial vault/outbox code and tests were introduced together without a captured red run; strict fail-first chronology is not claimed for those original tests. Observed red-before-fix regressions include initialized transport key loss causing replacement, duplicate replica owners inflating count (2 versus 0), incomplete batches reporting Complete rather than Partial, and unsolicited sync RPC admission returning a decoded Unauthorized response instead of failing protocol negotiation. Final checks include those fixes; no temporary reverts were used to manufacture evidence.

Remaining security/operational limits:

- Weak passphrases, rollback/backup theft, same-user compromise, swap/core dumps and stalled filesystems remain risks. Rust needs decrypted keys in memory. Account vault encryption does not encrypt client SQLite. Node transport keys depend on operator filesystem/volume protection.
- Budgets cap consumed raw TCP stream bytes, including transport/control overhead, not kernel buffering, packet headers or radio billing. Short CPU/SQLite finalization cannot be forcibly preempted. Optional storage allocation bounds authorized batch payload/cache size, not whole-process RAM or physical SQLite/WAL size.
- Known reachable volunteers are required. NAT/firewalls, routing loss, peer overlap and OS scheduling can prevent work. Cooperation is finite outbound replica forwarding, not inbound mobile serving, autonomous repair, durable mobile availability, NAT traversal or circuit relay.
- Notification delivery is at least once until host ack, with stable ids for coalescing; OS acceptance is not proof of visible display. Background authorization, Keychain/Keystore wrapping, Android/iOS packaging/permissions and physical-device lifecycle tests remain host work. The 20-second sample ceiling does not guarantee any OS execution time; neither scheduling nor force-quit behavior is promised.
- Existing M1 production gaps remain: no real CIE adapter, fresh distributed revocation service, real image moderation/encoder, global deletion guarantee or independent security audit. Public images and direct IP/traffic metadata remain exposed by design; no centralized swipe graph or push server is added.

Next: validate platform wrapping/authorization and scheduling on physical devices; add partial-frame/crash/filesystem-fault and adversarial parser tests; then harden abuse/physical quotas, bootstrap/NAT/repair and production issuer/revocation adapters. Full native applications remain outside this milestone.

Final documentation verification: Mermaid parsed all 28 diagrams (including ten M2 additions), relative links resolved across all 32 KB Markdown files, the repository KB skill validator reported `Skill is valid!`, and `git diff --check` was clean after generated-source whitespace normalization. Temporary Mermaid tooling is not a project dependency.

The following M1 report is a historical baseline. Its memory-only account/ephemeral transport limitations are superseded by the M2 delivery above.

---

# M1 delivery snapshot — 2026-10-16

Annoda delivers an experimental local-network vertical slice. It is not a production dating service. Intended architecture elsewhere in this KB includes planned features; this page is the delivery/evidence authority.

Repository started empty except read-only mount placeholders (`.git`, `.agents`, `.codex`, `.aws`). Existing files/mounts were preserved. Cargo project initialized; Git history could not be initialized inside the protected `.git` placeholder. Principal authored only `docs/`; three GPT-6 Luna/high agents implemented all Rust and root scaffolding, as requested.

## Implemented scope

| Component | Actual implementation | Boundary |
|---|---|---|
| Foundation | Four Cargo crates, edition 2024, Rust 1.99 tested target, locked dependencies, full AGPL-3.0-or-later license, root AGENTS, README and GitHub Actions | No GitHub-hosted CI run claimed |
| Identity | Fallible OS-random Ed25519 and separate X25519 HPKE device keys; IdentityIssuer trait with public-only IssuanceRequest; DevelopmentIssuer; first name and age-at-issue, 24-hour maximum validity; issuer allowlist and local revoked serial set | Synthetic attributes only; no actual CIE authentication or real identity claim |
| Protocol | Ordered Postcard signed claims, domain separation, BLAKE3 ids, revisioned signed profiles, leases, HPKE encrypted LikeIntent/contact envelopes | External interoperability/golden vectors and independent security audit remain gates |
| Storage | SQLite signed profile/blob/owner-lease retention; hash and quota checks, finite mailbox retention, trusted-clock startup/60-second cleanup (missed ticks skipped), active-profile and manifest gates, persistent match evidence and incoming-like deduplication | Capacity is logical payload/metadata budget, not a hard filesystem or WAL bound |
| Network | Tokio libp2p TCP/Noise/Yamux, Kademlia provider announcements/lookups, length-prefixed bounded binary RPC, bootstrap, bounded profile discovery, directed photo replication/fallback, node-owned injected time | Profile discovery queries known volunteers; no global geographic profile index |
| Mailbox | Opaque recipient-sealed parcels; hidden sender credential and kind; authenticated recipient poll; recipient verifies inner signature/key binding/time before applying intent | No destructive ack protocol; retained until expiry; source IP, recipient, timing and sizes visible |
| Matching | Incoming/outgoing positive intent, persistent match ids/evidence, reject/pass and block, delayed/duplicate suppression, explicit match-gated recipient-encrypted external contacts | Received-like state is persisted; richer paged inbox/profile display and contact-history APIs remain planned |
| Ranking | Stable sigmoid logistic SGD, finite bounds, filters, coarse-region constraints, seeded exploration, deduplication/recent history/reset, deterministic encoder, synthetic evaluator | No real visual preference embedding or dating-performance evidence |
| Safety | Bounded JPEG/PNG decode, metadata-free JPEG normalization, classification of exact normalized pixels, incoming hash/length/structure/classification gate, explicit fixture opt-in | Only deterministic classifier; no real NSFW moderation |
| Abuse interfaces | Persistent local blocking, bounded versioned report/decision records, independent moderation-verifier trait that fails unavailable | No report persistence/submission workflow or operational signature verifier/backend |
| Mobile | UniFFI version + LocalPreferenceModel constructor/score/feedback/reset, typed errors; Swift/Kotlin/Python bindings generated | No native applications, full account/network facade, cancellation/events or native runtime tests |
| Executables | Configurable annoda-node and annoda-simulator topology launcher | Storage nodes are not operational circuit relays; full automatic dating scenario is integration test |

Actual Rust mappings: `crates/core/src/{protocol,identity,storage,matching}.rs`; `crates/network/src/{node,wire}.rs`; `crates/intelligence/src/{ranking,safety,evaluation}.rs`; `crates/mobile-ffi/src/lib.rs`. Logical UML UserIdentity/LikeInbox/StorageNode/PeerDiscovery/Transport map to these aggregates/services, rather than one mandatory struct per box. PhotoId is represented by ContentHash. Planned VerificationService and RelayNode have no operational adapter.

## Real network scenario

Command:

```sh
cargo test -p annoda-network --test loopback local_swarms_replicate_photos_and_deliver_private_likes_and_contacts -- --nocapture
```

`crates/network/tests/loopback.rs` uses real local libp2p swarms and SQLite, generated JPEGs, synthetic adults and injected time. It generates Alice/Bob keys and development credentials, publishes Alice's signed three-photo profile to two volunteers, confirms distinct replicas, stops Alice, joins Bob, discovers Alice without supplying her account id to discovery, retrieves/hash-checks/classifies photos through explicit fixture mode, and queries Kademlia providers. Bob's signed like is recipient-sealed and retained while Alice is offline. A volunteer failure causes provider fallback; restarting the surviving volunteer from its data directory preserves profile, photos and queued parcel. Bob reconnects to the restarted transport identity. Alice reconnects, decrypts and sees Bob's positive intent before acceptance, reciprocates, both persist matched state and the same match id, then both explicitly exchange encrypted selected contacts. Repeated delivery stays idempotent. Advancing node time stops expired records from serving.

No real CIE account, external cloud, real personal image or mobile app is involved. Scheduling and cryptographic randomness vary; assertions and injected domain time make outcomes deterministic. Transport identity is ephemeral on node restart; account keys remain in test memory and bootstrap addresses are updated explicitly.

## Commands and proof

Principal's final serial gates all passed on Rust 1.99.0:

| Command (after local cache environment setup) | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --locked --offline --workspace --all-targets -- -D warnings` | PASS; warnings denied |
| `cargo test --locked --offline --workspace` | PASS; 39 tests, no failures/ignored, all four doctest suites passed |
| `cargo build --locked --offline --workspace` | PASS |
| `python3 crates/mobile-ffi/tests/python_ffi_smoke.py target/debug/libannoda_mobile_ffi.so` | PASS after final library build |
| `cargo run --locked --offline -p annoda-intelligence --example synthetic_evaluation` | PASS; synthetic metrics printed |

Test breakdown: core 13, intelligence 17 (including property tests), mobile FFI 2, network library 4, two CLI parser tests, real loopback integration 1. Final loopback execution completed in 1.11 seconds; timing is not an acceptance threshold. Additional built headless process smoke started `annoda-node` on a loopback ephemeral port with public test issuer key and explicit storage/lease/connection/bandwidth limits, then SIGINT shut it down with exit 0. Its temporary data directory was removed. Agent runs also generated bindings and reproduced security regressions. Concurrent agent Cargo jobs caused transient rustdoc E0463 missing-crate errors; isolated serial doctests passed. No doctest-disabling workaround was added.

- GitHub Actions is configured to run the four required gates plus Python ABI smoke after build. Hosted CI execution was not available in this uninitialized Git environment.
- Actual foreign ABI smoke: `python3 crates/mobile-ffi/tests/python_ffi_smoke.py target/debug/libannoda_mobile_ffi.so` → `UniFFI Python ABI smoke test passed` (also run independently by principal).
- Swift/Kotlin bindings were generated from the built shared library with UniFFI 0.32.2. `swift` and `kotlinc` are absent, so neither native language compilation nor invocation is claimed. Python uses generated ctypes bindings to exercise constructor, scoring, learning, reset and typed error transfer.
- Required generation commands and node CLI examples live in [root README](../README.md). `annoda-simulator` launches a topology and waits; it is not the automatic 15-step test.
- Sandbox prevented TCP loopback binding (EPERM). Reviewed elevated test execution ran real sockets successfully. No mocked transport substitution was made. Sandbox DNS and read-only default ccache also required dependency fetch access and temporary cache settings. Local verification uses `CARGO_HOME=/tmp/annoda-cargo`, `CCACHE_DISABLE=1`, and offline locked resolution after fetch; normal writable developer machines need no such cache workaround.

## Synthetic evaluation

`cargo run -p annoda-intelligence --example synthetic_evaluation` uses four synthetic users, sixteen candidate vectors, seed 2026, K=5 and no missing labels. Observed values:

| Stage | Precision@5 | Recall@5 | NDCG@5 | Mutual-positive rate | Coverage |
|---|---|---|---|---|---|
| Cold start | 0.300 | 0.250 | 0.287 | 0.062 | 1.000 |
| After synthetic feedback | 0.550 | 0.550 | 0.489 | 0.083 | 0.750 |

Exposure histograms were `{4:16}` and `{0:4,4:12}` respectively (exposure count → candidate count). Trained stage removes already seen candidates, so coverage denominators differ in eligibility; these values are diagnostics, not a controlled efficacy comparison. Principal's final Cargo example execution measured 332 microseconds wall / 336 microseconds process CPU, estimated 672 bytes model storage and 2064 bytes candidate records. Times vary and are not mobile benchmarks or peak resident memory. Synthetic labels and byte-shape encoder do not establish real dating performance.

## Contract-first and regression evidence

KB architecture, security, contracts, ADRs and all five class/twelve sequence diagrams existed before delegated Rust implementation. Changes found in review were specified before fixes: node-owned time, normalized-pixel safety, bounded binary framing, hidden sender mailbox carrier, authenticated inner intent binding, and match rejection transitions. The KB skill validates; root AGENTS links it.

Observed fail-before-fix regressions include extreme regularization accepted when it should reject, anonymous lease metadata exceeding quota, forged Mallory-signed payload claiming Bob, and Matched→Rejected being accepted. A storage-capacity regression also proves startup cleanup reclaims an expired 80 KB photo so a new 80 KB write fits under a 120 KB limit. Active-profile photo expiry was also verified with a negative control (temporarily removing the gate reproduced stale serving, restoring it passed). Initial foundation code/tests were introduced together in some agent work; a red run for every original unit test is not claimed. Future changes must follow [testing workflow](testing.md) strictly.

## Interaction status (sequence diagrams)

| Sequence | Delivered | Still planned |
|---|---|---|
| 1 registration | Development issuance and key-bound peer verification | Real CIE adapter/interactive issuance possession challenge |
| 2 profile | Signed revisions, actual volunteer publication | Global/selective discovery policy |
| 3 safety | Normalization, limits and explicit fixture gate | Real mobile inference |
| 4 replication | Distinct acknowledged persistent copies | Scheduled repair, diversity and authorized renewal |
| 5 discovery/retrieval | Bounded volunteer profile discovery, Kademlia providers, verified retrieval | Geographic DHT index and privacy-preserving selection |
| 6 online like | Directed sealed delivery/poll | Background push client orchestration |
| 7 offline like | Retention, restart and recipient retrieval | Ack/deletion, server-challenge anti-replay policy |
| 8 matching | Authenticated intents, persistent FSM/evidence | Unmatch/unblock/re-like policy |
| 9 contacts | Both directions explicitly encrypted after match | Durable contact-history and complete mobile API |
| 10 block/report | Persistent block; bounded report/decision interface | Report workflow, trusted signed decision implementation |
| 11 expiry/renewal/revocation | Expiry, local revocation checks, ability to issue another development credential | Real renewal/recovery and signed fresh revocation distribution |
| 12 deletion | Active revisioned manifest and lease expiry stop reads | Tombstone wire type, propagation and anti-resurrection retention |

## Concrete next milestones and security limits

1. Production trust adapter: authorized CIE authentication, verified private birthdate → current age, next-birthday expiry, possession challenge, issuer-local duplicate-account policy, key rotation/recovery and fresh signed revocation snapshots. Development credentials must never become default production trust.
2. Durable availability/deletion: fetchable original signed replica authorization, bounded jittered repair, renewal and diverse placement; persistent provider routing after restart; signed monotonic tombstones retained across maximum stale lifetime. Current profile revisions resist in-store rollback while retained, but expiry cleanup loses that history. Global erasure of downloaded public photos is impossible.
3. Harden resource/abuse controls: physical DB/WAL/disk caps, per-source fairness, anonymous mailbox admission/rate tokens, stale poll-proof replay protection, adversarial parser fuzzing and explicit peer-failure diagnostics. Current payload admission/egress budget excludes transport/Kademlia overhead and is not a kernel-level ingress throttle; anonymous invalid parcels can consume recipient quota. Signed poll proof can be replayed for 30 seconds to retrieve ciphertext, and polling is nondestructive. Direct IP/traffic metadata remains exposed. No global harvesting prevention or photo-to-identity biometric proof exists.
4. Real safety and embeddings: reproducibly licensed/checksummed model, native/ONNX inference adapters, calibration and on-device cost measurements; operational reporting and community moderation. Test classifier is not moderation. Independent security/privacy review and app-store abuse operations are required before launch.
5. Protected account/mobile lifecycle: platform-keystore or encrypted persistent secrets, encrypted sensitive local state policy, complete account/profile/inbox/match/contact facade, async cancellation/event/backpressure tests and actual Swift/Kotlin runtime calls. Keys currently remain memory-only; account reopening/recovery is not implemented. SQLite client state is not encrypted at rest.
6. Internet transport: NAT traversal, circuit-relay reservations, bootstrap governance, connection fairness and optional privacy transports. Headless node currently provides storage, not circuit relay. Production deployment and mobile applications remain unimplemented.

## Documentation verification

Final validation: all relative links resolved across 25 KB Markdown files. Mermaid 11.17.2 parsed all 18 blocks (architecture + five classes + twelve sequences); final revalidation passed after the sealed-carrier changes. Temporary Mermaid/DOM tooling under `/tmp` adds no project runtime dependency. Parser caught semicolon issues in sequence messages, fixed and reparsed. Skill validator reports `Skill is valid!` for `docs/skills/annoda-kb`. Skill source is repository-contained because mounted `.agents`/`.codex` are read-only; invoke by explicit path.
