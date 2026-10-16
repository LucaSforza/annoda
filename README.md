# Annoda

Annoda is an experimental, privacy-focused peer-to-peer matching prototype. Its normative behavior is described in the [knowledge base](docs/README.md); implementation evidence and gaps are tracked in [progress](docs/progress.md). This repository does not claim production readiness.

## Workspace

- `crates/core`: identity, signed protocol records, encrypted messages, SQLite storage, matching.
- `crates/network`: peer networking and local simulator.
- `crates/intelligence`: local ranking and photo-safety interfaces.
- `crates/mobile-ffi`: native-facing Rust facade.

## Build and checks

Install a current Rust stable toolchain with the 2024 edition, then run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

For a behavior change, load the workflow at [`docs/skills/annoda-kb/SKILL.md`](docs/skills/annoda-kb/SKILL.md) manually and read its linked authoritative documents before editing. Keep any development issuer and fixture classifier clearly marked as synthetic.

## Local demonstrations

Run the loopback peer demo, synthetic-ranking evaluator, and Python FFI smoke check with:

```sh
cargo test -p annoda-network --test loopback local_swarms_replicate_photos_and_deliver_private_likes_and_contacts -- --nocapture
cargo run -p annoda-intelligence --example synthetic_evaluation
cargo build -p annoda-mobile-ffi
python3 crates/mobile-ffi/tests/python_ffi_smoke.py target/debug/libannoda_mobile_ffi.so
```

The network demo is a local test topology. Production peers must be configured with trusted issuer public keys; the synthetic evaluator and development issuer use fixtures only.

Exercise the encrypted account vault, including a fresh-process restore, verification of the existing credential, and decryption of an old sealed message, with:

```sh
cargo test --locked -p annoda-core key_store::tests -- --test-threads=1
```

Background synchronization is a bounded Rust service shared by foreground and host-scheduled execution. Its real-loopback acceptance test is:

```sh
cargo test --locked -p annoda-network --test sync_loopback -- --nocapture
```

`PortableAccountVault` always encrypts account keys and requires an explicit create or unlock call with caller-supplied authorization. The volunteer node has a separate filesystem-protected plaintext transport identity in its private data directory so restarts retain the same PeerId; protect that directory and its storage volume. See [key management](docs/key-management.md) for permissions and recovery limits.

To start a volunteer node, set a real trusted issuer public key as 64 hexadecimal characters, then configure the listen address and resource bounds. Add `--bootstrap "$PEER_ID@$MULTIADDR"` when joining an existing network; omit it for the first node.

```sh
export ANNODA_TRUSTED_ISSUER_HEX="<64-hex-character trusted issuer public key>"
cargo run -p annoda-network --bin annoda-node -- \
  --issuer-key "$ANNODA_TRUSTED_ISSUER_HEX" \
  --listen /ip4/0.0.0.0/tcp/4001 \
  --data-dir ./annoda-data \
  --storage-bytes 1073741824 \
  --max-lease-seconds 2592000 \
  --max-connections 32 \
  --bandwidth-bytes-per-second 16777216
```

After building the mobile library, generate Swift and Kotlin bindings with:

```sh
cargo run -p annoda-mobile-ffi --features cli --bin uniffi-bindgen -- generate --language swift --out-dir bindings/swift --no-format target/debug/libannoda_mobile_ffi.so
cargo run -p annoda-mobile-ffi --features cli --bin uniffi-bindgen -- generate --language kotlin --out-dir bindings/kotlin --no-format target/debug/libannoda_mobile_ffi.so
```

Production work still planned includes real CIE-backed identity verification, a production inference and moderation service, NAT traversal and relay support, automatic recovery, and the full mobile facade.

See [`docs/progress.md`](docs/progress.md) for implementation status, verified commands, and remaining release limitations. The project is licensed under [AGPL-3.0-or-later](LICENSE).
