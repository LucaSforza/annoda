# Annoda

Annoda is an experimental, privacy-focused peer-to-peer matching prototype. Its normative behavior is described in the [knowledge base](docs/README.md); implementation evidence and gaps are tracked in [progress](docs/progress.md). This repository does not claim production readiness.

## Workspace

- `crates/core`: identity, signed protocol records, encrypted messages, SQLite storage, matching.
- `crates/network`: peer networking, local simulator, and high-level `AnnodaClient` application service.
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

The M3 application workflow and account-boundary security checks are:

```sh
cargo test --locked -p annoda-network --test application_client -- --nocapture
cargo test --locked -p annoda-network --test application_security -- --nocapture
```

See the [application API contract](docs/application-api.md) and [durable operations contract](docs/durable-operations.md) for supported service behavior and recovery semantics.

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

Normalize generated trailing whitespace after regenerating the checked-in bindings:

```sh
python3 - <<'PY'
from pathlib import Path
import re

paths = (
    Path("crates/mobile-ffi/generated/kotlin/uniffi/annoda_mobile_ffi/annoda_mobile_ffi.kt"),
    Path("crates/mobile-ffi/generated/python/annoda_mobile_ffi.py"),
    Path("crates/mobile-ffi/generated/swift/annoda_mobile_ffi.swift"),
    Path("crates/mobile-ffi/generated/swift/annoda_mobile_ffiFFI.h"),
)
for path in paths:
    path.write_bytes(re.sub(rb"[ \t]+(?=\r?$)", b"", path.read_bytes(), flags=re.MULTILINE))
PY
```

The UniFFI `ApplicationHandle` owns the unlocked account. Create or open it with a private
directory, trusted issuer keys, configured volunteer peers, and an app-held passphrase; then
request only public identity material for credential issuance. Keep the development safety
fixture disabled in production.

```swift
let app = try createApplication(config: config, passphrase: passphrase)
let publicIdentity = try app.identitySummary()
try app.importCredential(credential: verifiedCredentialBytes)
let candidates = try app.discover(query: query)
try app.close()
```

```kotlin
val app = createApplication(config, passphrase)
val publicIdentity = app.identitySummary()
app.importCredential(verifiedCredentialBytes)
val candidates = app.discover(query)
app.close()
```

Call `cancelCurrentOperation()` to cancel an active bounded network request. The checked-in
Swift and Kotlin files are generated bindings; successful generation does not demonstrate
compilation, runtime behavior, or OS execution guarantees with the target native toolchains.

Production work still planned includes real CIE integration, real local inference, platform
keystores, operational reporting, NAT traversal and relay support, distributed deletion, and
automatic replica repair.

See [`docs/progress.md`](docs/progress.md) for implementation status, verified commands, and remaining release limitations. The project is licensed under [AGPL-3.0-or-later](LICENSE).
