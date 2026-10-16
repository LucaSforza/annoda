# ADR 0004: portable account vault and stable node keys

Status: accepted before M2 implementation; delivered evidence tracked in progress.md.

Context: M1 loses account keys and libp2p PeerId across process termination. Account key regeneration invalidates credential binding and prevents decrypting retained likes.

Decision: AccountKeyStore with explicit create/unlock/lock, Argon2id-derived XChaCha20-Poly1305 portable vault, fixed versioned key material and private filesystem/atomic locking contract. RustCrypto latest primary docs checked before selection: [Argon2 0.6](https://docs.rs/argon2/latest/argon2/), [ChaCha20Poly1305 0.11](https://docs.rs/chacha20poly1305/latest/chacha20poly1305/). Exact maintained versions and APIs must resolve through Cargo/build. No raw keys across mobile ABI.

Transport store is distinct: intentional operator-controlled, filesystem-protected **plaintext** node key file for unattended execution; do not describe it as encrypted. Parent/private paths, 0600 files, atomic non-clobber writes and cross-process lock are mandatory. Node corruption never generates a replacement. Explicit replacement uses expected current PeerId and requires stopped node. First creation for pre-M2 data directories migrates their previously ephemeral identity once; account identity never migrates silently.

Alternatives: plaintext account SQLite fields fail account security; encrypting node key with adjacent secret offers no real at-rest protection; assuming hardware directly supports both app key algorithms misrepresents platform behavior. Platform wrapping-key adapters remain future backends.

Consequences: passphrase entropy and backup hygiene matter; unlocked Rust secrets reside in memory. File locks coordinate cooperating processes, not a malicious same-user process. Vault format is versioned with explicit unsupported-format failures. Account file rollback, account recovery, native keystores and encrypted client DB remain outside M2. Existing AGPL licensing is preserved.
