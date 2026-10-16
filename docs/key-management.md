# Persistent identity contract (M2)

Authority for account/transport persistence; [identity](identity.md) remains authority for credentials. M2 implementation evidence belongs in [progress](progress.md). This contract and [UML](uml/m2.md) precede code.

## AccountKeyStore

Creating and opening are separate operations. `create(authorization)` fails AlreadyExists if any account file exists, even if corrupted or inaccessible. `unlock(authorization)` never generates/replaces keys. Errors distinguish Missing, Locked/Busy, Inaccessible, AuthenticationFailed (wrong passphrase or authenticated corruption), CorruptFormat, UnsupportedVersion and InvalidInput. Error/debug formatting must contain no secrets. An `UnlockedAccount` owns keys and store lock; `lock`/drop releases private material and cross-process ownership. Callers cannot use a locked account. Private serialization/import helpers are crate-private, never UniFFI exports or public Debug/serde implementations.

`PortableAccountVault` implements AccountKeyStore for this prototype. The authorization input is a passphrase only for this backend; it does not prescribe mobile UX. Native stores may implement a backend-specific authorization grant or wrapping-key adapter. Public keys and ProfileId are reconstructed from the exact stored Ed25519 secret seed and actual X25519/HPKE private key bytes. Do not regenerate HPKE from a fresh seed. Credentials are not reissued or extended by restoration. Previously sealed messages must decrypt after a genuinely new process opens the vault.

## Vault v1

Use maintained RustCrypto Argon2id v19 to derive 32-byte key, XChaCha20-Poly1305 authenticated encryption, OS randomness, fresh 16-byte salt and 24-byte nonce. Version 1 fixes cost at 64 MiB, three iterations, one lane. Validate envelope size (≤16 KiB), magic, version, algorithm and exactly these KDF parameters before costly work/allocation; no attacker-chosen work factor. Other parameter sets require an explicit version/migration. Parameters are authenticated. Test-only reduced work must not become a release mode; tests may take longer. Empty/overlong authorization is invalid; passphrases are never command-line literals, persisted, Debug-printed or logged.

Header: magic/version, algorithm identifiers, KDF parameters, salt, nonce. Associated data is an Annoda account-vault purpose/version plus deterministic header bytes. Ciphertext contains versioned key material with exactly 32 Ed25519 secret bytes and exactly 32 serialized HPKE private bytes; reconstruct public keys and validate internal shape after authentication. Use zeroizing buffers for plaintext, derived keys and temporary secrets where library support permits. Complete memory zeroization/swap/core-dump exclusion cannot be promised.

V1 byte layout uses little-endian integers, independent of host architecture:

| Offset | Length | Value |
|---|---|---|
| 0 | 8 | ASCII `ANNOVLT1` |
| 8 | 2 | version 1 |
| 10 | 1 | AEAD identifier 1: XChaCha20-Poly1305 |
| 11 | 1 | KDF identifier 1: Argon2id v19 |
| 12 / 16 / 20 | 4 each | memory KiB / iterations / lanes, fixed as above |
| 24 | 16 | random salt |
| 40 | 24 | random nonce |
| 64 | 84 | encrypted 68-byte key record plus 16-byte authentication tag |

AEAD associated data is literal `annoda/account-vault/v1` followed by a zero byte and the exact 64-byte header. Authenticated plaintext is ASCII `KEY1`, signing seed (32 bytes), then actual HPKE private key (32 bytes). A valid v1 file is 148 bytes; the outer 16 KiB parser bound rejects oversized input before authentication. Unknown versions/algorithms/parameter sets fail explicitly, without attempting a fallback.

Vault directory is private (0700 Unix), vault/lock/temp files 0600. Reject symlink/nonregular/insecure key paths and unsupported permission guarantees with explicit error, never a plaintext fallback. Cross-process advisory exclusive lock coordinates cooperating processes; crash releases kernel lock. Writes use exclusive new/temp file, full write, file fsync, atomic non-clobber publication, then directory fsync. Creation failure must leave no plaintext or misleading valid account. A corrupt existing vault is an error and remains untouched; recovery requires deliberate operator action. No implicit key migration/rotation, password recovery or rollback prevention is claimed. Parent directories are host-controlled; same-user compromise remains out of scope.

## Persistent transport identity

`NodeIdentityStore` is separate from AccountKeyStore. Default volunteer startup creates a transport Ed25519 identity only when its identity file is absent; otherwise it opens exactly that identity. All libp2p public PeerIds derive from restored transport material. Store lock lives with swarm; a second process cannot run from the same node identity store. A public initialized-PeerId marker distinguishes first creation from loss of an existing key: a missing key with that marker is a recovery error. A valid key published before its marker during a first-create crash may safely finish initialization. Corruption, permission problems or unsupported format fail startup without replacement. Intentional replacement requires a separate API with expected current PeerId and an operator-controlled shutdown; it changes PeerId and must not touch account keys/data. A public replacement transition record can name old/new PeerIds so a crash during explicit replacement recovers to the already durable key; never use that mechanism for implicit account/key replacement.

For unattended nodes, M2 explicitly uses **filesystem-protected plaintext transport keys**, in a private subdirectory of data_dir, with 0600 files, advisory locking, versioned format, atomic creation and corruption checks. This is not encryption at rest and is never used for account vaults. Operator supplies protected volume/account permissions, optional full-disk encryption and backup policy; no adjacent decryption key is invented. New M2 identity files in old M1 data dirs are a one-time migration: the lost historical ephemeral PeerId cannot be recovered. Existing SQLite records remain. Subsequent restarts retain PeerId.

## Future native backends

Keychain accessibility must match actual host background authorization requirements (e.g. after-first-unlock access has different risk from when-unlocked). Android Keystore/iOS hardware assistance may protect a wrapping key for encrypted Ed25519/X25519 material. Do not assume these application algorithms run natively in Secure Enclave/Keystore. Rust still needs decrypted private bytes while unlocked; no non-exportability or permanent hardware isolation claim. Native adapter availability/interaction-required errors defer sync without replacing accounts. Native wrappers and device security tests are planned, not supplied by the portable vault.
