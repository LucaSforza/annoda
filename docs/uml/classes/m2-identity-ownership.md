## Identity ownership

```mermaid
classDiagram
    class AccountKeyStore {
        <<interface>>
        +create(authorization) UnlockedAccount
        +unlock(authorization) UnlockedAccount
    }
    class PortableAccountVault {
        -Path directory
        +create(passphrase) UnlockedAccount
        +unlock(passphrase) UnlockedAccount
    }
    class VaultEnvelope {
        +u16 version
        +KdfParameters parameters
        +bytes16 salt
        +bytes24 nonce
        +bytes ciphertext
    }
    class UnlockedAccount {
        -DeviceKeyPair keys
        -FileLock lock
        +identity() DeviceKeyPair
        +lock() void
    }
    class DeviceKeyPair {
        -bytes32 signing_secret
        -bytes32 hpke_secret
        +profile_id() ProfileId
    }
    class NodeIdentityStore {
        -Path private_directory
        -String initialized_peer_id
        +open() NodeIdentityLease
        +replace(expected_peer_id) Result
    }
    class NodeIdentityLease {
        -TransportKeyPair key
        -FileLock lock
        +peer_id() String
    }
    PortableAccountVault ..|> AccountKeyStore
    PortableAccountVault "1" --> "0..1" VaultEnvelope : encrypted disk record
    AccountKeyStore ..> UnlockedAccount : returns after authorization
    UnlockedAccount "1" *-- "0..1" DeviceKeyPair : absent when locked
    NodeIdentityStore ..> NodeIdentityLease : operator protected
    NodeIdentityLease "1" *-- "1" TransportKeyPair
```

Mapping: core key_store trait/structs and identity::DeviceKeyPair; network node_identity store/lease and libp2p keypair. VaultEnvelope serializes only authenticated ciphertext/header, never Debug secrets. UnlockedAccount owns exclusive key-store lock. NodeIdentityLease is separate, filesystem protected plaintext. [Key invariants](../../key-management.md): no open→create fallback, stable account/public keys and PeerId, no raw key ABI.
