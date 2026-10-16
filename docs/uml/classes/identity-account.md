## A. Identity and account

```mermaid
classDiagram
    class UserIdentity {
        +ProfileId id
        +VerifiedCredential credential
        +verify(now) Result
    }
    class ProfileId {
        +bytes32 digest
        +from_key(public_key) ProfileId
    }
    class DeviceKeyPair {
        -SigningKey signing
        -HpkePrivateKey encryption
        +generate() DeviceKeyPair
        +sign(bytes) Signature
        +decrypt(envelope) Payload
    }
    class VerifiedCredential {
        +u16 version
        +String issuer_id
        +bytes32 subject_key
        +bytes32 encryption_key
        +String first_name
        +u8 age
        +u64 expires_at
        +bytes signature
        +verify(trust, now) Result
    }
    class TrustedIssuer {
        +String id
        +bytes32 public_key
        +Set revoked_serials
    }
    class PublicProfile {
        +ProfileId owner
        +u64 expires_at
        +bytes signature
        +validate(trust, now) Result
    }
    class VerificationService {
        <<interface>>
        +authenticate_cie(response) PrivateAttributes
        +prove_possession(challenge) Result
    }
    class IdentityIssuer {
        <<interface>>
        +issue(attributes, public_keys) VerifiedCredential
    }
    UserIdentity "1" *-- "1" ProfileId
    UserIdentity "1" *-- "1" DeviceKeyPair
    UserIdentity "1" o-- "1..*" VerifiedCredential
    PublicProfile "1" *-- "1" VerifiedCredential
    VerifiedCredential "0..*" --> "1" TrustedIssuer : verified by
    VerificationService ..> IdentityIssuer : authenticates before issuing
    IdentityIssuer ..> VerifiedCredential : creates
    PublicProfile "0..*" --> "1" ProfileId : owned by
```

Mapping: core::identity structs DeviceKeyPair, VerifiedCredential, TrustedIssuer; core::protocol ProfileId/PublicProfile; IdentityIssuer trait. UserIdentity is account aggregate; VerificationService is planned CIE adapter trait/module. Invariants: credential subject matches owner and signing proof; issuer binds both keys; public age/name derived from attestation; private identity attributes never enter DHT. [Identity authority](../../identity.md).
