use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver, setup_sender_with_rng,
};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result, protocol::ProfileId};

const CREDENTIAL_DOMAIN: &[u8] = b"annoda/credential/v1\0";
const HPKE_INFO: &[u8] = b"annoda/hpke/v1/message";
const MAX_CREDENTIAL_LIFETIME: u64 = 24 * 60 * 60;

type HpkeKem = X25519HkdfSha256;
type HpkeAead = ChaCha20Poly1305;
type HpkeKdf = HkdfSha256;

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct CredentialClaims {
    pub version: u16,
    pub serial: [u8; 16],
    pub issuer_id: [u8; 32],
    pub subject: ProfileId,
    pub signing_key: [u8; 32],
    pub encryption_key: Vec<u8>,
    pub first_name: String,
    pub age_at_issue: u8,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct VerifiedCredential {
    pub claims: CredentialClaims,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct IssuanceRequest {
    pub signing_key: [u8; 32],
    pub encryption_key: Vec<u8>,
    pub first_name: String,
    pub age_at_issue: u8,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone)]
pub struct IssuerKeyPair {
    signing: SigningKey,
}

pub struct DevelopmentIssuer {
    keys: IssuerKeyPair,
}

pub trait IdentityIssuer {
    fn issuer_id(&self) -> [u8; 32];
    fn issue(&self, request: IssuanceRequest) -> Result<VerifiedCredential>;
}

#[derive(Clone, Default)]
pub struct TrustedIssuers {
    keys: BTreeSet<[u8; 32]>,
    revoked_serials: BTreeSet<[u8; 16]>,
}

pub struct DeviceKeyPair {
    signing: SigningKey,
    encryption: <HpkeKem as KemTrait>::PrivateKey,
    signing_public: [u8; 32],
    encryption_public: Vec<u8>,
}

impl IssuerKeyPair {
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *seed).map_err(|_| Error::Crypto)?;
        let signing = SigningKey::from_bytes(&seed);
        Ok(Self { signing })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn issuer_id(&self) -> [u8; 32] {
        *blake3::hash(&self.public_key()).as_bytes()
    }
}

impl DevelopmentIssuer {
    pub fn new() -> Result<Self> {
        Ok(Self {
            keys: IssuerKeyPair::generate()?,
        })
    }

    pub fn issuer_id(&self) -> [u8; 32] {
        self.keys.issuer_id()
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.keys.public_key()
    }

    #[cfg(test)]
    pub(crate) fn test_public_key(&self) -> [u8; 32] {
        self.keys.public_key()
    }

    pub fn trusted_issuers(&self) -> TrustedIssuers {
        TrustedIssuers::new([self.keys.public_key()])
    }

    /// Issues synthetic credentials for fixtures and local development only.
    pub fn issue_synthetic(
        &self,
        device: &DeviceKeyPair,
        first_name: &str,
        age_at_issue: u8,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<VerifiedCredential> {
        let request = IssuanceRequest {
            signing_key: device.signing_public,
            encryption_key: device.encryption_public.clone(),
            first_name: first_name.to_owned(),
            age_at_issue,
            issued_at,
            expires_at,
        };
        self.issue(request)
    }

    fn issue_claims(&self, request: IssuanceRequest) -> Result<VerifiedCredential> {
        let claims = make_claims(&self.keys, request)?;
        let signed = canonical(CREDENTIAL_DOMAIN, &claims)?;
        let signature = self.keys.signing.sign(&signed).to_bytes().to_vec();
        Ok(VerifiedCredential { claims, signature })
    }
}

impl IdentityIssuer for DevelopmentIssuer {
    fn issuer_id(&self) -> [u8; 32] {
        self.keys.issuer_id()
    }

    fn issue(&self, request: IssuanceRequest) -> Result<VerifiedCredential> {
        self.issue_claims(request)
    }
}

impl TrustedIssuers {
    pub fn new(keys: impl IntoIterator<Item = [u8; 32]>) -> Self {
        Self {
            keys: keys.into_iter().collect(),
            revoked_serials: BTreeSet::new(),
        }
    }

    pub fn revoke_serial(&mut self, serial: [u8; 16]) {
        self.revoked_serials.insert(serial);
    }

    pub fn contains_issuer(&self, issuer_id: [u8; 32]) -> bool {
        self.keys
            .iter()
            .any(|key| *blake3::hash(key).as_bytes() == issuer_id)
    }

    pub fn verify(&self, credential: &VerifiedCredential, now: u64) -> Result<()> {
        let claims = &credential.claims;
        if claims.version != 1
            || claims.age_at_issue < 18
            || claims.first_name.trim().is_empty()
            || claims.first_name.len() > 80
            || claims.encryption_key.len() != <HpkeKem as KemTrait>::PublicKey::size()
            || claims.expires_at <= claims.issued_at
            || claims.expires_at - claims.issued_at > MAX_CREDENTIAL_LIFETIME
            || now < claims.issued_at
            || now >= claims.expires_at
            || claims.subject != ProfileId::from_signing_key(&claims.signing_key)
            || self.revoked_serials.contains(&claims.serial)
        {
            return Err(Error::InvalidCredential);
        }
        let verifying = self
            .keys
            .iter()
            .find_map(|key| {
                let id = *blake3::hash(key).as_bytes();
                (id == claims.issuer_id)
                    .then(|| VerifyingKey::from_bytes(key).ok())
                    .flatten()
            })
            .ok_or(Error::InvalidCredential)?;
        let sig_bytes: [u8; 64] = credential
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        verifying
            .verify(&canonical(CREDENTIAL_DOMAIN, claims)?, &signature)
            .map_err(|_| Error::InvalidSignature)
    }
}

impl DeviceKeyPair {
    pub fn generate() -> Result<Self> {
        let mut signing_seed = Zeroizing::new([0u8; 32]);
        let mut encryption_seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *signing_seed).map_err(|_| Error::Crypto)?;
        getrandom::fill(&mut *encryption_seed).map_err(|_| Error::Crypto)?;
        let signing = SigningKey::from_bytes(&signing_seed);
        let (encryption, public) = HpkeKem::derive_keypair(&*encryption_seed);
        Ok(Self {
            signing_public: signing.verifying_key().to_bytes(),
            encryption_public: public.to_bytes().to_vec(),
            signing,
            encryption,
        })
    }

    pub fn profile_id(&self) -> ProfileId {
        ProfileId::from_signing_key(&self.signing_public)
    }

    pub(crate) fn export_secret_material(&self) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
        let signing = Zeroizing::new(self.signing.to_bytes());
        let mut serialized = self.encryption.to_bytes();
        let mut encryption = Zeroizing::new([0u8; 32]);
        encryption.copy_from_slice(serialized.as_slice());
        serialized.zeroize();
        (signing, encryption)
    }

    pub(crate) fn from_secret_material(
        signing_secret: &[u8; 32],
        encryption_secret: &[u8; 32],
    ) -> Result<Self> {
        let signing = SigningKey::from_bytes(signing_secret);
        let encryption = <HpkeKem as KemTrait>::PrivateKey::from_bytes(encryption_secret)
            .map_err(|_| Error::Crypto)?;
        let encryption_public = HpkeKem::sk_to_pk(&encryption).to_bytes().to_vec();
        Ok(Self {
            signing_public: signing.verifying_key().to_bytes(),
            encryption_public,
            signing,
            encryption,
        })
    }
    pub fn signing_public_key(&self) -> [u8; 32] {
        self.signing_public
    }
    pub fn encryption_public_key(&self) -> &[u8] {
        &self.encryption_public
    }

    pub fn sign(&self, domain: &[u8], bytes: &[u8]) -> Vec<u8> {
        self.signing
            .sign(&domain_message(domain, bytes))
            .to_bytes()
            .to_vec()
    }

    pub fn seal(
        &self,
        recipient_public_key: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        seal(recipient_public_key, aad, plaintext)
    }

    pub(crate) fn open(&self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (enc, body) = ciphertext
            .split_at_checked(<HpkeKem as KemTrait>::EncappedKey::size())
            .ok_or(Error::Crypto)?;
        let enc = <HpkeKem as KemTrait>::EncappedKey::from_bytes(enc).map_err(|_| Error::Crypto)?;
        let mut context = setup_receiver::<HpkeAead, HpkeKdf, HpkeKem>(
            &OpModeR::Base,
            &self.encryption,
            &enc,
            HPKE_INFO,
        )
        .map_err(|_| Error::Crypto)?;
        context.open(body, aad).map_err(|_| Error::Crypto)
    }
}

impl VerifiedCredential {
    pub fn verify(&self, issuers: &TrustedIssuers, now: u64) -> Result<()> {
        issuers.verify(self, now)
    }
    pub fn profile_id(&self) -> ProfileId {
        self.claims.subject
    }
}

pub fn verify_signature(
    public_key: &[u8; 32],
    domain: &[u8],
    bytes: &[u8],
    signature: &[u8],
) -> Result<()> {
    let verifying = VerifyingKey::from_bytes(public_key).map_err(|_| Error::InvalidSignature)?;
    let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| Error::InvalidSignature)?;
    verifying
        .verify(
            &domain_message(domain, bytes),
            &Signature::from_bytes(&sig_bytes),
        )
        .map_err(|_| Error::InvalidSignature)
}

pub fn seal(recipient_public_key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let public = <HpkeKem as KemTrait>::PublicKey::from_bytes(recipient_public_key)
        .map_err(|_| Error::Crypto)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed).map_err(|_| Error::Crypto)?;
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let (enc, mut context) = setup_sender_with_rng::<HpkeAead, HpkeKdf, HpkeKem>(
        &OpModeS::Base,
        &public,
        HPKE_INFO,
        &mut rng,
    )
    .map_err(|_| Error::Crypto)?;
    let body = context.seal(plaintext, aad).map_err(|_| Error::Crypto)?;
    let mut output = enc.to_bytes().to_vec();
    output.extend_from_slice(&body);
    Ok(output)
}

pub(crate) fn canonical<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>> {
    let bytes = postcard::to_allocvec(value).map_err(|_| Error::Serialization)?;
    Ok(domain_message(domain, &bytes))
}

fn domain_message(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + bytes.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(bytes);
    out
}

fn make_claims(issuer: &IssuerKeyPair, request: IssuanceRequest) -> Result<CredentialClaims> {
    let name = request.first_name.trim();
    if name.is_empty()
        || name.len() > 80
        || request.age_at_issue < 18
        || request.encryption_key.len() != <HpkeKem as KemTrait>::PublicKey::size()
        || request.expires_at <= request.issued_at
        || request.expires_at - request.issued_at > MAX_CREDENTIAL_LIFETIME
    {
        return Err(Error::InvalidInput);
    }
    let mut serial = [0u8; 16];
    getrandom::fill(&mut serial).map_err(|_| Error::Crypto)?;
    Ok(CredentialClaims {
        version: 1,
        serial,
        issuer_id: issuer.issuer_id(),
        subject: ProfileId::from_signing_key(&request.signing_key),
        signing_key: request.signing_key,
        encryption_key: request.encryption_key,
        first_name: name.to_owned(),
        age_at_issue: request.age_at_issue,
        issued_at: request.issued_at,
        expires_at: request.expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_binds_both_device_keys_and_expiry() {
        let issuer = DevelopmentIssuer::new().expect("issuer");
        let trusted = issuer.trusted_issuers();
        let device = DeviceKeyPair::generate().expect("generate device");
        let credential = issuer
            .issue_synthetic(&device, "Ada", 30, 10, 100)
            .expect("issue");
        assert!(credential.verify(&trusted, 10).is_ok());
        assert!(credential.verify(&trusted, 100).is_err());
        let mut rebound = credential.clone();
        rebound.claims.encryption_key[0] ^= 1;
        assert!(rebound.verify(&trusted, 20).is_err());
    }

    #[test]
    fn credential_rejects_untrusted_issuers_underage_and_revoked_signatures() {
        let issuer = DevelopmentIssuer::new().expect("issuer");
        let mut trusted = issuer.trusted_issuers();
        let device = DeviceKeyPair::generate().expect("device");
        let credential = issuer
            .issue_synthetic(&device, "Ada", 30, 10, 100)
            .expect("credential");

        assert!(credential.verify(&TrustedIssuers::default(), 20).is_err());
        assert!(issuer.issue_synthetic(&device, "Ada", 17, 10, 100).is_err());

        let mut tampered = credential.clone();
        tampered.signature[0] ^= 1;
        assert!(tampered.verify(&trusted, 20).is_err());

        trusted.revoke_serial(credential.claims.serial);
        assert!(credential.verify(&trusted, 20).is_err());
    }

    #[test]
    fn hpke_round_trip_authenticates_context() {
        let recipient = DeviceKeyPair::generate().expect("generate device");
        let sealed = seal(recipient.encryption_public_key(), b"purpose", b"private").expect("seal");
        assert_eq!(
            recipient.open(b"purpose", &sealed).expect("open"),
            b"private"
        );
        assert!(recipient.open(b"other purpose", &sealed).is_err());
    }
}
