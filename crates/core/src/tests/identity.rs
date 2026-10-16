use super::*;

impl DevelopmentIssuer {
    pub(crate) fn test_public_key(&self) -> [u8; 32] {
        self.keys.public_key()
    }
}

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
