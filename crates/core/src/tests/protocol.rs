use super::*;
use crate::identity::{DevelopmentIssuer, DeviceKeyPair};

#[test]
fn profile_signature_covers_ordered_manifests_and_expiry() {
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let device = DeviceKeyPair::generate().expect("device");
    let credential = issuer
        .issue_synthetic(&device, "Ada", 25, 10, 1000)
        .expect("credential");
    let a = PhotoManifest::from_bytes(b"a", "image/jpeg").expect("manifest");
    let b = PhotoManifest::from_bytes(b"b", "image/png").expect("manifest");
    let profile =
        PublicProfile::create(&device, credential, vec![a, b], 900, &trust, 20).expect("profile");
    assert!(profile.verify(&trust, 21).is_ok());
    let mut changed = profile;
    changed.photos.reverse();
    assert!(changed.verify(&trust, 21).is_err());
}

#[test]
fn envelope_round_trip_binds_recipient_and_sender() {
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let alice = DeviceKeyPair::generate().expect("alice");
    let bob = DeviceKeyPair::generate().expect("bob");
    let ac = issuer
        .issue_synthetic(&alice, "Alice", 25, 10, 1000)
        .expect("ac");
    let bc = issuer
        .issue_synthetic(&bob, "Bob", 25, 10, 1000)
        .expect("bc");
    let msg = MessageEnvelope::create(
        &alice,
        &ac,
        &bc,
        MessageKind::Like,
        [7; 16],
        20,
        100,
        b"like",
        &trust,
    )
    .expect("envelope");
    assert!(msg.verify(&ac, &trust, 21).is_ok());
    assert_eq!(msg.open(&bob, &ac, &bc, &trust, 21).expect("open"), b"like");
    assert!(msg.open(&alice, &ac, &ac, &trust, 21).is_err());

    let mut unsigned = msg.clone();
    unsigned.signature.clear();
    assert!(unsigned.verify(&ac, &trust, 21).is_err());
    let mut changed_ciphertext = msg;
    changed_ciphertext.ciphertext[0] ^= 1;
    assert!(changed_ciphertext.verify(&ac, &trust, 21).is_err());
}
