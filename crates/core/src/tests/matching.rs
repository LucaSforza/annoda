use super::*;
use crate::identity::{DevelopmentIssuer, DeviceKeyPair};

#[test]
fn contacts_are_unavailable_before_mutual_positive_intent_and_after_block() {
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let alice = DeviceKeyPair::generate().expect("alice");
    let bob = DeviceKeyPair::generate().expect("bob");
    let ac = issuer
        .issue_synthetic(&alice, "Alice", 25, 1, 100)
        .expect("credential");
    let bc = issuer
        .issue_synthetic(&bob, "Bob", 25, 1, 100)
        .expect("credential");
    let mut record = MatchRecord::new(ac.profile_id(), bc.profile_id()).expect("record");
    let handles = vec![ContactHandle {
        service: ContactService::Telegram,
        value: "@alice".into(),
    }];
    assert!(record.disclose(handles.clone()).is_err());
    record.like([1; 16]).expect("like");
    record
        .receive_like(bc.profile_id(), ac.profile_id(), [2; 16])
        .expect("incoming");
    let envelope = record
        .encrypted_disclosure(&alice, &ac, &bc, handles, [9; 16], 3, 50, &trust)
        .expect("disclose");
    let payload = envelope.open(&bob, &ac, &bc, &trust, 4).expect("decrypt");
    let disclosure = ContactDisclosure::decode(
        &payload,
        ac.profile_id(),
        bc.profile_id(),
        record.match_id().expect("id"),
    )
    .expect("decode");
    assert_eq!(disclosure.handles.len(), 1);
    record.block();
    assert!(
        record
            .disclose(vec![ContactHandle {
                service: ContactService::Instagram,
                value: "alice".into()
            }])
            .is_err()
    );
}

#[test]
fn reject_and_block_ignore_delayed_likes() {
    let mut state = MatchRecord::new(ProfileId([1; 32]), ProfileId([2; 32])).expect("record");
    state.reject().expect("reject");
    assert!(
        !state
            .receive_like(ProfileId([2; 32]), ProfileId([1; 32]), [1; 16])
            .expect("delayed")
    );
    state.block();
    assert!(
        !state
            .receive_like(ProfileId([2; 32]), ProfileId([1; 32]), [2; 16])
            .expect("blocked")
    );
    assert!(state.like([3; 16]).is_err());
}

#[test]
fn rejecting_a_matched_record_does_not_unmatch_it() {
    let mut state = MatchRecord::new(ProfileId([1; 32]), ProfileId([2; 32])).expect("record");
    state.like([1; 16]).expect("local like");
    state
        .receive_like(ProfileId([2; 32]), ProfileId([1; 32]), [2; 16])
        .expect("incoming like");
    assert_eq!(state.state(), MatchState::Matched);

    assert!(state.reject().is_err());
    assert_eq!(state.state(), MatchState::Matched);
}

#[test]
fn envelope_signer_cannot_claim_another_users_like() {
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let alice = DeviceKeyPair::generate().expect("alice");
    let bob = DeviceKeyPair::generate().expect("bob");
    let mallory = DeviceKeyPair::generate().expect("mallory");
    let ac = issuer
        .issue_synthetic(&alice, "Alice", 25, 1, 100)
        .expect("credential");
    let bc = issuer
        .issue_synthetic(&bob, "Bob", 25, 1, 100)
        .expect("credential");
    let mc = issuer
        .issue_synthetic(&mallory, "Mallory", 25, 1, 100)
        .expect("credential");
    let id = [9; 16];
    let payload = postcard::to_allocvec(&LikeIntent {
        sender: bc.profile_id(),
        recipient: ac.profile_id(),
        id,
    })
    .expect("payload");
    let forged_claim = MessageEnvelope::create(
        &mallory,
        &mc,
        &ac,
        MessageKind::Like,
        id,
        2,
        50,
        &payload,
        &trust,
    )
    .expect("envelope");
    let mut record = MatchRecord::new(ac.profile_id(), bc.profile_id()).expect("match");
    assert!(
        record
            .receive_envelope(&forged_claim, &mc, &alice, &ac, &trust, 3)
            .is_err()
    );
    assert_eq!(record.state(), MatchState::Neutral);
}
