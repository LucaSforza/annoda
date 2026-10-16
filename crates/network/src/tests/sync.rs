use super::*;

#[test]
fn default_contribution_is_disabled_and_peer_selection_is_unique_and_bounded() {
    let address: Multiaddr = "/ip4/127.0.0.1/tcp/1".parse().unwrap();
    let peer_id = PeerId::random();
    let peers = vec![
        BootstrapPeer {
            peer_id,
            address: address.clone(),
        },
        BootstrapPeer { peer_id, address },
    ];
    assert_eq!(select_peers(peers, 16).len(), 1);
    assert!(!ContributionInputs::default().policy.enabled);
}

#[test]
fn budget_validation_rejects_unbounded_inputs() {
    let budget = SyncBudget {
        max_peers: (MAX_SESSION_PEERS + 1) as u16,
        ..SyncBudget::default()
    };
    assert_eq!(
        validate_budget(&budget, &PeerContributionPolicy::default()),
        Err(SyncError::InvalidBudget)
    );
}
