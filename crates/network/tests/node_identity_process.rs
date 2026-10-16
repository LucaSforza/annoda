use std::{path::PathBuf, process::Command, sync::Arc};

use annoda_core::identity::DevelopmentIssuer;
use annoda_network::{NodeConfig, PeerNode, SystemClock};
use tempfile::TempDir;

#[tokio::test]
async fn identity_child() {
    let Some(data_dir) = std::env::var_os("ANNODA_NODE_IDENTITY_CHILD_DIR") else {
        return;
    };
    let config = NodeConfig {
        data_dir: PathBuf::from(data_dir),
        clock: Arc::new(SystemClock),
        ..NodeConfig::default()
    };
    let node = PeerNode::start(config, DevelopmentIssuer::new().unwrap().trusted_issuers())
        .await
        .unwrap();
    println!("RESTORED_PEER_ID={}", node.peer_id());
    node.shutdown().await;
}

#[test]
fn full_process_restart_restores_the_same_node_peer_id() {
    let parent = TempDir::new().unwrap();
    let data_dir = parent.path().join("new/private/deep");
    let run_child = || {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "identity_child", "--nocapture"])
            .env("ANNODA_NODE_IDENTITY_CHILD_DIR", &data_dir)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        stdout
            .lines()
            .find_map(|line| line.strip_prefix("RESTORED_PEER_ID="))
            .expect("child reported its PeerId")
            .to_owned()
    };

    assert_eq!(run_child(), run_child());
}
