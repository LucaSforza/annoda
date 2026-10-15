use std::{path::PathBuf, sync::Arc, time::Duration};

use annoda_core::identity::TrustedIssuers;
use annoda_network::{BootstrapPeer, NodeConfig, PeerNode};
use clap::Parser;
use libp2p::{Multiaddr, PeerId};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(about = "Run a bounded Annoda volunteer storage node")]
struct Args {
    /// Multiaddress to listen on; repeat to bind more than one interface.
    #[arg(long = "listen")]
    listen: Vec<String>,
    /// Bootstrap peer in PEER_ID@MULTIADDR form; repeat for additional peers.
    #[arg(long = "bootstrap")]
    bootstrap: Vec<String>,
    /// Directory for durable volunteer storage.
    #[arg(long, default_value = "annoda-data")]
    data_dir: PathBuf,
    /// Maximum SQLite payload bytes retained by this node.
    #[arg(long, default_value_t = 1024 * 1024 * 1024)]
    storage_bytes: u64,
    /// Maximum duration of a signed photo lease, in seconds.
    #[arg(long, default_value_t = 30 * 24 * 60 * 60)]
    max_lease_seconds: u64,
    /// Maximum established libp2p connections.
    #[arg(long, default_value_t = 32)]
    max_connections: u32,
    /// Sustained application payload budget in bytes per second.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    bandwidth_bytes_per_second: u64,
    /// Trusted credential issuer's 32-byte public key in hex; repeat to trust more issuers.
    #[arg(long = "issuer-key", required = true)]
    issuer_keys: Vec<String>,
    /// Request deadline in seconds.
    #[arg(long, default_value_t = 10)]
    request_timeout_seconds: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let issuer_keys = args
        .issuer_keys
        .iter()
        .map(|key| decode_key(key))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let issuers = TrustedIssuers::new(issuer_keys);
    let listen_addresses = args
        .listen
        .iter()
        .map(|address| address.parse::<Multiaddr>())
        .collect::<Result<Vec<_>, _>>()?;
    let bootstrap_peers = args
        .bootstrap
        .iter()
        .map(|peer| parse_bootstrap(peer))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let node = PeerNode::start(
        NodeConfig {
            listen_addresses,
            bootstrap_peers,
            data_dir: args.data_dir,
            storage_bytes: args.storage_bytes,
            max_lease_seconds: args.max_lease_seconds,
            max_connections: args.max_connections,
            bandwidth_bytes_per_second: args.bandwidth_bytes_per_second,
            request_timeout: Duration::from_secs(args.request_timeout_seconds),
            clock: Arc::new(annoda_network::SystemClock),
        },
        issuers,
    )
    .await?;
    let addresses = node.wait_for_listeners().await?;
    println!("peer id: {}", node.peer_id());
    for address in addresses {
        println!("listening: {address}/p2p/{}", node.peer_id());
    }
    tokio::signal::ctrl_c().await?;
    node.shutdown().await;
    Ok(())
}

fn parse_bootstrap(value: &str) -> anyhow::Result<BootstrapPeer> {
    let (peer, address) = value
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("bootstrap must use PEER_ID@MULTIADDR"))?;
    Ok(BootstrapPeer {
        peer_id: peer.parse::<PeerId>()?,
        address: address.parse::<Multiaddr>()?,
    })
}

fn decode_key(value: &str) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(
        value.len() == 64 && value.is_ascii(),
        "issuer public key must have 64 ASCII hex characters"
    );
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_ascii_issuer_keys_are_rejected_without_slicing_panic() {
        assert!(decode_key(&format!("€{}", "0".repeat(61))).is_err());
    }
}
