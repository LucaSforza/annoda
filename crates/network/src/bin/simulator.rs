use std::path::PathBuf;

use annoda_core::identity::TrustedIssuers;
use annoda_network::{BootstrapPeer, NodeConfig, PeerNode};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(about = "Start a local Annoda volunteer network")]
struct Args {
    /// Number of nodes to start (the first node is the bootstrap peer).
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(1..=16))]
    nodes: u8,
    /// Parent directory for per-node SQLite data.
    #[arg(long, default_value = "annoda-simulator-data")]
    data_dir: PathBuf,
    /// Trusted issuer public key in hex.
    #[arg(long, required = true)]
    issuer_key: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let issuer_key = decode_key(&args.issuer_key)?;
    let issuers = TrustedIssuers::new([issuer_key]);

    let mut nodes: Vec<PeerNode> = Vec::with_capacity(args.nodes as usize);
    let mut bootstrap: Option<BootstrapPeer> = None;
    for index in 0..args.nodes {
        let config = NodeConfig {
            bootstrap_peers: bootstrap.iter().cloned().collect(),
            data_dir: args.data_dir.join(format!("node-{index}")),
            ..NodeConfig::default()
        };
        let node = PeerNode::start(config, issuers.clone()).await?;
        let addresses = node.wait_for_listeners().await?;
        if index == 0
            && let Some(address) = addresses.first()
        {
            bootstrap = Some(BootstrapPeer {
                peer_id: node.peer_id(),
                address: address.clone(),
            });
        }
        println!("node {index}: peer id {}", node.peer_id());
        for address in addresses {
            println!("node {index} listening: {address}/p2p/{}", node.peer_id());
        }
        nodes.push(node);
    }
    tokio::signal::ctrl_c().await?;
    for node in nodes {
        node.shutdown().await;
    }
    Ok(())
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
#[path = "../tests/bin_simulator.rs"]
mod tests;
