//! Bounded libp2p transport and durable volunteer storage adapter.

mod node;
mod wire;

pub use node::{BootstrapPeer, Clock, ManualClock, NodeConfig, PeerNode, SystemClock};
pub use wire::{MAX_FRAME_BYTES, RpcRequest, RpcResponse};
