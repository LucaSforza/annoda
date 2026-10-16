//! Bounded libp2p transport and durable volunteer storage adapter.

mod node;
mod node_identity;
pub mod sync;
mod transfer;
mod wire;

pub use node::{BootstrapPeer, Clock, ManualClock, NodeConfig, PeerNode, SystemClock};
pub use node_identity::{NodeIdentityError, NodeIdentityLease, NodeIdentityStore};
pub use sync::{
    AuthorizedReplica, AuthorizedReplicaPhoto, ContributionInputs, HostConditions,
    PeerContributionPolicy, SyncBudget, SyncCancellationToken, SyncContext, SyncDeferredReason,
    SyncError, SyncPeerAddress, SyncReport, SyncStatus, sync_once,
};
pub use wire::{MAX_FRAME_BYTES, RpcMailboxCursor, RpcRequest, RpcResponse};
