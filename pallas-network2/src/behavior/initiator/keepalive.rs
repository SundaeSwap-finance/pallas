use crate::protocol::keepalive as keepalive_proto;

use crate::{OutboundQueue, PeerId, behavior::AnyMessage};

use super::{InitiatorBehavior, InitiatorState, PeerVisitor};

/// Sub-behavior that sends periodic keepalive messages to maintain connections.
pub struct KeepaliveBehavior {
    token: u16,
}

impl Default for KeepaliveBehavior {
    fn default() -> Self {
        Self { token: u16::MAX }
    }
}

/// Returns true when `peer` can be sent a keepalive right now: it is
/// handshaked, the keepalive protocol is ours to speak, and no earlier
/// keepalive of ours is still waiting for the IO layer to confirm its send.
fn peer_is_available(peer: &InitiatorState) -> bool {
    peer.is_initialized()
        && matches!(peer.keepalive, keepalive_proto::State::Client(_))
        && !peer.send_unconfirmed(keepalive_proto::CHANNEL_ID)
}

impl KeepaliveBehavior {
    /// Sends a keepalive message to the peer if the protocol state allows it.
    pub fn send_keepalive(
        &mut self,
        pid: &PeerId,
        peer: &mut InitiatorState,
        outbound: &mut OutboundQueue<super::InitiatorBehavior>,
    ) {
        if !peer_is_available(peer) {
            return;
        }

        let msg = keepalive_proto::Message::KeepAlive(self.token);

        super::send_to_peer(pid, peer, AnyMessage::KeepAlive(msg), outbound);
    }
}

impl PeerVisitor for KeepaliveBehavior {
    fn visit_housekeeping(
        &mut self,
        pid: &PeerId,
        state: &mut InitiatorState,
        outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) {
        self.send_keepalive(pid, state, outbound);
    }
}
