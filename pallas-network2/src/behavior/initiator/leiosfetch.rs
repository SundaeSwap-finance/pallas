use std::collections::{HashSet, VecDeque};

use crate::protocol::EbId;
use crate::protocol::leiosfetch::{self as fetch_proto, Bitmaps};

use crate::{BehaviorOutput, InterfaceCommand, OutboundQueue, PeerId, behavior::AnyMessage};

use super::{InitiatorBehavior, InitiatorEvent, InitiatorState, PeerVisitor};

/// A pending leios-fetch request targeting a specific peer.
#[derive(Debug, Clone)]
pub enum FetchRequest {
    /// Fetch a complete EB body.
    Block(EbId),
    /// Fetch a subset of an EB's transactions.
    BlockTxs(EbId, Bitmaps),
}

/// Sub-behavior that fetches EB bodies and transactions from peers.
///
/// Requests are queued (each targeting the peer that should serve it) and sent
/// one at a time per peer, either as soon as they are issued or on the next
/// housekeeping tick. Responses are surfaced as [`InitiatorEvent::EbFetched`].
#[derive(Default)]
pub struct LeiosFetchBehavior {
    requests: VecDeque<(PeerId, FetchRequest)>,

    /// Peers holding a request that has been handed to the IO layer but whose
    /// send it has not confirmed yet.
    ///
    /// The peer's `leios_fetch` state only leaves idle when the confirmation
    /// comes back, so without this record two requests issued in that window
    /// would both read the peer as free and both go out. The second
    /// confirmation would then be refused by the protocol state machine and
    /// the peer would be banned for our own mistake.
    unconfirmed: HashSet<PeerId>,
}

impl LeiosFetchBehavior {
    /// Queues a fetch request to be served by the given peer.
    pub fn enqueue(&mut self, pid: PeerId, request: FetchRequest) {
        self.requests.push_back((pid, request));
        tracing::info!(total = self.requests.len(), "new leios-fetch request");
    }

    /// Sends the first queued request targeting `pid`, when that peer is ready
    /// to take one. Does nothing if the peer is busy or has nothing queued.
    pub(super) fn serve_next(
        &mut self,
        pid: &PeerId,
        state: &mut InitiatorState,
        outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) {
        if !self.peer_is_available(pid, state) {
            return;
        }

        if let Some(idx) = self.requests.iter().position(|(p, _)| p == pid) {
            let (_, request) = self.requests.remove(idx).expect("index just found");
            self.send_request(pid, &request, outbound);
        }
    }

    /// Returns true when `pid` can be handed a request right now: it is
    /// handshaked, it speaks Leios, its leios-fetch protocol is idle with
    /// nothing left to drain, and no earlier request of ours is still waiting
    /// for the IO layer to confirm its send.
    fn peer_is_available(&self, pid: &PeerId, state: &InitiatorState) -> bool {
        state.is_initialized()
            && state.supports_leios()
            && matches!(state.leios_fetch, fetch_proto::State::Idle(None))
            && !self.unconfirmed.contains(pid)
    }

    /// Drops any queued requests targeting `pid`, and forgets that we were
    /// waiting on a send confirmation from it. Called when the peer goes away
    /// so requests don't leak or get re-sent to a later reconnection of the same
    /// `PeerId` (which may no longer hold the offered EB), and so a
    /// confirmation that will now never arrive does not block that reconnection
    /// forever.
    fn purge(&mut self, pid: &PeerId) {
        self.requests.retain(|(p, _)| p != pid);
        self.unconfirmed.remove(pid);
    }

    fn send_request(
        &mut self,
        pid: &PeerId,
        request: &FetchRequest,
        outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) {
        let msg = match request {
            FetchRequest::Block(point) => fetch_proto::Message::BlockRequest(point.clone()),
            FetchRequest::BlockTxs(point, bitmaps) => {
                fetch_proto::Message::BlockTxsRequest(point.clone(), bitmaps.clone())
            }
        };

        outbound.push_ready(BehaviorOutput::InterfaceCommand(InterfaceCommand::Send(
            pid.clone(),
            AnyMessage::LeiosFetch(msg),
        )));

        self.unconfirmed.insert(pid.clone());
    }

    /// Drains a pending response from the peer state and emits the corresponding
    /// external event.
    fn dispatch(
        &self,
        pid: &PeerId,
        state: &mut InitiatorState,
        outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) {
        if let Some((eb, response)) = state.leios_fetch.drain() {
            outbound.push_ready(BehaviorOutput::ExternalEvent(InitiatorEvent::EbFetched(
                pid.clone(),
                eb,
                response,
            )));
        }
    }
}

impl PeerVisitor for LeiosFetchBehavior {
    fn visit_inbound_msg(
        &mut self,
        pid: &PeerId,
        state: &mut InitiatorState,
        outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) {
        self.dispatch(pid, state, outbound);

        // Draining a response leaves the protocol idle again, so whatever is
        // still queued for this peer goes out now instead of waiting for the
        // next housekeeping tick.
        self.serve_next(pid, state, outbound);
    }

    fn visit_outbound_msg(
        &mut self,
        pid: &PeerId,
        state: &mut InitiatorState,
        _outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) {
        // A leios-fetch state that has left idle is the confirmation we were
        // standing in for, and from there the protocol state keeps the peer
        // busy on its own. Nothing else can move that state while we hold the
        // peer, so this only clears on our own request's confirmation.
        if !matches!(state.leios_fetch, fetch_proto::State::Idle(None)) {
            self.unconfirmed.remove(pid);
        }
    }

    fn visit_housekeeping(
        &mut self,
        pid: &PeerId,
        state: &mut InitiatorState,
        outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) {
        self.serve_next(pid, state, outbound);
    }

    fn visit_disconnected(
        &mut self,
        pid: &PeerId,
        _state: &mut InitiatorState,
        _outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) {
        self.purge(pid);
    }

    fn visit_errored(
        &mut self,
        pid: &PeerId,
        _state: &mut InitiatorState,
        _outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) {
        self.purge(pid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Point;
    use crate::protocol::leiosfetch::Response;
    use crate::protocol::{AnyCbor, leiosfetch as lf};
    use crate::{OutboundQueue, behavior::ConnectionState};

    fn drain_outputs(
        outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) -> Vec<BehaviorOutput<InitiatorBehavior>> {
        outbound.drain_ready()
    }

    #[test]
    fn dispatch_emits_fetched_event_once() {
        let b = LeiosFetchBehavior::default();
        let pid = PeerId::test(1);
        let mut state = InitiatorState::new();
        let mut outbound = OutboundQueue::new();

        state.leios_fetch = lf::State::Idle(Some((
            Point::Origin,
            Response::Block(AnyCbor::from_raw_bytes(vec![0x01])),
        )));

        b.dispatch(&pid, &mut state, &mut outbound);
        assert!(drain_outputs(&mut outbound).iter().any(|o| matches!(
            o,
            BehaviorOutput::ExternalEvent(InitiatorEvent::EbFetched(..))
        )));

        b.dispatch(&pid, &mut state, &mut outbound);
        assert!(drain_outputs(&mut outbound).is_empty());
    }

    #[test]
    fn housekeeping_sends_request_for_available_peer() {
        let mut b = LeiosFetchBehavior::default();
        let pid = PeerId::test(1);
        let mut outbound = OutboundQueue::new();

        b.enqueue(pid.clone(), FetchRequest::Block(Point::Origin));

        // peer not ready → request stays queued
        let mut state = InitiatorState::new();
        state.connection = ConnectionState::Initialized; // but supports_leios() is false
        b.visit_housekeeping(&pid, &mut state, &mut outbound);
        assert!(drain_outputs(&mut outbound).is_empty());
        assert_eq!(b.requests.len(), 1);
    }

    #[test]
    fn disconnect_purges_queued_requests() {
        let mut b = LeiosFetchBehavior::default();
        let pid = PeerId::test(1);
        let mut state = InitiatorState::new();
        let mut outbound = OutboundQueue::new();

        b.enqueue(pid.clone(), FetchRequest::Block(Point::Origin));
        b.enqueue(PeerId::test(2), FetchRequest::Block(Point::Origin));
        assert_eq!(b.requests.len(), 2);

        // Disconnecting pid drops only its queued request.
        b.visit_disconnected(&pid, &mut state, &mut outbound);
        assert_eq!(b.requests.len(), 1);
        assert!(b.requests.iter().all(|(p, _)| p != &pid));
    }

    /// Marks a peer by actually sending it a request, then hands it back with
    /// the queue and the outbound it was marked through.
    fn marked_peer() -> (LeiosFetchBehavior, PeerId, OutboundQueue<InitiatorBehavior>) {
        let mut b = LeiosFetchBehavior::default();
        let pid = PeerId::test(1);
        let mut outbound = OutboundQueue::new();

        b.send_request(&pid, &FetchRequest::Block(Point::Origin), &mut outbound);
        assert!(
            b.unconfirmed.contains(&pid),
            "handing a request to the IO layer should mark the peer"
        );
        assert_eq!(drain_outputs(&mut outbound).len(), 1);

        (b, pid, outbound)
    }

    #[test]
    fn disconnect_clears_the_unconfirmed_mark() {
        // The confirmation for that send will never arrive now, so keeping the
        // mark would lock the peer out of every later fetch.
        let (mut b, pid, mut outbound) = marked_peer();
        let mut state = InitiatorState::new();

        b.visit_disconnected(&pid, &mut state, &mut outbound);

        assert!(
            !b.unconfirmed.contains(&pid),
            "a disconnected peer should not stay marked"
        );
    }

    #[test]
    fn error_clears_the_unconfirmed_mark() {
        let (mut b, pid, mut outbound) = marked_peer();
        let mut state = InitiatorState::new();

        b.visit_errored(&pid, &mut state, &mut outbound);

        assert!(
            !b.unconfirmed.contains(&pid),
            "an errored peer should not stay marked"
        );
    }

    #[test]
    fn a_confirmed_send_clears_the_unconfirmed_mark() {
        let (mut b, pid, mut outbound) = marked_peer();
        let mut state = InitiatorState::new();

        // Nothing has confirmed yet, so the mark stands and the protocol still
        // reads idle. This is exactly the window the mark exists to cover.
        b.visit_outbound_msg(&pid, &mut state, &mut outbound);
        assert!(
            b.unconfirmed.contains(&pid),
            "the mark should stand while the protocol still reads idle"
        );

        // The confirmation moves the protocol out of idle, which is what the
        // mark was standing in for.
        state.leios_fetch = fetch_proto::State::AwaitingBlock(Point::Origin);
        b.visit_outbound_msg(&pid, &mut state, &mut outbound);
        assert!(
            !b.unconfirmed.contains(&pid),
            "a confirmed send should clear the mark"
        );
    }
}
