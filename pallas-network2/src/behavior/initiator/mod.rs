use futures::{Stream, StreamExt, stream::FusedStream};
use std::{
    collections::{HashMap, HashSet},
    task::Poll,
};

use crate::{
    Behavior, BehaviorOutput, Channel, InterfaceCommand, Message as MessageTrait, OutboundQueue,
    PeerId, protocol as proto,
};

use super::{AcceptedVersion, AnyMessage, BlockRange, ConnectionState};

mod blockfetch;
mod chainsync;
mod connection;
mod discovery;
mod handshake;
mod keepalive;
mod leiosfetch;
mod leiosnotify;
mod promotion;

pub use blockfetch::*;
pub use chainsync::*;
pub use connection::*;
pub use discovery::*;
pub use handshake::*;
pub use keepalive::*;
pub use leiosfetch::*;
pub use leiosnotify::*;
pub use promotion::*;

/// A visitor trait that allows sub-behaviors to react to peer lifecycle events.
///
/// Each method is called by the initiator behavior at the appropriate point
/// in a peer's lifecycle. Default implementations are no-ops.
pub trait PeerVisitor {
    /// Called when a TCP connection to the peer is established.
    #[allow(unused_variables)]
    fn visit_connected(
        &mut self,
        pid: &PeerId,
        state: &mut InitiatorState,
        outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) {
        // default implementation does nothing
    }

    /// Called when the peer has been disconnected.
    #[allow(unused_variables)]
    fn visit_disconnected(
        &mut self,
        pid: &PeerId,
        state: &mut InitiatorState,
        outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) {
        // default implementation does nothing
    }

    /// Called when an error occurred on the peer's connection.
    #[allow(unused_variables)]
    fn visit_errored(
        &mut self,
        pid: &PeerId,
        state: &mut InitiatorState,
        outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) {
        // default implementation does nothing
    }

    /// Called when a new peer has been discovered.
    #[allow(unused_variables)]
    fn visit_discovered(
        &mut self,
        pid: &PeerId,
        state: &mut InitiatorState,
        outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) {
        // default implementation does nothing
    }

    /// Called when a message has been received from the peer.
    #[allow(unused_variables)]
    fn visit_inbound_msg(
        &mut self,
        pid: &PeerId,
        state: &mut InitiatorState,
        outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) {
        // default implementation does nothing
    }

    /// Called after a message has been sent to the peer.
    #[allow(unused_variables)]
    fn visit_outbound_msg(
        &mut self,
        pid: &PeerId,
        state: &mut InitiatorState,
        outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) {
        // default implementation does nothing
    }

    /// Called when a peer's state has been modified by a tag function.
    #[allow(unused_variables)]
    fn visit_tagged(
        &mut self,
        pid: &PeerId,
        state: &mut InitiatorState,
        outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) {
        // default implementation does nothing
    }

    /// Called during periodic housekeeping for each tracked peer.
    #[allow(unused_variables)]
    fn visit_housekeeping(
        &mut self,
        pid: &PeerId,
        state: &mut InitiatorState,
        outbound: &mut OutboundQueue<InitiatorBehavior>,
    ) {
        // default implementation does nothing
    }
}

/// The promotion level of a peer, controlling which mini-protocols are active.
#[derive(PartialEq, Debug, Default, Copy, Clone)]
pub enum PromotionTag {
    /// Peer is known but not connected.
    #[default]
    Cold,
    /// Peer is connected and performing basic protocols (handshake, keepalive).
    Warm,
    /// Peer is fully active with all mini-protocols.
    Hot,
    /// Peer has been banned and will not be connected.
    Banned,
}

/// The per-peer state tracked by the initiator behavior, including connection
/// status and all mini-protocol state machines.
#[derive(Default, Debug)]
pub struct InitiatorState {
    pub(crate) connection: ConnectionState,
    pub(crate) promotion: PromotionTag,
    pub(crate) handshake: proto::handshake::State<proto::handshake::n2n::VersionData>,
    pub(crate) keepalive: proto::keepalive::State,
    pub(crate) peersharing: proto::peersharing::State,
    pub(crate) blockfetch: proto::blockfetch::State,
    pub(crate) chainsync: proto::chainsync::State<proto::chainsync::HeaderContent>,
    pub(crate) tx_submission: proto::txsubmission::State,
    pub(crate) leios_notify: proto::leiosnotify::State,
    pub(crate) leios_fetch: proto::leiosfetch::State,
    pub(crate) violation: bool,
    pub(crate) error_count: u32,
    pub(crate) continue_sync: bool,

    /// Channels holding a message handed to the IO layer whose send it has not
    /// confirmed yet.
    ///
    /// A mini-protocol state only leaves idle when the confirmation comes back,
    /// so without this record two housekeeping passes inside that window both
    /// read the protocol as free and both send a request. The second
    /// confirmation is then refused by the state machine.
    pub(crate) unconfirmed_sends: HashSet<Channel>,
}

impl InitiatorState {
    /// Creates a new initiator state with default values for all protocols.
    pub fn new() -> Self {
        InitiatorState {
            connection: ConnectionState::default(),
            promotion: PromotionTag::default(),
            handshake: proto::handshake::State::default(),
            keepalive: proto::keepalive::State::default(),
            peersharing: proto::peersharing::State::default(),
            blockfetch: proto::blockfetch::State::default(),
            chainsync: crate::protocol::chainsync::State::default(),
            tx_submission: crate::protocol::txsubmission::State::default(),
            leios_notify: proto::leiosnotify::State::default(),
            leios_fetch: proto::leiosfetch::State::default(),
            violation: false,
            error_count: 0,
            continue_sync: false,
            unconfirmed_sends: HashSet::new(),
        }
    }

    /// Returns true when a message on `channel` has been handed to the IO layer
    /// and its send has not come back confirmed.
    pub fn send_unconfirmed(&self, channel: Channel) -> bool {
        self.unconfirmed_sends.contains(&channel)
    }

    /// Returns true if the handshake has completed and mini-protocols are active.
    pub fn is_initialized(&self) -> bool {
        matches!(self.connection, ConnectionState::Initialized)
    }

    /// Returns the accepted version data if the handshake completed successfully.
    pub fn version(&self) -> Option<proto::handshake::n2n::VersionData> {
        match &self.handshake {
            proto::handshake::State::Done(proto::handshake::DoneState::Accepted(_, data)) => {
                Some(data.clone())
            }
            _ => None,
        }
    }

    /// Returns the current promotion level of this peer.
    pub fn promotion(&self) -> PromotionTag {
        self.promotion
    }

    /// Returns true if the negotiated version supports peer sharing.
    pub fn supports_peer_sharing(&self) -> bool {
        let val = self
            .version()
            .as_ref()
            .and_then(|v| v.peer_sharing)
            .unwrap_or(0);

        val > 0
    }

    /// Returns the negotiated N2N protocol version, if the handshake completed.
    pub fn accepted_version(&self) -> Option<u64> {
        super::accepted_version(&self.handshake)
    }

    /// Returns true if the negotiated version carries the Leios overlay.
    pub fn supports_leios(&self) -> bool {
        super::supports_leios(&self.handshake)
    }

    /// Applies a message received from the peer. A message the mini-protocol
    /// refuses marks the peer, which sent something the protocol it agreed to
    /// does not allow at that point.
    pub fn apply_inbound_msg(&mut self, msg: &AnyMessage) {
        if let Err(err) = self.apply(msg) {
            tracing::warn!(channel = msg.channel(), %err, "peer protocol violation");
            self.violation = true;
        }
    }

    /// Applies a message this node sent. A message the mini-protocol refuses
    /// was composed on this side, so it leaves the peer unmarked.
    pub fn apply_outbound_msg(&mut self, msg: &AnyMessage) {
        if let Err(err) = self.apply(msg) {
            tracing::warn!(channel = msg.channel(), %err, "refused our own outbound message");
        }
    }

    fn apply(&mut self, msg: &AnyMessage) -> Result<(), proto::Error> {
        match msg {
            AnyMessage::Handshake(msg) => {
                let new = self.handshake.apply(msg)?;
                self.handshake = new;
            }
            AnyMessage::KeepAlive(msg) => {
                let new = self.keepalive.apply(msg)?;
                self.keepalive = new;
            }
            AnyMessage::PeerSharing(msg) => {
                let new = self.peersharing.apply(msg)?;
                self.peersharing = new;
            }
            AnyMessage::BlockFetch(msg) => {
                let new = self.blockfetch.apply(msg)?;
                self.blockfetch = new;
            }
            AnyMessage::ChainSync(msg) => {
                let new = self.chainsync.apply(msg)?;
                self.chainsync = new;
            }
            AnyMessage::TxSubmission(msg) => {
                let new = self.tx_submission.apply(msg)?;
                self.tx_submission = new;
            }
            AnyMessage::LeiosNotify(msg) => {
                let new = self.leios_notify.apply(msg)?;
                self.leios_notify = new;
            }
            AnyMessage::LeiosFetch(msg) => {
                let new = self.leios_fetch.apply(msg)?;
                self.leios_fetch = new;
            }
        }

        Ok(())
    }

    /// Resets the state back to its initial state, except for error count
    pub fn reset(&mut self) {
        self.connection = ConnectionState::default();
        self.promotion = PromotionTag::default();
        self.handshake = proto::handshake::State::default();
        self.keepalive = proto::keepalive::State::default();
        self.peersharing = proto::peersharing::State::default();
        self.blockfetch = proto::blockfetch::State::default();
        self.chainsync = proto::chainsync::State::default();
        self.tx_submission = proto::txsubmission::State::default();
        self.leios_notify = proto::leiosnotify::State::default();
        self.leios_fetch = proto::leiosfetch::State::default();
        self.continue_sync = false;
        self.violation = false;
        self.unconfirmed_sends.clear();
    }
}

/// Sends `msg` to `pid` and records its channel as waiting for the IO layer to
/// confirm the send.
pub(crate) fn send_to_peer(
    pid: &PeerId,
    state: &mut InitiatorState,
    msg: AnyMessage,
    outbound: &mut OutboundQueue<InitiatorBehavior>,
) {
    state.unconfirmed_sends.insert(msg.channel());

    outbound.push_ready(InterfaceCommand::Send(pid.clone(), msg));
}

/// A function that mutates an [`InitiatorState`], used for tagging operations
/// like banning or demoting peers.
pub type TagFn = fn(&mut InitiatorState);

/// Commands that can be sent to the initiator behavior from external code.
#[derive(Debug)]
pub enum InitiatorCommand {
    /// Add a new peer to be tracked and potentially connected.
    IncludePeer(PeerId),
    /// Trigger periodic housekeeping (peer promotion, discovery, etc.).
    Housekeeping,
    /// Begin chain synchronization from the given known points.
    StartSync(Vec<proto::Point>),
    /// Resume chain synchronization for a specific peer.
    ContinueSync(PeerId),
    /// Request a range of blocks to be fetched.
    RequestBlocks(BlockRange),
    /// Submit a transaction to a specific peer.
    SendTx(
        PeerId,
        proto::txsubmission::EraTxId,
        proto::txsubmission::EraTxBody,
    ),
    /// Request a complete EB body from a peer (leios-fetch).
    FetchEb(PeerId, proto::EbId),
    /// Request a subset of an EB's transactions from a peer (leios-fetch).
    FetchEbTxs(PeerId, proto::EbId, proto::leiosfetch::Bitmaps),
    /// Ban a peer, preventing future connections.
    BanPeer(PeerId),
    /// Demote a peer back to cold status.
    DemotePeer(PeerId),
}

/// Why a peer's session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    /// The connection closed with no error reported by the interface.
    Closed,
    /// The interface reported an error on the connection.
    Errored,
}

/// Events emitted by the initiator behavior to external consumers.
#[derive(Debug)]
pub enum InitiatorEvent {
    /// A peer completed the handshake and is ready for mini-protocols.
    PeerInitialized(PeerId, AcceptedVersion),
    /// An intersection point was found during chain-sync.
    IntersectionFound(PeerId, proto::Point, proto::chainsync::Tip),
    /// A new block header was received via chain-sync.
    BlockHeaderReceived(
        PeerId,
        proto::chainsync::HeaderContent,
        proto::chainsync::Tip,
    ),
    /// A rollback was received via chain-sync.
    RollbackReceived(PeerId, proto::Point, proto::chainsync::Tip),
    /// A block body was received via block-fetch.
    BlockBodyReceived(PeerId, proto::blockfetch::Body),
    /// The remote peer requested a transaction via tx-submission.
    TxRequested(PeerId, proto::txsubmission::EraTxId),
    /// An EB announcement or offer was received via leios-notify.
    EbNotification(PeerId, proto::leiosnotify::Notification),
    /// An EB body or transactions were received via leios-fetch, for the given EB.
    EbFetched(PeerId, proto::EbId, proto::leiosfetch::Response),
    /// The session with the peer ended, cleanly or on an error.
    PeerDisconnected(PeerId, DisconnectReason),
}

/// The main initiator behavior that orchestrates outbound Cardano connections.
///
/// Manages peer lifecycle (discovery, connection, promotion) and coordinates
/// all mini-protocol sub-behaviors (handshake, keepalive, chain-sync,
/// block-fetch, peer-sharing, discovery).
#[derive(Default)]
pub struct InitiatorBehavior {
    pub promotion: promotion::PromotionBehavior,
    pub connection: connection::ConnectionBehavior,
    pub handshake: handshake::HandshakeBehavior,
    pub keepalive: keepalive::KeepaliveBehavior,
    pub discovery: discovery::DiscoveryBehavior,
    pub blockfetch: blockfetch::BlockFetchBehavior,
    pub chainsync: chainsync::ChainSyncBehavior,
    pub leiosnotify: leiosnotify::LeiosNotifyBehavior,
    pub leiosfetch: leiosfetch::LeiosFetchBehavior,
    pub peers: HashMap<PeerId, InitiatorState>,
    pub outbound: OutboundQueue<Self>,
}

macro_rules! all_visitors {
    ($self:ident, $pid:ident, $state:expr, $method:ident) => {
        $self.promotion.$method($pid, $state, &mut $self.outbound);
        $self.connection.$method($pid, $state, &mut $self.outbound);
        $self.handshake.$method($pid, $state, &mut $self.outbound);
        $self.keepalive.$method($pid, $state, &mut $self.outbound);
        $self.discovery.$method($pid, $state, &mut $self.outbound);
        $self.blockfetch.$method($pid, $state, &mut $self.outbound);
        $self.chainsync.$method($pid, $state, &mut $self.outbound);
        $self.leiosnotify.$method($pid, $state, &mut $self.outbound);
        $self.leiosfetch.$method($pid, $state, &mut $self.outbound);
    };
}

impl InitiatorBehavior {
    #[tracing::instrument(skip_all, fields(pid = %pid, channel = %msg.channel()))]
    /// Processes an inbound message from a peer, updating state and notifying visitors.
    pub fn on_inbound_msg(&mut self, pid: &PeerId, msg: &AnyMessage) {
        tracing::debug!(channel = msg.channel(), "new inbound message");

        self.peers.entry(pid.clone()).and_modify(|state| {
            state.apply_inbound_msg(msg);

            all_visitors!(self, pid, state, visit_inbound_msg);
        });
    }

    #[tracing::instrument(skip_all, fields(pid = %pid, channel = %msg.channel()))]
    /// Processes a confirmed outbound message to a peer, updating state and notifying visitors.
    pub fn on_outbound_msg(&mut self, pid: &PeerId, msg: &AnyMessage) {
        tracing::debug!(channel = msg.channel(), "new outbound message");

        self.peers.entry(pid.clone()).and_modify(|state| {
            state.unconfirmed_sends.remove(&msg.channel());
            state.apply_outbound_msg(msg);

            all_visitors!(self, pid, state, visit_outbound_msg);
        });
    }

    #[tracing::instrument(skip_all, fields(pid = %pid))]
    fn on_connected(&mut self, pid: &PeerId) {
        tracing::info!("connected");

        self.peers.entry(pid.clone()).and_modify(|state| {
            state.connection = ConnectionState::Connected;

            all_visitors!(self, pid, state, visit_connected);
        });
    }

    #[tracing::instrument(skip_all, fields(pid = %pid))]
    fn on_disconnected(&mut self, pid: &PeerId) {
        tracing::info!("disconnected");

        self.peers.entry(pid.clone()).and_modify(|state| {
            state.connection = ConnectionState::Disconnected;
            state.reset();

            all_visitors!(self, pid, state, visit_disconnected);

            self.outbound.push_ready(BehaviorOutput::ExternalEvent(
                InitiatorEvent::PeerDisconnected(pid.clone(), DisconnectReason::Closed),
            ));
        });
    }

    #[tracing::instrument(skip_all, fields(pid = %pid))]
    fn on_errored(&mut self, pid: &PeerId) {
        tracing::error!("error");

        self.peers.entry(pid.clone()).and_modify(|state| {
            state.connection = ConnectionState::Errored;
            state.error_count += 1;

            // A send handed to a failed connection will never be confirmed.
            state.unconfirmed_sends.clear();

            all_visitors!(self, pid, state, visit_errored);

            self.outbound.push_ready(BehaviorOutput::ExternalEvent(
                InitiatorEvent::PeerDisconnected(pid.clone(), DisconnectReason::Errored),
            ));
        });
    }

    #[tracing::instrument(skip_all, fields(pid = %pid))]
    fn on_tagged(&mut self, pid: &PeerId, tagger: TagFn) {
        tracing::debug!("tagged");

        self.peers.entry(pid.clone()).and_modify(|state| {
            tagger(state);

            all_visitors!(self, pid, state, visit_tagged);
        });
    }

    #[tracing::instrument(skip_all, fields(pid = %pid))]
    fn on_discovered(&mut self, pid: &PeerId) {
        let mut state = InitiatorState::new();

        all_visitors!(self, pid, &mut state, visit_discovered);

        self.peers.insert(pid.clone(), state);
    }

    fn move_discovered_into_promotion(&mut self) {
        let deficit = self.promotion.peer_deficit();

        if deficit == 0 {
            return;
        }

        let new = self.discovery.drain_new_peers(deficit);

        if new.is_empty() {
            tracing::trace!("no new peers discovered");
            return;
        }

        tracing::info!(deficit = deficit, new = new.len(), "discovered new peers",);

        for pid in new {
            if !self.peers.contains_key(&pid) {
                self.on_discovered(&pid);
            }
        }
    }

    #[tracing::instrument(skip_all)]
    fn housekeeping(&mut self) {
        for (pid, state) in self.peers.iter_mut() {
            all_visitors!(self, pid, state, visit_housekeeping);
        }

        self.move_discovered_into_promotion();
    }

    /// Puts a queued leios-fetch request on the wire for `pid` straight away,
    /// rather than waiting for the next housekeeping tick.
    fn serve_leios_fetch(&mut self, pid: &PeerId) {
        let Self {
            leiosfetch,
            peers,
            outbound,
            ..
        } = self;

        if let Some(state) = peers.get_mut(pid) {
            leiosfetch.serve_next(pid, state, outbound);
        }
    }
}

impl Stream for InitiatorBehavior {
    type Item = BehaviorOutput<Self>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let poll = self.outbound.futures.poll_next_unpin(cx);

        match poll {
            Poll::Ready(Some(x)) => Poll::Ready(Some(x)),
            Poll::Ready(None) => Poll::Pending,
            Poll::Pending => Poll::Pending,
        }
    }
}

impl FusedStream for InitiatorBehavior {
    fn is_terminated(&self) -> bool {
        false
    }
}

impl Behavior for InitiatorBehavior {
    type Event = InitiatorEvent;
    type Command = InitiatorCommand;
    type PeerState = InitiatorState;
    type Message = AnyMessage;

    fn handle_io(&mut self, event: crate::InterfaceEvent<Self::Message>) {
        match &event {
            crate::InterfaceEvent::Connected(pid) => {
                self.on_connected(pid);
            }
            crate::InterfaceEvent::Disconnected(pid) => {
                self.on_disconnected(pid);
            }
            crate::InterfaceEvent::Recv(pid, msgs) => {
                for msg in msgs {
                    self.on_inbound_msg(pid, msg);
                }
            }
            crate::InterfaceEvent::Sent(pid, msg) => {
                self.on_outbound_msg(pid, msg);
            }
            crate::InterfaceEvent::Error(pid, _) => {
                self.on_errored(pid);
            }
            crate::InterfaceEvent::Idle => {
                self.housekeeping();
            }
        }
    }

    fn execute(&mut self, cmd: Self::Command) {
        match cmd {
            InitiatorCommand::IncludePeer(pid) => {
                tracing::debug!("include peer command");
                self.on_discovered(&pid);
            }
            InitiatorCommand::StartSync(points) => {
                tracing::debug!("start sync command");
                self.chainsync.start(points);
            }
            InitiatorCommand::ContinueSync(pid) => {
                tracing::debug!("continue sync command");
                self.on_tagged(&pid, |state| state.continue_sync = true);
            }
            InitiatorCommand::RequestBlocks(range) => {
                tracing::debug!("request blocks command");
                self.blockfetch.enqueue(range);
            }
            InitiatorCommand::Housekeeping => {
                tracing::debug!("housekeeping command");
                self.housekeeping();
            }
            InitiatorCommand::BanPeer(pid) => {
                tracing::debug!("ban peer command");
                self.on_tagged(&pid, |state| state.promotion = PromotionTag::Banned);
            }
            InitiatorCommand::DemotePeer(pid) => {
                tracing::debug!("demote peer command");
                self.on_tagged(&pid, |state| state.promotion = PromotionTag::Cold);
            }
            InitiatorCommand::SendTx(..) => {
                tracing::warn!("SendTx not yet implemented");
            }
            InitiatorCommand::FetchEb(pid, point) => {
                tracing::debug!("fetch eb command");
                self.leiosfetch
                    .enqueue(pid.clone(), leiosfetch::FetchRequest::Block(point));
                self.serve_leios_fetch(&pid);
            }
            InitiatorCommand::FetchEbTxs(pid, point, bitmaps) => {
                tracing::debug!("fetch eb txs command");
                self.leiosfetch.enqueue(
                    pid.clone(),
                    leiosfetch::FetchRequest::BlockTxs(point, bitmaps),
                );
                self.serve_leios_fetch(&pid);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        AnyCbor, MAINNET_MAGIC, Point, blockfetch as bf, chainsync as cs, handshake, keepalive,
        leiosfetch as lf, leiosnotify as ln, peersharing,
    };
    use crate::testing::BehaviorOutputExt;
    use crate::{InterfaceCommand, InterfaceError, InterfaceEvent};
    use futures::StreamExt;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    fn drain_outputs(behavior: &mut InitiatorBehavior) -> Vec<BehaviorOutput<InitiatorBehavior>> {
        let mut outputs = Vec::new();
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);

        while let std::task::Poll::Ready(Some(output)) = behavior.poll_next_unpin(&mut cx) {
            outputs.push(output);
        }

        outputs
    }

    /// Collects the leios-fetch messages the behavior asked the IO layer to send.
    fn fetch_sends(outputs: &[BehaviorOutput<InitiatorBehavior>]) -> Vec<lf::Message> {
        outputs
            .iter()
            .filter_map(|o| match o {
                BehaviorOutput::InterfaceCommand(InterfaceCommand::Send(
                    _,
                    AnyMessage::LeiosFetch(msg),
                )) => Some(msg.clone()),
                _ => None,
            })
            .collect()
    }

    fn complete_handshake(behavior: &mut InitiatorBehavior, pid: &PeerId) {
        let version_data =
            handshake::n2n::VersionData::new(MAINNET_MAGIC, false, Some(1), Some(false));
        let mut values = HashMap::new();
        values.insert(13u64, version_data.clone());
        let version_table = handshake::VersionTable { values };

        let propose = AnyMessage::Handshake(handshake::Message::Propose(version_table));
        behavior.handle_io(InterfaceEvent::Sent(pid.clone(), propose));
        drain_outputs(behavior);

        let accept = AnyMessage::Handshake(handshake::Message::Accept(13, version_data));
        behavior.handle_io(InterfaceEvent::Recv(pid.clone(), vec![accept]));
        drain_outputs(behavior);
    }

    /// Completes a handshake negotiating a Leios-capable version (15).
    fn complete_handshake_leios(behavior: &mut InitiatorBehavior, pid: &PeerId) {
        let version_data =
            handshake::n2n::VersionData::new(MAINNET_MAGIC, false, Some(1), Some(false));
        let mut values = HashMap::new();
        values.insert(15u64, version_data.clone());
        let version_table = handshake::VersionTable { values };

        let propose = AnyMessage::Handshake(handshake::Message::Propose(version_table));
        behavior.handle_io(InterfaceEvent::Sent(pid.clone(), propose));
        drain_outputs(behavior);

        let accept = AnyMessage::Handshake(handshake::Message::Accept(15, version_data));
        behavior.handle_io(InterfaceEvent::Recv(pid.clone(), vec![accept]));
        drain_outputs(behavior);
    }

    // ---- Kept: genuinely cross-cutting tests ----

    #[tokio::test]
    async fn banned_peer_not_reconnected() {
        // Composition: violation flag → promotion ban → connection guard
        tokio::time::pause();

        let mut behavior = InitiatorBehavior::default();
        let pid = PeerId::test(1);

        behavior.execute(InitiatorCommand::IncludePeer(pid.clone()));
        behavior.execute(InitiatorCommand::Housekeeping);
        drain_outputs(&mut behavior);

        behavior.handle_io(InterfaceEvent::Connected(pid.clone()));
        drain_outputs(&mut behavior);

        let bad_msg = AnyMessage::KeepAlive(keepalive::Message::ResponseKeepAlive(42));
        behavior.handle_io(InterfaceEvent::Recv(pid.clone(), vec![bad_msg]));
        behavior.execute(InitiatorCommand::Housekeeping);
        drain_outputs(&mut behavior);

        behavior.handle_io(InterfaceEvent::Disconnected(pid.clone()));
        drain_outputs(&mut behavior);

        for _ in 0..10 {
            behavior.execute(InitiatorCommand::Housekeeping);
            let outputs = drain_outputs(&mut behavior);
            assert!(!outputs.has_connect_for(&pid));
        }
    }

    #[tokio::test]
    async fn demote_peer_returns_to_cold() {
        // Composition: handshake → promotion hot → demote tag → connection disconnect
        tokio::time::pause();

        let mut behavior = InitiatorBehavior::default();
        let pid = PeerId::test(2);

        behavior.execute(InitiatorCommand::IncludePeer(pid.clone()));
        behavior.execute(InitiatorCommand::Housekeeping);
        drain_outputs(&mut behavior);

        behavior.handle_io(InterfaceEvent::Connected(pid.clone()));
        drain_outputs(&mut behavior);
        complete_handshake(&mut behavior, &pid);

        behavior.execute(InitiatorCommand::Housekeeping);
        drain_outputs(&mut behavior);
        assert!(behavior.promotion.hot_peers.contains(&pid));

        behavior.execute(InitiatorCommand::DemotePeer(pid.clone()));
        drain_outputs(&mut behavior);

        let state = behavior.peers.get(&pid).unwrap();
        assert_eq!(state.promotion, PromotionTag::Cold);

        behavior.execute(InitiatorCommand::Housekeeping);
        let outputs = drain_outputs(&mut behavior);
        assert!(outputs.has_disconnect_for(&pid));
    }

    #[tokio::test]
    async fn error_count_persists_across_disconnect() {
        // Composition: on_errored increments → on_disconnected resets but preserves
        //              error_count → promotion bans on threshold
        tokio::time::pause();

        let mut behavior = InitiatorBehavior {
            promotion: PromotionBehavior::new(PromotionConfig {
                max_error_count: 2,
                ..PromotionConfig::default()
            }),
            ..Default::default()
        };
        let pid = PeerId::test(3);

        behavior.execute(InitiatorCommand::IncludePeer(pid.clone()));
        behavior.execute(InitiatorCommand::Housekeeping);
        drain_outputs(&mut behavior);

        for _ in 0..2 {
            behavior.handle_io(InterfaceEvent::Error(
                pid.clone(),
                InterfaceError::Other("err".into()),
            ));
            behavior.execute(InitiatorCommand::Housekeeping);
            drain_outputs(&mut behavior);
            behavior.handle_io(InterfaceEvent::Disconnected(pid.clone()));
            drain_outputs(&mut behavior);
        }

        assert!(!behavior.promotion.banned_peers.contains(&pid));

        behavior.handle_io(InterfaceEvent::Error(
            pid.clone(),
            InterfaceError::Other("err".into()),
        ));
        behavior.execute(InitiatorCommand::Housekeeping);
        drain_outputs(&mut behavior);

        assert!(behavior.promotion.banned_peers.contains(&pid));
    }

    // ---- New: composition tests ----

    #[tokio::test]
    async fn full_peer_lifecycle_include_to_chainsync() {
        // Composition: promotion → connection → handshake → promotion (warm→hot) → chainsync
        tokio::time::pause();

        let mut behavior = InitiatorBehavior::default();
        let pid = PeerId::test(10);

        // Start chainsync so the behavior will initiate it for hot peers
        behavior.execute(InitiatorCommand::StartSync(vec![Point::Origin]));

        // Include peer → housekeeping promotes cold→warm and connects
        behavior.execute(InitiatorCommand::IncludePeer(pid.clone()));
        behavior.execute(InitiatorCommand::Housekeeping);
        let outputs = drain_outputs(&mut behavior);

        assert!(behavior.promotion.warm_peers.contains(&pid));
        assert!(outputs.has_connect_for(&pid));

        // Connected → handshake proposes
        behavior.handle_io(InterfaceEvent::Connected(pid.clone()));
        let outputs = drain_outputs(&mut behavior);
        assert!(
            outputs
                .has_send(|m| matches!(m, AnyMessage::Handshake(handshake::Message::Propose(_))))
        );

        // Complete handshake → Initialized
        complete_handshake(&mut behavior, &pid);

        // Housekeeping promotes warm→hot, chainsync starts FindIntersect
        behavior.execute(InitiatorCommand::Housekeeping);
        let outputs = drain_outputs(&mut behavior);

        assert!(behavior.promotion.hot_peers.contains(&pid));
        assert!(
            outputs.has_send(|m| matches!(m, AnyMessage::ChainSync(cs::Message::FindIntersect(_)))),
            "chainsync should start for hot initialized peer"
        );
    }

    #[tokio::test]
    async fn housekeeping_promotes_and_connects_in_same_pass() {
        // Composition: visitor ordering — promotion runs before connection in all_visitors!
        tokio::time::pause();

        let mut behavior = InitiatorBehavior::default();
        let pid = PeerId::test(11);

        behavior.execute(InitiatorCommand::IncludePeer(pid.clone()));

        // Single housekeeping call should both promote cold→warm AND issue Connect
        behavior.execute(InitiatorCommand::Housekeeping);
        let outputs = drain_outputs(&mut behavior);

        assert!(
            behavior.promotion.warm_peers.contains(&pid),
            "peer should be promoted to warm"
        );
        assert!(
            outputs.has_connect_for(&pid),
            "Connect should be issued in the same housekeeping pass"
        );
    }

    #[tokio::test]
    async fn discovery_feeds_into_promotion() {
        // Composition: discovery accumulates peers → housekeeping drains → promotion adds to cold
        tokio::time::pause();

        let mut behavior = InitiatorBehavior::default();
        let seed_pid = PeerId::test(12);

        // Include and fully initialize a seed peer with peer-sharing support
        behavior.execute(InitiatorCommand::IncludePeer(seed_pid.clone()));
        behavior.execute(InitiatorCommand::Housekeeping);
        drain_outputs(&mut behavior);

        behavior.handle_io(InterfaceEvent::Connected(seed_pid.clone()));
        drain_outputs(&mut behavior);
        complete_handshake(&mut behavior, &seed_pid);
        behavior.execute(InitiatorCommand::Housekeeping);
        drain_outputs(&mut behavior);

        // Simulate peersharing response with 2 new peers
        let share_response = AnyMessage::PeerSharing(peersharing::Message::SharePeers(vec![
            peersharing::PeerAddress::V4(Ipv4Addr::new(192, 168, 1, 1), 3000),
            peersharing::PeerAddress::V4(Ipv4Addr::new(192, 168, 1, 2), 3001),
        ]));

        // We need the seed peer's peersharing state to be in the right state first.
        // Simulate the outbound ShareRequest being sent (to move state to Busy)
        let share_req = AnyMessage::PeerSharing(peersharing::Message::ShareRequest(10));
        behavior.handle_io(InterfaceEvent::Sent(seed_pid.clone(), share_req));
        drain_outputs(&mut behavior);

        // Now receive the response
        behavior.handle_io(InterfaceEvent::Recv(seed_pid.clone(), vec![share_response]));
        drain_outputs(&mut behavior);

        // Housekeeping should move discovered peers into promotion
        behavior.execute(InitiatorCommand::Housekeeping);
        drain_outputs(&mut behavior);

        // The discovered peers should now be tracked
        let discovered_1 = PeerId {
            host: "192.168.1.1".to_string(),
            port: 3000,
        };
        let discovered_2 = PeerId {
            host: "192.168.1.2".to_string(),
            port: 3001,
        };

        assert!(
            behavior.peers.contains_key(&discovered_1),
            "discovered peer 1 should be tracked after housekeeping"
        );
        assert!(
            behavior.peers.contains_key(&discovered_2),
            "discovered peer 2 should be tracked after housekeeping"
        );
    }

    #[tokio::test]
    async fn violation_bans_and_disconnects() {
        // Composition: apply_msg sets violation → promotion bans → connection disconnects
        tokio::time::pause();

        let mut behavior = InitiatorBehavior::default();
        let pid = PeerId::test(13);

        behavior.execute(InitiatorCommand::IncludePeer(pid.clone()));
        behavior.execute(InitiatorCommand::Housekeeping);
        drain_outputs(&mut behavior);

        behavior.handle_io(InterfaceEvent::Connected(pid.clone()));
        drain_outputs(&mut behavior);

        // Protocol violation
        let bad_msg = AnyMessage::KeepAlive(keepalive::Message::ResponseKeepAlive(42));
        behavior.handle_io(InterfaceEvent::Recv(pid.clone(), vec![bad_msg]));

        // Housekeeping should both ban (promotion) AND disconnect (connection)
        behavior.execute(InitiatorCommand::Housekeeping);
        let outputs = drain_outputs(&mut behavior);

        assert!(
            behavior.promotion.banned_peers.contains(&pid),
            "promotion should ban the violating peer"
        );
        assert!(
            outputs.has_disconnect_for(&pid),
            "connection should disconnect the banned peer"
        );
    }

    #[tokio::test]
    async fn blockfetch_requires_initialized_and_idle() {
        // Composition: handshake state gates blockfetch dispatch
        tokio::time::pause();

        let mut behavior = InitiatorBehavior::default();
        let pid = PeerId::test(14);

        let range = (Point::Origin, Point::new(100, vec![0xAA; 32]));
        behavior.blockfetch.enqueue(range.clone());

        // Include peer, promote to warm, connect (but NOT handshaked)
        behavior.execute(InitiatorCommand::IncludePeer(pid.clone()));
        behavior.execute(InitiatorCommand::Housekeeping);
        drain_outputs(&mut behavior);

        behavior.handle_io(InterfaceEvent::Connected(pid.clone()));
        drain_outputs(&mut behavior);

        // Housekeeping — peer is Connected but not Initialized, so no RequestRange
        behavior.execute(InitiatorCommand::Housekeeping);
        let outputs = drain_outputs(&mut behavior);
        assert!(
            !outputs
                .has_send(|m| matches!(m, AnyMessage::BlockFetch(bf::Message::RequestRange(_)))),
            "should NOT send RequestRange before handshake"
        );

        // Complete handshake → Initialized
        complete_handshake(&mut behavior, &pid);

        // Re-enqueue since housekeeping may have consumed nothing
        // (the request is still in the queue since peer wasn't available)
        // Housekeeping now — peer is Initialized + blockfetch Idle
        behavior.execute(InitiatorCommand::Housekeeping);
        let outputs = drain_outputs(&mut behavior);
        assert!(
            outputs.has_send(|m| matches!(m, AnyMessage::BlockFetch(bf::Message::RequestRange(_)))),
            "should send RequestRange after handshake completes"
        );
    }

    #[tokio::test]
    async fn leios_notify_and_fetch_flow() {
        // Composition: handshake negotiates v15 → supports_leios → notify pull
        // loop surfaces an offer → fetch command pulls the EB body.
        tokio::time::pause();

        let mut behavior = InitiatorBehavior::default();
        let pid = PeerId::test(20);
        let eb = Point::new(7, vec![0xAB; 32]);

        behavior.execute(InitiatorCommand::IncludePeer(pid.clone()));
        behavior.execute(InitiatorCommand::Housekeeping);
        drain_outputs(&mut behavior);

        behavior.handle_io(InterfaceEvent::Connected(pid.clone()));
        drain_outputs(&mut behavior);
        complete_handshake_leios(&mut behavior, &pid);
        assert!(behavior.peers.get(&pid).unwrap().supports_leios());

        // Housekeeping drives the notify pull loop once Leios is negotiated.
        behavior.execute(InitiatorCommand::Housekeeping);
        let outputs = drain_outputs(&mut behavior);
        assert!(
            outputs.has_send(|m| matches!(m, AnyMessage::LeiosNotify(ln::Message::RequestNext))),
            "should request next leios notification"
        );

        // Server moves to Busy (our request was sent), then offers an EB.
        behavior.handle_io(InterfaceEvent::Sent(
            pid.clone(),
            AnyMessage::LeiosNotify(ln::Message::RequestNext),
        ));
        drain_outputs(&mut behavior);

        let offer = AnyMessage::LeiosNotify(ln::Message::BlockOffer(eb.clone(), 99));
        behavior.handle_io(InterfaceEvent::Recv(pid.clone(), vec![offer]));
        let outputs = drain_outputs(&mut behavior);
        assert!(
            outputs.has_event(|e| matches!(e, InitiatorEvent::EbNotification(..))),
            "should surface the EB offer as an event"
        );

        // Application requests the EB body; housekeeping sends the fetch request.
        behavior.execute(InitiatorCommand::FetchEb(pid.clone(), eb.clone()));
        behavior.execute(InitiatorCommand::Housekeeping);
        let outputs = drain_outputs(&mut behavior);
        assert!(
            outputs.has_send(|m| matches!(m, AnyMessage::LeiosFetch(lf::Message::BlockRequest(_)))),
            "should send a leios-fetch block request"
        );

        // Server delivers the EB body, surfaced as EbFetched.
        behavior.handle_io(InterfaceEvent::Sent(
            pid.clone(),
            AnyMessage::LeiosFetch(lf::Message::BlockRequest(eb.clone())),
        ));
        drain_outputs(&mut behavior);

        let block =
            AnyMessage::LeiosFetch(lf::Message::Block(AnyCbor::from_raw_bytes(vec![1, 2, 3])));
        behavior.handle_io(InterfaceEvent::Recv(pid.clone(), vec![block]));
        let outputs = drain_outputs(&mut behavior);
        assert!(
            outputs.has_event(|e| matches!(e, InitiatorEvent::EbFetched(..))),
            "should surface the fetched EB body as an event"
        );
    }

    #[tokio::test]
    async fn fetch_command_sends_request_without_housekeeping() {
        // Composition: a fetch command enqueues and serves in one step, so the
        // request is sent without running the rest of housekeeping.
        tokio::time::pause();

        let mut behavior = InitiatorBehavior::default();
        let pid = PeerId::test(21);
        let eb = Point::new(7, vec![0xCD; 32]);

        behavior.execute(InitiatorCommand::IncludePeer(pid.clone()));
        behavior.execute(InitiatorCommand::Housekeeping);
        drain_outputs(&mut behavior);

        behavior.handle_io(InterfaceEvent::Connected(pid.clone()));
        drain_outputs(&mut behavior);
        complete_handshake_leios(&mut behavior, &pid);
        drain_outputs(&mut behavior);

        // Housekeeping drives the notify pull loop, so RequestNext marks a turn.
        behavior.execute(InitiatorCommand::Housekeeping);
        let ticked = drain_outputs(&mut behavior);
        assert!(
            ticked.has_send(|m| matches!(m, AnyMessage::LeiosNotify(ln::Message::RequestNext))),
            "should send RequestNext on a housekeeping tick"
        );

        // Issuing a fetch, with no tick of any kind.
        behavior.execute(InitiatorCommand::FetchEb(pid.clone(), eb.clone()));
        let issued = drain_outputs(&mut behavior);

        assert!(
            issued.has_send(|m| matches!(m, AnyMessage::LeiosFetch(lf::Message::BlockRequest(_)))),
            "should send the leios-fetch request when it is issued"
        );
        assert!(
            !issued.has_send(|m| matches!(m, AnyMessage::LeiosNotify(ln::Message::RequestNext))),
            "should NOT drive the notify pull loop"
        );
    }

    #[tokio::test]
    async fn back_to_back_fetch_commands_send_one_at_a_time() {
        // Composition: an issued fetch holds the peer's leios-fetch slot until
        // the IO layer confirms the send, so a second command queues instead of
        // overlapping, and the peer is never seen as violating the protocol.
        tokio::time::pause();

        let mut behavior = InitiatorBehavior::default();
        let pid = PeerId::test(22);
        let first = Point::new(7, vec![0xE1; 32]);
        let second = Point::new(8, vec![0xE2; 32]);

        behavior.execute(InitiatorCommand::IncludePeer(pid.clone()));
        behavior.execute(InitiatorCommand::Housekeeping);
        drain_outputs(&mut behavior);

        behavior.handle_io(InterfaceEvent::Connected(pid.clone()));
        drain_outputs(&mut behavior);
        complete_handshake_leios(&mut behavior, &pid);
        drain_outputs(&mut behavior);

        // Two fetch commands for the same peer, with nothing in between, which
        // is what a bursting consumer does.
        behavior.execute(InitiatorCommand::FetchEb(pid.clone(), first.clone()));
        behavior.execute(InitiatorCommand::FetchEb(pid.clone(), second.clone()));
        let issued = fetch_sends(&drain_outputs(&mut behavior));

        assert_eq!(
            issued.len(),
            1,
            "only the first fetch belongs on the wire, got {issued:?}"
        );
        assert!(
            matches!(&issued[0], lf::Message::BlockRequest(p) if p == &first),
            "the request on the wire should be the first one, got {:?}",
            issued[0]
        );

        // The IO layer confirms every request the behavior handed it, and that
        // confirmation is what moves the protocol out of idle. Confirming a
        // second request while the first is outstanding reads as a violation,
        // so this loop is driven by what actually went out, not by a count the
        // test picked.
        for msg in issued.iter() {
            behavior.handle_io(InterfaceEvent::Sent(
                pid.clone(),
                AnyMessage::LeiosFetch(msg.clone()),
            ));
        }
        let confirmed = fetch_sends(&drain_outputs(&mut behavior));
        assert!(
            confirmed.is_empty(),
            "confirming the first send should not put a second request on the wire, got {confirmed:?}"
        );
        assert!(
            !behavior.peers.get(&pid).unwrap().violation,
            "a second fetch command must not make the peer look like a violator"
        );

        // The response frees the slot, so the queued second request goes out.
        let block =
            AnyMessage::LeiosFetch(lf::Message::Block(AnyCbor::from_raw_bytes(vec![1, 2, 3])));
        behavior.handle_io(InterfaceEvent::Recv(pid.clone(), vec![block]));
        let outputs = drain_outputs(&mut behavior);
        assert!(
            outputs.has_event(|e| matches!(e, InitiatorEvent::EbFetched(..))),
            "should surface the first fetched EB body as an event"
        );

        let served = fetch_sends(&outputs);
        assert_eq!(
            served.len(),
            1,
            "the queued second fetch should go out once the peer is free, got {served:?}"
        );
        assert!(
            matches!(&served[0], lf::Message::BlockRequest(p) if p == &second),
            "the second request should carry the second EB, got {:?}",
            served[0]
        );

        assert!(
            !behavior.peers.get(&pid).unwrap().violation,
            "the peer should still be in good standing"
        );

        // Housekeeping is where a violation would turn into a ban and a
        // disconnect, which is the harm a burst of fetch commands must not do.
        behavior.execute(InitiatorCommand::Housekeeping);
        let swept = drain_outputs(&mut behavior);
        assert!(
            !behavior.promotion.banned_peers.contains(&pid),
            "a burst of fetch commands should not ban the peer"
        );
        assert!(
            !swept.has_disconnect_for(&pid),
            "a burst of fetch commands should not disconnect the peer"
        );
    }

    /// A peer that has been included, connected and handshaked on a
    /// Leios-capable version, with everything those steps produced drained.
    fn ready_leios_peer() -> (InitiatorBehavior, PeerId) {
        let mut behavior = InitiatorBehavior::default();
        let pid = PeerId::test(30);

        behavior.execute(InitiatorCommand::IncludePeer(pid.clone()));
        behavior.execute(InitiatorCommand::Housekeeping);
        drain_outputs(&mut behavior);

        behavior.handle_io(InterfaceEvent::Connected(pid.clone()));
        drain_outputs(&mut behavior);
        complete_handshake_leios(&mut behavior, &pid);
        drain_outputs(&mut behavior);

        (behavior, pid)
    }

    /// Collects every message the behavior asked the IO layer to send.
    fn all_sends(outputs: &[BehaviorOutput<InitiatorBehavior>]) -> Vec<AnyMessage> {
        outputs
            .iter()
            .filter_map(|o| match o {
                BehaviorOutput::InterfaceCommand(InterfaceCommand::Send(_, m)) => Some(m.clone()),
                _ => None,
            })
            .collect()
    }

    /// Collects every event the behavior surfaced to the external consumer.
    fn external_events(outputs: &[BehaviorOutput<InitiatorBehavior>]) -> Vec<&InitiatorEvent> {
        outputs
            .iter()
            .filter_map(|o| match o {
                BehaviorOutput::ExternalEvent(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    /// Collects the peer sessions the behavior reported as ended, in order.
    fn disconnections(
        outputs: &[BehaviorOutput<InitiatorBehavior>],
    ) -> Vec<(PeerId, DisconnectReason)> {
        outputs
            .iter()
            .filter_map(|o| match o {
                BehaviorOutput::ExternalEvent(InitiatorEvent::PeerDisconnected(pid, why)) => {
                    Some((pid.clone(), *why))
                }
                _ => None,
            })
            .collect()
    }

    type RequestKind = (&'static str, fn(&AnyMessage) -> bool);

    /// The three requests a housekeeping pass issues to a handshaked Leios
    /// peer, each with the name a failure should print.
    fn housekeeping_requests() -> [RequestKind; 3] {
        [
            ("keepalive", |m| matches!(m, AnyMessage::KeepAlive(_))),
            ("peer sharing", |m| matches!(m, AnyMessage::PeerSharing(_))),
            ("leios notify", |m| matches!(m, AnyMessage::LeiosNotify(_))),
        ]
    }

    #[tokio::test]
    async fn a_keepalive_response_nothing_asked_for_is_a_violation() {
        // A reply with no request of ours outstanding is the peer's own fault
        // and has to stay one, whatever the initiator forgives itself.
        tokio::time::pause();
        let (mut behavior, pid) = ready_leios_peer();

        let unprovoked = AnyMessage::KeepAlive(keepalive::Message::ResponseKeepAlive(42));
        behavior.handle_io(InterfaceEvent::Recv(pid.clone(), vec![unprovoked]));
        drain_outputs(&mut behavior);

        assert!(
            behavior.peers.get(&pid).unwrap().violation,
            "an unrequested keepalive response should mark the peer"
        );

        behavior.execute(InitiatorCommand::Housekeeping);
        let swept = drain_outputs(&mut behavior);
        assert!(
            behavior.promotion.banned_peers.contains(&pid),
            "an unrequested keepalive response should ban the peer"
        );
        assert!(
            swept.has_disconnect_for(&pid),
            "an unrequested keepalive response should disconnect the peer"
        );
    }

    #[tokio::test]
    async fn a_notification_nothing_asked_for_is_a_violation() {
        tokio::time::pause();
        let (mut behavior, pid) = ready_leios_peer();

        let unprovoked =
            AnyMessage::LeiosNotify(ln::Message::BlockOffer(Point::new(7, vec![0xF1; 32]), 99));
        behavior.handle_io(InterfaceEvent::Recv(pid.clone(), vec![unprovoked]));
        drain_outputs(&mut behavior);

        assert!(
            behavior.peers.get(&pid).unwrap().violation,
            "an offer with no request outstanding should mark the peer"
        );
        assert!(
            behavior.promotion.banned_peers.contains(&pid),
            "an offer with no request outstanding should ban the peer"
        );
    }

    #[tokio::test]
    async fn an_answered_request_is_asked_again_on_the_next_pass() {
        // The guard on a duplicate send must not become a guard on sending.
        tokio::time::pause();
        let (mut behavior, pid) = ready_leios_peer();

        behavior.execute(InitiatorCommand::Housekeeping);
        let first = all_sends(&drain_outputs(&mut behavior));
        assert_eq!(
            first.len(),
            3,
            "the first pass should ask for three, got {first:?}"
        );

        for msg in first.iter() {
            behavior.handle_io(InterfaceEvent::Sent(pid.clone(), msg.clone()));
        }
        drain_outputs(&mut behavior);

        let answers = vec![
            AnyMessage::KeepAlive(keepalive::Message::ResponseKeepAlive(u16::MAX)),
            AnyMessage::LeiosNotify(ln::Message::BlockOffer(Point::new(7, vec![0xA7; 32]), 99)),
        ];
        behavior.handle_io(InterfaceEvent::Recv(pid.clone(), answers));
        drain_outputs(&mut behavior);

        behavior.execute(InitiatorCommand::Housekeeping);
        let second = all_sends(&drain_outputs(&mut behavior));

        // Peer sharing is left unanswered here, and an answered one ends its
        // own loop, so keepalive and leios notify are the two that come round.
        let looping: [RequestKind; 2] = [
            ("keepalive", |m| matches!(m, AnyMessage::KeepAlive(_))),
            ("leios notify", |m| matches!(m, AnyMessage::LeiosNotify(_))),
        ];
        for (name, is_mine) in looping {
            let count = second.iter().filter(|m| is_mine(m)).count();
            assert_eq!(
                count, 1,
                "an answered {name} should be asked again, got {count} in {second:?}"
            );
        }
        assert!(
            !behavior.peers.get(&pid).unwrap().violation,
            "answering a request is not a violation"
        );
        assert!(
            !behavior.promotion.banned_peers.contains(&pid),
            "a peer that answers should not be banned"
        );
    }

    #[tokio::test]
    async fn a_request_this_node_sent_twice_is_not_the_peers_fault() {
        // The IO layer confirming two of our keepalives is a fault on this
        // side, and the peer has done nothing at all.
        tokio::time::pause();
        let (mut behavior, pid) = ready_leios_peer();

        let request = AnyMessage::KeepAlive(keepalive::Message::KeepAlive(u16::MAX));
        behavior.handle_io(InterfaceEvent::Sent(pid.clone(), request.clone()));
        behavior.handle_io(InterfaceEvent::Sent(pid.clone(), request));
        drain_outputs(&mut behavior);

        assert!(
            !behavior.peers.get(&pid).unwrap().violation,
            "our own duplicate should not mark the peer"
        );

        behavior.execute(InitiatorCommand::Housekeeping);
        let swept = drain_outputs(&mut behavior);
        assert!(
            !behavior.promotion.banned_peers.contains(&pid),
            "our own duplicate should not ban the peer"
        );
        assert!(
            !swept.has_disconnect_for(&pid),
            "our own duplicate should not disconnect the peer"
        );
    }

    #[tokio::test]
    async fn two_passes_before_a_confirmation_send_one_request_each() {
        // Nothing is drained between the passes, so the IO layer has confirmed
        // none of the first pass's sends when the second pass runs. This is the
        // shape a one second housekeeping tick produces against a real socket.
        tokio::time::pause();
        let (mut behavior, pid) = ready_leios_peer();

        behavior.execute(InitiatorCommand::Housekeeping);
        behavior.execute(InitiatorCommand::Housekeeping);
        let sends = all_sends(&drain_outputs(&mut behavior));

        for (name, is_mine) in housekeeping_requests() {
            let count = sends.iter().filter(|m| is_mine(m)).count();
            assert_eq!(
                count, 1,
                "{name} should have one request on the wire, got {count} in {sends:?}"
            );
        }

        for msg in sends.iter() {
            behavior.handle_io(InterfaceEvent::Sent(pid.clone(), msg.clone()));
        }
        drain_outputs(&mut behavior);
        assert!(
            !behavior.peers.get(&pid).unwrap().violation,
            "two housekeeping passes should not mark the peer"
        );

        behavior.execute(InitiatorCommand::Housekeeping);
        let swept = drain_outputs(&mut behavior);
        assert!(
            !behavior.promotion.banned_peers.contains(&pid),
            "two housekeeping passes should not ban the peer"
        );
        assert!(
            !swept.has_disconnect_for(&pid),
            "two housekeeping passes should not disconnect the peer"
        );
    }

    #[tokio::test]
    async fn a_confirmed_request_is_not_repeated_until_the_peer_answers() {
        tokio::time::pause();
        let (mut behavior, pid) = ready_leios_peer();

        for pass in 0..4 {
            behavior.execute(InitiatorCommand::Housekeeping);
            let sends = all_sends(&drain_outputs(&mut behavior));
            let expected = if pass == 0 { 3 } else { 0 };
            assert_eq!(
                sends.len(),
                expected,
                "pass {pass} should send {expected}, got {sends:?}"
            );

            for msg in sends.iter() {
                behavior.handle_io(InterfaceEvent::Sent(pid.clone(), msg.clone()));
            }
            drain_outputs(&mut behavior);
        }

        assert!(!behavior.peers.get(&pid).unwrap().violation);
        assert!(!behavior.promotion.banned_peers.contains(&pid));
    }

    #[tokio::test]
    async fn a_closed_session_is_reported_to_the_consumer() {
        tokio::time::pause();
        let (mut behavior, pid) = ready_leios_peer();

        behavior.execute(InitiatorCommand::Housekeeping);
        let live = drain_outputs(&mut behavior);
        assert!(
            disconnections(&live).is_empty(),
            "a peer still holding its connection has not ended a session"
        );

        behavior.handle_io(InterfaceEvent::Disconnected(pid.clone()));
        let ended = drain_outputs(&mut behavior);

        assert_eq!(
            disconnections(&ended),
            vec![(pid.clone(), DisconnectReason::Closed)],
            "a close should be reported once, naming the peer"
        );
        assert_eq!(
            external_events(&ended).len(),
            1,
            "a close should surface exactly one event, got {:?}",
            external_events(&ended)
        );
    }

    #[tokio::test]
    async fn an_errored_session_is_reported_to_the_consumer() {
        tokio::time::pause();
        let (mut behavior, pid) = ready_leios_peer();

        behavior.handle_io(InterfaceEvent::Error(
            pid.clone(),
            InterfaceError::Other("socket gone".into()),
        ));
        let ended = drain_outputs(&mut behavior);

        assert_eq!(
            disconnections(&ended),
            vec![(pid.clone(), DisconnectReason::Errored)],
            "an error should be reported once, naming the peer and the error"
        );
        assert_eq!(
            external_events(&ended).len(),
            1,
            "an error should surface exactly one event, got {:?}",
            external_events(&ended)
        );

        // The error makes the behavior close the socket, and that close is
        // reported in its own right.
        behavior.handle_io(InterfaceEvent::Disconnected(pid.clone()));
        let closed = drain_outputs(&mut behavior);
        assert_eq!(
            disconnections(&closed),
            vec![(pid.clone(), DisconnectReason::Closed)],
            "the close that follows an error should be reported too"
        );
    }
}
