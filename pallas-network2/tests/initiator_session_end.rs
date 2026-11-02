#![cfg(feature = "unstable")]

use std::time::Duration;

use tokio::net::TcpListener;

use pallas_network2::behavior::responder::{ResponderBehavior, ResponderCommand, ResponderEvent};
use pallas_network2::behavior::{
    AnyMessage, DisconnectReason, InitiatorBehavior, InitiatorCommand, InitiatorEvent,
};
use pallas_network2::interface::{TcpInterface, TcpListenerInterface};
use pallas_network2::{Manager, PeerId};

type Initiator = Manager<TcpInterface<AnyMessage>, InitiatorBehavior, AnyMessage>;

const WINDOW: Duration = Duration::from_millis(300);

const SETTLE: Duration = Duration::from_millis(50);

async fn bound() -> (TcpListener, PeerId) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pid = PeerId {
        host: addr.ip().to_string(),
        port: addr.port(),
    };

    (listener, pid)
}

async fn ends_within(
    manager: &mut Initiator,
    pid: &PeerId,
    window: Duration,
) -> (bool, Vec<DisconnectReason>) {
    let mut initialized = false;
    let mut reasons = Vec::new();

    let _ = tokio::time::timeout(window, async {
        loop {
            match manager.poll_next().await {
                Some(InitiatorEvent::PeerInitialized(p, _)) if p == *pid => initialized = true,
                Some(InitiatorEvent::PeerDisconnected(p, reason)) if p == *pid => {
                    reasons.push(reason)
                }
                _ => {}
            }
        }
    })
    .await;

    (initialized, reasons)
}

#[tokio::test]
async fn a_demote_a_remote_close_and_a_refused_connect_emit_closed_errored_errored() {
    let (listener, demoted) = bound().await;
    let responder = tokio::spawn(async move {
        let mut responder = Manager::new(
            TcpListenerInterface::<AnyMessage>::new(listener),
            ResponderBehavior::default(),
        );
        loop {
            if let Some(ResponderEvent::PeerInitialized(..)) = responder.poll_next().await {
                responder.execute(ResponderCommand::Housekeeping);
            }
        }
    });
    let (remote, closed) = bound().await;
    let remote = tokio::spawn(async move {
        let _ = remote.accept().await;
    });
    let (unused, refused) = bound().await;
    drop(unused);
    let mut initiator = Initiator::new(TcpInterface::new(), InitiatorBehavior::default());

    initiator.execute(InitiatorCommand::IncludePeer(demoted.clone()));
    initiator.execute(InitiatorCommand::Housekeeping);
    let (initialized, mut local) = ends_within(&mut initiator, &demoted, WINDOW).await;
    // Promotes the peer to hot, which the demote needs before it closes the connection.
    initiator.execute(InitiatorCommand::Housekeeping);
    local.extend(ends_within(&mut initiator, &demoted, SETTLE).await.1);
    initiator.execute(InitiatorCommand::DemotePeer(demoted.clone()));
    initiator.execute(InitiatorCommand::Housekeeping);
    local.extend(ends_within(&mut initiator, &demoted, WINDOW).await.1);
    responder.abort();

    initiator.execute(InitiatorCommand::IncludePeer(closed.clone()));
    initiator.execute(InitiatorCommand::Housekeeping);
    let (_, remote_closed) = ends_within(&mut initiator, &closed, WINDOW).await;
    remote.abort();

    initiator.execute(InitiatorCommand::IncludePeer(refused.clone()));
    initiator.execute(InitiatorCommand::Housekeeping);
    let (_, refused_connect) = ends_within(&mut initiator, &refused, WINDOW).await;

    assert_eq!(
        (initialized, local, remote_closed, refused_connect),
        (
            true,
            vec![DisconnectReason::Closed],
            vec![DisconnectReason::Errored],
            vec![DisconnectReason::Errored]
        ),
        "initialized, then the reasons emitted for a local demote, a remote close and a refused connect"
    );
}
