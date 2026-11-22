use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use pallas_network::multiplexer::{Bearer, Plexer};
use rand::{RngExt, distr::Uniform};
use tokio::net::TcpListener;

async fn setup_passive_muxer(server: TcpListener) -> Plexer {
    let (bearer, _) = Bearer::accept_tcp(&server).await.unwrap();

    Plexer::new(bearer)
}

async fn setup_active_muxer(address: SocketAddr) -> Plexer {
    let bearer = Bearer::connect_tcp(address).await.unwrap();

    println!("active plexer connected");

    Plexer::new(bearer)
}

fn random_payload(size: usize) -> Vec<u8> {
    let range = Uniform::new(0, 255).unwrap();
    rand::rng().sample_iter(&range).take(size).collect()
}

#[tokio::test]
async fn one_way_small_sequence_of_payloads() {
    let server = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let passive = tokio::task::spawn(setup_passive_muxer(server));

    let mut active = setup_active_muxer(address).await;

    let mut passive = passive.await.unwrap();

    let mut sender_channel = active.subscribe_client(3);
    let mut receiver_channel = passive.subscribe_server(3);

    let passive = passive.spawn();
    let active = active.spawn();

    for _ in 0..100 {
        let payload = random_payload(50);
        println!("sending chunk");
        sender_channel.enqueue_chunk(payload.clone()).await.unwrap();
        let received_payload = receiver_channel.dequeue_chunk().await.unwrap();
        assert_eq!(payload, received_payload);
    }

    passive.abort().await;
    active.abort().await;
}
