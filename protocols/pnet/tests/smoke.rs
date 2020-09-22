use futures::io::{AsyncWriteExt, AsyncReadExt};
use futures::stream::TryStreamExt;
use libp2p_core::{
    identity,
    multiaddr::Multiaddr,
    transport::{Transport, ListenerEvent},
    upgrade,
};
use log::debug;
use quickcheck::QuickCheck;
use libp2p_pnet::{PnetConfig, PreSharedKey};

#[test]
fn variable_msg_length() {
    let _ = env_logger::try_init();

    fn prop(msg: Vec<u8>) {
        debug!("message is {:?}", msg.clone());
        let mut msg_to_send = msg.clone();
        let msg_to_receive = msg;

        let psk = PreSharedKey::new([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
        ]);

        let server_id = identity::Keypair::generate_ed25519();
        let server_id_public = server_id.public();

        let client_id = identity::Keypair::generate_ed25519();
        let client_id_public = client_id.public();

        futures::executor::block_on(async {
            let server_transport = libp2p_core::transport::MemoryTransport{}.and_then(move |socket, _| {
                PnetConfig::new(psk).handshake(socket)
            });

            let client_transport = libp2p_core::transport::MemoryTransport{}.and_then(
                move |socket, _| {
                    PnetConfig::new(psk).handshake(socket)
                }
            );


            let server_address: Multiaddr = format!(
                "/memory/{}",
                std::cmp::Ord::max(1, rand::random::<u64>())
            ).parse().unwrap();

            let mut server = server_transport.listen_on(server_address.clone()).unwrap();

            // Ignore server listen address event.
            let _ = server.try_next()
                .await
                .expect("some event")
                .expect("no error")
                .into_new_address()
                .expect("listen address");

            let client_fut = async {
                debug!("dialing {:?}", server_address);
                let mut client_channel = client_transport.dial(server_address).unwrap().await.unwrap();
                // assert_eq!(received_server_id, server_id.public().into_peer_id());

                debug!("Client: writing message.");
                client_channel.write_all(&mut msg_to_send).await.expect("no error");
                debug!("Client: flushing channel.");
                client_channel.flush().await.expect("no error");
            };

            let server_fut = async {
                let mut server_channel = server.try_next()
                    .await
                    .expect("some event")
                    .map(ListenerEvent::into_upgrade)
                    .expect("no error")
                    .map(|client| client.0)
                    .expect("listener upgrade xyz")
                    .await
                    .expect("no error");

                let mut server_buffer = vec![0; msg_to_receive.len()];
                debug!("Server: reading message.");
                server_channel.read_exact(&mut server_buffer).await.expect("reading client message");

                // assert_eq!(server_buffer, msg_to_receive);
            };

            futures::future::join(server_fut, client_fut).await;
        })
    }

    QuickCheck::new().max_tests(1).quickcheck(prop as fn(Vec<u8>))
}
