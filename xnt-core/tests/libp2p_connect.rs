//! Nodes on localhost connecting over the libp2p stack (QUIC and libp2p TCP),
//! over the legacy TCP stack, and over both at once.

mod common;

use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use clap::Parser;
use common::genesis_node::GenesisNode;
use common::logging;
use neptune_privacy::application::config::cli_args::Args;
use neptune_privacy::application::config::parser::peer_address::PeerAddress;

/// The QUIC address of a node on localhost.
fn quic_address(args: &Args) -> PeerAddress {
    format!("/ip4/127.0.0.1/udp/{}/quic-v1", args.quic_port)
        .parse()
        .unwrap()
}

/// The libp2p TCP address of a node on localhost.
fn libp2p_tcp_address(args: &Args) -> PeerAddress {
    format!("/ip4/127.0.0.1/tcp/{}", args.tcp_port)
        .parse()
        .unwrap()
}

/// The address of a node on the legacy TCP stack.
fn legacy_address(args: &Args) -> PeerAddress {
    SocketAddr::new(args.peer_listen_addr, args.peer_port).into()
}

/// The addresses at which the node's peers are connected.
async fn peer_addresses(node: &GenesisNode) -> Vec<SocketAddr> {
    node.gsl
        .lock_guard()
        .await
        .net
        .peer_map
        .keys()
        .copied()
        .collect()
}

/// The connections of the node, each with the time it was established.
async fn connections(node: &GenesisNode) -> Vec<(SocketAddr, SystemTime)> {
    let mut connections: Vec<_> = node
        .gsl
        .lock_guard()
        .await
        .net
        .peer_map
        .iter()
        .map(|(address, peer_info)| (*address, peer_info.connection_established()))
        .collect();
    connections.sort();
    connections
}

/// test: two nodes on localhost connect to each other over QUIC.
///
/// scenario:
/// 1. alice starts with no peers, listening on localhost.
/// 2. bob starts with alice's QUIC address as his only peer. A QUIC address
///    is never dialed by the legacy stack, so the resulting connection can
///    only have been made by libp2p.
/// 3. both nodes see each other in their peer maps.
#[tokio::test(flavor = "multi_thread")]
pub async fn two_nodes_connect_over_libp2p() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 30;

    let alice_args = GenesisNode::default_args().await;
    let alice_quic_port = alice_args.quic_port;
    let alice_address = quic_address(&alice_args);
    let alice = GenesisNode::start_node(alice_args).await?;

    let mut bob_args = GenesisNode::default_args().await;
    bob_args.peers = vec![alice_address];
    let bob = GenesisNode::start_node(bob_args).await?;

    alice.wait_until_one_peer_connected(timeout_secs).await?;
    bob.wait_until_one_peer_connected(timeout_secs).await?;

    // Bob's record of alice must carry the QUIC port he dialed, which
    // confirms the connection went through libp2p.
    let alice_as_seen_by_bob = peer_addresses(&bob).await;
    assert_eq!(1, alice_as_seen_by_bob.len());
    assert_eq!(
        alice_quic_port,
        alice_as_seen_by_bob[0].port(),
        "expected a libp2p QUIC connection to alice, got {alice_as_seen_by_bob:?}"
    );

    Ok(())
}

/// test: three nodes on localhost form a complete graph over libp2p.
///
/// scenario:
/// 1. bob starts with no peers.
/// 2. alice and charlie each start with bob's QUIC address as their only
///    peer, so the only configured edges are alice-bob and bob-charlie.
/// 3. through identify and Kademlia, alice learns of charlie from bob and
///    dials him, so every node ends up with two peers.
#[tokio::test(flavor = "multi_thread")]
pub async fn three_nodes_form_complete_graph_over_libp2p() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 90;

    let bob_args = GenesisNode::default_args().await;
    let bob_address = quic_address(&bob_args);
    let bob = GenesisNode::start_node(bob_args).await?;

    let mut alice_args = GenesisNode::default_args().await;
    alice_args.peers = vec![bob_address.clone()];
    let alice = GenesisNode::start_node(alice_args).await?;

    let mut charlie_args = GenesisNode::default_args().await;
    charlie_args.peers = vec![bob_address];
    let charlie_libp2p_ports = [charlie_args.quic_port, charlie_args.tcp_port];
    let charlie = GenesisNode::start_node(charlie_args).await?;

    for node in [&alice, &bob, &charlie] {
        node.wait_until_peers_connected(2, timeout_secs).await?;
    }

    // Alice was never told about charlie through the CLI arguments. So her
    // entry of him in the peer map proves that a connection was established
    // through the libp2p peer discovery protocol.
    let alice_peer_addresses = peer_addresses(&alice).await;
    assert!(
        alice_peer_addresses
            .iter()
            .any(|address| charlie_libp2p_ports.contains(&address.port())),
        "expected alice to discover one of charlie's libp2p addresses, got {alice_peer_addresses:?}"
    );

    Ok(())
}

/// test: two nodes on localhost connect to each other over libp2p TCP.
///
/// scenario:
/// 1. alice starts with no peers, listening on localhost.
/// 2. bob starts with alice's libp2p TCP address as his only peer.
/// 3. both nodes see each other, and bob sees alice at her libp2p TCP port.
#[tokio::test(flavor = "multi_thread")]
pub async fn two_nodes_connect_over_libp2p_tcp() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 30;

    let alice_args = GenesisNode::default_args().await;
    let alice_tcp_port = alice_args.tcp_port;
    let alice_address = libp2p_tcp_address(&alice_args);
    let alice = GenesisNode::start_node(alice_args).await?;

    let mut bob_args = GenesisNode::default_args().await;
    bob_args.peers = vec![alice_address];
    let bob = GenesisNode::start_node(bob_args).await?;

    alice.wait_until_one_peer_connected(timeout_secs).await?;
    bob.wait_until_one_peer_connected(timeout_secs).await?;

    let alice_as_seen_by_bob = peer_addresses(&bob).await;
    assert_eq!(1, alice_as_seen_by_bob.len());
    assert_eq!(
        alice_tcp_port,
        alice_as_seen_by_bob[0].port(),
        "expected a libp2p TCP connection to alice, got {alice_as_seen_by_bob:?}"
    );

    Ok(())
}

/// test: a node without libp2p and a node with both stacks connect over the
/// legacy stack, whichever of the two dials.
///
/// scenario:
/// 1. alice runs both stacks; bob runs the legacy stack only, and dials
///    alice's legacy address.
/// 2. charlie runs the legacy stack only; dave runs both stacks, and dials
///    charlie at his legacy and at his QUIC address. Only the legacy address
///    answers.
/// 3. every node ends up with exactly one peer, connected over the legacy
///    stack.
#[tokio::test(flavor = "multi_thread")]
pub async fn legacy_only_node_and_dual_stack_node_connect_both_ways() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 30;

    // The node without libp2p dials.
    let alice_args = GenesisNode::default_args().await;
    let alice_legacy_port = alice_args.peer_port;
    let alice_address = legacy_address(&alice_args);
    let alice = GenesisNode::start_node(alice_args).await?;

    let mut bob_args = GenesisNode::default_args().await;
    bob_args.disable_libp2p = true;
    bob_args.peers = vec![alice_address];
    let bob = GenesisNode::start_node(bob_args).await?;

    // The node with both stacks dials.
    let mut charlie_args = GenesisNode::default_args().await;
    charlie_args.disable_libp2p = true;
    let charlie_legacy_port = charlie_args.peer_port;
    let charlie_addresses = vec![legacy_address(&charlie_args), quic_address(&charlie_args)];
    let charlie = GenesisNode::start_node(charlie_args).await?;

    let mut dave_args = GenesisNode::default_args().await;
    dave_args.peers = charlie_addresses;
    let dave = GenesisNode::start_node(dave_args).await?;

    for node in [&alice, &bob, &charlie, &dave] {
        node.wait_until_one_peer_connected(timeout_secs).await?;
    }

    // Give dave's libp2p stack time to try charlie's QUIC address.
    tokio::time::sleep(Duration::from_secs(5)).await;

    let alice_as_seen_by_bob = peer_addresses(&bob).await;
    assert_eq!(1, alice_as_seen_by_bob.len());
    assert_eq!(alice_legacy_port, alice_as_seen_by_bob[0].port());
    assert_eq!(1, peer_addresses(&alice).await.len());

    let charlie_as_seen_by_dave = peer_addresses(&dave).await;
    assert_eq!(1, charlie_as_seen_by_dave.len());
    assert_eq!(charlie_legacy_port, charlie_as_seen_by_dave[0].port());
    assert_eq!(1, peer_addresses(&charlie).await.len());

    Ok(())
}

/// test: two nodes that reach each other over both stacks keep exactly one
/// connection, and do not dial each other again.
///
/// scenario:
/// 1. alice runs both stacks and has no peers.
/// 2. bob runs both stacks and dials alice at her legacy and at her QUIC
///    address. Both connections can come up, and one of them is refused as
///    a duplicate.
/// 3. once settled, each node has exactly one peer, and the connection stays
///    the same for longer than the interval at which lost libp2p peers are
///    dialed again.
#[tokio::test(flavor = "multi_thread")]
pub async fn dual_stack_pair_keeps_a_single_connection() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 30;
    let stable_for = Duration::from_secs(40);
    let deadline = Instant::now() + Duration::from_secs(150);

    let alice_args = GenesisNode::default_args().await;
    let alice_addresses = vec![legacy_address(&alice_args), quic_address(&alice_args)];
    let alice = GenesisNode::start_node(alice_args).await?;

    let mut bob_args = GenesisNode::default_args().await;
    bob_args.peers = alice_addresses;
    let bob = GenesisNode::start_node(bob_args).await?;

    alice.wait_until_one_peer_connected(timeout_secs).await?;
    bob.wait_until_one_peer_connected(timeout_secs).await?;

    // Wait until both sides have kept the same single connection for
    // `stable_for`. A change starts the wait over. A pair that keeps dialing
    // each other never gets there.
    let mut settled = (connections(&alice).await, connections(&bob).await);
    let mut settled_since = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let current = (connections(&alice).await, connections(&bob).await);
        let single_connection = current.0.len() == 1 && current.1.len() == 1;
        if current != settled || !single_connection {
            tracing::info!("connections changed from {settled:?} to {current:?}");
            settled = current;
            settled_since = Instant::now();
        } else if settled_since.elapsed() >= stable_for {
            break;
        }

        assert!(
            Instant::now() < deadline,
            "connections did not settle; last seen: {settled:?}"
        );
    }

    Ok(())
}

/// test: blocks mined on one node reach the other over QUIC.
///
/// scenario:
/// 1. alice mines 25 blocks before bob starts.
/// 2. bob dials her over QUIC only, finds himself more blocks behind than his
///    sync mode threshold, and challenges her. The challenge response holds 20
///    blocks, well beyond the 64 KiB frame limit of handshake messages, so bob
///    only gets past it because the limit is lifted once the handshake is
///    done. He then syncs in batches, until he is less than half the
///    threshold behind.
/// 3. alice mines one more block. It reaches bob, who fetches the blocks
///    missing in between and ends up at alice's tip.
#[tokio::test(flavor = "multi_thread")]
pub async fn blocks_reach_peer_over_quic() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 120;
    let sync_mode_threshold = 10;
    let num_blocks_before_bob_starts = 25;

    let alice_args = GenesisNode::default_args().await;
    let alice_quic_port = alice_args.quic_port;
    let alice_address = quic_address(&alice_args);
    let mut alice = GenesisNode::start_node(alice_args).await?;
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(num_blocks_before_bob_starts, false)
        .await?;

    // The response to a sync challenge carries 20 blocks.
    let tip = alice.gsl.lock_guard().await.chain.light_state().clone();
    let block_size = bincode::serialized_size(&tip)?;
    assert!(
        20 * block_size > 64 * 1024,
        "a sync challenge response must exceed 64 KiB; block size is {block_size}"
    );

    let mut bob_args = Args::try_parse_from([
        "xnt-core".to_string(),
        "--sync-mode-threshold".to_string(),
        sync_mode_threshold.to_string(),
    ])?;
    let defaults = GenesisNode::default_args().await;
    bob_args.network = defaults.network;
    bob_args.peer_listen_addr = defaults.peer_listen_addr;
    bob_args.peer_port = defaults.peer_port;
    bob_args.rpc_port = defaults.rpc_port;
    bob_args.quic_port = defaults.quic_port;
    bob_args.tcp_port = defaults.tcp_port;
    bob_args.data_dir = defaults.data_dir;
    bob_args.tx_proving_capability = defaults.tx_proving_capability;
    bob_args.peers = vec![alice_address];
    let bob = GenesisNode::start_node(bob_args).await?;

    bob.wait_until_one_peer_connected(timeout_secs).await?;
    assert_eq!(alice_quic_port, peer_addresses(&bob).await[0].port());

    // Bob gets beyond the threshold only through the sync challenge.
    bob.wait_until_block_height(sync_mode_threshold + 1, timeout_secs)
        .await?;

    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, false)
        .await?;
    bob.wait_until_block_height(u64::from(num_blocks_before_bob_starts) + 1, timeout_secs)
        .await?;

    // All of it went over the one QUIC connection.
    let alice_as_seen_by_bob = peer_addresses(&bob).await;
    assert_eq!(1, alice_as_seen_by_bob.len());
    assert_eq!(alice_quic_port, alice_as_seen_by_bob[0].port());

    Ok(())
}
