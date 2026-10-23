//! How the main loop deals with the libp2p network actor: the actor's events,
//! and the bans, unbans, and dials that concern both network stacks.
//!
//! The standing of an IP address in the database is what both stacks go by.
//! The ban list of the libp2p stack refuses connections early, before any
//! handshake, and is kept in step with the standings here.

use std::net::IpAddr;
use std::net::SocketAddr;

use itertools::Itertools;
use multiaddr::Multiaddr;
use tokio::sync::oneshot;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::network_actor_link::NetworkActorLink;
use super::network_actor_link::NetworkEvent;
use super::MainLoopHandler;
use super::MutableMainLoopState;
use crate::application::config::cli_args;
use crate::application::config::parser::multiaddr::canonical_socket_addr;
use crate::application::config::parser::multiaddr::direct_socket_addr;
use crate::application::config::parser::multiaddr::ip_of;
use crate::application::loops::channel::MainToPeerTask;
use crate::application::rpc::server::network_overview_data::NetworkOverviewData;
use crate::protocol::peer::peer_info::PeerInfo;
use crate::protocol::peer::PeerStanding;

/// The socket addresses of the peers given with `--peer`, on either network
/// stack. A peer that the libp2p stack dialed is keyed by the address it was
/// dialed at.
pub(super) fn cli_peer_addresses(cli_args: &cli_args::Args) -> Vec<SocketAddr> {
    let mut addresses = cli_args.legacy_peers();
    addresses.extend(
        cli_args
            .libp2p_peers()
            .iter()
            .filter_map(direct_socket_addr),
    );
    addresses
}

/// Whether the peer is one of the `cli_peers`, as returned by
/// [`cli_peer_addresses`].
///
/// With libp2p running, a peer given as a legacy address may be connected over
/// libp2p, or may have dialed in from another port, so the legacy address it
/// announced in its handshake counts, too. Without libp2p, only the connected
/// address counts, as it always has.
///
/// Addresses are compared in canonical form, so that an IPv4 address matches
/// its IPv4-mapped IPv6 form.
pub(super) fn is_cli_peer(
    cli_args: &cli_args::Args,
    cli_peers: &[SocketAddr],
    peer: &PeerInfo,
) -> bool {
    let is_listed = |address: SocketAddr| {
        cli_peers
            .iter()
            .any(|&cli_peer| canonical_socket_addr(cli_peer) == canonical_socket_addr(address))
    };

    is_listed(peer.connected_address())
        || (cli_args.libp2p_enabled() && peer.listen_address().is_some_and(is_listed))
}

impl MainLoopHandler {
    /// Handle an event from the network actor.
    #[cfg(feature = "libp2p")]
    pub(super) fn handle_network_event(
        &self,
        event: NetworkEvent,
        main_loop_state: &mut MutableMainLoopState,
    ) {
        match event {
            NetworkEvent::NewPeerLoop { loop_handle } => {
                main_loop_state.task_handles.push(loop_handle);
                main_loop_state.task_handles.retain(|th| !th.is_finished());
            }
        }
    }

    /// Without libp2p, there are no events from a network actor.
    #[cfg(not(feature = "libp2p"))]
    pub(super) fn handle_network_event(
        &self,
        event: NetworkEvent,
        _main_loop_state: &mut MutableMainLoopState,
    ) {
        match event {}
    }

    /// The network actor has stopped on its own. The node goes on with the
    /// legacy network stack only, and the RPC server reports that the libp2p
    /// stack does not run.
    pub(super) fn handle_network_actor_stopped(&mut self) {
        error!(
            "The libp2p network stack has stopped. \
             Continuing with the legacy network stack only."
        );
        self.network_actor = None;
        self.global_state_lock.set_libp2p_stopped();
    }

    /// The network actor, or `None` with a warning that the action cannot be
    /// taken because the libp2p stack does not run.
    fn network_actor_for(&self, action: &str) -> Option<&NetworkActorLink> {
        if self.network_actor.is_none() {
            warn!("Cannot {action}: the libp2p network stack does not run.");
        }

        self.network_actor.as_ref()
    }

    /// Refuse the IP address of a peer that reached a bad standing on the
    /// libp2p stack, too. The legacy stack refuses it through the standing,
    /// which the connection-close callback of the peer stores.
    pub(super) async fn ban_peer_in_bad_standing(&self, peer_address: SocketAddr) {
        if let Some(network_actor) = &self.network_actor {
            let ip = peer_address.ip().to_canonical();
            info!("Refusing {ip} on the libp2p stack because of bad standing.");
            network_actor.ban(ip).await;
        }
    }

    /// Give the IP address a bad standing, disconnect the peers at it, and
    /// refuse it on both network stacks.
    ///
    /// The IP address is taken in canonical form, so that the ban applies to
    /// an IPv4 address and to its IPv4-mapped IPv6 form alike.
    pub(super) async fn ban_ip(&mut self, ip: IpAddr) {
        let ip = ip.to_canonical();
        let peer_tolerance = self.global_state_lock.cli().peer_tolerance;
        let make_bad = |standing: &mut PeerStanding| standing.standing = -i32::from(peer_tolerance);

        info!("Banning {ip}.");
        let peers_at_ip = {
            let mut global_state = self.global_state_lock.lock_guard_mut().await;

            // The connection-close callback stores the standing of a connected
            // peer, so the standing in the peer map must be bad as well.
            let peers_at_ip = global_state
                .net
                .peer_map
                .iter_mut()
                .filter(|(address, _)| address.ip().to_canonical() == ip)
                .map(|(address, peer_info)| {
                    make_bad(&mut peer_info.standing);
                    *address
                })
                .collect_vec();

            let mut standing = global_state
                .net
                .get_peer_standing_from_database(ip)
                .await
                .unwrap_or_else(|| PeerStanding::new(peer_tolerance));
            make_bad(&mut standing);
            global_state.net.write_peer_standing(ip, standing).await;

            peers_at_ip
        };

        for peer_address in peers_at_ip {
            self.main_to_peer_broadcast(MainToPeerTask::Disconnect(peer_address));
        }

        if let Some(network_actor) = &self.network_actor {
            network_actor.ban(ip).await;
        }
    }

    /// Clear the standing of the IP address, and lift its ban on both network
    /// stacks. A ban given with `--ban` stands. The peers at the IP address can
    /// reconnect at once: neither the reconnect cooldown nor their earlier
    /// connection attempts hold them back.
    pub(super) async fn unban_ip(&mut self, ip: IpAddr) {
        let ip = ip.to_canonical();
        info!("Lifting the ban of {ip}.");
        {
            let mut global_state = self.global_state_lock.lock_guard_mut().await;
            global_state
                .net
                .peer_map
                .iter_mut()
                .filter(|(address, _)| address.ip().to_canonical() == ip)
                .for_each(|(_, peer_info)| peer_info.standing.clear_standing());
            global_state.net.clear_ip_standing_in_database(ip).await;
            global_state.net.forget_disconnections_at(ip);
        }

        if let Some(network_actor) = &self.network_actor {
            network_actor.unban(ip).await;
        }
    }

    /// Clear all standings, and lift all bans on both network stacks, except
    /// those given with `--ban`. As with [`Self::unban_ip`], all peers can
    /// reconnect at once.
    pub(super) async fn unban_all(&mut self) {
        info!("Lifting all bans.");
        {
            let mut global_state = self.global_state_lock.lock_guard_mut().await;
            global_state
                .net
                .peer_map
                .values_mut()
                .for_each(|peer_info| peer_info.standing.clear_standing());
            global_state.net.clear_all_standings_in_database().await;
            global_state.net.forget_all_disconnections();
        }

        if let Some(network_actor) = &self.network_actor {
            network_actor.unban_all().await;
        }
    }

    /// Dial the address over the libp2p stack.
    ///
    /// A dial requested by the operator overturns a bad standing of the IP
    /// address, which would otherwise refuse the connection once established,
    /// and the reconnect cooldown of the peers at the IP address. A ban given
    /// with `--ban` stands.
    pub(super) async fn dial(&mut self, address: Multiaddr) {
        if self.network_actor_for(&format!("dial {address}")).is_none() {
            return;
        }

        if let Some(ip) = ip_of(&address).map(|ip| ip.to_canonical()) {
            let cli_banned = self.global_state_lock.cli().banned_ips().contains(&ip);
            let mut global_state = self.global_state_lock.lock_guard_mut().await;
            let standing = global_state.net.get_peer_standing_from_database(ip).await;
            if !cli_banned && standing.is_some_and(|standing| standing.is_bad()) {
                info!("Clearing the bad standing of {ip} to dial {address}.");
                global_state.net.clear_ip_standing_in_database(ip).await;
            }
            global_state.net.forget_disconnections_at(ip);
        }

        if let Some(network_actor) = &self.network_actor {
            network_actor.dial(address).await;
        }
    }

    pub(super) async fn probe_nat(&self) {
        if let Some(network_actor) = self.network_actor_for("probe NAT status") {
            network_actor.probe_nat().await;
        }
    }

    pub(super) async fn reset_relay_reservations(&self) {
        if let Some(network_actor) = self.network_actor_for("reset relay reservations") {
            network_actor.reset_relay_reservations().await;
        }
    }

    /// Send an overview of the libp2p stack over `reply`. Without libp2p, the
    /// sender is dropped.
    pub(super) async fn request_network_overview(
        &self,
        reply: oneshot::Sender<NetworkOverviewData>,
    ) {
        if let Some(network_actor) = self.network_actor_for("report on the libp2p stack") {
            network_actor.request_overview(reply).await;
        }
    }
}
