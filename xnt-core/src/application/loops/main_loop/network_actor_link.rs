//! The main loop's end of the channels to the libp2p network actor.
//!
//! The network actor runs if the node is built with the `libp2p` feature and
//! started without `--disable-libp2p`. The main loop holds an
//! `Option<NetworkActorLink>`. Without the feature, [`NetworkActorLink`] has no
//! values, so the option is always `None`, and the main loop behaves as it
//! does without a libp2p stack.

use std::net::IpAddr;
#[cfg(feature = "libp2p")]
use std::time::Duration;

#[cfg(feature = "libp2p")]
use itertools::Either;
use multiaddr::Multiaddr;
#[cfg(feature = "libp2p")]
use tokio::sync::mpsc;
use tokio::sync::oneshot;
#[cfg(feature = "libp2p")]
use tokio::task::JoinHandle;
#[cfg(feature = "libp2p")]
use tracing::error;
#[cfg(feature = "libp2p")]
use tracing::warn;

#[cfg(feature = "libp2p")]
use crate::application::network::channel::NetworkActorCommand;
#[cfg(feature = "libp2p")]
pub(crate) use crate::application::network::channel::NetworkEvent;
use crate::application::rpc::server::network_overview_data::NetworkOverviewData;

/// Without libp2p, there is no network actor to send events.
#[cfg(not(feature = "libp2p"))]
#[derive(Debug)]
pub(crate) enum NetworkEvent {}

/// The channels between the main loop and the running libp2p network actor,
/// and the task the actor runs in.
#[cfg(feature = "libp2p")]
#[derive(Debug)]
pub(crate) struct NetworkActorLink {
    command_tx: mpsc::Sender<NetworkActorCommand>,
    event_rx: mpsc::UnboundedReceiver<NetworkEvent>,
    actor_task: JoinHandle<()>,
}

/// Without libp2p, no network actor runs.
#[cfg(not(feature = "libp2p"))]
#[derive(Debug)]
pub(crate) enum NetworkActorLink {}

#[cfg(feature = "libp2p")]
impl NetworkActorLink {
    /// How long the main loop waits for the network actor to shut down.
    const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

    pub(crate) fn new(
        command_tx: mpsc::Sender<NetworkActorCommand>,
        event_rx: mpsc::UnboundedReceiver<NetworkEvent>,
        actor_task: JoinHandle<()>,
    ) -> Self {
        Self {
            command_tx,
            event_rx,
            actor_task,
        }
    }

    async fn send(&self, command: NetworkActorCommand) {
        if let Err(e) = self.command_tx.send(command).await {
            error!("Cannot send command to the network actor: {e}.");
        }
    }

    /// Refuse the IP address on the libp2p stack.
    pub(crate) async fn ban(&self, ip: IpAddr) {
        self.send(NetworkActorCommand::Ban(Either::Right(ip))).await;
    }

    /// Lift the libp2p ban of the IP address, unless it was given with
    /// `--ban`.
    pub(crate) async fn unban(&self, ip: IpAddr) {
        self.send(NetworkActorCommand::Unban(ip)).await;
    }

    /// Lift all libp2p bans, except those given with `--ban`.
    pub(crate) async fn unban_all(&self) {
        self.send(NetworkActorCommand::UnbanAll).await;
    }

    pub(crate) async fn dial(&self, address: Multiaddr) {
        self.send(NetworkActorCommand::Dial(address)).await;
    }

    pub(crate) async fn probe_nat(&self) {
        self.send(NetworkActorCommand::ProbeNat).await;
    }

    pub(crate) async fn reset_relay_reservations(&self) {
        self.send(NetworkActorCommand::ResetRelayReservations).await;
    }

    /// Ask the actor for an overview of the libp2p stack, to be sent over
    /// `reply`. The answer is awaited in a task of its own, so that the main
    /// loop does not wait for the actor.
    pub(crate) async fn request_overview(&self, reply: oneshot::Sender<NetworkOverviewData>) {
        let (overview_tx, overview_rx) = oneshot::channel();
        self.send(NetworkActorCommand::GetNetworkOverview(overview_tx))
            .await;
        tokio::spawn(async move {
            if let Ok(overview) = overview_rx.await {
                let _ = reply.send(overview.into());
            }
        });
    }

    /// The next event from the actor, or `None` once the actor has stopped.
    async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.event_rx.recv().await
    }

    /// Tell the actor to shut down, and wait for it to finish, for at most
    /// [`Self::SHUTDOWN_TIMEOUT`] in all. The command counts towards that
    /// time, too, as the command channel may be full.
    pub(crate) async fn shutdown(self) {
        let Self {
            command_tx,
            mut actor_task,
            ..
        } = self;
        if actor_task.is_finished() {
            return;
        }

        let shut_down = async {
            if command_tx
                .send(NetworkActorCommand::Shutdown)
                .await
                .is_err()
            {
                warn!("Network actor stopped before it was told to shut down.");
            }
            let _ = (&mut actor_task).await;
        };
        if tokio::time::timeout(Self::SHUTDOWN_TIMEOUT, shut_down)
            .await
            .is_err()
        {
            warn!("Network actor did not shut down in time. Aborting it.");
            actor_task.abort();
        }
    }
}

#[cfg(not(feature = "libp2p"))]
impl NetworkActorLink {
    pub(crate) async fn ban(&self, _ip: IpAddr) {
        match *self {}
    }

    pub(crate) async fn unban(&self, _ip: IpAddr) {
        match *self {}
    }

    pub(crate) async fn unban_all(&self) {
        match *self {}
    }

    pub(crate) async fn dial(&self, _address: Multiaddr) {
        match *self {}
    }

    pub(crate) async fn probe_nat(&self) {
        match *self {}
    }

    pub(crate) async fn reset_relay_reservations(&self) {
        match *self {}
    }

    pub(crate) async fn request_overview(&self, _reply: oneshot::Sender<NetworkOverviewData>) {
        match *self {}
    }

    async fn next_event(&mut self) -> Option<NetworkEvent> {
        match *self {}
    }

    pub(crate) async fn shutdown(self) {
        match self {}
    }
}

/// The next event from the network actor, or `None` once the actor has
/// stopped. Never completes if no network actor runs.
pub(crate) async fn next_network_event(
    network_actor: &mut Option<NetworkActorLink>,
) -> Option<NetworkEvent> {
    match network_actor {
        Some(network_actor) => network_actor.next_event().await,
        None => std::future::pending().await,
    }
}

#[cfg(all(test, feature = "libp2p"))]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn shutdown_ends_in_time_if_the_actor_takes_no_commands() {
        let (command_tx, _command_rx) = mpsc::channel(1);
        command_tx
            .send(NetworkActorCommand::ProbeNat)
            .await
            .unwrap();
        let (_event_tx, event_rx) = mpsc::unbounded_channel();
        let actor_task = tokio::spawn(std::future::pending::<()>());
        let link = NetworkActorLink::new(command_tx, event_rx, actor_task);

        let started = tokio::time::Instant::now();
        link.shutdown().await;
        assert!(started.elapsed() <= NetworkActorLink::SHUTDOWN_TIMEOUT + Duration::from_secs(1));
    }
}
