use std::fmt::Display;
use std::time::Duration;

use anyhow::anyhow;
use serde::Deserialize;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::application::loops::channel::RPCServerToMain;

/// How long an RPC server waits for the main loop to report on the libp2p
/// network stack.
const NETWORK_OVERVIEW_TIMEOUT: Duration = Duration::from_secs(5);

/// Overview of the node's libp2p network stack, for RPC clients.
///
/// The libp2p types (NAT status, multiaddresses, peer ID) and the reachability
/// state are rendered as strings, so that clients such as the dashboard need
/// no libp2p dependency, and so that this type exists whether or not the node
/// was built with libp2p.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkOverviewData {
    pub nat_status: String,
    pub reachability_state: String,
    pub external_addresses: Vec<String>,
    pub connection_count: usize,
    pub connection_limit: usize,
    pub num_active_relays: usize,
    pub peer_id: String,
    pub address_book_size: usize,
    pub num_banned_peers: usize,
}

impl Display for NetworkOverviewData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "PeerId:             {}", self.peer_id)?;
        writeln!(f, "NAT Status:         {}", self.nat_status)?;
        writeln!(f, "Reachability:       {}", self.reachability_state)?;
        writeln!(
            f,
            "Connections:        {}/{}",
            self.connection_count, self.connection_limit
        )?;
        writeln!(f, "Relay Reservations: {}", self.num_active_relays)?;

        if !self.external_addresses.is_empty() {
            writeln!(f, "External Addresses:")?;
            for addr in &self.external_addresses {
                writeln!(f, "        {}", addr)?;
            }
        }

        writeln!(f, "Address Book Size:  {}", self.address_book_size)?;
        writeln!(f, "Black List Size:    {}", self.num_banned_peers)?;

        Ok(())
    }
}

/// Ask the main loop for an overview of the libp2p network stack, on behalf of
/// an RPC client.
///
/// `None` if the libp2p stack does not run. If libp2p is disabled, the main
/// loop is not asked. Otherwise, the main loop drops the request if no network
/// actor runs, which yields `None` as well.
pub(crate) async fn request_network_overview(
    libp2p_enabled: bool,
    rpc_server_to_main_tx: &mpsc::Sender<RPCServerToMain>,
) -> anyhow::Result<Option<NetworkOverviewData>> {
    if !libp2p_enabled {
        return Ok(None);
    }

    let (overview_tx, overview_rx) = oneshot::channel();
    rpc_server_to_main_tx
        .send(RPCServerToMain::GetNetworkOverview(overview_tx))
        .await
        .map_err(|e| anyhow!("could not send message to main loop: {e}"))?;

    let overview = tokio::time::timeout(NETWORK_OVERVIEW_TIMEOUT, overview_rx)
        .await
        .map_err(|_| {
            anyhow!(
                "the libp2p network stack did not report within {} seconds",
                NETWORK_OVERVIEW_TIMEOUT.as_secs()
            )
        })?;

    Ok(overview.ok())
}
