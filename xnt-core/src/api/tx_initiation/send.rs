//! provides an easy-to-use `TransactionSender` with single send() method.
//!
//! This is highest-level and easiest to use API for sending a transaction.
//!
//! It should be preferred to lower-level APIs unless there is a need for
//! greater flexibility than this provides.
//!
//! see [tx_initiation](super) for other available API.
//!
//! Example:
//!
//! ```
//! use neptune_privacy::{api, api::export, api::tx_initiation::{self, send}};
//! use export::ChangePolicy;
//! use export::GlobalStateLock;
//! use export::NativeCurrencyAmount;
//! use export::ReceivingAddress;
//! use export::Timestamp;
//! use export::TxCreationArtifacts;
//!
//! async fn my_send_transaction(gsl: GlobalStateLock, recipient: ReceivingAddress, amount: NativeCurrencyAmount, change_policy: ChangePolicy, fee: NativeCurrencyAmount) -> Result<TxCreationArtifacts, tx_initiation::error::SendError> {
//!     let outputs = vec![(recipient, amount)];
//!
//!     send::TransactionSender::from(gsl)
//!         .send(
//!             outputs,
//!             change_policy,
//!             fee,
//!             Timestamp::now(),
//!             0,
//!             None,
//!         ).await
//! }
//! ```

use super::error;
use crate::api::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::api::tx_initiation::initiator::BridgeDepositAll;
use crate::api::tx_initiation::initiator::TransactionInitiator;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::state::transaction::chained_tx_artifacts::ChainedTxArtifacts;
use crate::state::transaction::link_tx_artifacts::LinkTxArtifacts;
use crate::state::transaction::tx_creation_artifacts::TxCreationArtifacts;
use crate::state::wallet::change_policy::ChangePolicy;
use crate::GlobalStateLock;

/// provides a send() method to send a neptune transaction in one call.
#[derive(Debug)]
pub struct TransactionSender {
    global_state_lock: GlobalStateLock,
}

impl From<GlobalStateLock> for TransactionSender {
    fn from(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }
}

impl TransactionSender {
    // You should call offchain-notifications() on the returned value
    // to retrieve (and store) offchain notifications, if any.
    pub async fn send(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        exclude_recent_blocks: usize,
        max_inputs: Option<usize>,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        TransactionInitiator {
            global_state_lock: self.global_state_lock.clone(),
        }
        .send(
            outputs,
            change_policy,
            fee,
            timestamp,
            exclude_recent_blocks,
            max_inputs,
        )
        .await
    }

    pub async fn bridge_deposit(
        &mut self,
        leviathan_account_id: [u64; 2],
        amount: NativeCurrencyAmount,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        exclude_recent_blocks: usize,
        max_inputs: Option<usize>,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        TransactionInitiator {
            global_state_lock: self.global_state_lock.clone(),
        }
        .bridge_deposit(
            leviathan_account_id,
            amount,
            fee,
            timestamp,
            exclude_recent_blocks,
            max_inputs,
        )
        .await
    }

    pub async fn bridge_deposit_all(
        &mut self,
        leviathan_account_id: [u64; 2],
        fee: NativeCurrencyAmount,
        keep: NativeCurrencyAmount,
        timestamp: Timestamp,
        exclude_recent_blocks: usize,
        max_inputs: Option<usize>,
    ) -> Result<BridgeDepositAll, error::SendError> {
        TransactionInitiator {
            global_state_lock: self.global_state_lock.clone(),
        }
        .bridge_deposit_all(
            leviathan_account_id,
            fee,
            keep,
            timestamp,
            exclude_recent_blocks,
            max_inputs,
        )
        .await
    }

    #[expect(clippy::too_many_arguments)]
    pub async fn submit_authority_rotation(
        &mut self,
        new_keys: Vec<Vec<u8>>,
        new_threshold: usize,
        signatures: Vec<[u8; 64]>,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        exclude_recent_blocks: usize,
        max_inputs: Option<usize>,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        TransactionInitiator {
            global_state_lock: self.global_state_lock.clone(),
        }
        .submit_authority_rotation(
            new_keys,
            new_threshold,
            signatures,
            fee,
            timestamp,
            exclude_recent_blocks,
            max_inputs,
        )
        .await
    }

    pub async fn submit_bridge_registration(
        &mut self,
        registration: crate::protocol::consensus::bridge::faucet_registration::BridgeRegistration,
        signatures: Vec<[u8; 64]>,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        exclude_recent_blocks: usize,
        max_inputs: Option<usize>,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        TransactionInitiator {
            global_state_lock: self.global_state_lock.clone(),
        }
        .submit_bridge_registration(
            registration,
            signatures,
            fee,
            timestamp,
            exclude_recent_blocks,
            max_inputs,
        )
        .await
    }

    /// Send a chained transaction, paying with unconfirmed funds. See
    /// [`TransactionInitiator::send_chained`].
    pub async fn send_chained(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> Result<ChainedTxArtifacts, error::SendError> {
        TransactionInitiator {
            global_state_lock: self.global_state_lock.clone(),
        }
        .send_chained(outputs, change_policy, fee, timestamp)
        .await
    }

    /// Send a chained transaction that stays a link transaction. See
    /// [`TransactionInitiator::send_chained_link`].
    pub async fn send_chained_link(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> Result<LinkTxArtifacts, error::SendError> {
        TransactionInitiator {
            global_state_lock: self.global_state_lock.clone(),
        }
        .send_chained_link(outputs, change_policy, fee, timestamp)
        .await
    }
}
