//! Integration tests for dCTIDH (CTIDH) addresses.
//!
//! Verifies bech32m encoding (long form) roundtrip and parsing.

mod common;

use common::genesis_node::GenesisNode;
use common::logging;
use bech32;
use neptune_privacy::api::export::KeyType;
use neptune_privacy::api::export::NativeCurrencyAmount;
use neptune_privacy::api::export::Network;
use neptune_privacy::api::export::ReceivingAddress;
use neptune_privacy::api::export::Timestamp;
use neptune_privacy::api::export::TxProvingCapability;
use num_traits::ops::checked::CheckedSub;
use num_traits::Zero;
use neptune_privacy::state::wallet::address::dctidh_address::{
    dCTIDHReceivingAddress, dCTIDHSpendingKey, CTIDH_ADDRESS_MAX_BECH32M_LEN,
};

const NETWORK: Network = Network::Testnet(0);

/// CTIDH address: bech32m roundtrip and length.
#[test]
fn dctidh_address_bech32m_roundtrip_and_length() {
    let key = dCTIDHSpendingKey::keygen();
    let addr = key.to_address();
    let receiving: ReceivingAddress = addr.into();

    let long = addr.to_bech32m(NETWORK).expect("to_bech32m");
    let (hrp, _, _) = bech32::decode(&long).expect("bech32 decode");
    assert!(
        hrp.starts_with("xntct"),
        "long form should start with xntct<network>, got hrp: {}",
        hrp
    );
    assert!(
        long.starts_with(&format!("{}1", hrp)),
        "long form should start with {}1, got: {}...",
        hrp,
        &long[..long.len().min(12)]
    );
    assert!(
        long.len() <= CTIDH_ADDRESS_MAX_BECH32M_LEN,
        "encoded len {} > CTIDH_ADDRESS_MAX_BECH32M_LEN {}",
        long.len(),
        CTIDH_ADDRESS_MAX_BECH32M_LEN
    );

    let decoded = ReceivingAddress::from_bech32m(&long, NETWORK).expect("from_bech32m");
    assert_eq!(receiving, decoded, "bech32m roundtrip must match");

    let decoded_dctidh = dCTIDHReceivingAddress::from_bech32m(&long, NETWORK).expect("from_bech32m");
    assert_eq!(addr, decoded_dctidh);
}

/// ReceivingAddress parses CTIDH from bech32m (prefix xntct).
#[test]
fn receiving_address_from_bech32m_parses_dctidh() {
    let key = dCTIDHSpendingKey::keygen();
    let addr = key.to_address();
    let encoded = addr.to_bech32m(NETWORK).unwrap();
    assert!(encoded.starts_with("xntct"), "CTIDH HRP should be xntct");

    let parsed = ReceivingAddress::from_bech32m(&encoded, NETWORK).unwrap();
    match &parsed {
        ReceivingAddress::dCTIDH(_) => {}
        _ => panic!("expected ReceivingAddress::dCTIDH, got {:?}", parsed),
    }
    assert_eq!(ReceivingAddress::from(addr), parsed);
}

/// Alice sends to Bob's CTIDH address; both nodes check balance before/after send and after confirm.
#[tokio::test(flavor = "multi_thread")]
async fn alice_sends_to_bob_dctidh_address() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 5u16;

    let mut base_args = GenesisNode::default_args().await;
    base_args.tx_proving_capability = Some(TxProvingCapability::PrimitiveWitness);

    let [mut alice, mut bob] = GenesisNode::start_connected_cluster(
        &GenesisNode::cluster_id(),
        2,
        Some(base_args),
        timeout_secs,
    )
    .await?;

    let bob_dctidh_address = bob
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::dCTIDH)
        .await?;
    println!("bob_dctidh_address: {}", bob_dctidh_address.to_bech32m(NETWORK).unwrap());

    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(3, false)
        .await?;

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let alice_balances_before_send = alice.gsl.api().wallet().balances(Timestamp::now()).await;
    let payment_amount = NativeCurrencyAmount::coins_from_str("1.0")?;
    let fee_amount = NativeCurrencyAmount::coins_from_str("0.01")?;
    let alice_spend_amount = payment_amount + fee_amount;

    let tx_artifacts = alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(bob_dctidh_address, payment_amount)],
            Default::default(),
            fee_amount,
            Timestamp::now(),
            0,
        )
        .await?;

    let alice_balances_after_send = alice.gsl.api().wallet().balances(Timestamp::now()).await;
    assert_eq!(
        alice_balances_after_send.confirmed_available,
        alice_balances_before_send.confirmed_available
    );
    assert_eq!(
        alice_balances_after_send.unconfirmed_available,
        alice_balances_before_send
            .confirmed_available
            .checked_sub(&alice_spend_amount)
            .unwrap()
    );

    bob.wait_until_unconfirmed_balance(timeout_secs).await?;

    alice
        .wait_until_tx_in_mempool_has_single_proof(tx_artifacts.transaction().txid(), timeout_secs)
        .await?;

    let bob_balances = bob.gsl.api().wallet().balances(Timestamp::now()).await;
    assert_eq!(bob_balances.unconfirmed_available, payment_amount);
    assert!(bob_balances.confirmed_available.is_zero());

    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, true)
        .await?;

    let alice_balances_after_confirmed = alice.gsl.api().wallet().balances(Timestamp::now()).await;
    assert_eq!(
        alice_balances_after_confirmed.confirmed_available,
        alice_balances_after_confirmed.unconfirmed_available
    );

    bob.wait_until_block_height(4, timeout_secs).await?;

    let bob_balances = bob.gsl.api().wallet().balances(Timestamp::now()).await;
    assert_eq!(bob_balances.confirmed_available, payment_amount);
    assert_eq!(bob_balances.unconfirmed_available, payment_amount);

    Ok(())
}

/// Alice sends to Bob's CTIDH bech32m address; both nodes check balance before/after send and after confirm.
#[tokio::test(flavor = "multi_thread")]
async fn alice_sends_to_bob_dctidh_bech32m_address() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 5u16;

    let mut base_args = GenesisNode::default_args().await;
    base_args.tx_proving_capability = Some(TxProvingCapability::PrimitiveWitness);

    let [mut alice, mut bob] = GenesisNode::start_connected_cluster(
        &GenesisNode::cluster_id(),
        2,
        Some(base_args),
        timeout_secs,
    )
    .await?;

    let bob_dctidh_address = bob
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::dCTIDH)
        .await?;

    // Encode to bech32m address and decode back to ReceivingAddress
    let bech32_addr = bob_dctidh_address.to_bech32m(NETWORK)?;
    let bob_dctidh_address_from_bech32 =
        ReceivingAddress::from_bech32m(&bech32_addr, NETWORK).expect("from_bech32m");

    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(3, false)
        .await?;

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let alice_balances_before_send = alice.gsl.api().wallet().balances(Timestamp::now()).await;
    let payment_amount = NativeCurrencyAmount::coins_from_str("1.0")?;
    let fee_amount = NativeCurrencyAmount::coins_from_str("0.01")?;
    let alice_spend_amount = payment_amount + fee_amount;

    let tx_artifacts = alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(bob_dctidh_address_from_bech32, payment_amount)],
            Default::default(),
            fee_amount,
            Timestamp::now(),
            0,
        )
        .await?;

    let alice_balances_after_send = alice.gsl.api().wallet().balances(Timestamp::now()).await;
    assert_eq!(
        alice_balances_after_send.confirmed_available,
        alice_balances_before_send.confirmed_available
    );
    assert_eq!(
        alice_balances_after_send.unconfirmed_available,
        alice_balances_before_send
            .confirmed_available
            .checked_sub(&alice_spend_amount)
            .unwrap()
    );

    bob.wait_until_unconfirmed_balance(timeout_secs).await?;

    alice
        .wait_until_tx_in_mempool_has_single_proof(tx_artifacts.transaction().txid(), timeout_secs)
        .await?;

    let bob_balances = bob.gsl.api().wallet().balances(Timestamp::now()).await;
    assert_eq!(bob_balances.unconfirmed_available, payment_amount);
    assert!(bob_balances.confirmed_available.is_zero());

    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, true)
        .await?;

    let alice_balances_after_confirmed = alice.gsl.api().wallet().balances(Timestamp::now()).await;
    assert_eq!(
        alice_balances_after_confirmed.confirmed_available,
        alice_balances_after_confirmed.unconfirmed_available
    );

    bob.wait_until_block_height(4, timeout_secs).await?;

    let bob_balances = bob.gsl.api().wallet().balances(Timestamp::now()).await;
    assert_eq!(bob_balances.confirmed_available, payment_amount);
    assert_eq!(bob_balances.unconfirmed_available, payment_amount);

    Ok(())
}
