//! Integration tests for dCTIDH (CTIDH) addresses.
//!
//! Verifies bech32m encoding (long form) roundtrip and parsing.

mod common;

use bech32;
use bech32::FromBase32;
use bech32::ToBase32;
use common::genesis_node::GenesisNode;
use common::logging;
use neptune_privacy::api::export::Digest;
use neptune_privacy::api::export::KeyType;
use neptune_privacy::api::export::NativeCurrencyAmount;
use neptune_privacy::api::export::Network;
use neptune_privacy::api::export::ReceivingAddress;
use neptune_privacy::api::export::Timestamp;
use neptune_privacy::api::export::TxProvingCapability;
use neptune_privacy::state::wallet::address::dctidh_address::{
    dCTIDHReceivingAddress, dCTIDHSpendingKey, CTIDH_ADDRESS_MAX_BECH32M_LEN,
};
use num_traits::ops::checked::CheckedSub;
use num_traits::Zero;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;

const NETWORK: Network = Network::Testnet(0);

/// Replace the bytes of a bech32m-encoded address payload, keeping its prefix.
fn with_payload_bytes(encoded: &str, replace: impl FnOnce(&mut Vec<u8>)) -> String {
    let (hrp, data, variant) = bech32::decode(encoded).unwrap();
    let mut payload = Vec::<u8>::from_base32(&data).unwrap();
    replace(&mut payload);
    bech32::encode(&hrp, payload.to_base32(), variant).unwrap()
}

/// The lock preimage that versions before v0.3 derived from a public key.
fn legacy_lock_preimage(public_key: &[u8]) -> Digest {
    let mut padded = public_key.to_vec();
    padded.resize(public_key.len().div_ceil(8) * 8, 0);
    let mut bfes = vec![BFieldElement::new(public_key.len() as u64)];
    for chunk in padded.chunks(8) {
        let int = u64::from_be_bytes(chunk.try_into().unwrap());
        if int < BFieldElement::P - 1 {
            bfes.push(BFieldElement::new(int));
        } else {
            bfes.push(BFieldElement::new(BFieldElement::P - 1));
            bfes.push(BFieldElement::new(int & 0xffff_ffff));
        }
    }
    Tip5::hash_varlen(&bfes)
}

/// The address of the dCTIDH key derived from `seed`, but with the
/// legacy-format lock of its public key, the way versions before v0.3 encoded
/// addresses.
fn legacy_format_address(seed: Digest) -> String {
    let address = dCTIDHSpendingKey::derive_from_seed(seed).to_address();
    let encoded = address.to_bech32m(NETWORK).unwrap();
    let mut public_key = Vec::new();
    with_payload_bytes(&encoded, |payload| public_key = payload[..64].to_vec());
    let legacy_lock = legacy_lock_preimage(&public_key).hash();
    with_payload_bytes(&encoded, |payload| {
        for (i, limb) in legacy_lock.values().iter().enumerate() {
            payload[64 + 8 * i..72 + 8 * i].copy_from_slice(&limb.value().to_le_bytes());
        }
    })
}

/// A dCTIDH address whose public key bytes do not encode a valid curve.
fn address_with_invalid_public_key(network: Network) -> String {
    let address = dCTIDHSpendingKey::derive_from_seed(rand::random()).to_address();
    let encoded = address.to_bech32m(network).unwrap();
    with_payload_bytes(&encoded, |payload| payload[..64].fill(0xff))
}

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

    let decoded_dctidh =
        dCTIDHReceivingAddress::from_bech32m(&long, NETWORK).expect("from_bech32m");
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
    println!(
        "bob_dctidh_address: {}",
        bob_dctidh_address.to_bech32m(NETWORK).unwrap()
    );

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
            None,
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
            None,
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

/// An address that carries a legacy-format lock is not accepted.
#[test]
fn address_with_legacy_lock_is_refused() {
    let seed: Digest = rand::random();
    let legacy = legacy_format_address(seed);
    assert!(dCTIDHReceivingAddress::from_bech32m(&legacy, NETWORK).is_err());
    assert!(ReceivingAddress::from_bech32m(&legacy, NETWORK).is_err());

    // with the current-format lock, the same public key is accepted
    let current = dCTIDHSpendingKey::derive_from_seed(seed)
        .to_address()
        .to_bech32m(NETWORK)
        .unwrap();
    assert!(ReceivingAddress::from_bech32m(&current, NETWORK).is_ok());
}

/// Field elements in the address payload must be canonical.
#[test]
fn address_with_non_canonical_limb_is_refused() {
    let address = dCTIDHSpendingKey::derive_from_seed(rand::random()).to_address();
    let encoded = address.to_bech32m(NETWORK).unwrap();
    let non_canonical = with_payload_bytes(&encoded, |payload| payload[96..104].fill(0xff));
    assert!(ReceivingAddress::from_bech32m(&non_canonical, NETWORK).is_err());
}

/// Sending to an address whose public key is invalid fails with an error
/// before any proof is produced, and the node keeps running.
#[tokio::test(flavor = "multi_thread")]
async fn send_to_address_with_invalid_public_key_fails() -> anyhow::Result<()> {
    logging::tracing_logger();

    let mut node = GenesisNode::start_default_node().await?;
    node.gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(3, false)
        .await?;

    let address = address_with_invalid_public_key(Network::RegTest);
    let receiving_address = ReceivingAddress::from_bech32m(&address, Network::RegTest)?;
    assert!(receiving_address.validate_as_recipient().is_err());

    let result = node
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(
                receiving_address,
                NativeCurrencyAmount::coins_from_str("1.0")?,
            )],
            Default::default(),
            NativeCurrencyAmount::coins_from_str("0.01")?,
            Timestamp::now(),
            0,
            None,
        )
        .await;
    let error = result.expect_err("sending to an invalid public key must fail");
    assert!(error.to_string().contains("invalid public key"), "{error}");

    assert!(!node.main_loop_join_handle.is_finished());
    Ok(())
}
