mod common;

use std::fs::File;
use std::io::Write;

use common::logging;
use neptune_privacy::api::export::BlockHeight;
use neptune_privacy::api::export::NativeCurrencyAmount;
use neptune_privacy::api::export::Network;
use neptune_privacy::api::export::Timestamp;
use neptune_privacy::protocol::consensus::block::Block;
use tasm_lib::twenty_first::bfe;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;

use crate::common::fetch_files::test_helper_data_dir;
use crate::common::fetch_files::try_fetch_file_from_server;
use crate::common::genesis_node::GenesisNode;

/// test: Verify that the genesis block on main net has not changed.
#[test]
pub fn genesis_block_hasnt_changed_main_net() {
    assert_eq!(
        "3b012c9abf353d9201bc3328391bbd0d43c5edb91da1085be15a3fc52ad55f65ea115d255922b5a4",
        Block::genesis(Network::Main).hash().to_hex()
    );
}

/// test: Verify that the genesis block on testnet-0 has not changed.
#[test]
pub fn genesis_block_hasnt_changed_testnet_0() {
    assert_eq!(
        "fa3cd0f699c963923ad4f60a312ede9c13136c1d1f45c629e90420a57821fd333ac6bc82e591a00f",
        Block::genesis(Network::Testnet(0)).hash().to_hex()
    );
}

/// test: Verify that first ~250 blocks on main net are still considered valid,
/// and that a global state can be restored from it.
#[ignore = "replays Neptune Cash block files; no XNT main net block files are published"]
#[tokio::test(flavor = "multi_thread")]
async fn can_restore_from_real_mainnet_data_with_reorganizations() {
    logging::tracing_logger();

    let expected_blk_files = ["blk0.dat", "blk1.dat"];

    let network = Network::Main;
    let cli = GenesisNode::default_args_with_network_and_devnet_wallet(network).await;
    let mut alice = GenesisNode::start_node(cli).await.unwrap();

    let mut state = alice.gsl.lock_guard_mut().await;

    // Are the required blk files present on disk? If not, fetch them
    // from a server.
    let test_data_dir = test_helper_data_dir();
    for blk_file_name in expected_blk_files {
        let mut path = test_data_dir.clone();
        path.push(blk_file_name);
        if File::open(&path).is_err() {
            // Try fetching file from server and write it to disk.
            let (file, _server) = try_fetch_file_from_server(blk_file_name.to_owned())
                .unwrap_or_else(|| panic!("File {blk_file_name} must be available from a server"));
            let mut f = File::create_new(&path).unwrap();
            f.write_all(&file).unwrap();
        }
    }

    let validate_blocks = true;
    state
        .import_blocks_from_directory(&test_data_dir, 0, validate_blocks)
        .await
        .unwrap();
    let restored_block_height = state.chain.light_state().header().height;
    println!("restored_block_height: {restored_block_height}");
    assert_eq!(
        BlockHeight::new(bfe!(250)),
        restored_block_height,
        "Expected block height not reached in state-recovery. Reached: {restored_block_height}"
    );

    // Verify that wallet state was handled correctly, that balance is still
    // premine reward, since the devnet reward was not spent during first
    // blocks.
    let wallet_status = state.get_wallet_status_for_tip().await;
    let balance = wallet_status.available_confirmed(network.launch_date() + Timestamp::months(7));
    assert_eq!(
        NativeCurrencyAmount::coins(20),
        balance,
        "Expected balance must be available after state-recovery"
    );
}
