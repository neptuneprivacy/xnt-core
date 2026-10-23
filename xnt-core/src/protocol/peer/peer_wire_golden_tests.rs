//! Golden files of the transaction frames across versions: the
//! `TransferTransaction`, and the `PeerMessage` frames that carry a
//! transaction and its notification.
//!
//! The files in `test_data/peer_wire/` were written by the previous release
//! (v0.2.5), which main net runs until the `UpgradeVMv8` fork, with its
//! harness. Both directions are covered: the frames of the previous release
//! decode here and encode to the same bytes, and this version encodes the same
//! transactions to the same bytes, which the previous release decodes and
//! encodes alike (its harness checks the frames that
//! [`write_frames_of_this_version`] writes).
//!
//! The transactions carry mock or placeholder proofs and a deterministic
//! kernel, which holds commitments, index sets and one authenticated chunk,
//! no keys.

use std::path::PathBuf;

use bincode::Options;
use proptest::prelude::Strategy;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;

use crate::application::loops::connect_to_peers::MAX_PEER_FRAME_LENGTH_IN_BYTES;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::peer::transaction_notification::TransactionNotification;
use crate::protocol::peer::transfer_transaction::TransferTransaction;
use crate::protocol::peer::PeerMessage;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::tests::shared::files::test_helper_data_dir;
use crate::util_types::mutator_set::removal_record::chunk_dictionary::ChunkDictionary;

fn golden_dir() -> PathBuf {
    test_helper_data_dir().join("peer_wire")
}

fn read(name: &str) -> Vec<u8> {
    let path = golden_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The encoding of the peer connection codec, see `get_bincode_codec`.
fn wire_options() -> impl Options {
    bincode::DefaultOptions::new().with_limit(MAX_PEER_FRAME_LENGTH_IN_BYTES as u64)
}

/// A transaction with a mock proof collection and one with a short
/// placeholder single proof, of the same deterministic kernel. Neither proof
/// is valid; the frames carry them as bytes. The harness of the previous
/// release makes the same.
fn transactions() -> [(&'static str, Transaction); 2] {
    let mut primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 1)
        .new_tree(&mut TestRunner::deterministic())
        .unwrap()
        .current();

    // One authenticated chunk, of the first input, keeps the files small and
    // still covers the encoding of chunk dictionaries.
    let mut inputs = primitive_witness.kernel.inputs.clone();
    for (i, removal_record) in inputs.iter_mut().enumerate() {
        let kept = if i == 0 {
            removal_record
                .target_chunks
                .dictionary
                .iter()
                .take(1)
                .cloned()
                .collect()
        } else {
            vec![]
        };
        removal_record.target_chunks = ChunkDictionary::new(kept);
    }
    primitive_witness.kernel = TransactionKernelModifier::default()
        .inputs(inputs)
        .modify(primitive_witness.kernel);

    let proof_collection = ProofCollection::produce_mock(&primitive_witness, true);
    [
        (
            "pc",
            Transaction {
                kernel: primitive_witness.kernel.clone(),
                proof: TransactionProof::ProofCollection(proof_collection),
            },
        ),
        (
            "sp",
            Transaction {
                kernel: primitive_witness.kernel.clone(),
                proof: TransactionProof::SingleProof(Proof::invalid_with_size(8)),
            },
        ),
    ]
}

/// The frames of a transaction, by file name.
fn frames(prefix: &str, transaction: &Transaction) -> [(String, Vec<u8>); 3] {
    let transfer = TransferTransaction::try_from(transaction).unwrap();
    let notification = TransactionNotification::try_from(transaction).unwrap();
    [
        (
            format!("{prefix}_transfer_transaction.bin"),
            bincode::serialize(&transfer).unwrap(),
        ),
        (
            format!("{prefix}_peer_message_transaction.bin"),
            wire_options()
                .serialize(&PeerMessage::Transaction(Box::new(transfer)))
                .unwrap(),
        ),
        (
            format!("{prefix}_peer_message_transaction_notification.bin"),
            wire_options()
                .serialize(&PeerMessage::TransactionNotification(notification))
                .unwrap(),
        ),
    ]
}

/// The line of the kernels file that names a transaction's kernel.
fn kernel_line(prefix: &str, transfer: &TransferTransaction) -> String {
    format!(
        "{prefix} txid={} mast_hash={}\n",
        transfer.kernel.txid(),
        transfer.kernel.mast_hash().to_hex()
    )
}

/// The frames of the previous release decode, encode to the same bytes, and
/// name the kernel it recorded; the transaction converts back and forth, and
/// its notification is the one this version makes.
#[test]
fn frames_of_the_previous_release_decode_and_encode_identically() {
    let kernels = String::from_utf8(read("kernels.txt")).unwrap();
    for prefix in ["pc", "sp"] {
        let transfer_bytes = read(&format!("{prefix}_transfer_transaction.bin"));
        let transfer: TransferTransaction = bincode::deserialize(&transfer_bytes).unwrap();
        assert_eq!(
            transfer_bytes,
            bincode::serialize(&transfer).unwrap(),
            "{prefix}"
        );
        assert!(
            kernels.contains(&kernel_line(prefix, &transfer)),
            "{prefix}: kernel"
        );

        let message_bytes = read(&format!("{prefix}_peer_message_transaction.bin"));
        let message: PeerMessage = wire_options().deserialize(&message_bytes).unwrap();
        assert_eq!(
            message_bytes,
            wire_options().serialize(&message).unwrap(),
            "{prefix}"
        );
        let PeerMessage::Transaction(wire_transfer) = message else {
            panic!("{prefix}: expected a transaction");
        };
        assert_eq!(transfer, *wire_transfer, "{prefix}");

        let transaction = Transaction::from(transfer.clone());
        assert_eq!(
            transfer,
            TransferTransaction::try_from(&transaction).unwrap(),
            "{prefix}"
        );
        let notification_bytes = read(&format!(
            "{prefix}_peer_message_transaction_notification.bin"
        ));
        let notification_message: PeerMessage =
            wire_options().deserialize(&notification_bytes).unwrap();
        assert_eq!(
            notification_bytes,
            wire_options().serialize(&notification_message).unwrap(),
            "{prefix}"
        );
        let PeerMessage::TransactionNotification(notification) = notification_message else {
            panic!("{prefix}: expected a transaction notification");
        };
        assert_eq!(
            TransactionNotification::try_from(&transaction).unwrap(),
            notification,
            "{prefix}"
        );
    }
}

/// This version encodes the transactions that the previous release encoded
/// into the files to the same bytes.
#[test]
fn this_version_encodes_the_frames_as_the_previous_release() {
    let kernels = String::from_utf8(read("kernels.txt")).unwrap();
    for (prefix, transaction) in transactions() {
        for (name, bytes) in frames(prefix, &transaction) {
            assert_eq!(read(&name), bytes, "{name}");
        }
        let transfer = TransferTransaction::try_from(&transaction).unwrap();
        assert!(
            kernels.contains(&kernel_line(prefix, &transfer)),
            "{prefix}"
        );
    }
}

/// Write this version's frames to the directory named by `P6_GOLDEN_DIR`, for
/// the harness of the previous release to check.
#[ignore = "writes the frames of this version to P6_GOLDEN_DIR"]
#[test]
fn write_frames_of_this_version() {
    let dir = PathBuf::from(std::env::var("P6_GOLDEN_DIR").expect("P6_GOLDEN_DIR"));
    std::fs::create_dir_all(&dir).unwrap();
    let mut kernels = String::new();
    for (prefix, transaction) in transactions() {
        for (name, bytes) in frames(prefix, &transaction) {
            std::fs::write(dir.join(name), bytes).unwrap();
        }
        let transfer = TransferTransaction::try_from(&transaction).unwrap();
        kernels.push_str(&kernel_line(prefix, &transfer));
    }
    std::fs::write(dir.join("kernels.txt"), kernels).unwrap();
}
