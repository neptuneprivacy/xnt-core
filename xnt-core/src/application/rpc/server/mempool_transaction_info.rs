use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Tip5;

use crate::api::export::NativeCurrencyAmount;
use crate::api::export::Transaction;
use crate::api::export::TransactionKernelId;
use crate::api::export::TransactionProof;
use crate::api::export::TransactionProofType;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MempoolTransactionInfo {
    pub id: TransactionKernelId,
    pub proof_type: TransactionProofType,
    pub num_inputs: usize,
    pub inputs: Vec<String>,
    pub num_outputs: usize,
    pub outputs: Vec<String>,
    pub positive_balance_effect: NativeCurrencyAmount,
    pub negative_balance_effect: NativeCurrencyAmount,
    pub fee: NativeCurrencyAmount,
    pub synced: bool,
}

impl From<&Transaction> for MempoolTransactionInfo {
    fn from(mptx: &Transaction) -> Self {
        MempoolTransactionInfo {
            id: mptx.kernel.txid(),
            proof_type: match mptx.proof {
                TransactionProof::Witness(_) => TransactionProofType::PrimitiveWitness,
                TransactionProof::SingleProof(_) => TransactionProofType::SingleProof,
                TransactionProof::ProofCollection(_) => TransactionProofType::ProofCollection,
            },
            num_inputs: mptx.kernel.inputs.len(),
            inputs: mptx
                .kernel
                .inputs
                .iter()
                .map(|input| Tip5::hash(&input.absolute_indices).to_hex())
                .collect(),
            num_outputs: mptx.kernel.outputs.len(),
            outputs: mptx
                .kernel
                .outputs
                .iter()
                .map(|output| output.canonical_commitment.to_hex())
                .collect(),
            positive_balance_effect: NativeCurrencyAmount::zero(),
            negative_balance_effect: NativeCurrencyAmount::zero(),
            fee: mptx.kernel.fee,
            synced: false,
        }
    }
}

impl MempoolTransactionInfo {
    pub(crate) fn with_positive_effect_on_balance(
        mut self,
        positive_balance_effect: NativeCurrencyAmount,
    ) -> Self {
        self.positive_balance_effect = positive_balance_effect;
        self
    }

    pub(crate) fn with_negative_effect_on_balance(
        mut self,
        negative_balance_effect: NativeCurrencyAmount,
    ) -> Self {
        self.negative_balance_effect = negative_balance_effect;
        self
    }

    pub fn synced(mut self) -> Self {
        self.synced = true;
        self
    }
}

#[cfg(feature = "mock-rpc")]
impl rand::distr::Distribution<MempoolTransactionInfo> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> MempoolTransactionInfo {
        use tasm_lib::prelude::Digest;
        MempoolTransactionInfo {
            id: rng.random(),
            proof_type: rng.random(),
            num_inputs: rng.random_range(0..10),
            inputs: (0..5).map(|_| rng.random::<Digest>().to_hex()).collect(),
            num_outputs: rng.random_range(0..10),
            outputs: (0..5).map(|_| rng.random::<Digest>().to_hex()).collect(),
            positive_balance_effect: rng
                .random::<NativeCurrencyAmount>()
                .lossy_f64_fraction_mul(0.0001),
            negative_balance_effect: rng
                .random::<NativeCurrencyAmount>()
                .lossy_f64_fraction_mul(0.0001),
            fee: rng
                .random::<NativeCurrencyAmount>()
                .lossy_f64_fraction_mul(0.0001),
            synced: rng.random(),
        }
    }
}
