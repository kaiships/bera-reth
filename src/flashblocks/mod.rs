use crate::{primitives::header::BlsPublicKey, transaction::BerachainTxEnvelope};
use alloy_consensus::{crypto::RecoveryError, transaction::Recovered};
use alloy_eips::{
    eip2718::WithEncoded,
    eip4895::{Withdrawal, Withdrawals},
};
use alloy_primitives::{Address, B256, Bloom, Bytes, U256};
use reth::rpc::types::engine::PayloadId;
use reth_optimism_flashblocks::{FlashblockDiff, FlashblockPayload, FlashblockPayloadBase};

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BerachainFlashblockPayloadBase {
    /// Parent beacon block root.
    pub parent_beacon_block_root: B256,
    /// Hash of the parent block.
    pub parent_hash: B256,
    /// Address that receives fees for this block.
    pub fee_recipient: Address,
    /// The previous randao value.
    pub prev_randao: B256,
    /// Block number.
    #[serde(with = "alloy_serde::quantity")]
    pub block_number: u64,
    /// Gas limit for this block.
    #[serde(with = "alloy_serde::quantity")]
    pub gas_limit: u64,
    /// Block timestamp.
    #[serde(with = "alloy_serde::quantity")]
    pub timestamp: u64,
    /// Extra data for the block.
    pub extra_data: Bytes,
    /// Base fee per gas for this block.
    pub base_fee_per_gas: U256,
    /// Berachain specific BlsPublicKey
    pub prev_proposer_pubkey: Option<BlsPublicKey>,
}

impl FlashblockPayloadBase for BerachainFlashblockPayloadBase {
    fn parent_hash(&self) -> B256 {
        self.parent_hash
    }

    fn block_number(&self) -> u64 {
        self.block_number
    }

    fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BerachainFlashblockPayloadDiff {
    /// The state root of the block.
    pub state_root: B256,
    /// The receipts root of the block.
    pub receipts_root: B256,
    /// The logs bloom of the block.
    pub logs_bloom: Bloom,
    /// The gas used of the block.
    #[serde(with = "alloy_serde::quantity")]
    pub gas_used: u64,
    /// The block hash of the block.
    pub block_hash: B256,
    /// The transactions of the block.
    pub transactions: Vec<Bytes>,
    /// Array of [`Withdrawal`] enabled with V2
    pub withdrawals: Vec<Withdrawal>,
    /// The withdrawals root of the block.
    pub withdrawals_root: B256,
    /// The estimated cumulative blob gas used for the block. Introduced in Jovian.
    /// spec: <https://docs.optimism.io/notices/upgrade-17#block-header-changes>
    /// Defaults to 0 if not present (for pre-Jovian blocks).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "alloy_serde::quantity::opt")]
    pub blob_gas_used: Option<u64>,
}

impl FlashblockDiff for BerachainFlashblockPayloadDiff {
    fn block_hash(&self) -> B256 {
        self.block_hash
    }

    fn state_root(&self) -> B256 {
        self.state_root
    }

    fn gas_used(&self) -> u64 {
        self.gas_used
    }

    fn logs_bloom(&self) -> &Bloom {
        &self.logs_bloom
    }

    fn receipts_root(&self) -> B256 {
        self.receipts_root
    }

    fn transactions_raw(&self) -> &[Bytes] {
        &self.transactions
    }

    fn withdrawals(&self) -> Option<&Withdrawals> {
        None
    }

    fn withdrawals_root(&self) -> Option<B256> {
        None
    }
}

// Note: this uses mixed camel, snake case: <https://github.com/flashbots/rollup-boost/blob/dd12e8e8366004b4758bfa0cfa98efa6929b7e9f/crates/flashblocks-rpc/src/cache.rs#L31>

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BerachainFlashblockPayload {
    pub payload_id: PayloadId,
    pub index: u64,
    pub base: Option<BerachainFlashblockPayloadBase>,
    pub diff: BerachainFlashblockPayloadDiff,
    // pub metadata: OpFlashblockPayloadMetadata,
}

impl FlashblockPayload for BerachainFlashblockPayload {
    type Base = BerachainFlashblockPayloadBase;
    type Diff = BerachainFlashblockPayloadDiff;
    type SignedTx = BerachainTxEnvelope;

    fn index(&self) -> u64 {
        self.index
    }

    fn payload_id(&self) -> PayloadId {
        self.payload_id
    }

    fn base(&self) -> Option<Self::Base> {
        self.base.clone()
    }

    fn diff(&self) -> &Self::Diff {
        &self.diff
    }

    fn block_number(&self) -> u64 {
        self.base.as_ref().map(|b| b.block_number()).unwrap_or(0)
    }

    fn recover_transactions(
        &self,
    ) -> impl Iterator<Item = Result<WithEncoded<Recovered<Self::SignedTx>>, RecoveryError>> {
        std::iter::from_fn(|| todo!("implement transaction recovery"))
    }
}
