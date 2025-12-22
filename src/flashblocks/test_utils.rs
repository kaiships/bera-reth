use crate::{
    flashblocks::{
        BerachainFlashblockPayload, BerachainFlashblockPayloadBase, BerachainFlashblockPayloadDiff,
        BerachainFlashblockPayloadMetadata,
    },
    primitives::header::BlsPublicKey,
};
use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::{Address, B256, Bloom, Bytes, U256};
use reth::rpc::types::engine::PayloadId;

#[derive(Debug)]
pub struct BerachainTestFlashBlockFactory {
    block_time: u64,
    base_timestamp: u64,
    current_block_number: u64,
}

impl BerachainTestFlashBlockFactory {
    pub fn new() -> Self {
        Self { block_time: 2, base_timestamp: 1_000_000, current_block_number: 100 }
    }

    pub fn with_block_time(mut self, block_time: u64) -> Self {
        self.block_time = block_time;
        self
    }

    pub fn with_base_timestamp(mut self, timestamp: u64) -> Self {
        self.base_timestamp = timestamp;
        self
    }

    pub fn with_block_number(mut self, block_number: u64) -> Self {
        self.current_block_number = block_number;
        self
    }

    pub fn flashblock_at(&self, index: u64) -> BerachainTestFlashBlockBuilder {
        self.builder().index(index).block_number(self.current_block_number)
    }

    pub fn flashblock_after(
        &self,
        previous: &BerachainFlashblockPayload,
    ) -> BerachainTestFlashBlockBuilder {
        let parent_hash =
            previous.base.as_ref().map(|b| b.parent_hash).unwrap_or(previous.diff.block_hash);

        self.builder()
            .index(previous.index + 1)
            .block_number(previous.metadata.block_number)
            .payload_id(previous.payload_id)
            .parent_hash(parent_hash)
            .timestamp(previous.base.as_ref().map(|b| b.timestamp).unwrap_or(self.base_timestamp))
    }

    pub fn flashblock_for_next_block(
        &self,
        previous: &BerachainFlashblockPayload,
    ) -> BerachainTestFlashBlockBuilder {
        let prev_timestamp =
            previous.base.as_ref().map(|b| b.timestamp).unwrap_or(self.base_timestamp);
        let prev_block_number = previous.metadata.block_number;

        self.builder()
            .index(0)
            .block_number(prev_block_number + 1)
            .payload_id(PayloadId::new(B256::random().0[0..8].try_into().unwrap()))
            .parent_hash(previous.diff.block_hash)
            .timestamp(prev_timestamp + self.block_time)
    }

    pub fn builder(&self) -> BerachainTestFlashBlockBuilder {
        BerachainTestFlashBlockBuilder {
            index: 0,
            block_number: self.current_block_number,
            payload_id: PayloadId::new([1u8; 8]),
            parent_hash: B256::random(),
            timestamp: self.base_timestamp,
            base: None,
            block_hash: B256::random(),
            state_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Bloom::default(),
            gas_used: 0,
            gas_limit: 30_000_000,
            transactions: vec![],
            withdrawals: vec![],
            withdrawals_root: B256::ZERO,
            blob_gas_used: None,
            prev_proposer_pubkey: Some(BlsPublicKey::random()),
        }
    }
}

impl Default for BerachainTestFlashBlockFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct BerachainTestFlashBlockBuilder {
    index: u64,
    block_number: u64,
    payload_id: PayloadId,
    parent_hash: B256,
    timestamp: u64,
    base: Option<BerachainFlashblockPayloadBase>,
    block_hash: B256,
    state_root: B256,
    receipts_root: B256,
    logs_bloom: Bloom,
    gas_used: u64,
    gas_limit: u64,
    transactions: Vec<Bytes>,
    withdrawals: Vec<Withdrawal>,
    withdrawals_root: B256,
    blob_gas_used: Option<u64>,
    prev_proposer_pubkey: Option<BlsPublicKey>,
}

impl BerachainTestFlashBlockBuilder {
    pub fn index(mut self, index: u64) -> Self {
        self.index = index;
        self
    }

    pub fn block_number(mut self, block_number: u64) -> Self {
        self.block_number = block_number;
        self
    }

    pub fn payload_id(mut self, payload_id: PayloadId) -> Self {
        self.payload_id = payload_id;
        self
    }

    pub fn parent_hash(mut self, parent_hash: B256) -> Self {
        self.parent_hash = parent_hash;
        self
    }

    pub fn timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }

    #[allow(dead_code)]
    pub fn base(mut self, base: BerachainFlashblockPayloadBase) -> Self {
        self.base = Some(base);
        self
    }

    #[allow(dead_code)]
    pub fn block_hash(mut self, block_hash: B256) -> Self {
        self.block_hash = block_hash;
        self
    }

    #[allow(dead_code)]
    pub fn state_root(mut self, state_root: B256) -> Self {
        self.state_root = state_root;
        self
    }

    #[allow(dead_code)]
    pub fn receipts_root(mut self, receipts_root: B256) -> Self {
        self.receipts_root = receipts_root;
        self
    }

    pub fn transactions(mut self, transactions: Vec<Bytes>) -> Self {
        self.transactions = transactions;
        self
    }

    #[allow(dead_code)]
    pub fn gas_used(mut self, gas_used: u64) -> Self {
        self.gas_used = gas_used;
        self
    }

    #[allow(dead_code)]
    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    pub fn prev_proposer_pubkey(mut self, pubkey: Option<BlsPublicKey>) -> Self {
        self.prev_proposer_pubkey = pubkey;
        self
    }

    pub fn build(mut self) -> BerachainFlashblockPayload {
        if self.index == 0 && self.base.is_none() {
            self.base = Some(BerachainFlashblockPayloadBase {
                parent_hash: self.parent_hash,
                parent_beacon_block_root: B256::random(),
                fee_recipient: Address::default(),
                prev_randao: B256::random(),
                block_number: self.block_number,
                gas_limit: self.gas_limit,
                timestamp: self.timestamp,
                extra_data: Default::default(),
                base_fee_per_gas: U256::from(1_000_000_000u64),
                prev_proposer_pubkey: self.prev_proposer_pubkey,
            });
        }

        BerachainFlashblockPayload {
            index: self.index,
            payload_id: self.payload_id,
            base: self.base,
            diff: BerachainFlashblockPayloadDiff {
                block_hash: self.block_hash,
                state_root: self.state_root,
                receipts_root: self.receipts_root,
                logs_bloom: self.logs_bloom,
                gas_used: self.gas_used,
                transactions: self.transactions,
                withdrawals: self.withdrawals,
                withdrawals_root: self.withdrawals_root,
                blob_gas_used: self.blob_gas_used,
            },
            metadata: BerachainFlashblockPayloadMetadata { block_number: self.block_number },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_optimism_flashblocks::{FlashblockDiff, FlashblockPayload, FlashblockPayloadBase};

    #[test]
    fn test_factory_creates_valid_flashblock_at_index_0() {
        let factory = BerachainTestFlashBlockFactory::new();
        let fb = factory.flashblock_at(0).build();

        assert_eq!(fb.index, 0);
        assert!(fb.base.is_some());
        assert_eq!(fb.base.as_ref().unwrap().block_number, 100);
    }

    #[test]
    fn test_factory_creates_followup_flashblock() {
        let factory = BerachainTestFlashBlockFactory::new();
        let fb0 = factory.flashblock_at(0).build();
        let fb1 = factory.flashblock_after(&fb0).build();

        assert_eq!(fb1.index, 1);
        assert!(fb1.base.is_none());
        assert_eq!(fb1.payload_id, fb0.payload_id);
    }

    #[test]
    fn test_factory_creates_next_block_flashblock() {
        let factory = BerachainTestFlashBlockFactory::new();
        let fb0 = factory.flashblock_at(0).build();
        let fb_next = factory.flashblock_for_next_block(&fb0).build();

        assert_eq!(fb_next.index, 0);
        assert!(fb_next.base.is_some());
        assert_eq!(fb_next.base.as_ref().unwrap().block_number, 101);
        assert_eq!(fb_next.base.as_ref().unwrap().parent_hash, fb0.diff.block_hash);
        assert_ne!(fb_next.payload_id, fb0.payload_id);
    }

    #[test]
    fn test_flashblock_trait_implementations() {
        let factory = BerachainTestFlashBlockFactory::new();
        let fb =
            factory.flashblock_at(0).transactions(vec![Bytes::from_static(&[1, 2, 3])]).build();

        assert_eq!(fb.index(), 0);
        assert_eq!(fb.block_number(), 100);
        assert!(fb.base().is_some());

        let base = fb.base().unwrap();
        assert_eq!(base.block_number(), 100);
        assert_eq!(base.timestamp(), 1_000_000);

        let diff = fb.diff();
        assert_eq!(diff.transactions_raw().len(), 1);
        assert_eq!(diff.gas_used(), 0);
    }

    #[test]
    fn test_berachain_specific_fields() {
        let factory = BerachainTestFlashBlockFactory::new();
        let pubkey = BlsPublicKey::random();
        let fb = factory.flashblock_at(0).prev_proposer_pubkey(Some(pubkey)).build();

        assert_eq!(fb.base.as_ref().unwrap().prev_proposer_pubkey, Some(pubkey));
    }
}
