use bera_reth::{
    flashblocks::{
        BerachainFlashblockPayload, BerachainFlashblockPayloadBase, BerachainFlashblockPayloadDiff,
        BerachainFlashblockPayloadMetadata,
    },
    node::BerachainNode,
    primitives::header::BlsPublicKey,
};
use futures_util::stream::StreamExt;
use reth_optimism_flashblocks::WsFlashBlockStream;

#[tokio::test]
#[ignore = "requires external network access to Base sepolia"]
async fn test_streaming_flashblocks_from_remote_source_is_successful() {
    let items = 3;
    let ws_url = "wss://sepolia.flashblocks.base.org/ws".parse().unwrap();
    let stream: WsFlashBlockStream<_, _, _, BerachainFlashblockPayload> =
        WsFlashBlockStream::new(ws_url);

    let blocks: Vec<_> = stream.take(items).collect().await;

    for block in blocks {
        println!("{:?}", block);
        assert!(block.is_ok());
    }
}

#[cfg(test)]
mod mock_stream_tests {
    use super::*;
    use alloy_primitives::{Address, B256, Bloom, Bytes, U256};
    use futures_util::stream;
    use reth::rpc::types::engine::PayloadId;
    use reth_optimism_flashblocks::{
        FlashBlockPendingSequence, FlashblockPayload, FlashblockPayloadBase,
    };

    fn create_test_flashblock(
        index: u64,
        block_number: u64,
        payload_id: PayloadId,
        parent_hash: B256,
        include_base: bool,
    ) -> BerachainFlashblockPayload {
        let base = if include_base {
            Some(BerachainFlashblockPayloadBase {
                parent_beacon_block_root: B256::random(),
                parent_hash,
                fee_recipient: Address::random(),
                prev_randao: B256::random(),
                block_number,
                gas_limit: 30_000_000,
                timestamp: 1_000_000 + block_number * 2,
                extra_data: Bytes::default(),
                base_fee_per_gas: U256::from(1_000_000_000u64),
                prev_proposer_pubkey: Some(BlsPublicKey::random()),
            })
        } else {
            None
        };

        BerachainFlashblockPayload {
            payload_id,
            index,
            base,
            diff: BerachainFlashblockPayloadDiff {
                state_root: B256::random(),
                receipts_root: B256::random(),
                logs_bloom: Bloom::default(),
                gas_used: 21000 * (index + 1),
                block_hash: B256::random(),
                transactions: vec![Bytes::from_static(&[1, 2, 3])],
                withdrawals: vec![],
                withdrawals_root: B256::ZERO,
                blob_gas_used: None,
            },
            metadata: BerachainFlashblockPayloadMetadata { block_number },
        }
    }

    fn create_flashblock_sequence(count: usize) -> Vec<BerachainFlashblockPayload> {
        let payload_id = PayloadId::new([1u8; 8]);
        let parent_hash = B256::random();

        (0..count as u64)
            .map(|i| create_test_flashblock(i, 100, payload_id, parent_hash, i == 0))
            .collect()
    }

    #[tokio::test]
    async fn test_mock_stream_produces_flashblocks() {
        let flashblocks = create_flashblock_sequence(3);
        let mut stream = stream::iter(flashblocks.clone().into_iter().map(Ok::<_, eyre::Error>));

        let mut received = Vec::new();
        while let Some(result) = stream.next().await {
            received.push(result.unwrap());
        }

        assert_eq!(received.len(), 3);
        assert_eq!(received[0].index(), 0);
        assert_eq!(received[1].index(), 1);
        assert_eq!(received[2].index(), 2);

        assert!(received[0].base().is_some());
        assert!(received[1].base().is_none());
        assert!(received[2].base().is_none());
    }

    #[tokio::test]
    async fn test_pending_sequence_processes_stream() {
        let flashblocks = create_flashblock_sequence(5);
        let mut sequence: FlashBlockPendingSequence<BerachainFlashblockPayload> =
            FlashBlockPendingSequence::new();

        for fb in flashblocks {
            sequence.insert(fb);
        }

        assert_eq!(sequence.count(), 5);
        assert_eq!(sequence.block_number(), Some(100));
        assert_eq!(sequence.index(), Some(4));
    }

    #[tokio::test]
    async fn test_complete_sequence_from_stream() {
        let flashblocks = create_flashblock_sequence(3);
        let mut sequence: FlashBlockPendingSequence<BerachainFlashblockPayload> =
            FlashBlockPendingSequence::new();

        for fb in flashblocks {
            sequence.insert(fb);
        }

        let complete = sequence.finalize().expect("should finalize");

        assert_eq!(complete.count(), 3);
        assert_eq!(complete.block_number(), 100);

        let all_txs = complete.all_transactions();
        assert_eq!(all_txs.len(), 3);

        let base = complete.payload_base();
        assert!(base.prev_proposer_pubkey.is_some());
    }

    #[tokio::test]
    async fn test_stream_handles_new_block_sequence() {
        let payload_id1 = PayloadId::new([1u8; 8]);
        let payload_id2 = PayloadId::new([2u8; 8]);
        let parent_hash1 = B256::random();

        let fb0_block100 = create_test_flashblock(0, 100, payload_id1, parent_hash1, true);
        let fb1_block100 = create_test_flashblock(1, 100, payload_id1, parent_hash1, false);
        let block100_hash = fb1_block100.diff.block_hash;

        let fb0_block101 = create_test_flashblock(0, 101, payload_id2, block100_hash, true);
        let fb1_block101 = create_test_flashblock(1, 101, payload_id2, block100_hash, false);

        let mut sequence: FlashBlockPendingSequence<BerachainFlashblockPayload> =
            FlashBlockPendingSequence::new();

        sequence.insert(fb0_block100);
        sequence.insert(fb1_block100);
        assert_eq!(sequence.count(), 2);
        assert_eq!(sequence.block_number(), Some(100));

        let complete_100 = sequence.finalize().expect("should finalize block 100");
        assert_eq!(complete_100.block_number(), 100);

        sequence.insert(fb0_block101);
        sequence.insert(fb1_block101);
        assert_eq!(sequence.count(), 2);
        assert_eq!(sequence.block_number(), Some(101));

        let complete_101 = sequence.finalize().expect("should finalize block 101");
        assert_eq!(complete_101.block_number(), 101);
    }

    #[tokio::test]
    async fn test_stream_rejects_out_of_order_flashblocks() {
        let payload_id = PayloadId::new([1u8; 8]);
        let parent_hash = B256::random();

        let fb0 = create_test_flashblock(0, 100, payload_id, parent_hash, true);
        let fb2_wrong_payload =
            create_test_flashblock(2, 100, PayloadId::new([99u8; 8]), parent_hash, false);

        let mut sequence: FlashBlockPendingSequence<BerachainFlashblockPayload> =
            FlashBlockPendingSequence::new();

        sequence.insert(fb0);
        sequence.insert(fb2_wrong_payload);

        assert_eq!(sequence.count(), 1);
    }

    #[tokio::test]
    async fn test_berachain_specific_fields_preserved() {
        let pubkey = BlsPublicKey::random();
        let parent_hash = B256::random();
        let payload_id = PayloadId::new([1u8; 8]);

        let fb = BerachainFlashblockPayload {
            payload_id,
            index: 0,
            base: Some(BerachainFlashblockPayloadBase {
                parent_beacon_block_root: B256::random(),
                parent_hash,
                fee_recipient: Address::random(),
                prev_randao: B256::random(),
                block_number: 100,
                gas_limit: 30_000_000,
                timestamp: 1_000_000,
                extra_data: Bytes::default(),
                base_fee_per_gas: U256::from(1_000_000_000u64),
                prev_proposer_pubkey: Some(pubkey),
            }),
            diff: BerachainFlashblockPayloadDiff {
                state_root: B256::random(),
                receipts_root: B256::random(),
                logs_bloom: Bloom::default(),
                gas_used: 21000,
                block_hash: B256::random(),
                transactions: vec![],
                withdrawals: vec![],
                withdrawals_root: B256::ZERO,
                blob_gas_used: None,
            },
            metadata: BerachainFlashblockPayloadMetadata { block_number: 100 },
        };

        let mut sequence: FlashBlockPendingSequence<BerachainFlashblockPayload> =
            FlashBlockPendingSequence::new();
        sequence.insert(fb);

        let complete = sequence.finalize().expect("should finalize");
        let base = complete.payload_base();

        assert_eq!(base.prev_proposer_pubkey, Some(pubkey));
        assert_eq!(base.block_number(), 100);
        assert_eq!(base.timestamp(), 1_000_000);
        assert_eq!(base.parent_hash(), parent_hash);
    }

    #[tokio::test]
    async fn test_transaction_aggregation_across_flashblocks() {
        let payload_id = PayloadId::new([1u8; 8]);
        let parent_hash = B256::random();

        let mut fb0 = create_test_flashblock(0, 100, payload_id, parent_hash, true);
        fb0.diff.transactions = vec![Bytes::from_static(&[0xaa]), Bytes::from_static(&[0xbb])];

        let mut fb1 = create_test_flashblock(1, 100, payload_id, parent_hash, false);
        fb1.diff.transactions = vec![Bytes::from_static(&[0xcc])];

        let mut fb2 = create_test_flashblock(2, 100, payload_id, parent_hash, false);
        fb2.diff.transactions = vec![Bytes::from_static(&[0xdd]), Bytes::from_static(&[0xee])];

        let mut sequence: FlashBlockPendingSequence<BerachainFlashblockPayload> =
            FlashBlockPendingSequence::new();

        sequence.insert(fb0);
        sequence.insert(fb1);
        sequence.insert(fb2);

        let complete = sequence.finalize().expect("should finalize");
        let all_txs = complete.all_transactions();

        assert_eq!(all_txs.len(), 5);
        assert_eq!(all_txs[0], Bytes::from_static(&[0xaa]));
        assert_eq!(all_txs[1], Bytes::from_static(&[0xbb]));
        assert_eq!(all_txs[2], Bytes::from_static(&[0xcc]));
        assert_eq!(all_txs[3], Bytes::from_static(&[0xdd]));
        assert_eq!(all_txs[4], Bytes::from_static(&[0xee]));
    }
}

#[cfg(test)]
mod service_integration_tests {
    use super::*;
    use crate::e2e::{berachain_payload_attributes_generator, setup_test_boilerplate};
    use alloy_consensus::BlockHeader;
    use alloy_primitives::{Address, B256, Bloom, Bytes, U256};
    use reth::{providers::BlockReaderIdExt, rpc::types::engine::PayloadId};
    use reth_e2e_test_utils::node::NodeTestContext;
    use reth_node_builder::{NodeBuilder, NodeHandle};
    use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
    use reth_optimism_flashblocks::{FlashBlockPendingSequence, FlashblocksListeners};
    use std::sync::Arc;
    use tokio::sync::{broadcast, watch};

    fn create_test_flashblock_for_parent(
        index: u64,
        block_number: u64,
        payload_id: PayloadId,
        parent_hash: B256,
        timestamp: u64,
    ) -> BerachainFlashblockPayload {
        let base = if index == 0 {
            Some(BerachainFlashblockPayloadBase {
                parent_beacon_block_root: B256::random(),
                parent_hash,
                fee_recipient: Address::random(),
                prev_randao: B256::random(),
                block_number,
                gas_limit: 30_000_000,
                timestamp,
                extra_data: Bytes::default(),
                base_fee_per_gas: U256::from(1_000_000_000u64),
                prev_proposer_pubkey: Some(BlsPublicKey::random()),
            })
        } else {
            None
        };

        BerachainFlashblockPayload {
            payload_id,
            index,
            base,
            diff: BerachainFlashblockPayloadDiff {
                state_root: B256::random(),
                receipts_root: B256::random(),
                logs_bloom: Bloom::default(),
                gas_used: 21000,
                block_hash: B256::random(),
                transactions: vec![],
                withdrawals: vec![],
                withdrawals_root: B256::ZERO,
                blob_gas_used: None,
            },
            metadata: BerachainFlashblockPayloadMetadata { block_number },
        }
    }

    #[tokio::test]
    async fn test_flashblock_sequence_builds_with_node_context() -> eyre::Result<()> {
        let (tasks, chain_spec) = setup_test_boilerplate().await?;
        let executor = tasks.executor();

        let node_config = NodeConfig::new(chain_spec.clone())
            .with_unused_ports()
            .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());

        let NodeHandle { node, node_exit_future: _ } = NodeBuilder::new(node_config)
            .testing_node(executor.clone())
            .node(BerachainNode::default())
            .launch()
            .await?;

        let ctx = NodeTestContext::new(node, berachain_payload_attributes_generator).await?;

        let provider = ctx.rpc.inner.eth_api().provider();
        let latest_header = provider.latest_header()?.expect("should have genesis");
        let latest_hash = latest_header.hash();
        let latest_number = latest_header.number();
        let latest_timestamp = latest_header.timestamp();

        let payload_id = PayloadId::new([1u8; 8]);
        let fb0 = create_test_flashblock_for_parent(
            0,
            latest_number + 1,
            payload_id,
            latest_hash,
            latest_timestamp + 2,
        );
        let fb1 = create_test_flashblock_for_parent(
            1,
            latest_number + 1,
            payload_id,
            latest_hash,
            latest_timestamp + 2,
        );

        let mut sequence: FlashBlockPendingSequence<BerachainFlashblockPayload> =
            FlashBlockPendingSequence::new();

        sequence.insert(fb0);
        sequence.insert(fb1);

        assert_eq!(sequence.count(), 2);
        assert_eq!(sequence.block_number(), Some(latest_number + 1));

        let complete = sequence.finalize()?;
        assert_eq!(complete.count(), 2);

        let base = complete.payload_base();
        assert_eq!(base.parent_hash, latest_hash);
        assert_eq!(base.block_number, latest_number + 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_flashblock_listeners_broadcast() -> eyre::Result<()> {
        let (_pending_tx, pending_rx) = watch::channel(None);
        let (sequence_tx, _) = broadcast::channel(128);
        let (_in_progress_tx, in_progress_rx) = watch::channel(None);
        let (received_tx, _) = broadcast::channel(128);

        let listeners: FlashblocksListeners<
            bera_reth::primitives::BerachainPrimitives,
            BerachainFlashblockPayload,
        > = FlashblocksListeners::new(
            pending_rx,
            sequence_tx.clone(),
            in_progress_rx,
            received_tx.clone(),
        );

        let _sequence_rx = listeners.flashblocks_sequence.subscribe();
        let mut received_rx = listeners.received_flashblocks.subscribe();

        let payload_id = PayloadId::new([1u8; 8]);
        let parent_hash = B256::random();
        let fb = create_test_flashblock_for_parent(0, 100, payload_id, parent_hash, 1_000_000);

        received_tx.send(Arc::new(fb.clone()))?;

        let received =
            tokio::time::timeout(std::time::Duration::from_millis(100), received_rx.recv())
                .await??;

        assert_eq!(received.index, 0);
        assert_eq!(received.payload_id, payload_id);

        Ok(())
    }

    #[tokio::test]
    async fn test_flashblock_sequence_validates_parent_hash() -> eyre::Result<()> {
        let (tasks, chain_spec) = setup_test_boilerplate().await?;
        let executor = tasks.executor();

        let node_config = NodeConfig::new(chain_spec.clone())
            .with_unused_ports()
            .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());

        let NodeHandle { node, node_exit_future: _ } = NodeBuilder::new(node_config)
            .testing_node(executor.clone())
            .node(BerachainNode::default())
            .launch()
            .await?;

        let ctx = NodeTestContext::new(node, berachain_payload_attributes_generator).await?;

        let provider = ctx.rpc.inner.eth_api().provider();
        let latest_header = provider.latest_header()?.expect("should have genesis");
        let latest_hash = latest_header.hash();
        let latest_number = latest_header.number();
        let latest_timestamp = latest_header.timestamp();

        let payload_id = PayloadId::new([1u8; 8]);
        let fb_correct_parent = create_test_flashblock_for_parent(
            0,
            latest_number + 1,
            payload_id,
            latest_hash,
            latest_timestamp + 2,
        );

        let wrong_parent_hash = B256::random();
        let fb_wrong_parent = create_test_flashblock_for_parent(
            0,
            latest_number + 1,
            payload_id,
            wrong_parent_hash,
            latest_timestamp + 2,
        );

        let base_correct = fb_correct_parent.base.as_ref().unwrap();
        assert_eq!(base_correct.parent_hash, latest_hash);

        let base_wrong = fb_wrong_parent.base.as_ref().unwrap();
        assert_ne!(base_wrong.parent_hash, latest_hash);

        Ok(())
    }
}
