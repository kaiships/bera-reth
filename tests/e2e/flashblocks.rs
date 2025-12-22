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
    use crate::e2e::setup_test_boilerplate;
    use alloy_consensus::BlockHeader;
    use alloy_primitives::{Address, B256, Bloom, Bytes, U256};
    use bera_reth::{
        evm::BerachainEvmFactory, node::evm::config::BerachainEvmConfig,
        primitives::BerachainPrimitives,
    };
    use reth::{providers::BlockReaderIdExt, rpc::types::engine::PayloadId};
    use reth_node_builder::{NodeBuilder, NodeHandle};
    use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
    use reth_optimism_flashblocks::{
        FlashBlockCompleteSequence, FlashBlockService, PendingFlashBlock,
    };
    use std::{pin::Pin, task::Poll, time::Duration};
    use tokio::sync::watch;

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

    struct MockFlashblockStream {
        rx: tokio::sync::mpsc::Receiver<BerachainFlashblockPayload>,
    }

    impl futures_util::Stream for MockFlashblockStream {
        type Item = eyre::Result<BerachainFlashblockPayload>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            match Pin::new(&mut self.rx).poll_recv(cx) {
                Poll::Ready(Some(fb)) => Poll::Ready(Some(Ok(fb))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    #[tokio::test]
    async fn test_flashblock_service_receives_and_broadcasts() -> eyre::Result<()> {
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

        let evm_config = BerachainEvmConfig::new_with_evm_factory(
            chain_spec.clone(),
            BerachainEvmFactory::default(),
        );
        let provider = node.provider().clone();

        let (fb_tx, fb_rx) = tokio::sync::mpsc::channel::<BerachainFlashblockPayload>(128);
        let stream = MockFlashblockStream { rx: fb_rx };

        let service = FlashBlockService::new(stream, evm_config, provider, executor.clone(), false);

        let mut received_rx = service.flashblocks_broadcaster().subscribe();
        let mut sequence_rx = service.subscribe_block_sequence();

        let (pending_tx, _pending_rx) = watch::channel(None);
        executor.spawn_critical(
            "flashblock-service",
            Box::pin(async move {
                service.run(pending_tx).await;
            }),
        );

        let latest = node.provider().latest_header()?.expect("should have genesis");
        let latest_hash = latest.hash();
        let next_block = latest.number() + 1;
        let next_timestamp = latest.timestamp() + 2;

        let payload_id = PayloadId::new([1u8; 8]);
        let fb0 = create_test_flashblock_for_parent(
            0,
            next_block,
            payload_id,
            latest_hash,
            next_timestamp,
        );

        fb_tx.send(fb0.clone()).await?;

        let received =
            tokio::time::timeout(Duration::from_millis(500), received_rx.recv()).await??;

        assert_eq!(received.index, 0);
        assert_eq!(received.payload_id, payload_id);
        assert_eq!(received.metadata.block_number, next_block);

        let fb1 = create_test_flashblock_for_parent(
            1,
            next_block,
            payload_id,
            latest_hash,
            next_timestamp,
        );
        fb_tx.send(fb1).await?;

        let received2 =
            tokio::time::timeout(Duration::from_millis(500), received_rx.recv()).await??;
        assert_eq!(received2.index, 1);

        let payload_id2 = PayloadId::new([2u8; 8]);
        let fb_next_block = create_test_flashblock_for_parent(
            0,
            next_block + 1,
            payload_id2,
            B256::random(),
            next_timestamp + 2,
        );
        fb_tx.send(fb_next_block).await?;

        let sequence: FlashBlockCompleteSequence<BerachainFlashblockPayload> =
            tokio::time::timeout(Duration::from_millis(500), sequence_rx.recv()).await??;

        assert_eq!(sequence.block_number(), next_block);
        assert_eq!(sequence.count(), 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_flashblock_service_builds_pending_block() -> eyre::Result<()> {
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

        let evm_config = BerachainEvmConfig::new_with_evm_factory(
            chain_spec.clone(),
            BerachainEvmFactory::default(),
        );
        let provider = node.provider().clone();

        let (fb_tx, fb_rx) = tokio::sync::mpsc::channel::<BerachainFlashblockPayload>(128);
        let stream = MockFlashblockStream { rx: fb_rx };

        let service =
            FlashBlockService::new(stream, evm_config, provider.clone(), executor.clone(), false);

        let mut in_progress_rx = service.subscribe_in_progress();

        let (pending_tx, mut pending_rx) = watch::channel(None);
        executor.spawn_critical(
            "flashblock-service",
            Box::pin(async move {
                service.run(pending_tx).await;
            }),
        );

        let latest = node.provider().latest_header()?.expect("should have genesis");
        let latest_hash = latest.hash();
        let next_block = latest.number() + 1;
        let next_timestamp = latest.timestamp() + 2;

        let payload_id = PayloadId::new([1u8; 8]);
        let fb0 = create_test_flashblock_for_parent(
            0,
            next_block,
            payload_id,
            latest_hash,
            next_timestamp,
        );

        fb_tx.send(fb0).await?;

        in_progress_rx.changed().await?;
        let build_info = in_progress_rx.borrow().clone();

        if let Some(info) = build_info {
            assert_eq!(info.block_number, next_block);
            assert_eq!(info.parent_hash, latest_hash);
        }

        pending_rx.changed().await?;
        let pending_block: Option<PendingFlashBlock<BerachainPrimitives>> =
            pending_rx.borrow().clone();

        if let Some(pending) = pending_block {
            assert_eq!(pending.parent_hash(), latest_hash);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_flashblock_service_validates_parent_hash() -> eyre::Result<()> {
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

        let evm_config = BerachainEvmConfig::new_with_evm_factory(
            chain_spec.clone(),
            BerachainEvmFactory::default(),
        );
        let provider = node.provider().clone();

        let (fb_tx, fb_rx) = tokio::sync::mpsc::channel::<BerachainFlashblockPayload>(128);
        let stream = MockFlashblockStream { rx: fb_rx };

        let service =
            FlashBlockService::new(stream, evm_config, provider.clone(), executor.clone(), false);

        let (pending_tx, mut pending_rx) = watch::channel(None);
        executor.spawn_critical(
            "flashblock-service",
            Box::pin(async move {
                service.run(pending_tx).await;
            }),
        );

        let latest = node.provider().latest_header()?.expect("should have genesis");
        let next_block = latest.number() + 1;
        let next_timestamp = latest.timestamp() + 2;

        let wrong_parent_hash = B256::random();
        let payload_id = PayloadId::new([1u8; 8]);
        let fb_wrong_parent = create_test_flashblock_for_parent(
            0,
            next_block,
            payload_id,
            wrong_parent_hash,
            next_timestamp,
        );

        fb_tx.send(fb_wrong_parent).await?;

        let result = tokio::time::timeout(Duration::from_millis(200), pending_rx.changed()).await;

        assert!(result.is_err(), "Should not build pending block with wrong parent hash");

        Ok(())
    }
}
