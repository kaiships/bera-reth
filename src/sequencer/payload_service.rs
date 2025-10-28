//! Minimal payload service that properly handles subscriptions

use crate::{
    chainspec::BerachainChainSpec,
    engine::{
        BerachainEngineTypes,
        builder::default_berachain_payload,
        payload::{BerachainBuiltPayload, BerachainPayloadBuilderAttributes},
    },
    node::evm::BerachainEvmConfig,
    primitives::BerachainHeader,
    transaction::BerachainTxEnvelope,
};
use alloy_primitives::B256;
use reth::{payload::PayloadId, providers::BlockReaderIdExt};
use reth_basic_payload_builder::{BuildArguments, BuildOutcome, PayloadConfig};
use reth_chainspec::ChainSpecProvider;
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_payload_builder::{PayloadBuilderError, PayloadBuilderHandle, PayloadServiceCommand};
use reth_payload_primitives::PayloadBuilderAttributes;
use reth_provider::StateProviderFactory;
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// State machine for the sequencer payload service.
///
/// The sequencer follows a simple two-state pattern:
/// 1. `WaitingForForkchoiceUpdate`: Idle, waiting for a new payload build request
/// 2. `BuildingPayload`: Actively building a payload in a background task
///
/// State transitions:
/// - `WaitingForForkchoiceUpdate` -> `BuildingPayload`: On `BuildNewPayload` command (fcu)
/// - `BuildingPayload` -> `WaitingForForkchoiceUpdate`: On `Resolve` command (getPayload)
///
/// Only one payload can be built at a time to preserve pre-confirmations
pub enum SequencerStateMachine {
    /// Waiting for a forkchoice update to trigger a new payload build.
    /// This is the initial and idle state.
    WaitingForForkchoiceUpdate,
    /// Actively building a payload in a background blocking task.
    /// The receiver is taken when the payload is resolved (getPayload).
    BuildingPayload {
        payload_id: PayloadId,
        attributes: BerachainPayloadBuilderAttributes,
        /// Receiver for the built payload - becomes None after resolution
        receiver: Option<oneshot::Receiver<Result<BerachainBuiltPayload, PayloadBuilderError>>>,
        /// Token to signal the build task to stop adding transactions and finalize
        cancel_token: CancellationToken,
    },
}

pub struct SequencerPayloadService<Pool, Client> {
    status: SequencerStateMachine,
    command_rx: mpsc::UnboundedReceiver<PayloadServiceCommand<BerachainEngineTypes>>,
    events_tx: broadcast::Sender<reth_node_api::Events<BerachainEngineTypes>>,
    client: Client,
    pool: Pool,
    evm_config: BerachainEvmConfig,
    builder_config: EthereumBuilderConfig,
}

impl<Pool, Client> SequencerPayloadService<Pool, Client>
where
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec = BerachainChainSpec>
        + Clone
        + 'static
        + BlockReaderIdExt<Header = BerachainHeader>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = BerachainTxEnvelope>> + 'static,
{
    /// Creates a new minimal payload service with proper event handling
    pub fn new(
        client: Client,
        pool: Pool,
        evm_config: BerachainEvmConfig,
        builder_config: EthereumBuilderConfig,
    ) -> (Self, PayloadBuilderHandle<BerachainEngineTypes>) {
        let (service_tx, command_rx) = mpsc::unbounded_channel();
        let (events_tx, _) = broadcast::channel(100);

        let service = Self {
            command_rx,
            events_tx,
            status: SequencerStateMachine::WaitingForForkchoiceUpdate,
            client,
            pool,
            evm_config,
            builder_config,
        };

        let handle = PayloadBuilderHandle::new(service_tx);
        (service, handle)
    }

    /// Processes commands and manages state transitions.
    ///
    /// Command handling by state:
    /// - `WaitingForForkchoiceUpdate`:
    ///   - `Subscribe`: Returns event receiver for payload notifications
    ///   - `BuildNewPayload`: Spawns build task, transitions to BuildingPayload
    /// - `BuildingPayload`:
    ///   - `PayloadTimestamp`: Returns timestamp from stored attributes
    ///   - `Resolve`: Cancels build, waits for result, transitions to WaitingForForkchoiceUpdate
    fn transition(&mut self, cmd: PayloadServiceCommand<BerachainEngineTypes>) {
        match &mut self.status {
            SequencerStateMachine::WaitingForForkchoiceUpdate => match cmd {
                PayloadServiceCommand::Subscribe(tx) => {
                    info!(target: "sequencer", "Received Subscribe request - sending events receiver");
                    let events_rx = self.events_tx.subscribe();
                    let _ = tx.send(events_rx);
                }
                PayloadServiceCommand::BuildNewPayload(attr, tx) => {
                    info!(target: "sequencer", "Received BuildNewPayload request");
                    let id = attr.payload_id();

                    info!(target: "sequencer", payload_id = ?id, "Starting async payload build");

                    // Create cancellation token and oneshot channel for the build
                    let cancel_token = CancellationToken::new();
                    let (build_tx, build_rx) = oneshot::channel();

                    // Clone data for the blocking task
                    let client = self.client.clone();
                    let pool = self.pool.clone();
                    let evm_config = self.evm_config.clone();
                    let builder_config = self.builder_config.clone();
                    let cancel = cancel_token.clone();
                    let attr_clone = attr.clone();

                    // Spawn a blocking task for CPU-intensive payload building
                    tokio::task::spawn_blocking(move || {
                        info!(target: "sequencer", payload_id = ?id, "Payload build blocking task started");

                        // Execute the CPU-intensive build synchronously
                        let result = Self::build_payload_blocking(
                            client,
                            pool,
                            evm_config,
                            builder_config,
                            attr_clone,
                            cancel,
                        );

                        match result {
                            Ok(payload) => {
                                info!(target: "sequencer", payload_id = ?id, "Payload build completed successfully");
                                let _ = build_tx.send(Ok(payload));
                            }
                            Err(err) => {
                                error!(target: "sequencer", payload_id = ?id, ?err, "Payload build failed");
                                let _ = build_tx.send(Err(err));
                            }
                        }
                    });

                    // Transition to building state
                    info!(target: "sequencer", payload_id = ?id, "Transitioning to BuildingPayload state");
                    self.status = SequencerStateMachine::BuildingPayload {
                        payload_id: id,
                        attributes: attr,
                        receiver: Some(build_rx),
                        cancel_token,
                    };

                    // Immediately respond with the payload ID
                    let _ = tx.send(Ok(id));
                }
                cmd => {
                    warn!(target: "sequencer", ?cmd, "Received unexpected PayloadServiceCommand while waiting for forkchoice update");
                }
            },
            SequencerStateMachine::BuildingPayload {
                payload_id,
                attributes,
                receiver,
                cancel_token,
            } => match cmd {
                PayloadServiceCommand::PayloadTimestamp(id, tx) => {
                    info!(target: "sequencer", "Received PayloadTimestamp request for payload {}", id);

                    let timestamp =
                        if id == *payload_id { Some(Ok(attributes.timestamp)) } else { None };

                    let _ = tx.send(timestamp);
                }
                PayloadServiceCommand::Resolve(id, _kind, tx) => {
                    info!(target: "sequencer", payload_id = ?id, "Received Resolve request for payload");

                    if id != *payload_id {
                        warn!(target: "sequencer", payload_id = ?id, current_id = ?payload_id, "Resolve request for different payload ID");
                        let _ = tx.send(None);
                        return;
                    }

                    if let Some(receiver) = receiver.take() {
                        info!(target: "sequencer", payload_id = ?payload_id, "Signaling build task to complete");
                        cancel_token.cancel();

                        info!(target: "sequencer", payload_id = ?payload_id, "Waiting for build task to complete");

                        let result = tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(receiver)
                        });

                        let response = match result {
                            Ok(Ok(payload)) => {
                                info!(target: "sequencer", payload_id = ?payload_id, "Payload successfully retrieved");
                                Some(Box::pin(async move { Ok(payload) }) as _)
                            }
                            Ok(Err(err)) => {
                                error!(target: "sequencer", payload_id = ?payload_id, ?err, "Payload build failed");
                                Some(Box::pin(async move { Err(err) }) as _)
                            }
                            Err(_) => {
                                warn!(target: "sequencer", payload_id = ?payload_id, "Build task dropped without result");
                                None
                            }
                        };

                        let _ = tx.send(response);

                        self.status = SequencerStateMachine::WaitingForForkchoiceUpdate;
                        info!(target: "sequencer", "Transitioned to WaitingForForkchoiceUpdate state");
                    } else {
                        warn!(target: "sequencer", payload_id = ?payload_id, "Payload already resolved");
                        let _ = tx.send(None);
                    }
                }
                cmd => {
                    warn!(target: "sequencer", ?cmd, "Received unexpected PayloadServiceCommand while BuildingPayload");
                }
            },
        }
    }

    fn build_payload_blocking(
        client: Client,
        pool: Pool,
        evm_config: BerachainEvmConfig,
        builder_config: EthereumBuilderConfig,
        attributes: BerachainPayloadBuilderAttributes,
        _cancel_token: CancellationToken,
    ) -> Result<BerachainBuiltPayload, PayloadBuilderError> {
        let payload_id = attributes.id;
        info!(target: "sequencer", payload_id = ?payload_id, parent = ?attributes.parent, timestamp = attributes.timestamp, "Beginning payload construction");

        let parent_header = if attributes.parent().is_zero() {
            // Use latest header for genesis block case
            client
                .latest_header()
                .map_err(PayloadBuilderError::from)?
                .ok_or_else(|| PayloadBuilderError::MissingParentHeader(B256::ZERO))?
        } else {
            // Fetch specific header by hash
            client
                .sealed_header_by_hash(attributes.parent())
                .map_err(PayloadBuilderError::from)?
                .ok_or_else(|| PayloadBuilderError::MissingParentHeader(attributes.parent()))?
        };

        info!(target: "sequencer", payload_id = ?payload_id, parent_number = parent_header.number, "Retrieved parent block");

        // Create the payload config
        let config = PayloadConfig::new(Arc::new(parent_header.clone()), attributes.clone());

        // TODO: The cancel token should be passed to default_berachain_payload and checked
        // after each transaction is processed. When cancelled, it should stop processing
        // more transactions and immediately finalize the block with transactions processed so far.
        // This will enable getPayload to signal "stop adding txs and return what you have".
        // For now, we don't pass the cancel token to avoid complexity.
        let args = BuildArguments::new(
            Default::default(), // cached_reads
            config,
            Default::default(), // cancel token - TODO: integrate with our cancel_token
            None,               // best_payload
        );

        info!(target: "sequencer", payload_id = ?payload_id, "Calling default_berachain_payload to build block");

        // Build the payload using the standard function
        let outcome = default_berachain_payload(
            evm_config,
            client.clone(),
            pool.clone(),
            builder_config,
            args,
            |attrs| pool.best_transactions_with_attributes(attrs),
        )?;

        // Return the built payload
        match outcome {
            BuildOutcome::Better { payload, .. } => {
                let block_number = payload.block.header().number;
                let tx_count = payload.block.body().transactions.len();
                info!(target: "sequencer",
                    payload_id = ?payload_id,
                    block_number = block_number,
                    tx_count = tx_count,
                    "Successfully built payload"
                );
                Ok(payload)
            }
            _ => {
                warn!(target: "sequencer", payload_id = ?payload_id, "Build did not produce a better payload");
                panic!("cannot happen as payloads will always be better");
            }
        }
    }
}

impl<Pool, Client> Future for SequencerPayloadService<Pool, Client>
where
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec = BerachainChainSpec>
        + Clone
        + 'static
        + BlockReaderIdExt<Header = BerachainHeader>
        + Unpin,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = BerachainTxEnvelope>>
        + Unpin
        + 'static,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            match this.command_rx.poll_recv(cx) {
                Poll::Ready(Some(cmd)) => this.transition(cmd),
                Poll::Ready(None) => {
                    info!(target: "sequencer", "Payload service channel closed, shutting down");
                    return Poll::Ready(());
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
