//! Custom payload service builder for the sequencer

use crate::{
    node::evm::BerachainEvmConfig, sequencer::minimal_payload_service::MinimalPayloadService,
};
use reth_node_api::{FullNodeTypes, NodeTypes};
use reth_node_builder::{BuilderContext, components::PayloadServiceBuilder};
use reth_payload_builder::PayloadBuilderHandle;
use reth_transaction_pool::TransactionPool;
use tracing::info;

/// Custom payload service builder that spawns a NoopPayloadBuilder for now
#[derive(Debug, Clone, Default)]
pub struct SequencerPayloadServiceBuilder;

impl<N, Pool> PayloadServiceBuilder<N, Pool, BerachainEvmConfig> for SequencerPayloadServiceBuilder
where
    N: FullNodeTypes,
    Pool: TransactionPool + Unpin + 'static,
{
    async fn spawn_payload_builder_service(
        self,
        _ctx: &BuilderContext<N>,
        _pool: Pool,
        _evm_config: BerachainEvmConfig,
    ) -> eyre::Result<PayloadBuilderHandle<<N::Types as NodeTypes>::Payload>> {
        info!(target: "sequencer", "Spawning minimal sequencer payload service");

        let (service, handle) = MinimalPayloadService::<<N::Types as NodeTypes>::Payload>::new();

        // Spawn the service to run indefinitely
        tokio::spawn(async move {
            service.await;
            info!(target: "sequencer", "Payload service terminated");
        });

        Ok(handle)
    }
}
