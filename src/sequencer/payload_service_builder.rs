//! Custom payload service builder for the sequencer

use crate::{
    engine::BerachainEngineTypes, node::evm::BerachainEvmConfig,
    sequencer::payload_service::SequencerPayloadService,
};
use reth::chainspec::EthChainSpec;
use reth_node_api::FullNodeTypes;
use reth_node_builder::{BuilderContext, PayloadBuilderConfig, components::PayloadServiceBuilder};
use reth_payload_builder::PayloadBuilderHandle;
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use tracing::info;

/// Custom payload service builder that spawns a NoopPayloadBuilder for now
#[derive(Debug, Clone, Default)]
pub struct SequencerPayloadServiceBuilder;

impl<N, Pool> PayloadServiceBuilder<N, Pool, BerachainEvmConfig> for SequencerPayloadServiceBuilder
where
    N: FullNodeTypes<
        Types: reth_node_api::NodeTypes<
            Payload = BerachainEngineTypes,
            ChainSpec = crate::chainspec::BerachainChainSpec,
            Primitives = crate::primitives::BerachainPrimitives,
        >,
    >,
    N::Provider: reth_provider::StateProviderFactory
        + reth_chainspec::ChainSpecProvider<ChainSpec = crate::chainspec::BerachainChainSpec>
        + reth_provider::BlockReader
        + Clone
        + Unpin
        + 'static,
    Pool: TransactionPool<
            Transaction: PoolTransaction<Consensus = crate::transaction::BerachainTxEnvelope>,
        > + Unpin
        + Clone
        + 'static,
{
    async fn spawn_payload_builder_service(
        self,
        ctx: &BuilderContext<N>,
        pool: Pool,
        evm_config: BerachainEvmConfig,
    ) -> eyre::Result<PayloadBuilderHandle<<N::Types as reth_node_api::NodeTypes>::Payload>> {
        info!(target: "sequencer", "Spawning minimal sequencer payload service");

        // Get configuration
        let conf = ctx.payload_builder_config();
        let chain = ctx.chain_spec().chain();
        let gas_limit = conf.gas_limit_for(chain);

        let builder_config =
            reth_ethereum_payload_builder::EthereumBuilderConfig::new().with_gas_limit(gas_limit);

        let (service, handle) =
            SequencerPayloadService::new(ctx.provider().clone(), pool, evm_config, builder_config);

        // Spawn the service to run indefinitely
        tokio::spawn(async move {
            service.await;
            info!(target: "sequencer", "Payload service terminated");
        });

        Ok(handle)
    }
}
