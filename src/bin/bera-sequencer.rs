//! Berachain Sequencer Binary
//!
//! This binary runs bera-reth with a custom payload builder for sequencing.
//!
//! Usage: `cargo run --bin bera-sequencer -- node`

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

use bera_reth::{
    chainspec::{BerachainChainSpec, BerachainChainSpecParser},
    consensus::{BerachainBeaconConsensus, BerachainConsensusBuilder},
    engine::BerachainEngineTypes,
    evm::BerachainEvmFactory,
    node::{
        BerachainAddOns, BerachainExecutorBuilder, BerachainNode, BerachainPoolBuilder,
        evm::config::BerachainEvmConfig,
    },
    primitives::{BerachainHeader, BerachainPrimitives},
    sequencer::SequencerPayloadServiceBuilder,
    transaction::BerachainTxEnvelope,
    version::init_bera_version,
};
use clap::Parser;
use reth::{CliRunner, api::BlockTy};
use reth_cli_commands::node::NoArgs;
use reth_engine_local::LocalPayloadAttributesBuilder;
use reth_ethereum_cli::Cli;
use reth_node_api::{FullNodeComponents, FullNodeTypes, NodeTypes};
use reth_node_builder::{
    DebugNode, Node, NodeAdapter, NodeComponentsBuilder, NodeHandle, WithLaunchContext,
    components::ComponentsBuilder,
};
use reth_node_ethereum::node::EthereumNetworkBuilder;
use reth_payload_primitives::{PayloadAttributesBuilder, PayloadTypes};
use reth_provider::EthStorage;
use std::sync::Arc;
use tracing::info;

/// Custom sequencer node type
#[derive(Debug, Clone, Default)]
pub struct SequencerNode;

impl NodeTypes for SequencerNode {
    type Primitives = BerachainPrimitives;
    type ChainSpec = BerachainChainSpec;
    type Storage = EthStorage<BerachainTxEnvelope, BerachainHeader>;
    type Payload = BerachainEngineTypes;
}

impl<N> Node<N> for SequencerNode
where
    N: FullNodeTypes<Types = Self>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        BerachainPoolBuilder,
        SequencerPayloadServiceBuilder,
        EthereumNetworkBuilder,
        BerachainExecutorBuilder,
        BerachainConsensusBuilder,
    >;

    type AddOns = BerachainAddOns<
        NodeAdapter<N, <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components>,
        bera_reth::rpc::BerachainEthApiBuilder,
        bera_reth::engine::validator::BerachainEngineValidatorBuilder,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        ComponentsBuilder::default()
            .node_types()
            .pool(BerachainPoolBuilder)
            .executor(BerachainExecutorBuilder)
            .payload(SequencerPayloadServiceBuilder::default())
            .network(EthereumNetworkBuilder::default())
            .consensus(BerachainConsensusBuilder)
    }

    fn add_ons(&self) -> Self::AddOns {
        BerachainAddOns::default()
    }
}

impl<N> DebugNode<N> for SequencerNode
where
    N: FullNodeComponents<Types = Self>,
{
    type RpcBlock = alloy_rpc_types::Block<BerachainTxEnvelope, BerachainHeader>;

    fn rpc_to_primitive_block(rpc_block: Self::RpcBlock) -> BlockTy<Self> {
        rpc_block.into_consensus_block().convert_transactions()
    }

    fn local_payload_attributes_builder(
        chain_spec: &Self::ChainSpec,
    ) -> impl PayloadAttributesBuilder<<<Self as NodeTypes>::Payload as PayloadTypes>::PayloadAttributes>
    {
        LocalPayloadAttributesBuilder::new(Arc::new(chain_spec.clone()))
    }
}

fn main() {
    // Install signal handler for better crash reporting
    reth_cli_util::sigsegv_handler::install();

    // Initialize Bera-Reth version metadata
    init_bera_version().expect("Failed to initialize Bera-Reth version metadata");

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    let cli_components_builder = |spec: Arc<BerachainChainSpec>| {
        (
            BerachainEvmConfig::new_with_evm_factory(spec.clone(), BerachainEvmFactory::default()),
            Arc::new(BerachainBeaconConsensus::new(spec)),
        )
    };

    if let Err(err) = Cli::<BerachainChainSpecParser, NoArgs>::parse()
        .with_runner_and_components::<SequencerNode>(
            CliRunner::try_default_runtime().expect("Failed to create default runtime"),
            cli_components_builder,
            async move |builder, _| {
                info!(target: "reth::cli", "Launching Berachain Sequencer node");
                let NodeHandle { node: _node, node_exit_future } =
                    builder.node(SequencerNode::default()).launch_with_debug_capabilities().await?;

                node_exit_future.await
            },
        )
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
