use crate::{
    chainspec::BerachainChainSpec,
    consensus::BerachainConsensusBuilder,
    engine::BerachainEngineTypes,
    node::{BerachainAddOns, BerachainExecutorBuilder, BerachainPoolBuilder},
    primitives::{BerachainHeader, BerachainPrimitives},
    rpc::BerachainEthApiBuilder,
    sequencer::SequencerPayloadServiceBuilder,
    transaction::BerachainTxEnvelope,
};
use reth::api::BlockTy;
use reth_engine_local::LocalPayloadAttributesBuilder;
use reth_node_api::{FullNodeComponents, FullNodeTypes, NodeTypes};
use reth_node_builder::{
    DebugNode, Node, NodeAdapter, NodeComponentsBuilder, components::ComponentsBuilder,
};
use reth_node_ethereum::node::EthereumNetworkBuilder;
use reth_payload_primitives::{PayloadAttributesBuilder, PayloadTypes};
use reth_provider::EthStorage;
use std::sync::Arc;

/// Custom sequencer node type for Berachain
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
        BerachainEthApiBuilder,
        crate::engine::validator::BerachainEngineValidatorBuilder,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        ComponentsBuilder::default()
            .node_types()
            .pool(BerachainPoolBuilder)
            .executor(BerachainExecutorBuilder)
            .payload(SequencerPayloadServiceBuilder)
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
