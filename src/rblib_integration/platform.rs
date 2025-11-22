use super::limits::BerachainLimits;
use crate::{
    chainspec::BerachainChainSpec,
    engine::{BerachainEngineTypes, payload::BerachainPayloadBuilderAttributes},
    node::{BerachainNode, evm::config::BerachainEvmConfig},
    pool::transaction::BerachainPooledTransaction,
    primitives::BerachainHeader,
};
use alloy_eips::eip1559::ETHEREUM_BLOCK_GAS_LIMIT_36M;
use rblib::prelude::*;
use reth::api::PayloadTypes;
use std::sync::Arc;

/// Platform implementation for Berachain
///
/// This type implements rblib's Platform trait for Berachain,
/// allowing the use of rblib's advanced block building capabilities.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BerachainPlatform;

impl Platform for BerachainPlatform {
    type NodeTypes = BerachainNode;
    type EvmConfig = BerachainEvmConfig;
    type PooledTransaction = BerachainPooledTransaction;
    type Bundle = FlashbotsBundle<Self>;
    type DefaultLimits = BerachainLimits;

    fn evm_config<P>(chainspec: Arc<BerachainChainSpec>) -> BerachainEvmConfig
    where
        P: traits::PlatformExecBounds<Self>,
    {
        // Create EVM config with the Berachain chain spec
        use crate::evm::BerachainEvmFactory;
        BerachainEvmConfig::new_with_evm_factory(chainspec, BerachainEvmFactory::default())
    }

    fn next_block_environment_context<P>(
        _chainspec: &BerachainChainSpec,
        parent: &BerachainHeader,
        attributes: &BerachainPayloadBuilderAttributes,
    ) -> <BerachainEvmConfig as reth::api::ConfigureEvm>::NextBlockEnvCtx
    where
        P: traits::PlatformExecBounds<Self>,
    {
        use crate::node::evm::config::BerachainNextBlockEnvAttributes;

        BerachainNextBlockEnvAttributes {
            timestamp: attributes.timestamp,
            suggested_fee_recipient: attributes.suggested_fee_recipient,
            prev_randao: attributes.prev_randao,
            gas_limit: ETHEREUM_BLOCK_GAS_LIMIT_36M, /* TODO: Get from config, e.g.
                                                      * ETHEREUM_BLOCK_GAS_LIMIT_36M */
            parent_beacon_block_root: attributes.parent_beacon_block_root,
            withdrawals: Some(attributes.withdrawals.clone()),
            prev_proposer_pubkey: attributes.prev_proposer_pubkey.clone(),
        }
    }

    fn build_payload<P>(
        _checkpoint: Checkpoint<P>,
        _provider: &dyn reth::providers::StateProvider,
    ) -> Result<<BerachainEngineTypes as PayloadTypes>::BuiltPayload, PayloadBuilderError>
    where
        P: traits::PlatformExecBounds<Self>,
    {
        // For now, return an error indicating this is not yet implemented
        // A proper implementation would extract state from the checkpoint
        // and build a BerachainBuiltPayload
        Err(PayloadBuilderError::Other(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "BerachainPlatform payload building not yet fully implemented",
        ))))
    }
}
