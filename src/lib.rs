//! Bera-Reth: Ethereum execution client for Berachain
//!
//! Built on Reth SDK with Ethereum compatibility plus Prague1 hardfork for minimum base fee.

pub mod chainspec;
pub mod consensus;
pub mod engine;
pub mod evm;
pub mod genesis;
pub mod hardforks;
pub mod node;
pub mod pool;
pub mod primitives;
pub mod rpc;
pub mod sequencer;
#[cfg(test)]
pub mod test_utils;
pub mod transaction;
pub mod version;

// // Re-export reth crates
pub use reth::{self, *};
pub use reth_basic_payload_builder as basic_payload_builder;
pub use reth_chainspec;
pub use reth_cli as cli;
pub use reth_cli_commands as cli_commands;
pub use reth_cli_util as cli_util;
pub use reth_codecs as codecs;
pub use reth_consensus_common as consensus_common;
pub use reth_db as db;
pub use reth_db_api as db_api;
pub use reth_engine_local as engine_local;
pub use reth_engine_primitives as engine_primitives;
pub use reth_errors as errors;
pub use reth_ethereum_cli as ethereum_cli;
pub use reth_ethereum_engine_primitives as ethereum_engine_primitives;
pub use reth_ethereum_payload_builder as ethereum_payload_builder;
pub use reth_ethereum_primitives as ethereum_primitives;
pub use reth_evm;
pub use reth_evm_ethereum as evm_ethereum;
pub use reth_network_peers as network_peers;
pub use reth_node_api as node_api;
pub use reth_node_builder as node_builder;
pub use reth_node_core as node_core;
pub use reth_node_ethereum as node_ethereum;
pub use reth_payload_builder;
pub use reth_payload_primitives as payload_primitives;
pub use reth_payload_validator as payload_validator;
pub use reth_primitives_traits as primitives_traits;
pub use reth_rpc;
pub use reth_rpc_convert as rpc_convert;
pub use reth_rpc_engine_api as rpc_engine_api;
pub use reth_rpc_eth_api as rpc_eth_api;
pub use reth_rpc_eth_types as rpc_eth_types;
pub use reth_transaction_pool as transaction_pool;
//
// // Re-export alloy crates
// pub use alloy_evm;
// pub use {
//     alloy_consensus, alloy_eips, alloy_genesis,
//     alloy_network, alloy_primitives, alloy_rlp,
//     alloy_rpc_types, alloy_rpc_types_eth,
//     alloy_serde, alloy_signer_local,
//     alloy_sol_macro, alloy_sol_types,
// };
