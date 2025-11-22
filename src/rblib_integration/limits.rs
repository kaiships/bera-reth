use rblib::prelude::*;
use std::time::Duration;

use super::platform::BerachainPlatform;

/// Default limits for Berachain payload building
#[derive(Debug, Clone, Default)]
pub struct BerachainLimits;

impl PlatformLimits<BerachainPlatform> for BerachainLimits {
    fn create(&self, _block: &BlockContext<BerachainPlatform>) -> Limits {
        Limits {
            gas_limit: 30_000_000, // TODO: calculate correctly
            blob_params: None,     // TODO: Get blob configuration from chainspec
            max_transactions: Some(1_000),
            deadline: Some(Duration::from_secs(2)), // bera block time
        }
    }
}
