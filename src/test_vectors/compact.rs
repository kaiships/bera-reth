//! Compact test vectors for Berachain custom types
//!
//! This module extends reth's compact test vectors to include Berachain-specific types
//! while reusing all the core infrastructure to minimize code duplication.

// Re-export reth's compact test vector infrastructure
pub use reth_cli_commands::test_vectors::compact::{
    VECTOR_SIZE, VECTORS_FOLDER, generate_vector, generate_vectors_with, read_vector,
    read_vectors_with, type_name,
};

use crate::primitives::header::BerachainHeader;
use proptest::test_runner::TestRunner;
use reth_cli_commands::compact_types;

// Define Berachain-specific types using reth's macro pattern
compact_types!(
    regular: [
        BerachainHeader
    ],
    identifier: []
);

/// Generates test vectors for both reth standard types and Berachain extensions
pub fn generate_all_vectors() -> eyre::Result<()> {
    println!("Generating test vectors for reth standard types...");
    reth_cli_commands::test_vectors::compact::generate_vectors()?;

    println!("Generating test vectors for Berachain custom types...");
    generate_vectors_with(GENERATE_VECTORS)
}

/// Reads and validates test vectors for both reth standard types and Berachain extensions  
pub fn read_all_vectors() -> eyre::Result<()> {
    println!("Reading test vectors for reth standard types...");
    reth_cli_commands::test_vectors::compact::read_vectors()?;

    println!("Reading test vectors for Berachain custom types...");
    read_vectors_with(READ_VECTORS)
}

/// Generates test vectors for only Berachain custom types
pub fn generate_berachain_vectors() -> eyre::Result<()> {
    generate_vectors_with(GENERATE_VECTORS)
}

/// Reads and validates test vectors for only Berachain custom types
pub fn read_berachain_vectors() -> eyre::Result<()> {
    read_vectors_with(READ_VECTORS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_berachain_header_test_vectors() {
        // Test that we can generate and read back BerachainHeader
        let result = generate_berachain_vectors();
        assert!(result.is_ok(), "Failed to generate BerachainHeader test vectors: {:?}", result);

        let result = read_berachain_vectors();
        assert!(result.is_ok(), "Failed to read BerachainHeader test vectors: {:?}", result);
    }
}
