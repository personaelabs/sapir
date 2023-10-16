#![allow(non_snake_case)]
pub mod frontend;
pub mod r1cs;
pub mod spartan;
mod timer;
#[macro_use]
pub mod wasm;

use ark_ec::{CurveConfig, CurveGroup};

// Exports
pub type ScalarField<C> = <<C as CurveGroup>::Config as CurveConfig>::ScalarField;
pub use frontend::constraint_system;
pub use frontend::test_utils::*;

// Re-export
pub use ark_ec;
pub use ark_ff;
pub use ark_secq256k1;
pub use merkle_tree;
pub use poseidon;
