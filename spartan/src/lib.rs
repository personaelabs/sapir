#![allow(non_snake_case)]
pub mod frontend;
pub mod r1cs;
pub mod spartan;
mod timer;

use ark_ec::{CurveConfig, CurveGroup};

pub type ScalarField<C> = <<C as CurveGroup>::Config as CurveConfig>::ScalarField;

// Exports
pub use frontend::constraint_system;
pub use frontend::test_utils::*;
pub use frontend::wasm;

// Re-export
pub use ark_ec;
pub use ark_ff;
pub use ark_secq256k1;
