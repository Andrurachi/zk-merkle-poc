use halo2_proofs::{
    arithmetic::Field,
    circuit::*,
    plonk::*,
};
use halo2_poseidon::poseidon::{
    PoseidonInstructions,
    Pow5Chip,
    Pow5Config,
    StateWord,
    PoseidonSpongeInstructions,
};
use crate::swap::{SwapConfig, SwapChip};

// Sponge dimensions
const WIDTH: usize = 3;
const RATE: usize = 2;

// The motherboard configuration (holds column IDs for the entire circuit)
#[derive(Clone, Debug)]
pub struct MerkleConfig<F: Field> {
    pub swap_config: SwapConfig,
    pub hash_config: Pow5Config<F, WIDTH, RATE>,
}

// The motherboard struct (where halo2 circuit trait is implemented)
pub struct MerklePathCircuit<F: Field> {
    pub leaf: Value<F>,
    pub path_elements: Vec<Value<F>>,
    pub path_indices: Vec<Value<F>>, // THe bits
}