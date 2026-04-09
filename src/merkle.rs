use crate::swap::{SwapChip, SwapConfig};
use halo2_poseidon::poseidon::primitives::Spec;
use halo2_poseidon::poseidon::{primitives::ConstantLength, Pow5Chip, Pow5Config};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::ff::PrimeField,
    plonk::{Circuit, ConstraintSystem, Error},
};
use std::marker::PhantomData;

// Sponge dimensions
const WIDTH: usize = 3;
const RATE: usize = 2;

// The motherboard configuration (holds column IDs for the entire circuit)
#[derive(Clone, Debug)]
pub struct MerkleConfig<F: PrimeField> {
    pub swap_config: SwapConfig,
    pub hash_config: Pow5Config<F, WIDTH, RATE>,
}

// The motherboard struct (where halo2 circuit trait is implemented)
pub struct MerklePathCircuit<F: PrimeField, S: Spec<F, WIDTH, RATE>> {
    pub leaf: Value<F>,
    pub path_elements: Vec<Value<F>>,
    pub path_indices: Vec<Value<F>>, // THe bits
    pub _marker: PhantomData<S>,
}

impl<F: PrimeField, S: Spec<F, WIDTH, RATE>> Circuit<F> for MerklePathCircuit<F, S> {
    type Config = MerkleConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            leaf: Value::unknown(),
            path_elements: vec![Value::unknown(); self.path_elements.len()],
            path_indices: vec![Value::unknown(); self.path_indices.len()],
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // Pass the drafting table to the SwapChip
        let swap_config = SwapChip::configure(meta);

        // Create a dedicated column for constants (fix NotEnoughColumnsForConstants error)
        let constant_col = meta.fixed_column();
        meta.enable_constant(constant_col);

        // Pass the drafting table to the Poseidon hash chip (width 3 = 3 state columns are required)
        let state = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let partial_sbox = meta.advice_column();

        // Turn on equality to wire the SwapChip outputs into the hash inputs
        for col in state.iter() {
            meta.enable_equality(*col);
        }

        let rc_a = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let rc_b = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];

        let hash_config = Pow5Chip::configure::<S>(meta, state, partial_sbox, rc_a, rc_b);

        // Return the fully populated motherboard
        MerkleConfig {
            swap_config,
            hash_config,
        }
    }

    // The master builder
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // Instantiate the custom swap microchip
        let swap_chip = SwapChip::construct(config.swap_config.clone());

        // Set the starting point (level 0)
        // Load the private leaf into the circuit as the initial "current_hash".
        // There is no gadget for loading a single value, so a tiny 1-row region
        // will be assigned manually to get and ´AssignedCell´.
        let mut current_hash = layouter.assign_region(
            || "Load initial leaf",
            |mut region| {
                region.assign_advice(
                    || "leaf",
                    config.swap_config.node, // The node column is borrowed to load it
                    0,
                    || self.leaf,
                )
            },
        )?;

        // The Merkle Climbing Loop
        // Iterates thorugh every sibling and bit in the path
        for (i, (element, bit)) in self
            .path_elements
            .iter()
            .zip(self.path_indices.iter())
            .enumerate()
        {
            // Swap logic
            // A sub-manager (namespace) is passed to the assing function
            let (left_input, right_input) = swap_chip.assign(
                layouter.namespace(|| format!("swap_level_{}", i)),
                *bit,
                current_hash.value().copied(), // Extract the value<F> wrapper
                *element,
            )?;

            // Hash logic
            let poseidon_chip = Pow5Chip::construct(config.hash_config.clone());
            // The generic spec S is used to initialize the Poseidon gadget Hash struct
            let hasher = halo2_poseidon::poseidon::Hash::<
                F,
                Pow5Chip<F, WIDTH, RATE>,
                S,
                ConstantLength<2>,
                WIDTH,
                RATE,
            >::init(
                poseidon_chip,
                layouter.namespace(|| format!("hash_init_{}", i)),
            )?;

            // Feed the left and right cells into the sponge
            let hashed_node = hasher.hash(
                layouter.namespace(|| format!("hash_level_{}", i)),
                [left_input, right_input],
            )?;

            // Update state
            // The output of this hash becomes the node for the next level up
            current_hash = hashed_node;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        dev::MockProver,
        halo2curves::pasta::Fp, 
    };
    // PSE standard Poseidon Spec (128-bit security, width=3)
    use halo2_poseidon::poseidon::primitives::P128Pow5T3;

    #[test]
    fn test_merkle_path_math() {
        // Circuit size (Spreadsheet will have 2^k rows)
        let k = 8; // The circuit is tiny, so 256 rows are enough 

        // The private data
        // Normally, this is a 256-bit hashed numbers. For testing simple numbers is valid
        let leaf = Fp::from(100);

        // A two level merkle tree path
        let siblings = vec![
            Fp::from(200), // Level 0 sibling
            Fp::from(300), // Level 1 sibling
        ];

        // Path bits (0 = current is left, 1 = current is right)
        let bits = vec![
            Fp::from(0), // Level 0: Leaf is Left, Sibling is Right
            Fp::from(1), // Level 1: Current is Right, Sibling is Left
        ];

        // Wrap the data in Value::Known()
        let path_elements: Vec<Value<Fp>> = siblings.iter().map(|v| Value::known(*v)).collect();
        let path_indices: Vec<Value<Fp>> = bits.iter().map(|v| Value::known(*v)).collect();

        // Instantiate the motherboard circuit with the Field and the Poseidon spec
        let circuit = MerklePathCircuit::<Fp, P128Pow5T3> {
            leaf: Value::known(leaf),
            path_elements,
            path_indices,
            _marker: PhantomData,
        };

        // Run the MockProver
        let prover = MockProver::run(k, &circuit, vec![]).unwrap(); // vec is empty because there is no Public Inputs yet
        prover.assert_satisfied();
    }
}
