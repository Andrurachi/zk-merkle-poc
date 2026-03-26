use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, Value},
    plonk::*,
    poly::Rotation,
};
use std::marker::PhantomData;

// Configuration struct
// Defines the shape of the Plonkish matrix for this specific gadget
#[derive(Clone, Debug)]
pub struct SwapConfig {
    pub s_swap: Selector,        //Toggles the swap constraints on and off
    pub bit: Column<Advice>,     // The path bit (0 or 1)
    pub node: Column<Advice>,    // The current hash state
    pub sibling: Column<Advice>, // The sibling node from the merkle path
}

pub struct SwapChip<F: Field> {
    config: SwapConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> SwapChip<F> {
    pub fn construct(config: SwapConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    // Configuration function
    // The polynomial math
    pub fn configure(meta: &mut ConstraintSystem<F>) -> SwapConfig {
        let s_swap = meta.selector();
        let bit = meta.advice_column();
        let node = meta.advice_column();
        let sibling = meta.advice_column();

        // Enable equality checks (To copy values between cells later)
        meta.enable_equality(bit);
        meta.enable_equality(node);
        meta.enable_equality(sibling);

        meta.create_gate("Swap logic", |meta| {
            // Read the selector
            let s = meta.query_selector(s_swap);

            // Read the inputs from the current row
            let b = meta.query_advice(bit, Rotation::cur());
            let n = meta.query_advice(node, Rotation::cur());
            let s_node = meta.query_advice(sibling, Rotation::cur());

            // Read the outputs from the next row
            // The node and sibling columns are reused to output ´left´ and ´right´
            let out_left = meta.query_advice(node, Rotation::next());
            let out_right = meta.query_advice(sibling, Rotation::next());

            // Constraint one: Bit must be boolean -> b * (1 - b) = 0
            let one = Expression::Constant(F::ONE);
            let bool_check = b.clone() * (one - b.clone());

            // Constraint two: Swap left -> L - node - b * (sibling - node) = 0
            let swap_left = out_left - n.clone() - b.clone() * (s_node.clone() - n.clone());

            // Constraint three: Swap right -> R - sibling + b * (sibling - node) = 0
            let swap_right = out_right - s_node.clone() + b.clone() * (s_node.clone() - n.clone());

            // Each constraint is multiplied by the selector
            // If the selector is 0, the whole equation is 0 (passes automatically)
            // If the selector is 1, the inner polynomial must equal 0
            vec![
                s.clone() * bool_check,
                s.clone() * swap_left,
                s.clone() * swap_right,
            ]
        });

        SwapConfig {
            s_swap,
            bit,
            node,
            sibling,
        }
    }

    // Builder function
    // Prover plugs in the private data
    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        bit: Value<F>,
        node: Value<F>,
        sibling: Value<F>,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), halo2_proofs::plonk::Error> {
        // Ask memory manager for a blank block of rows
        Ok(layouter.assign_region(
            || "Swap logic region",
            |mut region| {
                // Turn on the math rules for row 0 (offset 0)
                self.config.s_swap.enable(&mut region, 0)?;

                // Write the inputs into row 0
                region.assign_advice(|| "bit", self.config.bit, 0, || bit)?;
                region.assign_advice(|| "node", self.config.node, 0, || node)?;
                region.assign_advice(|| "sibling", self.config.sibling, 0, || sibling)?;

                // Calculate what the answers should be
                // .zip and .map because the values might be "Unknown" during Key Generation
                let (left_val, right_val) = bit
                    .zip(node)
                    .zip(sibling)
                    .map(|((b, n), s)| if b == F::ONE { (s, n) } else { (n, s) })
                    .unzip();

                // Write the calculated outputs into row 1 (offset 1)
                let left_cell =
                    region.assign_advice(|| "left out", self.config.node, 1, || left_val)?;
                let right_cell =
                    region.assign_advice(|| "right out", self.config.sibling, 1, || right_val)?;

                // Return the exact cells of R and L, so hash gadget can use them
                Ok((left_cell, right_cell))
            },
        )?)
    }
}
