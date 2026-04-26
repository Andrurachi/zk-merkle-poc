# ZK Merkle PoC: A Halo2 Zero-Knowledge Implementation

This project was developed as an exploration of Plonkish arithmetization, custom circuit design, and SNARK generation.

### Project Components
* **[Swap Gadget](https://hackmd.io/@Andrurachi/SkON2Sshbg):** A custom Halo2 microchip that conditionally swaps Left/Right tree nodes based on a private path bit.
* **Poseidon Gadget Integration:** Implementation of the Privacy Scaling Explorations (PSE) highly optimized Poseidon hash.
* **[Merkle Motherboard](https://hackmd.io/@Andrurachi/BybLhBjhbg):** The hierarchical circuit that wires the sub-components together to process an entire Merkle path.
* **[Execution Pipeline](https://hackmd.io/@Andrurachi/H1RNGUj3-x):** The testing infrastructure, moving from mathematical mock proving to generating a real `2688-byte` binary SNARK payload, and then verifying it.

---

### Phase 1: The Blueprint (`configure`)
The first phase of the project focused on defining the "laws of physics" for the circuit. This means establishing the Plonkish constraints before any data is introduced. 

A custom `SwapChip` was designed so it allocates 4 columns (1 selector, 3 advice) and defines the polynomial equations required to prove a node swap is valid without revealing the direction of the swap. 

*Key Learnings:*
* Understanding `ConstraintSystem` and `meta` drafting tables.
* Defining polynomial constraints using `Rotation::cur()` and `Rotation::next()`.
* Understanding the role of `PhantomData` and `Value::unknown()` during Key Generation.

### Phase 2: The Matrix (`synthesize`)
The second phase transitioned from rules to data. This involved writing the execution loop that physically fills out the Plonkish spreadsheet (the 2^k matrix) with the private witnesses.

This phase wires the outputs of the `SwapChip` directly into the `Pow5Chip` (Poseidon Hash), executing a loop that climbs the Merkle tree level by level. 

*Key Learnings:*
* Managing `Layouter` namespaces for clean execution traces.
* Assigning `Advice` columns and extracting physical `AssignedCell` coordinates.
* Understanding hierarchical circuit design (instantiating microchips inside a master loop).

### Phase 3: The Cryptographic Engine (IPA)
With the mathematical logic verified using Halo2's `MockProver`, the final phase involved generating the actual cryptographic SNARK. 

For this Proof of Concept, the circuit leverages the Zcash `pasta::Fp` curve and the **IPA (Inner Product Argument)** commitment scheme. 

*The Pipeline:*
1.  **Setup:** Generating the Structured Reference String (SRS) for $k=8$ (256 rows).
2.  **Keygen:** Generating the deterministic Verifying Key (`vk`) and Proving Key (`pk`).
3.  **Prove:** Using the Fiat-Shamir heuristic (`Blake2b` transcript) to generate the non-interactive proof payload.
4.  **Verify:** Mathematically validating the proof against the public parameters.

---

### The Next Iteration Plan: Ethereum Alignment (KZG & BN254)
While this PoC successfully generates a valid SNARK using IPA, it is not yet Ethereum compatible. 

The immediate next goal for this project is to transition the cryptographic engine to the Ethereum standard. This involves:
1.  Replacing `pasta::Fp` with the Ethereum `BN254` curve.
2.  Replacing the IPA commitment scheme with **KZG**.
3.  Importing the specific 128-bit security Poseidon Round Constants derived for the BN254 prime modulus.
4.  Using the PSE `halo2-solidity-verifier` to auto-generate a Solidity Smart Contract to verify the resulting proof directly on-chain.
