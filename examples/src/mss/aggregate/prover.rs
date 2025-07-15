#[cfg(feature = "concurrent")]

use winterfell::iterators::*;

use winterfell::{
    crypto::ElementHasher,
    math::{fields::f128::BaseElement, FieldElement, StarkField},
    TraceTable, Prover, TraceInfo, ProofOptions,
    crypto::{DefaultRandomCoin, MerkleTree},
    StarkDomain, PartitionOptions, DefaultTraceLde, DefaultConstraintCommitment, DefaultConstraintEvaluator, TracePolyTable, 
    CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients, AuxRandElements,
    matrix::{ColMatrix},
};

use core::marker::PhantomData;
use super::air::PublicInputs;
use super::{CYCLE_LENGTH, SIG_CYCLE_LENGTH, TRACE_WIDTH, NUM_HASH_ROUNDS, rescue};
use super::Signature;
use crate::utils::rescue::Hash;
use crate::mss::aggregate::get_power_series;
use crate::mss::aggregate::HASH_STATE_WIDTH;


pub struct MssAggregateProver<H: ElementHasher> {
    pub_inputs: PublicInputs,
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> MssAggregateProver<H> 
where
    H:ElementHasher<BaseField = BaseElement> + Sync, 
{
    pub fn new(
        pub_keys: &[[BaseElement; 2]],
        messages: &[[BaseElement; 2]],
        auth_paths: &[Vec<Hash>],
        tree_root: Hash,
        options: ProofOptions,
    ) -> Self {
        // Store all public inputs in the prover struct for later retrieval.
        let pub_inputs = PublicInputs {
            pub_keys: pub_keys.to_vec(),
            messages: messages.to_vec(),
            auth_paths: auth_paths.to_vec(),
            tree_root,
        };
        Self {
            pub_inputs,
            options,
            _hasher: PhantomData,
        }
    }


    /// Builds the execution trace (TraceTable) for all signatures and their Merkle paths.
    /// The trace will consist of `num_signatures` segments, each of length `SIG_CYCLE_LENGTH + tree_depth * CYCLE_LENGTH`.
    /// Each segment first verifies a Lamport+ signature, then computes the Merkle root from the one-time public key.
    pub fn build_trace(
        &self,
        messages: &[[BaseElement; 2]],
        signatures: &[Signature],
    ) -> TraceTable<BaseElement> {
        // Determine the length of one segment (one signature + its Merkle path) in trace steps.
        let tree_depth = self.pub_inputs.auth_paths[0].len();
        let per_leaf = SIG_CYCLE_LENGTH + tree_depth * CYCLE_LENGTH;
        let padded_leaf = per_leaf.next_power_of_two();
        // Total trace length = segment length * number of signatures.
        let trace_length = padded_leaf * messages.len();
        // Compute the next power of two ≥ actual_len:
        let padded_len = trace_length.next_power_of_two() as usize;               // :contentReference[oaicite:1]{index=1}
        assert!(padded_len.is_power_of_two(), "padding failed to get power-of-two");
        // Initialize an empty trace table with the required width and length.
        let mut trace = TraceTable::new(TRACE_WIDTH, padded_len);

        // Precompute powers of two up to 2^127 for message bit weighting (used in Lamport message accumulation).
        let powers_of_two = get_power_series(BaseElement::new(2), 128);

        // Fill the trace table for each signature in sequence.
        trace.fragments(padded_leaf).for_each(|mut trace_segment| {
            let i = trace_segment.index();  // index of the current signature segment
            let sig = &signatures[i];
            let msg = &messages[i];
            let auth_path = &self.pub_inputs.auth_paths[i];
            // Build an object with precomputed data for this signature (message bits and key schedule).
            let sig_info = build_sig_info(msg, sig);
            // Each segment trace is filled by providing initial state and transition function.
            trace_segment.fill(
                |state| {
                    // Initialization function for the first row of the segment.
                    // Set up the initial state for Lamport signature verification:
                    init_sig_verification_state(&sig_info, state);
                    // At the very start of Merkle path (which comes after Lamport in this segment), 
                    // we don't initialize anything here. The transition function will handle Merkle setup when needed.
                },
                |step, state| {
                    // Transition function called for each step within the segment.
                    if step < SIG_CYCLE_LENGTH {
                        // 1. Lamport signature verification transition:
                        // For steps within the 1024-step Lamport cycle, apply the transition logic (Rescue rounds or bit injection).
                        update_sig_verification_state(step, &sig_info, &powers_of_two, state);
                    } else if step < per_leaf {
                        // 2. Merkle path verification transition:
                        let path_step = step - SIG_CYCLE_LENGTH;         // step index within the Merkle portion
                        let level = path_step / CYCLE_LENGTH;           // current Merkle tree level (0 = leaf -> parent, etc.)
                        let cycle_step = path_step % CYCLE_LENGTH;      // step within the 8-step hash cycle for this level
                        if cycle_step < NUM_HASH_ROUNDS {
                            // (cycle_step 0-6): Rescue permutation rounds for Merkle hash state.
                            // If this is the first round of the first level (path_step == 0), we need to initialize the hash state with the leaf.
                            if path_step == 0 {
                                // Take the one-time public key (2 field elements) from the end of Lamport part (registers 16,17 of current state).
                                let pk_elem0 = state[16];
                                let pk_elem1 = state[17];
                                // Determine branch bit for leaf level: 0 if this leaf is a left child, 1 if right child.
                                let bit0 = if (i & 1) == 1 { BaseElement::ONE } else { BaseElement::ZERO };
                                // Place the leaf hash into the hash state depending on branch:
                                if bit0 == BaseElement::ZERO {
                                    // Leaf is left child: put leaf in state[0..2], right side empty.
                                    state[0] = pk_elem0;
                                    state[1] = pk_elem1;
                                    state[2] = BaseElement::ZERO;
                                    state[3] = BaseElement::ZERO;
                                } else {
                                    // Leaf is right child: put leaf in state[2..4], left side empty.
                                    state[0] = BaseElement::ZERO;
                                    state[1] = BaseElement::ZERO;
                                    state[2] = pk_elem0;
                                    state[3] = pk_elem1;
                                }
                                // Set capacity registers to 0.
                                state[4] = BaseElement::ZERO;
                                state[5] = BaseElement::ZERO;
                                // We leave state[6] (path bit register) as is (it will be enforced only at injection steps).
                            }
                            // Apply one round of the Rescue permutation to the first 6 registers (the Merkle hash state).
                            rescue::apply_round(&mut state[..HASH_STATE_WIDTH], cycle_step);
                            // (Note: During these rounds, the path bit register [6] and the rest of the state remain unchanged or irrelevant.)
                        } else {
                            // (cycle_step == 7): Injection step for this Merkle level.
                            // We are about to incorporate the sibling node from the authentication path.
                            // Determine the direction bit for this level: 0 if current node was left, 1 if it was right.
                            let raw = i;
                            let shifted = raw.checked_shr(level as u32).unwrap_or(0);
                            let bit = if (shifted & 1) == 1 { BaseElement::ONE } else { BaseElement::ZERO };
                            // Set the next state's path bit (this value will be enforced in constraints).
                            state[6] = bit;
                            // Capture the hash from the current state (the result of hashing the partial data so far).
                            let curr0 = state[0];
                            let curr1 = state[1];
                            // Get the sibling hash for this level from the provided Merkle path.
                            let sibling = auth_path[level];
                            // Inject the sibling hash into the state:
                            let inner = sibling.0;
                            if bit == BaseElement::ZERO {
                                // Current node was left child: keep current hash in left side, place sibling in right side.
                                state[0] = curr0;
                                state[1] = curr1;
                                state[2] = inner[0];
                                state[3] = inner[1];
                            } else {
                                // Current node was right child: place sibling in left side, move current hash to right side.
                                state[0] = inner[0];
                                state[1] = inner[1];
                                state[2] = curr0;
                                state[3] = curr1;
                            }
                            // Reset the capacity registers to zero after injection (per Merkle path constraints).
                            state[4] = BaseElement::ZERO;
                            state[5] = BaseElement::ZERO;
                            // (The state now represents the combined two-child node, ready to be hashed in the next level.)
                        } 
                
                      } else {
                   }

                },
            );
        });

        trace
    }
}

impl<H: ElementHasher> Prover for MssAggregateProver<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    type BaseField = BaseElement;
    type Air = super::air::MssAggregateAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = H;
    type VC = MerkleTree<H>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, H, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PublicInputs {
        // Return a copy of public inputs (the verifier will use these to check assertions).
        self.pub_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    /// Delegate to the default LDE builder.
    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
    }

    /// Delegate to the default constraint evaluator.
    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,              
        air: &'a Self::Air,    // ← same lifetime 'a
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coeffs: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coeffs)
    }

    /// Delegate to the default constraint commitment builder.
    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_queries: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {

        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_queries,
            domain,
            partition_options,
        )
    }
}

// HELPER FUNCTIONS FOR TRACE INITIALIZATION
// ================================================================================================

/// Initialize the first row of the trace for a given signature's verification.
/// This sets up the message bits and hashing states for the two secret keys and the public key aggregator.
fn init_sig_verification_state(sig_info: &SignatureInfo, state: &mut [BaseElement]) {
    // The message bits (m0, m1) for the 0-th bit position (LSB of each 127-bit element).
    state[0] = BaseElement::new(sig_info.m0 & 1);
    state[1] = BaseElement::new(sig_info.m1 & 1);
    // Message accumulators start at 0.
    state[2] = BaseElement::ZERO;
    state[3] = BaseElement::ZERO;
    // Initialize Rescue hash state for secret key 1 (6 registers):
    init_hash_state(&mut state[4..10], &sig_info.key_schedule.sec_keys1[0]);
    // Initialize Rescue hash state for secret key 2 (6 registers):
    init_hash_state(&mut state[10..16], &sig_info.key_schedule.sec_keys2[0]);
    // Initialize Rescue hash state for public key aggregator (6 registers):
    // Initially all zeros (no hashes injected yet).
    for j in 16..22 {
        state[j] = BaseElement::ZERO;
    }
}

/// Performs one transition (one step) of the Lamport signature verification state machine.
/// This applies Rescue rounds on hashing states for 7 steps, and on the 8th step handles bit injection and state updates.
fn update_sig_verification_state(
    step: usize,
    sig_info: &SignatureInfo,
    powers_of_two: &[BaseElement],
    state: &mut [BaseElement],
) {
    // Identify which 8-step cycle and which step within that cycle we are on.
    let cycle_num = step / CYCLE_LENGTH;      // which bit index (0 to 127) we are processing
    let cycle_step = step % CYCLE_LENGTH;     // position within the 8-step cycle (0-7)
    // Split the state into logical parts for clarity:
    let (msg_bits, rest) = state.split_at_mut(4);            // message bits (0,1) + accumulators (2,3)
    let (sec_key1_hash, rest) = rest.split_at_mut(6);        // secret key 1 hash state (6 elements)
    let (sec_key2_hash, pub_key_hash) = rest.split_at_mut(6);// secret key 2 hash state (6 elements) and public key hash state (6 elements)

    if cycle_step < NUM_HASH_ROUNDS {
        // Steps 0-6 of each cycle: apply one round of Rescue permutation to each active hasher state.
        // The message bits and accumulators remain unchanged during these steps.
        rescue::apply_round(sec_key1_hash, cycle_step);
        rescue::apply_round(sec_key2_hash, cycle_step);
        rescue::apply_round(pub_key_hash, cycle_step);
    } else {
        // Step 7 of each cycle: bit injection and state update.
        // 1. Determine current message bits (from previous state).
        let m0_bit = msg_bits[0];
        let m1_bit = msg_bits[1];
        // 2. Incorporate the just-computed hashes of secret keys (or previously stored public key parts) into the public key aggregator:
        update_pub_key_hash(
            pub_key_hash,
            m0_bit,
            m1_bit,
            sec_key1_hash,
            sec_key2_hash,
            &sig_info.key_schedule.pub_keys1[cycle_num],
            &sig_info.key_schedule.pub_keys2[cycle_num],
        );
        // 3. Reinitialize the secret key hash states with the next secrets (for the next bit cycle):
        if cycle_num + 1 < sig_info.key_schedule.sec_keys1.len() {
            init_hash_state(sec_key1_hash, &sig_info.key_schedule.sec_keys1[cycle_num + 1]);
            init_hash_state(sec_key2_hash, &sig_info.key_schedule.sec_keys2[cycle_num + 1]);
        } else {
            // If no more bits (end of signature), we still reset states to zero to satisfy constraints.
            for reg in sec_key1_hash.iter_mut() { *reg = BaseElement::ZERO; }
            for reg in sec_key2_hash.iter_mut() { *reg = BaseElement::ZERO; }
        }
        // 4. Update the message bit registers to the next bits of m0 and m1 (for the next cycle).
        //    Also update message accumulators.
        let next_bit_m0 = if cycle_num + 1 < 128 {
            BaseElement::new((sig_info.m0 >> (cycle_num + 1)) & 1)
        } else {
            BaseElement::ZERO
        };
        let next_bit_m1 = if cycle_num + 1 < 128 {
            BaseElement::new((sig_info.m1 >> (cycle_num + 1)) & 1)
        } else {
            BaseElement::ZERO
        };
        msg_bits[0] = next_bit_m0;
        msg_bits[1] = next_bit_m1;
        // Accumulate the message values (treating each 127-bit element as a binary number).
        msg_bits[2] += m0_bit * powers_of_two[cycle_num];
        msg_bits[3] += m1_bit * powers_of_two[cycle_num];
    }
}

/// Initializes a 6-element Rescue hash state with a 2-element input value (and zeros elsewhere).
/// We place the 2 input elements in the first two registers and set the remaining 4 registers to zero.
fn init_hash_state(state: &mut [BaseElement], values: &[BaseElement; 2]) {
    state[0] = values[0];
    state[1] = values[1];
    state[2] = BaseElement::ZERO;
    state[3] = BaseElement::ZERO;
    state[4] = BaseElement::ZERO;
    state[5] = BaseElement::ZERO;
}

/// Updates the public key hash state on a bit injection step:
/// If the message bit is 1, inject the freshly computed hash of the corresponding secret key into the aggregator state;
/// if the message bit is 0, inject the stored public key component (pre-hashed secret) for that bit instead.
fn update_pub_key_hash(
    state: &mut [BaseElement],                // 6-element state for pubkey hash (only first 4 used for data, 2 are capacity)
    m0_bit: BaseElement, m1_bit: BaseElement, // current message bits
    sec_key1_hash: &[BaseElement],           // hash state of secret key1 (after 7 rounds, first 2 elements represent hash output)
    sec_key2_hash: &[BaseElement],           // hash state of secret key2
    pub_key1: &[BaseElement; 2],             // stored public key hash for secret key1 (if bit=0)
    pub_key2: &[BaseElement; 2],             // stored public key hash for secret key2 (if bit=0)
) {
    // The aggregator state `state` has 4 "rate" registers [0..3] which we treat as two 2-element slots.
    // Add either secret key hash or precomputed public key component to each slot based on message bits.
    if m0_bit == BaseElement::ONE {
        // If bit0 is 1, use the hash of secret key #1 (just computed in sec_key1_hash[0..1]).
        state[0] += sec_key1_hash[0];
        state[1] += sec_key1_hash[1];
    } else {
        // If bit0 is 0, use the public key part corresponding to secret key #1 (which was stored in pub_key1).
        state[0] += pub_key1[0];
        state[1] += pub_key1[1];
    }
    if m1_bit == BaseElement::ONE {
        // If bit1 is 1, inject hash of secret key #2.
        state[2] += sec_key2_hash[0];
        state[3] += sec_key2_hash[1];
    } else {
        // If bit1 is 0, inject stored public key part for secret key #2.
        state[2] += pub_key2[0];
        state[3] += pub_key2[1];
    }
}

// SIGNATURE KEY SCHEDULE
// ================================================================================================

/// Holds the expanded information about a signature needed for trace initialization and updates:
/// - m0, m1: the two 128-bit message components as integers (to extract bits)
/// - key_schedule: the structured secret and public key values for each bit position.
struct SignatureInfo {
    m0: u128,
    m1: u128,
    key_schedule: KeySchedule,
}

/// The key schedule splits the signature's revealed secrets and unrevealed public key components into sequences aligned with bit positions:
/// - sec_keys1/sec_keys2: each length 128, contain the actual secret values (as 2 field elements) for bits where the message bit = 1; zeros for bits where message bit = 0.
/// - pub_keys1/pub_keys2: each length 128, contain the hashed public key components (2 field elements) for bits where message bit = 0; zeros for bits where message bit = 1.
struct KeySchedule {
    sec_keys1: Vec<[BaseElement; 2]>,
    sec_keys2: Vec<[BaseElement; 2]>,
    pub_keys1: Vec<[BaseElement; 2]>,
    pub_keys2: Vec<[BaseElement; 2]>,
}

/// Constructs the SignatureInfo for a given message and signature.
/// It extracts the 128-bit values for m0 and m1 (the two field elements of the message),
/// and builds the key schedule by distributing signature components into the appropriate vectors.
fn build_sig_info(msg: &[BaseElement; 2], sig: &Signature) -> SignatureInfo {
    let m0 = msg[0].as_int();  // convert first field element to raw u128 (lower 127 bits of message)
    let m1 = msg[1].as_int();  // convert second field element to u128
    let key_schedule = build_key_schedule(m0, m1, sig);
    SignatureInfo { m0, m1, key_schedule }
}

/// Builds the key schedule for all 254 bits (127 bits in each of two field elements) of the message.
/// We iterate through each bit position of m0 and m1:
/// - If the bit is 1, we take the next "ones" element from the signature (which corresponds to a revealed secret) and put it into sec_keys1 or sec_keys2.
/// - If the bit is 0, we take the next "zeros" element (which corresponds to the hashed unrevealed key) and put it into pub_keys1 or pub_keys2.
/// Bits that are not present (because we always treat message length as 127 bits each) are set to a default zero value.
fn build_key_schedule(m0: u128, m1: u128, sig: &Signature) -> KeySchedule {
    // ZERO_KEY is a 2-element array of zeros used for placeholder values.
    const ZERO_KEY: [BaseElement; 2] = [BaseElement::ZERO, BaseElement::ZERO];
    let mut n_ones = 0;   // index for next element in sig.ones
    let mut n_zeros = 0;  // index for next element in sig.zeros
    let mut result = KeySchedule {
        sec_keys1: vec![ZERO_KEY; 128],
        sec_keys2: vec![ZERO_KEY; 128],
        pub_keys1: vec![ZERO_KEY; 128],
        pub_keys2: vec![ZERO_KEY; 128],
    };

    // Process 127 bits of m0 (element 0 of the message).
    for i in 0..127 {
        if (m0 >> i) & 1 == 1 {
            // If bit i of m0 is 1: use the next revealed secret from sig.ones.
            result.sec_keys1[i] = sig.ones[n_ones];
            n_ones += 1;
        } else {
            // If bit i is 0: use the next public key component from sig.zeros.
            result.pub_keys1[i] = sig.zeros[n_zeros];
            n_zeros += 1;
        }
    }
    // Process 127 bits of m1 (element 1 of the message).
    for i in 0..127 {
        if (m1 >> i) & 1 == 1 {
            result.sec_keys2[i] = sig.ones[n_ones];
            n_ones += 1;
        } else {
            result.pub_keys2[i] = sig.zeros[n_zeros];
            n_zeros += 1;
        }
    }

    // (Any remaining indices in sec_keys or pub_keys beyond the message length remain zero.)
    result
}

