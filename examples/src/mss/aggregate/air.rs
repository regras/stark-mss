use core_utils::flatten_slice_elements;
use winterfell::{
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use super::{
    // Import Rescue hash helper and constants (cycle lengths, etc.)
    rescue, CYCLE_LENGTH as HASH_CYCLE_LEN, SIG_CYCLE_LENGTH, TRACE_WIDTH
};
use crate::utils::{are_equal, is_binary, is_zero, not, EvaluationResult};
use crate::utils::rescue::Hash;


// CONSTANTS
// ================================================================================================
// Number of periodic columns needed for selector and round constants sequences.
const NUM_PERIODIC: usize = 40;

// AGGREGATE LAMPORT+ SIGNATURE AIR
// ================================================================================================

#[derive(Clone)]
pub struct PublicInputs {
    pub pub_keys: Vec<[BaseElement; 2]>,       // One-time public keys (2 field elements each)
    pub messages: Vec<[BaseElement; 2]>,       // Messages (each split into two 127-bit field elements)
    pub auth_paths: Vec<Vec<Hash>>,// Merkle authentication paths for each public key
    pub tree_root: Hash,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        // Flatten all public inputs into a single vector of BaseElements for verification.
        let mut result = Vec::new();
        result.extend_from_slice(flatten_slice_elements(&self.pub_keys));
        result.extend_from_slice(flatten_slice_elements(&self.messages));
        for path in &self.auth_paths {
        for &hash in path {
            let [a, b] = hash.0;  // destructure the inner array out of your tuple‐struct
                result.push(a);
                result.push(b);
            }
        }

        // 4) tree_root: Hash
        let [r0, r1] = self.tree_root.0;  // again, destructure
            result.push(r0);
            result.push(r1);

        result
    }
}

pub struct MssAggregateAir {
    context: AirContext<BaseElement>,
    pub_keys: Vec<[BaseElement; 2]>,
    messages: Vec<[BaseElement; 2]>,
    auth_paths: Vec<Vec<Hash>>,
    tree_root: Hash,
}

impl Air for MssAggregateAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        // Define transition constraint degrees for Lamport+ and Merkle path verification.
        //let mut degrees = lamport_degrees();
        let degrees = vec![TransitionConstraintDegree::new(1)];
        //degrees.extend(merkle_degrees());  // append Merkle path constraint degrees (7 constraints)
        assert_eq!(TRACE_WIDTH, trace_info.width());
        MssAggregateAir {
            context: AirContext::new(trace_info, degrees, NUM_PERIODIC, options),
            pub_keys: pub_inputs.pub_keys,
            messages: pub_inputs.messages,
            auth_paths: pub_inputs.auth_paths,
            tree_root: pub_inputs.tree_root,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        _frame: &EvaluationFrame<E>,
        _periodic: &[E],
        _result: &mut [E],
    ) {
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let _last_cycle_step = SIG_CYCLE_LENGTH - 1;
        // Transpose public messages and keys into two vectors each (for element-wise assertions).
        let _messages = transpose(&self.messages);
        let _pub_keys = transpose(&self.pub_keys);

        // Compute combined cycle length for one signature + its Merkle path (per_leaf segment).
        let tree_depth = self.auth_paths[0].len();
        println!("AUTH PATH LEN: {}", self.auth_paths[0].len());
        let _per_leaf = SIG_CYCLE_LENGTH + tree_depth * HASH_CYCLE_LEN;
        let _padded_leaf = (SIG_CYCLE_LENGTH + tree_depth * HASH_CYCLE_LEN).next_power_of_two();

        vec![]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        // 1) Compute how many steps one leaf's sub-trace (signature + path) occupies:
        //    - SIG_CYCLE_LENGTH (Lamport one-time signature cycle)
        //    - plus tree_depth * HASH_CYCLE_LEN (Merkle hashing cycles for each tree level)
        let tree_depth = self.auth_paths[0].len();
        let _per_leaf = SIG_CYCLE_LENGTH + tree_depth * HASH_CYCLE_LEN;
        
        let trace_len = self.context.trace_info().length();
        vec![vec![BaseElement::ZERO; trace_len]; NUM_PERIODIC]
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Aggregates the constraints for Lamport signature verification (bit checks, message accumulation,
/// and Rescue hash enforcement for secret key hashing and public key aggregation).
#[rustfmt::skip]
fn evaluate_constraints<E: FieldElement + From<BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    ark: &[E],
    hash_flag: E,
    sig_cycle_end_flag: E,
    power_of_two: E,
) {
    // When hash_flag = 1 (on all steps except those immediately before an 8-step cycle boundary, e.g., steps 0-6, 8-14, ...),
    // and we are NOT at the last step of a signature cycle, enforce Rescue round transitions for all three hashers:
    // The first 4 registers (message bits and accumulators) should carry over unchanged on pure hash steps,
    // and registers 4..9, 10..15, 16..21 each undergo one round of the Rescue permutation (for secret key 1, secret key 2, and pubkey aggregator respectively).
    let flag = not(sig_cycle_end_flag) * hash_flag;
    result.agg_constraint(0, flag, are_equal(current[0], next[0]));
    result.agg_constraint(1, flag, are_equal(current[1], next[1]));
    result.agg_constraint(2, flag, are_equal(current[2], next[2]));
    result.agg_constraint(3, flag, are_equal(current[3], next[3]));
    rescue::enforce_round(&mut result[4..10],  &current[4..10],  &next[4..10],   ark, flag);
    rescue::enforce_round(&mut result[10..16], &current[10..16], &next[10..16], ark, flag);
    rescue::enforce_round(&mut result[16..22], &current[16..22], &next[16..22], ark, flag);

    // When hash_flag = 0 (i.e., on the injection steps at the end of each 8-step sub-cycle: steps 7, 15, 23, ...),
    // and we are not on the last step of a signature cycle:
    let flag = not(sig_cycle_end_flag) * not(hash_flag);
    // Enforce that the two message bits registers are binary (0 or 1).
    result.agg_constraint(0, flag, is_binary(current[0]));
    result.agg_constraint(1, flag, is_binary(current[1]));
    // Enforce correct update of message accumulators: next = current + (bit * 2^k).
    let next_m0 = current[2] + current[0] * power_of_two;
    result.agg_constraint(2, flag, are_equal(next_m0, next[2]));
    let next_m1 = current[3] + current[1] * power_of_two;
    result.agg_constraint(3, flag, are_equal(next_m1, next[3]));
    // Ensure that after processing a bit, the now-unused secret key hash states are reset to zero (they'll be reinitialized with the next secret).
    result.agg_constraint(4, flag, is_zero(next[6]));
    result.agg_constraint(5, flag, is_zero(next[7]));
    result.agg_constraint(6, flag, is_zero(next[8]));
    result.agg_constraint(7, flag, is_zero(next[9]));
    result.agg_constraint(8, flag, is_zero(next[12]));
    result.agg_constraint(9, flag, is_zero(next[13]));
    result.agg_constraint(10, flag, is_zero(next[14]));
    result.agg_constraint(11, flag, is_zero(next[15]));
    // Ensure the capacity section of the public key hasher (registers 20,21) carries over unchanged during injection (it holds running sum of previous injections).
    result.agg_constraint(12, flag, are_equal(current[20], next[20]));
    result.agg_constraint(13, flag, are_equal(current[21], next[21]));
    // If the current m0 bit = 1, inject the hash of secret key 1 (which is in registers 4,5) into the public key aggregator state (registers 16,17).
    let m0_bit = current[0];
    result.agg_constraint(14, flag * m0_bit, are_equal(current[16] + current[4], next[16]));
    result.agg_constraint(15, flag * m0_bit, are_equal(current[17] + current[5], next[17]));
    // If the current m1 bit = 1, inject the hash of secret key 2 (registers 10,11) into the public key aggregator state (registers 18,19).
    let m1_bit = current[1];
    result.agg_constraint(16, flag * m1_bit, are_equal(current[18] + current[10], next[18]));
    result.agg_constraint(17, flag * m1_bit, are_equal(current[19] + current[11], next[19]));
}

/// Transpose a list of 2-element arrays into two parallel vectors (useful for sequence assertions).
fn transpose(values: &[[BaseElement; 2]]) -> (Vec<BaseElement>, Vec<BaseElement>) {
    let n = values.len();
    let mut r1 = Vec::with_capacity(n);
    let mut r2 = Vec::with_capacity(n);
    for element in values {
        r1.push(element[0]);
        r2.push(element[1]);
    }
    (r1, r2)
}

/// Defines the transition constraint degrees for the Lamport+ signature aggregation portion.
/// There are 22 constraints total for Lamport verification:
///  - 2 for binary bit checks
///  - 2 for message accumulator updates
///  - 6 (degree 5) for hashing secret key 1 (one per each of its 6 state registers)
///  - 6 (degree 5) for hashing secret key 2
///  - 6 (degree 5) for hashing the public key aggregator
fn lamport_degrees() -> Vec<TransitionConstraintDegree> {
    vec![
        // bit m0 is binary
        TransitionConstraintDegree::with_cycles(2, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),
        // bit m1 is binary
        TransitionConstraintDegree::with_cycles(2, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),

        // message m0 accumulation (degree 1, spans hash cycle + two signature cycles)
        TransitionConstraintDegree::with_cycles(1, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),
        // message m1 accumulation
        TransitionConstraintDegree::with_cycles(1, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH, SIG_CYCLE_LENGTH]),

        // Secret key 1 hashing: 6 constraints of degree 5 (one per register in its 6-element Rescue state)
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),

        // Secret key 2 hashing: another 6 of degree 5
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),

        // Public key aggregator hashing: 6 more of degree 5
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LENGTH]),
    ]
}

/// Transition constraint degrees for Merkle path verification (7 constraints total):
///  - 6 constraints of degree 5 for Rescue round transitions on the 6 register state (one per register)
///  - 1 constraint of degree 2 for the binary path bit enforcement.
fn merkle_degrees() -> Vec<TransitionConstraintDegree> {
    vec![
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),  // Merkle state register 0 (Rescue round)
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),  // Merkle state register 1
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),  // Merkle state register 2
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),  // Merkle state register 3
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),  // Merkle state register 4 (capacity)
        TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]),  // Merkle state register 5 (capacity)
        TransitionConstraintDegree::new(2),                                // Path bit is binary (degree 2 check)
    ]
}

// MASKS
// ================================================================================================

/// A single 8-step hash cycle mask for Rescue: 7 ones followed by a zero.
/// (Used to indicate which steps are permutation rounds and which is the injection step.)
const HASH_CYCLE_MASK: [BaseElement; HASH_CYCLE_LEN] = [
    BaseElement::ONE,  // Round 1
    BaseElement::ONE,  // Round 2
    BaseElement::ONE,  // Round 3
    BaseElement::ONE,  // Round 4
    BaseElement::ONE,  // Round 5
    BaseElement::ONE,  // Round 6
    BaseElement::ONE,  // Round 7
    BaseElement::ZERO, // Injection step
];

