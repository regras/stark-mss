use core::marker::PhantomData;
use std::time::Instant;

use tracing::{field, info_span};
use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, MerkleTree},
    math::{fields::f128::BaseElement, get_power_series,},
    Prover, Proof, ProofOptions, VerifierError, Trace,
};

use super::{
    message_to_elements, rescue, Example, PrivateKey, Signature, CYCLE_LENGTH, NUM_HASH_ROUNDS,
};
use crate::{Blake3_192, Blake3_256, ExampleOptions, HashFunction, Sha3_256};
use crate::utils::rescue::{
    STATE_WIDTH as HASH_STATE_WIDTH,
};
use crate::utils::rescue::{
    Rescue128,
};
use crate::utils::rescue::Hash;
mod air;
use air::{MssAggregateAir, PublicInputs};

mod prover;
use prover::MssAggregateProver;

// CONSTANTS
// ================================================================================================
// Trace width is 22 registers: 
//  - 2 for message bits
//  - 2 for message accumulators
//  - 3 parallel Rescue hash states of width 6 each (secret key1, secret key2, and pubkey aggregator) = 18 registers
const TRACE_WIDTH: usize = 22;
const SIG_CYCLE_LENGTH: usize = 128 * CYCLE_LENGTH;  // One Lamport signature trace cycle = 128 * 8 = 1024 steps

// LAMPORT+ MERKLE SIGNATURE EXAMPLE
// ================================================================================================
/// Returns an example of aggregating multiple Lamport+ signatures with Merkle tree authentication.
/// `num_signatures` must be a power of 2 (for a full binary Merkle tree), and `tree_depth` is the height of the Merkle tree.
/// This example uses the Rescue hash (128-bit security, 2-element digests) for both the one-time signatures and the Merkle tree.
pub fn get_example(
    options: &ExampleOptions,
    num_signatures: usize,
    tree_depth: usize,
) -> Result<Box<dyn Example>, String> {
    // We fix blowup = 28 and grinding_factor = 8 for proof options in this example
    let (options, hash_fn) = options.to_proof_options(28, 8);

    // Ensure the number of signatures matches the Merkle tree depth.
    assert!(num_signatures.is_power_of_two(), "number of signatures must be a power of 2");
    assert_eq!(1 << tree_depth, num_signatures, "tree_depth does not match number of signatures");

    // Note: In this example, we select the hash function from options but internally use Rescue for signature and Merkle hashing.
    // Only certain hash functions are supported for Merkle commitments in Winterfell (Blake3_192, Blake3_256, Sha3_256).
    // We will use one of those for proof commitments, while the signature logic itself uses Rescue.
    match hash_fn {
        HashFunction::Blake3_192 => {
            Ok(Box::new(MssAggregateExample::<Blake3_192>::new(num_signatures, tree_depth, options)))
        },
        HashFunction::Blake3_256 => {
            Ok(Box::new(MssAggregateExample::<Blake3_256>::new(num_signatures, tree_depth, options)))
        },
        HashFunction::Sha3_256 => {
            Ok(Box::new(MssAggregateExample::<Sha3_256>::new(num_signatures, tree_depth, options)))
        },
        _ => Err("The specified hash function cannot be used with this example.".to_string()),
    }
}

pub struct MssAggregateExample<H: ElementHasher> {
    options: ProofOptions,
    pub_keys: Vec<[BaseElement; 2]>,
    messages: Vec<[BaseElement; 2]>,
    signatures: Vec<Signature>,
    auth_paths: Vec<Vec<Hash>>,
    tree_root: Hash,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> MssAggregateExample<H> {
    pub fn new(num_signatures: usize, tree_depth: usize, options: ProofOptions) -> Self {
        assert!(num_signatures.is_power_of_two(), "number of signatures must be a power of 2");
        // 1. Generate `num_signatures` Lamport+ one-time key pairs (private and public).
        let mut private_keys = Vec::with_capacity(num_signatures);
        let mut public_keys = Vec::with_capacity(num_signatures);
        let now = Instant::now();
        for i in 0..num_signatures {
            // We derive each private key from a distinct seed for reproducibility (this example uses a simple seeded PRNG).
            private_keys.push(PrivateKey::from_seed([i as u8; 32]));
            // Compute the corresponding one-time public key (2 field elements, using Rescue hash internally).
            public_keys.push(private_keys[i].pub_key().to_elements());
        }
        println!(
            "Generated {} private-public key pairs in {} ms",
            num_signatures,
            now.elapsed().as_millis()
        );

        // 2. Sign messages with each private key.
        let now = Instant::now();
        let mut signatures = Vec::new();
        let mut messages = Vec::new();
        for (i, private_key) in private_keys.iter().enumerate() {
            let msg = format!("test message {i}");
            // Produce a signature for the message.
            signatures.push(private_key.sign(msg.as_bytes()));
            // Convert the message into two 128-bit field elements (each message is split into 2 field elements for this example).
            messages.push(message_to_elements(msg.as_bytes()));
        }
        println!("Signed {} messages in {} ms", num_signatures, now.elapsed().as_millis());

        // 3. Verify each signature with its public key (to ensure signatures are valid before proving).
        let now = Instant::now();
        let mut pub_keys = Vec::new();
        for (i, signature) in signatures.iter().enumerate() {
            let pk = private_keys[i].pub_key();
            pub_keys.push(pk.to_elements());
            let msg = format!("test message {i}");
            assert!(pk.verify(msg.as_bytes(), signature), "Signature {i} failed verification");
        }
        println!("Verified {} signatures in {} ms", num_signatures, now.elapsed().as_millis());

        // 4. Build a Merkle tree over all one-time public keys and collect authentication paths.
        // We use the same 2-element digest (Rescue hash outputs) for tree nodes.
        let now = Instant::now();
        let leaves: Vec<Hash> = pub_keys
            .iter()
            .map(|pk| Hash(*pk))
            .collect();
        let tree = MerkleTree::<Rescue128>::new(leaves).expect("failed to build Merkle tree");
        let tree_root: Hash = *tree.root();  // Merkle tree root (2 field elements)
        let mut auth_paths = Vec::with_capacity(num_signatures);
        for idx in 0..num_signatures {
            // Retrieve the authentication path (sibling node hashes) for leaf at index `idx`.
            // let proof = tree.prove(idx).expect("failed to generate Merkle proof");
            // Convert proof to the vector of 2-element sibling hashes.
            // auth_paths.push(proof.nodes().iter().map(|node| *node.value()).collect());
            let (_leaf, siblings): (Hash, Vec<Hash>) =
                tree.prove(idx).expect("failed to generate Merkle proof");
            auth_paths.push(siblings);

        }
        println!("Constructed Merkle tree of depth {} in {} ms", tree_depth, now.elapsed().as_millis());

        MssAggregateExample {
            options,
            pub_keys,
            messages,
            auth_paths,
            tree_root,
            signatures,
            _hasher: PhantomData,
        }
    }
}

impl<H: ElementHasher> Example for MssAggregateExample<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    fn prove(&self) -> Proof {
        // generate the execution trace for verifying all signatures
        println!("Generating proof for verifying {} MSS signatures", self.signatures.len());

        // Create a prover instance with all public inputs (public keys, messages, Merkle paths, root).
        let prover = MssAggregateProver::<H>::new(
            &self.pub_keys,
            &self.messages,
            &self.auth_paths,
            self.tree_root,
            self.options.clone()
        );

        // Build the execution trace (all trace rows) for the given messages and signatures.
        let trace = info_span!("generate_execution_trace", num_cols = TRACE_WIDTH, steps = field::Empty)
            .in_scope(|| {
                let trace = prover.build_trace(&self.messages, &self.signatures);
                tracing::Span::current().record("steps", trace.length());
                trace
            });

        // Generate the STARK proof from the execution trace.
        prover.prove(trace).unwrap()
    }

    fn verify(&self, proof: Proof) -> Result<(), VerifierError> {
        // Prepare public inputs for verification (must match those used in proof generation).
        let pub_inputs = PublicInputs {
            pub_keys: self.pub_keys.clone(),
            messages: self.messages.clone(),
            auth_paths: self.auth_paths.clone(),
            tree_root: self.tree_root.clone(),
        };
        let acceptable_options = winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        // Use the Winterfell verifier with our custom AIR (MssAggregateAir), hash function H, and MerkleTree commitment.
        winterfell::verify::<MssAggregateAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    }

    fn verify_with_wrong_inputs(&self, proof: Proof) -> Result<(), VerifierError> {
        // For a negative test, swap two public keys (which should break the proof verification).
        let mut pub_keys = self.pub_keys.clone();
        if pub_keys.len() > 1 {
            pub_keys.swap(0, 1);
        }
        let pub_inputs = PublicInputs {
            pub_keys,
            messages: self.messages.clone(),
            auth_paths: self.auth_paths.clone(),
            tree_root: self.tree_root.clone(),
        };
        let acceptable_options = winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        // This verification is expected to fail because the public inputs no longer match the proof.
        winterfell::verify::<MssAggregateAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    }
}

