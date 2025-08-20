## Basic Information

This repository is associated with the research project submitted to the "Workshop de Trabalhos de Iniciação Científica e Graduação" (WTICG) of the "XXV Simpósio Brasileiro em Segurança da Informação e de Sistemas Computacionais" (SBSeg 2025).

**Project Title:** Scalable Batch Verification for Hash-Based Post-Quantum Signatures Using STARKs

**Abstract:** This paper introduces a STARK-based batch verifier for a Merkle Signature Scheme (MSS) built from parallel Lamport-style one-time signatures and implemented in the Winterfell framework. The method compresses the validation of N signatures under a single Merkle root into a compact proof of 50-75 KiB. Verification then requires only a few dozen hash evaluations and completesin under 3.1 s for N = 64, outperforming naı̈ve per-signature checks for all N ≥ 8. Requiring no trusted setup, this approach paves the way for scalable, efficient validation of multiple post-quantum signatures.

Many of the scripts available in this repository are an adaptation of the example implementations in [Winterfell](https://github.com/facebook/winterfell) (v0.12.2).

The following badges are used to guide reviewers:  
- **Selo D - Available**: All source code, build instructions and documentation are present in this repository.  
- **Selo F - Functional**: The artifact has been tested on Linux and reproduces the results reported in the paper.

## Dependencies

- Ubuntu (or another Linux distribution) [20.04.4 LTS]
- [Rust](https://www.rust-lang.org/tools/install) (via `rustup`) (v1.84.1)
- Git (v2.34.1)
- Build tools (`gcc`, `make`, etc.) 

## Installation

Run the following commands in order to prepare the environment:

```bash
# Update system packages
sudo apt update
sudo apt upgrade -y

# Install required dependencies
sudo apt install -y git build-essential

# Install rustup (Rust toolchain manager)
sudo apt install -y rustup
```
1. Clone the repository:
```
git clone https://github.com/regras/stark-mss.git
cd stark-mss
```
2. Building the project:
```bash
cargo build
```

### Overview

The workspace crates are organized as follows (all fetched automatically by `cargo`):

```
utils         // Shared traits, macros and I/O/error‑handling, RNG integration.
math          // Finite‑field arithmetic, FFTs, polynomial eval/interpolation.
crypto        // Hash functions, Merkle trees and commitment schemes.
fri           // Fast Reed‑Solomon IOP implementation for low‑degree testing.
air           // Algebraic intermediate‑representation trait for encoding transition constraints.
prover        // End‑to‑end STARK proof generation (trace building, constraint composition, FRI).
verifier      // STARK proof verifier (transcript, commitment checks, FRI validation).
winterfell    // Re-exporting prover and verifier.
examples      // Collection of default examples.
```

All specified in top-level `Cargo.toml`. The implementation associated with this work is available in the `examples` crate as `mss`.
  
## Quick Test

In the `examples` crate, run the `mss` example by executing:

```bash
cargo run mss -n 4 -h 2
```

Where the flags `-n` and `-h` flags respectively consist in the number of MSS signatures to be aggregated and the height of associated Merkle tree. The scheme only supports a number of signatures that is a power of two, so that the associated Merkle tree height is given by log(n). If no flags are specified, the default option is `n = 4`, `h = 2`.

If the tests are sucessful, the program should output:

```
Generated 4 private-public key pairs in XXX ms
Signed 4 messages in XXX ms
Verified 4 signatures in XXX ms
Constructed Merkle tree of depth h in XXX ms
...
Proof generated in XXX ms
Proof size: XXX KB
```

**NOTE:** The execution may take a while, specially for large batches. For the default execution (`n= 4`, `h = 2`), the processing time is expected to be between 4 and 5 minutes depending on the available hardware.

## Security Recommendations

*This repository is a research prototype and is not production-ready. It should be used strictly for experimentation.*
- The examples generate temporary key pairs and sign toy messages. Do not use real secrets or sensitive data.
- The security of the signing scheme (MSS) relies on the underlying hash function (Rescue128).
- The scheme is stateful. Each one-time key pair must be used only once. Reusing ephemeral keys compromises security.
  
---
## License

This work is released under the MIT License.
