# QVM

The QVM is the execution layer of Quantova, a sovereign post quantum Layer 1 built from scratch with no classical escape hatch anywhere. It is a register machine that runs compiled containers, with the post quantum primitives wired in as first class instructions. It is not the Ethereum virtual machine. The instruction set, the container format, the gas model, and the crypto opcodes are all our own.

## What it is

A deterministic register machine. Sixteen general registers hold 64 bit words, a linear scratch memory of 64 KiB is zeroed at entry, and an operand and call stack is bounded at a fixed depth. Every instruction has a fixed byte encoding and one deterministic gas cost. The interpreter decodes, meters gas per instruction, faults on overflow, division by zero, a bad jump, a bad memory access, or running out of gas, and on any fault it rolls back and records nothing. Only a clean halt surfaces state changes and effects. Nothing in the machine is timing dependent or platform dependent, so every node reaches the same result.

The scratch memory is sized to hold a full post quantum key, signature, or proof, because the cryptographic opcodes read those artifacts from a single contiguous region. That sizing is deliberate. The QVM is built to verify post quantum objects in bytecode, not to bolt them on afterward.

## The instruction set

The ISA is a compact register machine. Data movement and immediates, full and wrapping arithmetic including a high word multiply for wide math, bitwise and comparison operators, a stack, linear memory load and store, control flow with calls and returns, and contract storage load and store. Two native effects, a native asset transfer and a typed event emission, are recorded rather than applied, so the host enforces balances against the ledger and indexes events into the block event trie only after a clean halt.

Cryptography is a first class opcode group, and every primitive comes from the Q-Crypto crate.

- `HASH` computes SHA3-256 over a memory region.
- `VERIFY_ML` verifies an ML-DSA-65 signature.
- `VERIFY_SLH` verifies an SLH-DSA hash based signature.
- `MERKLE_VERIFY` verifies a domain separated SHA3-256 Merkle authentication path of at most 64 levels, the depth a 64 bit leaf index can address. A contract fixes the size of its tree by fixing the path length it accepts.

There is no elliptic curve opcode and no classical verify. Each crypto opcode carries a fixed base cost, and its variable length work, the hashed input, the appended message tail, and the Merkle path, is metered per absorbed Keccak block and per Merkle level before the work runs, so a long input cannot be smuggled inside a flat charge. Every crypto dispatch runs behind a firewall that maps a primitive panic to a fault, so gas and rollback still apply.

## Execution rules

The interpreter runs under the current rules by default. Reading an existing keyed row is priced as a state read, and the full leaf price is charged once, on the first write that creates a row. An event selector must fit in four bytes. A Merkle path deeper than 64 levels is refused. The genesis entry of a container opens only through `for_genesis`, never through `for_entry`, and a container that names one selector twice cannot be entered. The chain applies the earlier rules through `with_legacy_rules` to the blocks finalised before its upgrade height, so its history replays unchanged.

The unmetered `for_system_program` path accepts only code compiled into the host binary, since it takes a static code slice. Programs from transactions always run through `for_entry` with their manifest, dispatch and code scan charges.

## The container format

A contract is a container. It holds the code, a constant pool, and an interface of callable entries, each named by a four byte selector, carrying its code offset and a declared state access manifest of the slots it reads and writes. A selector is the leading bytes of the SHA3 hash of the entry signature. The container identifier is the SHA3-256 of a canonical, length prefixed serialization of the whole container, so two distinct containers never share an identifier and a change to code, constants, an entry offset, or the access manifest changes it. The declared read and write sets are what let the node schedule contract execution in parallel without guessing at conflicts.

## Components

- `qtv-vm` is the machine. `isa` defines the opcodes and their encoding, `interp` is the metered interpreter and its fault and effect model, `state` is the register and memory and stack, `gas` is the fixed schedule, `container` is the bytecode container and its identifier, `crypto` is the post quantum opcode group, and `asm` is a small text assembler for writing test programs.
- `fuzz` feeds random bytes and random programs over every opcode to the decoder and interpreter, with a storage loader attached, and checks that neither panics, that every metered run terminates within a fixed gas bound and that two runs of the same input give the same outcome.

## Build and test

```
cargo test
cargo test --release --manifest-path fuzz/Cargo.toml
cargo deny check
```

The suite covers decoding, arithmetic and its overflow faults, memory and stack bounds, control flow, gas metering including the length scaled crypto charges, the container identifier and selector resolution, the deploy time container verifier, the manifest enforcement on storage access and computed control flow, and the crypto opcodes against real keys and signatures. The fuzz harness exercises the decoder and interpreter on random input under a fixed gas bound, and a second batch drives the hash, verify and Merkle opcodes over unconstrained bytes with enough gas to reach the SLH-DSA primitive to prove the crypto firewall never lets a primitive panic escape. `cargo deny` enforces the classical crypto ban and the single pinned crypto version.

## Where it sits in the stack

The QVM is a standalone crate. Quantova-Chain composes it into the node as the execution layer, and the node uses the container access manifest to run contract calls in parallel over the state trie. The one cryptographic dependency is Q-Crypto, pinned by git commit, and no other crate. The Quanta language compiles to this container format.

## Status

Live on the Quantova network. The chain pins a QVM commit as its execution crate. Contract transactions are admitted under a per block compute budget and an admission ceiling, so on chain compute is metered and bounded rather than open ended.

## License

Dual licensed under Apache 2.0 and MIT. See `LICENSE-APACHE` and `LICENSE-MIT`.
