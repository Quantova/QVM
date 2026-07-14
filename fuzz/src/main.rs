//! Driver that runs a large batch of random inputs through the decoder and interpreter.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let mut args = std::env::args().skip(1);
    let seed = args
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(default_seed);
    let count = args
        .next()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1_000_000);

    qtv_vm_fuzz::run_batch(seed, count);
    println!("fuzz batch of {count} cases passed for seed {seed}");
}

fn default_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
