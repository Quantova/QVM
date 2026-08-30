// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_main]

use std::collections::{BTreeMap, BTreeSet};

use arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;

use qtv_vm::abi::scalar_key;
use qtv_vm::container::{Container, Entry, StateAccess, SELECTOR_BYTES};
use qtv_vm::interp::{Interpreter, StorageKey, STORAGE_KEY_BYTES};
use qtv_vm::isa::{Instr, NUM_REGS};
use qtv_vm::meter::DISPATCH;

const METER_CAP: u64 = 100_000;

fn reg(u: &mut Unstructured) -> Result<u8> {
    Ok(u.arbitrary::<u8>()? % NUM_REGS as u8)
}

fn gen_instr(u: &mut Unstructured, n_consts: usize) -> Result<Instr> {
    let instr = match u.int_in_range(0u8..=41)? {
        0 => Instr::Halt,
        1 => Instr::Nop,
        2 => Instr::Mov {
            d: reg(u)?,
            a: reg(u)?,
        },
        3 => Instr::Ldi {
            d: reg(u)?,
            imm: u.arbitrary()?,
        },
        4 => {
            if n_consts == 0 {
                Instr::Nop
            } else {
                Instr::Ldc {
                    d: reg(u)?,
                    idx: (u.arbitrary::<u16>()? as usize % n_consts) as u16,
                }
            }
        }
        5 => Instr::Add {
            d: reg(u)?,
            a: reg(u)?,
            b: reg(u)?,
        },
        6 => Instr::Sub {
            d: reg(u)?,
            a: reg(u)?,
            b: reg(u)?,
        },
        7 => Instr::Mul {
            d: reg(u)?,
            a: reg(u)?,
            b: reg(u)?,
        },
        8 => Instr::Div {
            d: reg(u)?,
            a: reg(u)?,
            b: reg(u)?,
        },
        9 => Instr::Rem {
            d: reg(u)?,
            a: reg(u)?,
            b: reg(u)?,
        },
        10 => Instr::AddW {
            d: reg(u)?,
            a: reg(u)?,
            b: reg(u)?,
        },
        11 => Instr::SubW {
            d: reg(u)?,
            a: reg(u)?,
            b: reg(u)?,
        },
        12 => Instr::MulW {
            d: reg(u)?,
            a: reg(u)?,
            b: reg(u)?,
        },
        13 => Instr::MulHi {
            d: reg(u)?,
            a: reg(u)?,
            b: reg(u)?,
        },
        14 => Instr::And {
            d: reg(u)?,
            a: reg(u)?,
            b: reg(u)?,
        },
        15 => Instr::Or {
            d: reg(u)?,
            a: reg(u)?,
            b: reg(u)?,
        },
        16 => Instr::Xor {
            d: reg(u)?,
            a: reg(u)?,
            b: reg(u)?,
        },
        17 => Instr::Not {
            d: reg(u)?,
            a: reg(u)?,
        },
        18 => Instr::Shl {
            d: reg(u)?,
            a: reg(u)?,
            b: reg(u)?,
        },
        19 => Instr::Shr {
            d: reg(u)?,
            a: reg(u)?,
            b: reg(u)?,
        },
        20 => Instr::Eq {
            d: reg(u)?,
            a: reg(u)?,
            b: reg(u)?,
        },
        21 => Instr::LtU {
            d: reg(u)?,
            a: reg(u)?,
            b: reg(u)?,
        },
        22 => Instr::GtU {
            d: reg(u)?,
            a: reg(u)?,
            b: reg(u)?,
        },
        23 => Instr::Push { a: reg(u)? },
        24 => Instr::Pop { d: reg(u)? },
        25 => Instr::MLoad {
            d: reg(u)?,
            a: reg(u)?,
        },
        26 => Instr::MStore {
            a: reg(u)?,
            b: reg(u)?,
        },
        27 => Instr::Jmp {
            target: u.arbitrary()?,
        },
        28 => Instr::Jz {
            a: reg(u)?,
            target: u.arbitrary()?,
        },
        29 => Instr::Jnz {
            a: reg(u)?,
            target: u.arbitrary()?,
        },
        30 => Instr::Call {
            target: u.arbitrary()?,
        },
        31 => Instr::Ret,
        32 => Instr::SLoad {
            d: reg(u)?,
            a: reg(u)?,
        },
        33 => Instr::SStore {
            a: reg(u)?,
            b: reg(u)?,
        },
        34 => Instr::Send {
            a: reg(u)?,
            b: reg(u)?,
            c: reg(u)?,
        },
        35 => Instr::Emit {
            a: reg(u)?,
            b: reg(u)?,
            c: reg(u)?,
        },
        36 => Instr::Hash {
            a: reg(u)?,
            b: reg(u)?,
            c: reg(u)?,
        },
        37 => Instr::VerifyMl {
            a: reg(u)?,
            b: reg(u)?,
            c: reg(u)?,
        },
        38 => Instr::MerkleVerify {
            a: reg(u)?,
            b: reg(u)?,
            c: reg(u)?,
        },
        39 => Instr::VerifySlh {
            a: reg(u)?,
            b: reg(u)?,
            c: reg(u)?,
        },
        40 => Instr::Kem {
            a: reg(u)?,
            b: reg(u)?,
            c: reg(u)?,
        },
        _ => Instr::Addr {
            a: reg(u)?,
            b: reg(u)?,
            c: reg(u)?,
        },
    };
    Ok(instr)
}

fn remap_target(instr: &mut Instr, starts: &[u32]) {
    let land = |t: u32| starts[(t as usize) % starts.len()];
    match instr {
        Instr::Jmp { target } => *target = land(*target),
        Instr::Jz { target, .. } => *target = land(*target),
        Instr::Jnz { target, .. } => *target = land(*target),
        Instr::Call { target } => *target = land(*target),
        _ => {}
    }
}

fn gen_slots(u: &mut Unstructured) -> Result<Vec<u64>> {
    let n = u.int_in_range(0..=6)?;
    (0..n).map(|_| u.arbitrary()).collect()
}

fn gen_storage(u: &mut Unstructured) -> Result<BTreeMap<StorageKey, u64>> {
    let n = u.int_in_range(0..=6)?;
    let mut storage = BTreeMap::new();
    for _ in 0..n {
        let mut key = [0u8; STORAGE_KEY_BYTES];
        u.fill_buffer(&mut key)?;
        storage.insert(key, u.arbitrary()?);
    }
    Ok(storage)
}

fn drive(u: &mut Unstructured) -> Result<()> {
    let n_consts = u.int_in_range(0..=8)?;
    let consts: Vec<u64> = (0..n_consts)
        .map(|_| u.arbitrary())
        .collect::<Result<_>>()?;

    let n_instr = u.int_in_range(0..=48)?;
    let mut instrs: Vec<Instr> = Vec::with_capacity(n_instr + 1);
    for _ in 0..n_instr {
        instrs.push(gen_instr(u, consts.len())?);
    }
    instrs.push(Instr::Halt);

    let mut starts: Vec<u32> = Vec::with_capacity(instrs.len());
    let mut off: u32 = 0;
    for instr in &instrs {
        starts.push(off);
        off = off.saturating_add(instr.encoded_len() as u32);
    }
    for instr in &mut instrs {
        remap_target(instr, &starts);
    }
    let mut code = Vec::new();
    for instr in &instrs {
        instr.encode(&mut code);
    }

    let n_entries = u.int_in_range(0..=8)?;
    let mut entries = Vec::with_capacity(n_entries);
    for _ in 0..n_entries {
        let mut selector = [0u8; SELECTOR_BYTES];
        u.fill_buffer(&mut selector)?;
        let offset = if u.arbitrary()? {
            starts[u.arbitrary::<u32>()? as usize % starts.len()]
        } else {
            u.arbitrary()?
        };
        entries.push(Entry {
            selector,
            offset,
            access: StateAccess {
                reads: gen_slots(u)?,
                writes: gen_slots(u)?,
                keyed_reads: gen_slots(u)?,
                keyed_writes: gen_slots(u)?,
            },
        });
    }

    let container = Container::new(code, consts, entries);
    if container.verify().is_err() {
        return Ok(());
    }

    let selector = if !container.entries.is_empty() && u.arbitrary()? {
        let i = u.arbitrary::<u32>()? as usize % container.entries.len();
        container.entries[i].selector
    } else {
        let mut selector = [0u8; SELECTOR_BYTES];
        u.fill_buffer(&mut selector)?;
        selector
    };

    let meter_limit = u.arbitrary::<u64>()? % (METER_CAP + 1);

    let mem_len = u.int_in_range(0..=2048)?;
    let mut mem = vec![0u8; mem_len];
    u.fill_buffer(&mut mem)?;

    let initial = gen_storage(u)?;

    let interp = match Interpreter::for_entry(&container, selector, meter_limit) {
        Ok(interp) => interp,
        Err(_) => return Ok(()),
    };
    let outcome = match interp.with_storage(initial.clone()).with_memory(&mem).run() {
        Ok(outcome) => outcome,
        Err(_) => return Ok(()),
    };

    assert!(
        outcome.meter_used <= meter_limit,
        "metered run exceeded its budget"
    );
    assert!(outcome.meter_used >= DISPATCH, "dispatch was not charged");

    if let Some(entry) = container.entries.iter().find(|e| e.selector == selector) {
        if entry.access.keyed_writes.is_empty() {
            let allowed: BTreeSet<StorageKey> =
                entry.access.writes.iter().map(|&s| scalar_key(s)).collect();
            for (key, value) in &outcome.storage {
                if initial.get(key) != Some(value) {
                    assert!(allowed.contains(key), "entry mutated an undeclared slot");
                }
            }
        }
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let _ = drive(&mut u);
});
