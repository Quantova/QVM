// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::interp::Fault;
use crate::isa::{decode, Instr};

pub const ABORT_TAG: u64 = 0x5154 << 48;
const TAG_MASK: u64 = 0xffff << 48;
pub const ABORT_REG: u8 = 0;
pub const ZERO_REG: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum Rule {
    Unknown = 0,
    Guard = 1,
    Limits = 2,
    Denies = 3,
    Invariant = 4,
    TooEarly = 5,
    OrderExpired = 6,
    SignatureInvalid = 7,
    SignerNotAuthorised = 8,
    OrderMalformed = 9,
    QuorumDuplicate = 10,
    QuorumNotMember = 11,
    ArithmeticOverflow = 12,
    ValueOutOfRange = 13,
    BalanceTooLow = 14,
    AssetTooLow = 15,
    UnexpectedPayment = 16,
    PaymentMismatch = 17,
    AlreadyInitialised = 18,
    DeployParams = 19,
    NameInvalid = 20,
    GuardianSetInvalid = 21,
    LegacyRule = 22,
    OutOfMeter = 64,
    UnknownEntry = 65,
    MemoryOutOfRange = 66,
    EffectsTooLarge = 67,
    UndeclaredState = 68,
    UnsupportedScheme = 69,
    ContractFault = 70,
    CryptoFault = 71,
    InsufficientFunds = 72,
    NoContract = 73,
    ValueExceedsBalance = 74,
    TransferRejected = 75,
    DeployRejected = 76,
    BlockStateLimit = 77,
    DivisionByZero = 78,
    MintCeiling = 79,
    AssetStopped = 80,
    GenesisCall = 81,
}

const ALL: [Rule; 42] = [
    Rule::Unknown,
    Rule::Guard,
    Rule::Limits,
    Rule::Denies,
    Rule::Invariant,
    Rule::TooEarly,
    Rule::OrderExpired,
    Rule::SignatureInvalid,
    Rule::SignerNotAuthorised,
    Rule::OrderMalformed,
    Rule::QuorumDuplicate,
    Rule::QuorumNotMember,
    Rule::ArithmeticOverflow,
    Rule::ValueOutOfRange,
    Rule::BalanceTooLow,
    Rule::AssetTooLow,
    Rule::UnexpectedPayment,
    Rule::PaymentMismatch,
    Rule::AlreadyInitialised,
    Rule::DeployParams,
    Rule::NameInvalid,
    Rule::GuardianSetInvalid,
    Rule::LegacyRule,
    Rule::OutOfMeter,
    Rule::UnknownEntry,
    Rule::MemoryOutOfRange,
    Rule::EffectsTooLarge,
    Rule::UndeclaredState,
    Rule::UnsupportedScheme,
    Rule::ContractFault,
    Rule::CryptoFault,
    Rule::InsufficientFunds,
    Rule::NoContract,
    Rule::ValueExceedsBalance,
    Rule::TransferRejected,
    Rule::DeployRejected,
    Rule::BlockStateLimit,
    Rule::DivisionByZero,
    Rule::MintCeiling,
    Rule::AssetStopped,
    Rule::GenesisCall,
    Rule::Unknown,
];

impl Rule {
    pub fn code(self) -> u16 {
        self as u16
    }

    pub fn from_code(code: u16) -> Rule {
        ALL.iter()
            .copied()
            .find(|r| r.code() == code)
            .unwrap_or(Rule::Unknown)
    }

    pub fn all() -> &'static [Rule] {
        &ALL[..ALL.len() - 1]
    }

    pub fn name(self) -> &'static str {
        match self {
            Rule::Unknown => "unknown",
            Rule::Guard => "guard_failed",
            Rule::Limits => "limits_exceeded",
            Rule::Denies => "entry_closed",
            Rule::Invariant => "invariant_broken",
            Rule::TooEarly => "too_early",
            Rule::OrderExpired => "order_expired",
            Rule::SignatureInvalid => "signature_invalid",
            Rule::SignerNotAuthorised => "signer_not_authorised",
            Rule::OrderMalformed => "order_malformed",
            Rule::QuorumDuplicate => "quorum_approval_repeated",
            Rule::QuorumNotMember => "quorum_approver_not_member",
            Rule::ArithmeticOverflow => "arithmetic_out_of_range",
            Rule::ValueOutOfRange => "value_out_of_range",
            Rule::BalanceTooLow => "balance_too_low",
            Rule::AssetTooLow => "asset_too_low",
            Rule::UnexpectedPayment => "payment_not_accepted",
            Rule::PaymentMismatch => "payment_mismatch",
            Rule::AlreadyInitialised => "already_initialised",
            Rule::DeployParams => "deploy_parameters_invalid",
            Rule::NameInvalid => "name_invalid",
            Rule::GuardianSetInvalid => "guardian_set_invalid",
            Rule::LegacyRule => "contract_rule",
            Rule::OutOfMeter => "out_of_meter",
            Rule::UnknownEntry => "unknown_entry",
            Rule::MemoryOutOfRange => "memory_out_of_range",
            Rule::EffectsTooLarge => "effects_too_large",
            Rule::UndeclaredState => "undeclared_state",
            Rule::UnsupportedScheme => "unsupported_scheme",
            Rule::ContractFault => "contract_fault",
            Rule::CryptoFault => "crypto_fault",
            Rule::InsufficientFunds => "insufficient_funds",
            Rule::NoContract => "no_contract",
            Rule::ValueExceedsBalance => "value_exceeds_balance",
            Rule::TransferRejected => "transfer_rejected",
            Rule::DeployRejected => "deploy_rejected",
            Rule::BlockStateLimit => "block_state_limit",
            Rule::DivisionByZero => "division_by_zero",
            Rule::MintCeiling => "mint_ceiling_exceeded",
            Rule::AssetStopped => "asset_stopped",
            Rule::GenesisCall => "genesis_not_callable",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Rule::Unknown => "The call was rejected",
            Rule::Guard => "A contract condition was not met",
            Rule::Limits => "The call would exceed a contract limit",
            Rule::Denies => "This entry is closed in the current contract state",
            Rule::Invariant => "The call would break a contract invariant",
            Rule::TooEarly => "This entry cannot run yet",
            Rule::OrderExpired => "The signed order has expired",
            Rule::SignatureInvalid => "The order signature does not verify",
            Rule::SignerNotAuthorised => {
                "The order was signed by an account without the required role"
            }
            Rule::OrderMalformed => "The signed order is malformed",
            Rule::QuorumDuplicate => "A quorum approval is repeated or out of order",
            Rule::QuorumNotMember => "A quorum approval is not from a current member",
            Rule::ArithmeticOverflow => "A calculation went out of range",
            Rule::ValueOutOfRange => "A value is too large for its type",
            Rule::BalanceTooLow => "The account balance is too low",
            Rule::AssetTooLow => "The contract does not hold enough of the asset",
            Rule::UnexpectedPayment => "This entry does not accept a payment",
            Rule::PaymentMismatch => "The payment does not match the asset argument",
            Rule::AlreadyInitialised => "The contract has already been initialised",
            Rule::DeployParams => "The deploy parameters are incomplete",
            Rule::NameInvalid => "The name is not valid",
            Rule::GuardianSetInvalid => "The new guardian set is not valid",
            Rule::LegacyRule => "The call was rejected by a contract rule",
            Rule::OutOfMeter => "The call ran out of meter",
            Rule::UnknownEntry => "The contract has no such entry",
            Rule::MemoryOutOfRange => "The call arguments do not fit the contract memory",
            Rule::EffectsTooLarge => "The call produced too many effects",
            Rule::UndeclaredState => "The contract touched state it did not declare",
            Rule::UnsupportedScheme => "The signature scheme is not supported",
            Rule::ContractFault => "The contract code stopped unexpectedly",
            Rule::CryptoFault => "A signature check could not be completed",
            Rule::InsufficientFunds => "The contract does not hold enough to pay out",
            Rule::NoContract => "There is no contract at this address",
            Rule::ValueExceedsBalance => "The sender cannot cover the attached value",
            Rule::TransferRejected => "A payment made by the contract was refused",
            Rule::DeployRejected => "The contract deploy was refused",
            Rule::BlockStateLimit => "The block had no room for more new state",
            Rule::DivisionByZero => "The contract divided by zero",
            Rule::MintCeiling => "The mint would exceed the declared ceiling",
            Rule::AssetStopped => "The asset issuer is stopped",
            Rule::GenesisCall => "The genesis entry cannot be called",
        }
    }

    pub fn help(self) -> &'static str {
        match self {
            Rule::Unknown => "The contract refused the call. Check the inputs against the contract source and try again.",
            Rule::Guard => "A guard statement in the contract was false for these inputs and the current contract state. Read the guard on the reported line and send values that satisfy it.",
            Rule::Limits => "The entry declares a limits clause and this call would break it, for example by minting past the maximum supply. Lower the amount or read the current totals before calling.",
            Rule::Denies => "The entry declares a denies clause that is true right now, for example the escrow is already funded or already settled. Read the contract state and call the entry only when it is open.",
            Rule::Invariant => "Every call must leave the contract invariants true. This call would have broken the invariant on the reported line, so nothing was changed.",
            Rule::TooEarly => "The entry declares an after clause and its waiting period has not finished. Wait until the period ends and call again.",
            Rule::OrderExpired => "The order expiry is earlier than the block time. Sign a new order with a later expiry, at most 24 hours ahead, and send it promptly.",
            Rule::SignatureInvalid => "The signature does not match the order that reached the contract. Sign the order with the Quantova SDK for this exact contract, entry, chain and current nonce, list the fields in the order the contract ABI gives, and do not change any value after signing.",
            Rule::SignerNotAuthorised => "The entry requires an order signed by a specific role, such as the owner, issuer or registrar. Sign the order with the key that holds that role on this contract.",
            Rule::OrderMalformed => "The order uses an unsupported signature scheme or its signature region lies outside the call memory. Build the call with the Quantova SDK instead of encoding it by hand.",
            Rule::QuorumDuplicate => "Each approval must come from a different member and the approvals must be listed in increasing member index order. Remove the repeated approval and sort the rest by member index.",
            Rule::QuorumNotMember => "An approval was signed by a key that is not in the guardian set at the given index. Use approvals from current members and give each one its correct index.",
            Rule::ArithmeticOverflow => "An arithmetic result in the contract would leave its range, for example a subtraction below zero or a total above the type limit. Use smaller amounts or check the current values first.",
            Rule::ValueOutOfRange => "One of the inputs does not fit the declared type, for example a number above the u8 or u64 range. Send a value inside the range of the parameter type.",
            Rule::BalanceTooLow => "The contract tried to take more from an account balance than the account holds. Read the balance and send a smaller amount.",
            Rule::AssetTooLow => "The contract tried to split or send more of an asset than it holds. Lower the amount or fund the contract first.",
            Rule::UnexpectedPayment => "Native value was attached to an entry that has no asset parameter. Call it again with a value of zero.",
            Rule::PaymentMismatch => "The value attached to the call must equal the amount given for the asset parameter. Set both to the same number.",
            Rule::AlreadyInitialised => "Genesis runs once when the contract is deployed and cannot run again.",
            Rule::DeployParams => "The deploy did not carry every parameter the contract genesis reads, or the parameter frame is not terminated. Deploy with the Quantova IDE or SDK so the parameters are framed correctly.",
            Rule::NameInvalid => "Names must be between 3 and 32 bytes of lower case letters, digits and hyphens, with nothing after the declared length. Correct the name and call again.",
            Rule::GuardianSetInvalid => "A guardian set must contain distinct members and no empty slot. Correct the member list and submit it again.",
            Rule::LegacyRule => "A guard, limits, denies, signature or invariant check in the contract refused these inputs, so nothing was changed. This contract was compiled before rejection reasons were recorded. Check the inputs against the contract source, or recompile with the current Quanta compiler and deploy again to get the exact rule and line.",
            Rule::OutOfMeter => "The call needed more meter than its limit allows. Raise the meter limit, up to 12,500,000 for a call or 50,000,000 for a deploy, or split the work across calls.",
            Rule::UnknownEntry => "The call selector does not match any entry of this contract. Use the selector from the contract ABI for the entry you want.",
            Rule::MemoryOutOfRange => "An argument or signature region points outside the contract memory. Build the call with the Quantova SDK so every offset matches the contract ABI.",
            Rule::EffectsTooLarge => "The call emitted more events or payments than one call may carry. Split the work across several calls.",
            Rule::UndeclaredState => "The contract read or wrote state outside its declared access list. This is a fault in the contract build. Recompile with the current Quanta compiler and deploy again.",
            Rule::UnsupportedScheme => "Only the ML-DSA and SLH-DSA schemes are accepted. Sign with a supported Quantova key.",
            Rule::ContractFault => "The contract code reached an invalid instruction or jump. Recompile the contract with the current Quanta compiler and deploy it again.",
            Rule::CryptoFault => "The signature check received data it could not process. Rebuild the signed call with the Quantova SDK.",
            Rule::InsufficientFunds => "The contract tried to pay out more native value than it holds. Lower the amount or fund the contract first.",
            Rule::NoContract => "No contract code is deployed at the target address. Check the address, or wait until the deploy has finalised.",
            Rule::ValueExceedsBalance => "The value attached to the call is larger than the sender balance in that asset. Lower the value or fund the sender first.",
            Rule::TransferRejected => "A payment the contract tried to make was refused by the ledger, for example to an address that cannot receive it. Check the recipient and amount.",
            Rule::DeployRejected => "The container is not valid or does not carry an accepted provenance stamp. Compile and deploy with the Quantova IDE or SDK.",
            Rule::BlockStateLimit => "The block reached its limit of new state entries. Send the transaction again, it will be included in a later block.",
            Rule::DivisionByZero => "The contract divided by a value that was zero. Check the inputs that feed the division in the contract source.",
            Rule::MintCeiling => "The contract tried to mint more than the ceiling declared at deploy. Lower the amount or deploy with a higher ceiling.",
            Rule::AssetStopped => "The issuer of this asset has been stopped by governance, so the asset cannot move. Contact the issuer.",
            Rule::GenesisCall => "Genesis runs only at deploy. Call one of the contract entries instead.",
        }
    }
}

pub fn abort_code(rule: Rule, line: u32) -> u64 {
    ABORT_TAG | (u64::from(rule.code()) << 32) | u64::from(line)
}

pub fn split_code(code: u64) -> Option<(Rule, u32)> {
    if code & TAG_MASK != ABORT_TAG {
        return None;
    }
    let rule = ((code >> 32) & 0xffff) as u16;
    Some((Rule::from_code(rule), code as u32))
}

pub fn abort_stub(code: u64) -> [Instr; 3] {
    [
        Instr::Ldi {
            d: ABORT_REG,
            imm: code,
        },
        Instr::Ldi {
            d: ZERO_REG,
            imm: 0,
        },
        Instr::Div {
            d: ABORT_REG,
            a: ABORT_REG,
            b: ZERO_REG,
        },
    ]
}

pub fn halting_stubs(code: &[u8]) -> Option<Vec<u8>> {
    let mut list = Vec::new();
    let mut pc = 0usize;
    while pc < code.len() {
        let (instr, len) = decode(code, pc).ok()?;
        list.push((pc, instr, len));
        pc += len;
    }
    let mut out = code.to_vec();
    let mut found = false;
    for w in list.windows(3) {
        let (first, second, third) = (&w[0], &w[1], &w[2]);
        let tagged = matches!(first.1, Instr::Ldi { d, imm } if d == ABORT_REG && imm & TAG_MASK == ABORT_TAG);
        let zeroed = second.1
            == (Instr::Ldi {
                d: ZERO_REG,
                imm: 0,
            });
        let divides = third.1
            == (Instr::Div {
                d: ABORT_REG,
                a: ABORT_REG,
                b: ZERO_REG,
            });
        let legacy = second.1
            == (Instr::Ldi {
                d: ABORT_REG,
                imm: 0,
            })
            && third.1
                == (Instr::Div {
                    d: ABORT_REG,
                    a: ABORT_REG,
                    b: ABORT_REG,
                });
        if (tagged && zeroed && divides) || legacy {
            let mut patch = Vec::with_capacity(third.2);
            Instr::Halt.encode(&mut patch);
            while patch.len() < third.2 {
                Instr::Nop.encode(&mut patch);
            }
            out[third.0..third.0 + third.2].copy_from_slice(&patch);
            found = true;
        }
    }
    found.then_some(out)
}

pub fn reason_in(regs: &[u64]) -> Option<(Rule, u32)> {
    match regs.get(ABORT_REG as usize).copied() {
        Some(0) => Some((Rule::LegacyRule, 0)),
        Some(code) => split_code(code),
        None => None,
    }
}

pub fn rule_of_fault(fault: &Fault) -> Rule {
    match fault {
        Fault::OutOfMeter => Rule::OutOfMeter,
        Fault::Overflow => Rule::ArithmeticOverflow,
        Fault::DivByZero => Rule::DivisionByZero,
        Fault::StackOverflow
        | Fault::StackUnderflow
        | Fault::BadJump
        | Fault::BadConst
        | Fault::Malformed
        | Fault::Decode(_) => Rule::ContractFault,
        Fault::BadMemory => Rule::MemoryOutOfRange,
        Fault::UnknownSelector => Rule::UnknownEntry,
        Fault::BadScheme => Rule::UnsupportedScheme,
        Fault::EffectsTooLarge => Rule::EffectsTooLarge,
        Fault::UndeclaredSlot => Rule::UndeclaredState,
        Fault::CryptoFault => Rule::CryptoFault,
    }
}
