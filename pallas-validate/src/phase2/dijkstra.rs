//! Native protocol-12 V3 spending, minting, withdrawals and registration evaluation.
//! Ledger rules and exclusions: test_data/musashi-dijkstra-validation/README.md.
use super::{
    error::{Error, Unsupported},
    evaluator,
    native_evaluator::Builtin,
    script_context::{ScriptPurpose, SlotConfig, TimeRange, V3TxInfo},
    to_plutus_data::{MintValue, ToPlutusData, v3_script_context_data, wrap_multiple_with_constr},
    tx::TxEvalResult,
};
use crate::utils::{DijkstraTimeContext, EraTime, MultiEraProtocolParameters, TxoRef, UtxoMap};
use pallas_addresses::{Address, ShelleyDelegationPart, ShelleyPaymentPart, StakePayload};
use pallas_codec::utils::CborWrap;
use pallas_primitives::{conway as c, dijkstra as n};
use pallas_traverse::{ComputeHash, MultiEraOutput, MultiEraScriptRef, MultiEraTx, OriginalHash};
use std::collections::BTreeMap;

fn unsupported<T>(feature: &'static str) -> Result<T, Error> {
    Err(Error::DijkstraUnsupported(Unsupported(feature)))
}

/// A V3 context exposes only the original reference-script hash. Keep script
/// discovery separate from that projection: Dijkstra native constructors must
/// never be decoded as Conway just to obtain a V3 output representation.
#[derive(Debug, Clone)]
enum ContextReferenceScript {
    Native(n::ScriptHash),
    PlutusV1(n::ScriptHash),
    PlutusV2(n::ScriptHash),
    PlutusV3(n::PlutusScript<3>),
}

impl ContextReferenceScript {
    fn hash(&self) -> n::ScriptHash {
        match self {
            Self::Native(hash) | Self::PlutusV1(hash) | Self::PlutusV2(hash) => *hash,
            Self::PlutusV3(script) => script.compute_hash(),
        }
    }
}

#[derive(Debug, Clone)]
struct ContextOutput {
    address: Address,
    value: c::Value,
    datum: Option<c::DatumOption<'static>>,
    script: Option<ContextReferenceScript>,
}

impl ToPlutusData for ContextOutput {
    fn to_plutus_data(&self) -> c::PlutusData {
        wrap_multiple_with_constr(
            0,
            vec![
                self.address.to_plutus_data(),
                self.value.to_plutus_data(),
                self.datum.to_plutus_data(),
                self.script
                    .as_ref()
                    .map(ContextReferenceScript::hash)
                    .to_plutus_data(),
            ],
        )
    }
}

#[derive(Debug, Clone)]
struct ContextInput {
    out_ref: n::TransactionInput,
    resolved: ContextOutput,
}

impl ToPlutusData for ContextInput {
    fn to_plutus_data(&self) -> c::PlutusData {
        wrap_multiple_with_constr(
            0,
            vec![
                self.out_ref.to_plutus_data(),
                self.resolved.to_plutus_data(),
            ],
        )
    }
}

/// Ledger Babbage.transTxOutV2 (also used by Dijkstra V3) hashes native
/// reference scripts without inspecting constructors, including RequireGuard.
/// Retained CBOR is authoritative; constructed or mutated scripts fall back to
/// encoding their current value.
/// See test_data/musashi-guard-reference/README.md for pinned reference evidence.
fn context_output(output: &MultiEraOutput<'_>, _reference: bool) -> Result<ContextOutput, Error> {
    let address = output.address()?;
    match &address {
        Address::Shelley(a) if matches!(a.delegation(), ShelleyDelegationPart::Pointer(_)) => {
            return unsupported("pointer address in a V3 script context");
        }
        Address::Shelley(_) => {}
        _ => return unsupported("output address (requires Shelley)"),
    }
    let script = match output.multi_era_script_ref() {
        None => None,
        Some(MultiEraScriptRef::Dijkstra(s)) => match s.as_ref() {
            n::ScriptRef::NativeScript(s) => Some(ContextReferenceScript::Native(
                pallas_traverse::MultiEraNativeScript::from_dijkstra(s).hash(),
            )),
            n::ScriptRef::PlutusV1Script(s) => {
                Some(ContextReferenceScript::PlutusV1(s.compute_hash()))
            }
            n::ScriptRef::PlutusV2Script(s) => {
                Some(ContextReferenceScript::PlutusV2(s.compute_hash()))
            }
            n::ScriptRef::PlutusV3Script(s) => Some(ContextReferenceScript::PlutusV3(s.clone())),
            n::ScriptRef::PlutusV4Script(_) => {
                return unsupported("reference script language (requires V3)");
            }
        },
        Some(MultiEraScriptRef::Conway(s)) => match s.as_ref() {
            c::ScriptRef::NativeScript(s) => Some(ContextReferenceScript::Native(
                pallas_traverse::MultiEraNativeScript::from_alonzo_compatible(s).hash(),
            )),
            c::ScriptRef::PlutusV1Script(s) => {
                Some(ContextReferenceScript::PlutusV1(s.compute_hash()))
            }
            c::ScriptRef::PlutusV2Script(s) => {
                Some(ContextReferenceScript::PlutusV2(s.compute_hash()))
            }
            c::ScriptRef::PlutusV3Script(s) => Some(ContextReferenceScript::PlutusV3(s.clone())),
        },
        _ => return unsupported("reference script language (requires V3)"),
    };
    Ok(ContextOutput {
        address,
        value: output.value().into_conway(),
        datum: output.datum().map(|d| match d {
            c::DatumOption::Hash(h) => c::DatumOption::Hash(h),
            c::DatumOption::Data(d) => c::DatumOption::Data(CborWrap(d.0.unwrap().into())),
        }),
        script,
    })
}

fn resolve(
    inputs: &[n::TransactionInput],
    utxos: &UtxoMap,
    reference: bool,
) -> Result<Vec<ContextInput>, Error> {
    let mut ordered: Vec<_> = inputs.iter().collect();
    ordered.sort();
    if ordered.windows(2).any(|x| x[0] == x[1]) {
        return Err(Error::DijkstraInvalid("duplicate input"));
    }
    ordered
        .into_iter()
        .map(|i| {
            let index =
                u32::try_from(i.index).map_err(|_| Error::DijkstraInvalid("input index"))?;
            let raw = utxos
                .get(&TxoRef(i.transaction_id, index))
                .ok_or_else(|| Error::ResolvedInputNotFound(i.clone()))?;
            let output = MultiEraOutput::decode(raw.0, &raw.1)
                .map_err(|_| Error::DijkstraInvalid("input decoding for original era"))?;
            Ok(ContextInput {
                out_ref: i.clone(),
                resolved: context_output(&output, reference)?,
            })
        })
        .collect()
}

pub(super) fn eval_tx(
    tx: &MultiEraTx,
    pparams: &MultiEraProtocolParameters,
    utxos: &UtxoMap,
    slots: &SlotConfig,
) -> Result<Vec<TxEvalResult>, Error> {
    let results = eval_tx_with_mode(tx, pparams, utxos, &linear_time(slots)?, false)?;
    Ok(results.into_iter().map(|(result, _)| result).collect())
}

pub(super) fn estimate_tx(
    tx: &MultiEraTx,
    pparams: &MultiEraProtocolParameters,
    utxos: &UtxoMap,
    slots: &SlotConfig,
) -> Result<Vec<(TxEvalResult, Vec<Builtin>)>, Error> {
    eval_tx_with_mode(tx, pparams, utxos, &linear_time(slots)?, true)
}

fn linear_time(slots: &SlotConfig) -> Result<DijkstraTimeContext, Error> {
    DijkstraTimeContext::new(
        vec![EraTime {
            start_slot: slots.zero_slot,
            start_time_ms: slots.zero_time,
            slot_length_ms: slots.slot_length,
        }],
        slots.zero_slot,
    )
    .map_err(Error::from)
}

pub(super) fn eval_tx_with_mode(
    tx: &MultiEraTx,
    pparams: &MultiEraProtocolParameters,
    utxos: &UtxoMap,
    time: &DijkstraTimeContext,
    estimate: bool,
) -> Result<Vec<(TxEvalResult, Vec<Builtin>)>, Error> {
    let native = tx.as_dijkstra().ok_or(Error::WrongEra())?;
    let MultiEraProtocolParameters::Dijkstra(pp) = pparams else {
        return unsupported("protocol parameters require Dijkstra");
    };
    if pp.protocol_version != (12, 0) {
        return unsupported("protocol version (requires 12.0)");
    }
    let b = &native.transaction_body;
    let w = &native.transaction_witness_set;
    if b.sub_transactions.is_some() {
        return unsupported("subtransactions");
    }
    if b.required_top_level_guards.is_some()
        || b.direct_deposits.is_some()
        || b.account_balance_intervals.is_some()
        || b.starting_account_balance_intervals.is_some()
    {
        return unsupported("account features or required top-level guards");
    }
    if b.voting_procedures.is_some()
        || b.proposal_procedures.is_some()
        || b.treasury_value.is_some()
        || b.donation.is_some()
    {
        return unsupported("governance");
    }
    if w.plutus_v1_script.is_some() || w.plutus_v2_script.is_some() || w.bootstrap_witness.is_some()
    {
        return unsupported("unsupported witness scripts or bootstrap witnesses");
    }
    let mut signatories = match &b.guards {
        None => vec![],
        Some(n::Guards::AddrKeyhashes(keys)) => keys.to_vec(),
        Some(n::Guards::Credentials(credentials)) => credentials
            .iter()
            .map(|g| match g {
                n::StakeCredential::AddrKeyhash(key) => Ok(*key),
                _ => unsupported("script guards"),
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    signatories.sort();
    signatories.dedup();
    let certificates = b
        .certificates
        .iter()
        .flat_map(|x| x.iter())
        .map(|cert| match cert {
            n::Certificate::Reg(credential, deposit) => {
                Ok(c::Certificate::Reg(credential.clone(), *deposit))
            }
            _ => unsupported("certificate kind (requires Reg)"),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let inputs = resolve(&b.inputs, utxos, false)?;
    let refs: Vec<_> = b
        .reference_inputs
        .iter()
        .flat_map(|x| x.iter())
        .cloned()
        .collect();
    if refs.iter().any(|r| b.inputs.contains(r)) {
        return Err(Error::DijkstraInvalid(
            "overlapping spending/reference inputs",
        ));
    }
    let reference_inputs = resolve(&refs, utxos, true)?;
    let outputs = b
        .outputs
        .iter()
        .map(|o| context_output(&MultiEraOutput::from_dijkstra(o), false))
        .collect::<Result<Vec<_>, _>>()?;
    // Collateral is a phase-one concern and is not part of the V3 context or
    // script lookup.
    let mut natives = std::collections::BTreeSet::new();
    for script in w.native_script.iter().flat_map(|x| x.iter()) {
        natives.insert(script.original_hash());
    }
    for input in inputs.iter().chain(&reference_inputs) {
        if let Some(ContextReferenceScript::Native(hash)) = &input.resolved.script {
            natives.insert(*hash);
        }
    }
    let mut scripts = BTreeMap::new();
    for script in w.plutus_v3_script.iter().flat_map(|x| x.iter()) {
        super::native_evaluator::check_plutus_script(script.as_ref())?;
        scripts.insert(script.compute_hash(), script.clone());
    }
    let mut unevaluable = std::collections::BTreeSet::new();
    for i in inputs.iter().chain(&reference_inputs) {
        match &i.resolved.script {
            Some(ContextReferenceScript::PlutusV3(s)) => {
                scripts.insert(s.compute_hash(), s.clone());
            }
            Some(
                ContextReferenceScript::PlutusV1(hash) | ContextReferenceScript::PlutusV2(hash),
            ) => {
                unevaluable.insert(*hash);
            }
            Some(ContextReferenceScript::Native(_)) | None => {}
        }
    }
    let mut expected = BTreeMap::new();
    let mut purposes_by_pointer = BTreeMap::new();
    let mut spending_datums = BTreeMap::new();
    let datums: BTreeMap<_, _> = w
        .plutus_data
        .iter()
        .flat_map(|x| x.iter())
        .map(|d| {
            (
                pallas_crypto::hash::Hasher::<256>::hash_cbor(d),
                (**d).clone(),
            )
        })
        .collect();
    for (index, input) in inputs.iter().enumerate() {
        if let Address::Shelley(address) = &input.resolved.address
            && let ShelleyPaymentPart::Script(hash) = address.payment()
        {
            if natives.contains(hash) {
                continue;
            }
            let key = n::RedeemersKey {
                tag: n::RedeemerTag::Spend,
                index: index as u32,
            };
            let datum = match input.resolved.datum.clone() {
                Some(c::DatumOption::Data(d)) => Some(d.0.unwrap()),
                Some(c::DatumOption::Hash(hash)) => Some(datums.get(&hash).cloned().ok_or_else(
                    || Error::MissingRequiredDatum {
                        hash: hash.to_string(),
                    },
                )?),
                None => None,
            };
            if let Some(datum) = datum {
                spending_datums.insert(key.clone(), datum);
            }
            expected.insert(key.clone(), *hash);
            purposes_by_pointer.insert(key, ScriptPurpose::Spending(input.out_ref.clone(), ()));
        }
    }
    for (index, (hash, _)) in b.mint.iter().flat_map(|x| x.iter()).enumerate() {
        let key = n::RedeemersKey {
            tag: n::RedeemerTag::Mint,
            index: index as u32,
        };
        expected.insert(key.clone(), *hash);
        purposes_by_pointer.insert(key, ScriptPurpose::Minting(*hash));
    }
    for (index, cert) in certificates.iter().enumerate() {
        if let c::Certificate::Reg(n::StakeCredential::ScriptHash(hash), _) = cert {
            let key = n::RedeemersKey {
                tag: n::RedeemerTag::Cert,
                index: index as u32,
            };
            expected.insert(key.clone(), *hash);
            purposes_by_pointer.insert(key, ScriptPurpose::Certifying(index, cert.clone()));
        }
    }
    let mut withdrawals = b
        .withdrawals
        .iter()
        .flat_map(|x| x.iter())
        .map(|(raw, amount)| {
            let address = Address::from_bytes(raw)?;
            if !matches!(address, Address::Stake(_)) {
                return Err(Error::BadWithdrawalAddress);
            }
            Ok((raw, address, *amount))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    withdrawals.sort_by(|a, b| super::script_context::sort_reward_accounts(a.0, b.0));
    for (index, (_, address, _)) in withdrawals.iter().enumerate() {
        if let Address::Stake(address) = address
            && let StakePayload::Script(hash) = address.payload()
        {
            let key = n::RedeemersKey {
                tag: n::RedeemerTag::Reward,
                index: index as u32,
            };
            expected.insert(key.clone(), *hash);
            purposes_by_pointer.insert(
                key,
                ScriptPurpose::Rewarding(n::StakeCredential::ScriptHash(*hash)),
            );
        }
    }
    expected.retain(|_, hash| !natives.contains(hash));
    purposes_by_pointer.retain(|key, _| expected.contains_key(key));
    for hash in expected.values() {
        if unevaluable.contains(hash) && !scripts.contains_key(hash) {
            return unsupported("reference script language (requires V3)");
        }
        if !scripts.contains_key(hash) {
            return Err(Error::MissingRequiredScript {
                hash: hash.to_string(),
            });
        }
    }
    let redeemers = tx.redeemers();
    let mut purposes = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for r in &redeemers {
        let (key, value) = r.as_dijkstra().ok_or(Error::WrongEra())?;
        let purpose = purposes_by_pointer
            .get(key)
            .ok_or(Error::ExtraneousRedeemer)?;
        if !seen.insert(key.clone()) {
            return Err(Error::ExtraneousRedeemer);
        }
        let tag = match key.tag {
            n::RedeemerTag::Spend => c::RedeemerTag::Spend,
            n::RedeemerTag::Mint => c::RedeemerTag::Mint,
            n::RedeemerTag::Cert => c::RedeemerTag::Cert,
            n::RedeemerTag::Reward => c::RedeemerTag::Reward,
            _ => return unsupported("redeemer purpose"),
        };
        purposes.push((
            purpose.clone(),
            c::Redeemer {
                tag,
                index: key.index,
                data: value.data.clone(),
                ex_units: value.ex_units,
            },
        ));
    }
    if purposes.len() != expected.len() {
        return Err(Error::RequiredRedeemersMismatch {
            missing: expected
                .keys()
                .filter(|key| !seen.contains(key))
                .map(|key| format!("{:?}[{}]", key.tag, key.index))
                .collect(),
            extra: vec![],
        });
    }
    if purposes.is_empty() {
        return Ok(vec![]);
    }
    let (lower_bound, upper_bound) = time.validity_bounds(b.validity_interval_start, b.ttl)?;
    let info = V3TxInfo {
        inputs,
        reference_inputs,
        outputs,
        fee: b.fee,
        mint: MintValue {
            mint_value: b.mint.clone().unwrap_or_default(),
        },
        certificates,
        withdrawals: withdrawals
            .into_iter()
            .map(|(_, a, n)| (a, n))
            .collect::<Vec<_>>()
            .into(),
        valid_range: TimeRange {
            lower_bound,
            upper_bound,
        },
        signatories,
        redeemers: purposes.clone().into(),
        data: datums.into_iter().collect::<Vec<_>>().into(),
        id: pallas_crypto::hash::Hasher::<256>::hash_cbor(b),
        votes: vec![].into(),
        proposal_procedures: vec![],
        current_treasury_amount: None,
        treasury_donation: None,
    };
    let cost_model_v3 = pp
        .cost_models_for_script_languages
        .plutus_v3
        .as_ref()
        .ok_or(Error::CostModelNotFound(c::Language::PlutusV3))?;
    if !estimate {
        let mut total_mem = 0u64;
        let mut total_steps = 0u64;
        for (_, r) in &purposes {
            total_mem = total_mem
                .checked_add(r.ex_units.mem)
                .ok_or(Error::DijkstraInvalid("budget overflow"))?;
            total_steps = total_steps
                .checked_add(r.ex_units.steps)
                .ok_or(Error::DijkstraInvalid("budget overflow"))?;
        }
        if total_mem > pp.max_tx_ex_units.mem || total_steps > pp.max_tx_ex_units.steps {
            return Err(Error::DijkstraInvalid(
                "declared transaction budget exceeds maximum",
            ));
        }
    }
    let execution_limit = pp.max_tx_ex_units;
    if estimate
        && (execution_limit.mem > i64::MAX as u64 || execution_limit.steps > i64::MAX as u64)
    {
        return Err(Error::DijkstraInvalid(
            "transaction execution limit overflow",
        ));
    }
    purposes
        .iter()
        .map(|(purpose, r)| {
            let tag = match r.tag {
                c::RedeemerTag::Spend => n::RedeemerTag::Spend,
                c::RedeemerTag::Mint => n::RedeemerTag::Mint,
                c::RedeemerTag::Cert => n::RedeemerTag::Cert,
                c::RedeemerTag::Reward => n::RedeemerTag::Reward,
                _ => return unsupported("redeemer purpose"),
            };
            let key = n::RedeemersKey {
                tag,
                index: r.index,
            };
            let data = v3_script_context_data(
                info.to_plutus_data_with_protocol(12),
                &r.data,
                &purpose
                    .clone()
                    .into_script_info(spending_datums.get(&key).cloned()),
                12,
            );
            let (result, calls) = evaluator::eval_native_v3(
                scripts[&expected[&key]].as_ref(),
                &data,
                cost_model_v3,
                if estimate {
                    execution_limit
                } else {
                    r.ex_units
                },
            )?;
            let result = TxEvalResult {
                tag: r.tag,
                index: r.index,
                units: result.units,
                success: result.success,
                logs: result.logs,
                failure_message: result.failure.map(|f| f.message),
            };
            Ok((result, calls))
        })
        .collect()
}

#[cfg(test)]
#[path = "dijkstra_native_context_tests.rs"]
mod native_context_tests;
