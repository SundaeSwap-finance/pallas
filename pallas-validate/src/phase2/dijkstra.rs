//! Deliberately scoped native protocol-12 V3 registration evaluation.
//! Ledger rules and exclusions: test_data/musashi-phase2/README.md.
use super::{
    error::Error,
    evaluator,
    script_context::{ScriptPurpose, SlotConfig, TimeRange, TxInInfo, TxInfo, TxInfoV3},
    to_plutus_data::MintValue,
    tx::TxEvalResult,
};
use crate::utils::{MultiEraProtocolParameters, TxoRef, UtxoMap};
use pallas_addresses::{Address, ShelleyDelegationPart, ShelleyPaymentPart};
use pallas_codec::utils::CborWrap;
use pallas_primitives::{conway as c, dijkstra as n};
use pallas_traverse::{ComputeHash, MultiEraOutput, MultiEraScriptRef, MultiEraTx, OriginalHash};
use std::collections::BTreeMap;

fn unsupported<T>(feature: &'static str) -> Result<T, Error> {
    Err(Error::DijkstraUnsupported(feature))
}

/// Project checked ledger output fields into the shared V3 TxOut
/// representation. Decode under the original era first; never decode native
/// CBOR as Conway or change its era. V3 exposes the same
/// address/value/datum/script-hash fields.
fn context_output(
    output: &MultiEraOutput<'_>,
    reference: bool,
) -> Result<c::TransactionOutput<'static>, Error> {
    let address = output.address()?;
    match &address {
        Address::Shelley(a)
            if (reference || matches!(a.payment(), ShelleyPaymentPart::Key(_)))
                && !matches!(a.delegation(), ShelleyDelegationPart::Pointer(_)) => {}
        _ => return unsupported("output address (requires Shelley payment key, no pointer)"),
    }
    if output.datum().is_some() || !output.value().assets().is_empty() {
        return unsupported("output datum or multiasset");
    }
    let script = match output.multi_era_script_ref() {
        None => None,
        Some(MultiEraScriptRef::Dijkstra(s)) => match s.as_ref() {
            n::ScriptRef::PlutusV3Script(s) => Some(s.clone()),
            _ => return unsupported("reference script language (requires V3)"),
        },
        Some(MultiEraScriptRef::Conway(s)) => match s.as_ref() {
            c::ScriptRef::PlutusV3Script(s) => Some(s.clone()),
            _ => return unsupported("reference script language (requires V3)"),
        },
        _ => return unsupported("reference script language (requires V3)"),
    };
    Ok(c::TransactionOutput::PostAlonzo(
        c::PostAlonzoTransactionOutput {
            address: address.to_vec().into(),
            value: c::Value::Coin(output.value().coin()),
            datum_option: None,
            script_ref: script.map(|s| CborWrap(c::ScriptRef::PlutusV3Script(s))),
        }
        .into(),
    ))
}

fn resolve(
    inputs: &[n::TransactionInput],
    utxos: &UtxoMap,
    reference: bool,
) -> Result<Vec<TxInInfo<'static>>, Error> {
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
            Ok(TxInInfo {
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
    if b.mint.is_some()
        || b.withdrawals.is_some()
        || b.voting_procedures.is_some()
        || b.proposal_procedures.is_some()
        || b.treasury_value.is_some()
        || b.donation.is_some()
    {
        return unsupported("mint, withdrawals or governance");
    }
    if b.ttl.is_some() {
        return unsupported("upper validity bound requires forecast state");
    }
    if w.plutus_v1_script.is_some()
        || w.plutus_v2_script.is_some()
        || w.plutus_v3_script.is_some()
        || w.native_script.is_some()
        || w.bootstrap_witness.is_some()
        || w.plutus_data.is_some()
    {
        return unsupported("witness scripts, bootstrap witnesses or datums");
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
    let mut scripts = BTreeMap::new();
    for i in inputs.iter().chain(&reference_inputs) {
        if let c::TransactionOutput::PostAlonzo(o) = &i.resolved
            && let Some(CborWrap(c::ScriptRef::PlutusV3Script(s))) = &o.script_ref
        {
            scripts.insert(s.compute_hash(), s.clone());
        }
    }
    let mut expected = BTreeMap::new();
    for (index, cert) in certificates.iter().enumerate() {
        if let c::Certificate::Reg(n::StakeCredential::ScriptHash(hash), _) = cert {
            if !scripts.contains_key(hash) {
                return Err(Error::MissingRequiredScript {
                    hash: hash.to_string(),
                });
            }
            expected.insert(index as u32, *hash);
        }
    }
    let redeemers = tx.redeemers();
    let mut purposes = Vec::new();
    for r in &redeemers {
        let (key, value) = r.as_dijkstra().ok_or(Error::WrongEra())?;
        if key.tag != n::RedeemerTag::Cert {
            return unsupported("redeemer purpose (requires Cert)");
        }
        let cert = certificates
            .get(key.index as usize)
            .ok_or(Error::MissingScriptForRedeemer)?;
        if !expected.contains_key(&key.index) {
            return Err(Error::NonScriptStakeCredential);
        }
        purposes.push((
            ScriptPurpose::Certifying(key.index as usize, cert.clone()),
            c::Redeemer {
                tag: c::RedeemerTag::Cert,
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
                .filter(|i| !purposes.iter().any(|(_, r)| r.index == **i))
                .map(|i| format!("Cert[{i}]"))
                .collect(),
            extra: vec![],
        });
    }
    let lower_bound = b
        .validity_interval_start
        .map(|s| {
            let elapsed = s
                .checked_sub(slots.zero_slot)
                .ok_or(Error::SlotTooFarInThePast {
                    oldest_allowed: slots.zero_slot,
                })?;
            elapsed
                .checked_mul(slots.slot_length)
                .and_then(|x| slots.zero_time.checked_add(x))
                .ok_or(Error::DijkstraInvalid("slot time overflow"))
        })
        .transpose()?;
    let info = TxInfo::V3(TxInfoV3 {
        inputs,
        reference_inputs,
        outputs,
        fee: b.fee,
        mint: MintValue {
            mint_value: Default::default(),
        },
        certificates,
        withdrawals: vec![].into(),
        valid_range: TimeRange {
            lower_bound,
            upper_bound: None,
        },
        signatories,
        redeemers: purposes.clone().into(),
        data: vec![].into(),
        id: b.original_hash(),
        votes: vec![].into(),
        proposal_procedures: vec![],
        current_treasury_amount: None,
        treasury_donation: None,
    });
    let plutus = pp
        .plutus
        .as_ref()
        .ok_or(Error::CostModelNotFound(c::Language::PlutusV3))?;
    if plutus.cost_model_v3.len() != 350 {
        return unsupported("protocol-12 V3 cost model requires 350 entries");
    }
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
    if total_mem > plutus.max_tx_ex_units.mem || total_steps > plutus.max_tx_ex_units.steps {
        return Err(Error::DijkstraInvalid(
            "declared transaction budget exceeds maximum",
        ));
    }
    purposes
        .iter()
        .map(|(_, r)| {
            let context = info
                .clone()
                .into_script_context(r, None)
                .ok_or(Error::ScriptContextBuildError)?;
            let data = context.to_plutus_data_with_protocol(12);
            let result = evaluator::eval_native_v3(
                scripts[&expected[&r.index]].as_ref(),
                &data,
                &plutus.cost_model_v3,
                r.ex_units,
            )?;
            Ok(TxEvalResult {
                tag: r.tag,
                index: r.index,
                units: result.units,
                success: result.success,
                logs: result.logs,
                failure_message: result.failure.map(|f| f.message),
            })
        })
        .collect()
}
