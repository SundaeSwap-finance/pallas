//! Native protocol-12 evaluation of the Plutus V1, V2 and V3 scripts the top level of a Dijkstra transaction runs.
//! Ledger rules and exclusions: test_data/musashi-dijkstra-validation/README.md.
use super::{
    error::{Error, Unsupported},
    evaluator,
    native_evaluator::Builtin,
    script_context::{
        ScriptPurpose, SlotConfig, TimeRange, V1TxInfo, V2TxInfo, V3TxInfo, get_votes_info,
    },
    to_plutus_data::{
        LegacyContextData, MintValue, ToPlutusData, WithWrappedTransactionId, WithZeroAdaAsset,
        v1v2_script_context_data, v3_script_context_data, wrap_multiple_with_constr,
    },
    tx::TxEvalResult,
};
use crate::phase1::dijkstra_ledger::{Level, needs};
use crate::utils::{
    DijkstraTimeContext, EraTime, ForecastHorizon, MultiEraProtocolParameters, TxoRef, UtxoMap,
    dijkstra_context::check_translatable,
};
use pallas_addresses::{Address, ShelleyPaymentPart};
use pallas_codec::{minicbor, utils::CborWrap};
use pallas_crypto::hash::{Hash, Hasher};
use pallas_primitives::{conway as c, dijkstra as n};
use pallas_traverse::{ComputeHash, MultiEraOutput, MultiEraScriptRef, MultiEraTx, OriginalHash};
use std::collections::{BTreeMap, BTreeSet};

fn unsupported<T>(feature: &'static str) -> Result<T, Error> {
    Err(Error::DijkstraUnsupported(Unsupported(feature)))
}

#[derive(Debug, Clone)]
struct ContextOutput {
    address: Address,
    value: c::Value,
    datum: Option<c::DatumOption<'static>>,
    script: Option<n::ScriptHash>,
}

impl ToPlutusData for ContextOutput {
    fn to_plutus_data(&self) -> c::PlutusData {
        wrap_multiple_with_constr(
            0,
            vec![
                self.address.to_plutus_data(),
                self.value.to_plutus_data(),
                self.datum.to_plutus_data(),
                self.script.to_plutus_data(),
            ],
        )
    }
}

impl LegacyContextData for ContextOutput {
    fn to_plutus_data_v1(&self) -> c::PlutusData {
        let datum_hash = match &self.datum {
            Some(c::DatumOption::Hash(hash)) => Some(*hash),
            _ => None,
        };
        wrap_multiple_with_constr(
            0,
            vec![
                self.address.to_plutus_data(),
                WithZeroAdaAsset(&self.value).to_plutus_data(),
                datum_hash.to_plutus_data(),
            ],
        )
    }

    fn to_plutus_data_v2(&self) -> c::PlutusData {
        wrap_multiple_with_constr(
            0,
            vec![
                self.address.to_plutus_data(),
                WithZeroAdaAsset(&self.value).to_plutus_data(),
                self.datum.to_plutus_data(),
                self.script.to_plutus_data(),
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

impl LegacyContextData for ContextInput {
    fn to_plutus_data_v1(&self) -> c::PlutusData {
        wrap_multiple_with_constr(
            0,
            vec![
                WithWrappedTransactionId(&self.out_ref).to_plutus_data(),
                self.resolved.to_plutus_data_v1(),
            ],
        )
    }

    fn to_plutus_data_v2(&self) -> c::PlutusData {
        wrap_multiple_with_constr(
            0,
            vec![
                WithWrappedTransactionId(&self.out_ref).to_plutus_data(),
                self.resolved.to_plutus_data_v2(),
            ],
        )
    }
}

/// The fields of an output a script context holds, with any reference script reduced to the hash of its original bytes.
fn context_output(output: &MultiEraOutput<'_>, _reference: bool) -> Result<ContextOutput, Error> {
    let address = output.address()?;
    if !matches!(address, Address::Shelley(_)) {
        return unsupported("output address (requires Shelley)");
    }
    let script = match output.multi_era_script_ref() {
        None => None,
        Some(MultiEraScriptRef::Dijkstra(s)) => Some(match s.as_ref() {
            n::ScriptRef::NativeScript(s) => {
                pallas_traverse::MultiEraNativeScript::from_dijkstra(s).hash()
            }
            n::ScriptRef::PlutusV1Script(s) => s.compute_hash(),
            n::ScriptRef::PlutusV2Script(s) => s.compute_hash(),
            n::ScriptRef::PlutusV3Script(s) => s.compute_hash(),
            n::ScriptRef::PlutusV4Script(_) => {
                return unsupported("reference script language (requires V3)");
            }
        }),
        Some(MultiEraScriptRef::Conway(s)) => Some(match s.as_ref() {
            c::ScriptRef::NativeScript(s) => {
                pallas_traverse::MultiEraNativeScript::from_alonzo_compatible(s).hash()
            }
            c::ScriptRef::PlutusV1Script(s) => s.compute_hash(),
            c::ScriptRef::PlutusV2Script(s) => s.compute_hash(),
            c::ScriptRef::PlutusV3Script(s) => s.compute_hash(),
        }),
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

/// The output `input` spends or references, decoded under its own era.
fn decode<'a>(
    input: &n::TransactionInput,
    utxos: &'a UtxoMap,
) -> Result<MultiEraOutput<'a>, Error> {
    let index = u32::try_from(input.index).map_err(|_| Error::DijkstraInvalid("input index"))?;
    let raw = utxos
        .get(&TxoRef(input.transaction_id, index))
        .ok_or_else(|| Error::ResolvedInputNotFound(input.clone()))?;
    MultiEraOutput::decode(raw.0, &raw.1)
        .map_err(|_| Error::DijkstraInvalid("input decoding for original era"))
}

/// The inputs in the order the ledger indexes their redeemers.
fn ordered(inputs: &[n::TransactionInput]) -> Result<Vec<&n::TransactionInput>, Error> {
    let mut ordered: Vec<_> = inputs.iter().collect();
    ordered.sort();
    if ordered.windows(2).any(|x| x[0] == x[1]) {
        return Err(Error::DijkstraInvalid("duplicate input"));
    }
    Ok(ordered)
}

fn resolve(
    inputs: &[n::TransactionInput],
    utxos: &UtxoMap,
    reference: bool,
) -> Result<Vec<ContextInput>, Error> {
    ordered(inputs)?
        .into_iter()
        .map(|i| {
            Ok(ContextInput {
                out_ref: i.clone(),
                resolved: context_output(&decode(i, utxos)?, reference)?,
            })
        })
        .collect()
}

/// A script a transaction provides, as its top level runs it.
enum Provided {
    Native,
    Plutus(c::Language, Vec<u8>),
    PlutusV4,
}

/// The script a reference output carries, by hash.
fn reference_script(output: &MultiEraOutput<'_>) -> Result<Option<(Hash<28>, Provided)>, Error> {
    let Some(script) = output.multi_era_script_ref() else {
        return Ok(None);
    };
    let plutus = |language, bytes: &[u8]| Provided::Plutus(language, bytes.to_vec());
    let provided = match &script {
        MultiEraScriptRef::Dijkstra(s) => match s.as_ref() {
            n::ScriptRef::NativeScript(_) => Provided::Native,
            n::ScriptRef::PlutusV1Script(x) => plutus(c::Language::PlutusV1, x.as_ref()),
            n::ScriptRef::PlutusV2Script(x) => plutus(c::Language::PlutusV2, x.as_ref()),
            n::ScriptRef::PlutusV3Script(x) => plutus(c::Language::PlutusV3, x.as_ref()),
            n::ScriptRef::PlutusV4Script(_) => Provided::PlutusV4,
        },
        MultiEraScriptRef::Conway(s) => match s.as_ref() {
            c::ScriptRef::NativeScript(_) => Provided::Native,
            c::ScriptRef::PlutusV1Script(x) => plutus(c::Language::PlutusV1, x.as_ref()),
            c::ScriptRef::PlutusV2Script(x) => plutus(c::Language::PlutusV2, x.as_ref()),
            c::ScriptRef::PlutusV3Script(x) => plutus(c::Language::PlutusV3, x.as_ref()),
        },
        _ => return unsupported("reference script language (requires V3)"),
    };
    Ok(Some((script.hash(), provided)))
}

/// The scripts the witness sets and the spent and referenced outputs of every level of a batch provide.
fn provided_scripts(
    tx: &n::BlockTransaction<'_>,
    utxos: &UtxoMap,
) -> Result<BTreeMap<Hash<28>, Provided>, Error> {
    let b = &tx.transaction_body;
    let subs = b.sub_transactions.iter().flatten();
    let witnesses = std::iter::once(&tx.transaction_witness_set)
        .chain(subs.clone().map(|x| &x.transaction_witness_set));
    let mut provided = BTreeMap::new();
    for w in witnesses {
        for script in w.native_script.iter().flatten() {
            provided.insert(script.original_hash(), Provided::Native);
        }
        let v1 = w.plutus_v1_script.iter().flatten();
        let v2 = w.plutus_v2_script.iter().flatten();
        let v3 = w.plutus_v3_script.iter().flatten();
        for (hash, language, bytes) in v1
            .map(|x| (x.compute_hash(), c::Language::PlutusV1, x.as_ref()))
            .chain(v2.map(|x| (x.compute_hash(), c::Language::PlutusV2, x.as_ref())))
            .chain(v3.map(|x| (x.compute_hash(), c::Language::PlutusV3, x.as_ref())))
        {
            super::native_evaluator::check_plutus_script(bytes)?;
            provided.insert(hash, Provided::Plutus(language, bytes.to_vec()));
        }
        for script in w.plutus_v4_script.iter().flatten() {
            provided.insert(script.compute_hash(), Provided::PlutusV4);
        }
    }
    let levels = std::iter::once((&b.inputs, &b.reference_inputs)).chain(subs.map(|x| {
        (
            &x.sub_transaction_body.inputs,
            &x.sub_transaction_body.reference_inputs,
        )
    }));
    for (inputs, references) in levels {
        for input in inputs.iter().chain(references.iter().flatten()) {
            if let Some((hash, script)) = reference_script(&decode(input, utxos)?)? {
                provided.insert(hash, script);
            }
        }
    }
    Ok(provided)
}

/// The Conway form of a Dijkstra certificate, without the pool BLS key no script context holds.
fn conway_certificate(cert: &n::Certificate) -> c::Certificate {
    match cert.clone() {
        n::Certificate::StakeDelegation(x, pool) => c::Certificate::StakeDelegation(x, pool),
        n::Certificate::PoolRegistration {
            operator,
            vrf_keyhash,
            bls_key: _,
            pledge,
            cost,
            margin,
            reward_account,
            pool_owners,
            relays,
            pool_metadata,
        } => c::Certificate::PoolRegistration {
            operator,
            vrf_keyhash,
            pledge,
            cost,
            margin,
            reward_account,
            pool_owners: pool_owners.to_vec().into(),
            relays,
            pool_metadata,
        },
        n::Certificate::PoolRetirement(pool, epoch) => c::Certificate::PoolRetirement(pool, epoch),
        n::Certificate::Reg(x, deposit) => c::Certificate::Reg(x, deposit),
        n::Certificate::UnReg(x, deposit) => c::Certificate::UnReg(x, deposit),
        n::Certificate::VoteDeleg(x, drep) => c::Certificate::VoteDeleg(x, drep),
        n::Certificate::StakeVoteDeleg(x, pool, drep) => {
            c::Certificate::StakeVoteDeleg(x, pool, drep)
        }
        n::Certificate::StakeRegDeleg(x, pool, deposit) => {
            c::Certificate::StakeRegDeleg(x, pool, deposit)
        }
        n::Certificate::VoteRegDeleg(x, drep, deposit) => {
            c::Certificate::VoteRegDeleg(x, drep, deposit)
        }
        n::Certificate::StakeVoteRegDeleg(x, pool, drep, deposit) => {
            c::Certificate::StakeVoteRegDeleg(x, pool, drep, deposit)
        }
        n::Certificate::AuthCommitteeHot(cold, hot) => c::Certificate::AuthCommitteeHot(cold, hot),
        n::Certificate::ResignCommitteeCold(cold, anchor) => {
            c::Certificate::ResignCommitteeCold(cold, anchor)
        }
        n::Certificate::RegDRepCert(x, deposit, anchor) => {
            c::Certificate::RegDRepCert(x, deposit, anchor)
        }
        n::Certificate::UnRegDRepCert(x, deposit) => c::Certificate::UnRegDRepCert(x, deposit),
        n::Certificate::UpdateDRepCert(x, anchor) => c::Certificate::UpdateDRepCert(x, anchor),
    }
}

/// The Conway form of a Dijkstra proposal, which exists when its protocol parameter update has a Conway encoding.
fn conway_proposal(proposal: &n::ProposalProcedure) -> Result<c::ProposalProcedure, Error> {
    let raw = minicbor::to_vec(proposal)
        .map_err(|_| Error::DijkstraInvalid("proposal procedure encoding"))?;
    minicbor::decode(&raw)
        .or_else(|_| unsupported("protocol parameter update outside Conway in a script context"))
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
        ForecastHorizon::Unbounded,
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
    if b.sub_transactions.iter().flatten().any(|x| {
        x.transaction_witness_set
            .redeemer
            .as_ref()
            .is_some_and(|x| !x.is_empty())
    }) {
        return unsupported("subtransaction redeemers");
    }
    let id = Hasher::<256>::hash_cbor(b);
    let inputs = ordered(&b.inputs)?;
    let mut expected = BTreeMap::new();
    for (index, input) in inputs.iter().enumerate() {
        if let Address::Shelley(address) = decode(input, utxos)?.address()?
            && let ShelleyPaymentPart::Script(hash) = address.payment()
        {
            let key = n::RedeemersKey {
                tag: n::RedeemerTag::Spend,
                index: index as u32,
            };
            expected.insert(key, *hash);
        }
    }
    let policies: Vec<_> = b.mint.iter().flat_map(|x| x.keys()).copied().collect();
    for (index, policy) in policies.iter().enumerate() {
        let key = n::RedeemersKey {
            tag: n::RedeemerTag::Mint,
            index: index as u32,
        };
        expected.insert(key, *policy);
    }
    let level = Level::top(b, id);
    let ledger = needs(&level).map_err(|_| Error::BadWithdrawalAddress)?;
    expected.extend(ledger.scripts);
    let scripts = provided_scripts(native, utxos)?;
    expected.retain(|_, hash| !matches!(scripts.get(hash), Some(Provided::Native)));
    let mut languages = BTreeSet::new();
    for hash in expected.values() {
        match scripts.get(hash) {
            Some(Provided::Plutus(language, _)) => {
                languages.insert(language.clone());
            }
            Some(Provided::PlutusV4) => {
                return unsupported("reference script language (requires V3)");
            }
            Some(Provided::Native) | None => {
                return Err(Error::MissingRequiredScript {
                    hash: hash.to_string(),
                });
            }
        }
    }
    let redeemers = tx.redeemers();
    if expected.is_empty() && redeemers.is_empty() {
        return Ok(vec![]);
    }
    let references: Vec<_> = b.reference_inputs.iter().flatten().cloned().collect();
    let spent = inputs
        .iter()
        .map(|x| decode(x, utxos))
        .collect::<Result<Vec<_>, _>>()?;
    let referenced = references
        .iter()
        .map(|x| decode(x, utxos))
        .collect::<Result<Vec<_>, _>>()?;
    for language in &languages {
        check_translatable(
            language.clone(),
            b,
            &spent.iter().collect::<Vec<_>>(),
            &referenced.iter().collect::<Vec<_>>(),
        )
        .map_err(|x| Error::DijkstraInvalid(x.0))?;
    }
    let certificates: Vec<_> = b
        .certificates
        .iter()
        .flatten()
        .map(conway_certificate)
        .collect();
    let proposals = b
        .proposal_procedures
        .iter()
        .flatten()
        .map(conway_proposal)
        .collect::<Result<Vec<_>, _>>()?;
    let voters: Vec<_> = b.voting_procedures.iter().flat_map(|x| x.keys()).collect();
    let withdrawals: Vec<_> = level.ordered_withdrawals();
    let mut purposes = Vec::new();
    let mut seen = BTreeSet::new();
    for r in &redeemers {
        let (key, value) = r.as_dijkstra().ok_or(Error::WrongEra())?;
        let index = key.index as usize;
        if !expected.contains_key(key) || !seen.insert(key.clone()) {
            return Err(Error::ExtraneousRedeemer);
        }
        let (tag, purpose) = match key.tag {
            n::RedeemerTag::Spend => (
                c::RedeemerTag::Spend,
                ScriptPurpose::Spending(inputs[index].clone(), ()),
            ),
            n::RedeemerTag::Mint => (
                c::RedeemerTag::Mint,
                ScriptPurpose::Minting(policies[index]),
            ),
            n::RedeemerTag::Cert => (
                c::RedeemerTag::Cert,
                ScriptPurpose::Certifying(index, certificates[index].clone()),
            ),
            n::RedeemerTag::Reward => (
                c::RedeemerTag::Reward,
                ScriptPurpose::Rewarding(n::StakeCredential::ScriptHash(expected[key])),
            ),
            n::RedeemerTag::Vote => (
                c::RedeemerTag::Vote,
                ScriptPurpose::Voting(voters[index].clone()),
            ),
            n::RedeemerTag::Propose => (
                c::RedeemerTag::Propose,
                ScriptPurpose::Proposing(index, proposals[index].clone()),
            ),
            n::RedeemerTag::Guarding => return unsupported("redeemer purpose"),
        };
        purposes.push((
            key.clone(),
            purpose,
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
    let (lower_bound, upper_bound) = time.validity_bounds(b.validity_interval_start, b.ttl)?;
    let valid_range = TimeRange {
        lower_bound,
        upper_bound,
    };
    let datums: BTreeMap<_, _> = w
        .plutus_data
        .iter()
        .flat_map(|x| x.iter())
        .map(|d| (Hasher::<256>::hash_cbor(d), (**d).clone()))
        .collect();
    let mut spending_datums = BTreeMap::new();
    for (key, _, _) in &purposes {
        if key.tag != n::RedeemerTag::Spend {
            continue;
        }
        let datum = match spent[key.index as usize].datum() {
            Some(c::DatumOption::Data(d)) => d.0.unwrap(),
            Some(c::DatumOption::Hash(hash)) => {
                datums
                    .get(&hash)
                    .cloned()
                    .ok_or_else(|| Error::MissingRequiredDatum {
                        hash: hash.to_string(),
                    })?
            }
            None => continue,
        };
        spending_datums.insert(key.clone(), datum);
    }
    let inputs = resolve(&b.inputs, utxos, false)?;
    let reference_inputs = resolve(&references, utxos, true)?;
    let outputs = b
        .outputs
        .iter()
        .map(|o| context_output(&MultiEraOutput::from_dijkstra(o), false))
        .collect::<Result<Vec<_>, _>>()?;
    let withdrawals = withdrawals
        .into_iter()
        .map(|(raw, amount)| match Address::from_bytes(raw)? {
            address @ Address::Stake(_) => Ok((address, amount)),
            _ => Err(Error::BadWithdrawalAddress),
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let signatories = {
        let mut keys: Vec<_> = match &b.guards {
            None => vec![],
            Some(n::Guards::AddrKeyhashes(keys)) => keys.to_vec(),
            Some(n::Guards::Credentials(credentials)) => credentials
                .iter()
                .filter_map(|g| match g {
                    n::StakeCredential::AddrKeyhash(key) => Some(*key),
                    n::StakeCredential::ScriptHash(_) => None,
                })
                .collect(),
        };
        keys.sort();
        keys.dedup();
        keys
    };
    let mint = MintValue {
        mint_value: b.mint.clone().unwrap_or_default(),
    };
    let redeemer_pairs: Vec<_> = purposes
        .iter()
        .map(|(_, purpose, r)| (purpose.clone(), r.clone()))
        .collect();
    let info = |language: c::Language| match language {
        c::Language::PlutusV1 => V1TxInfo {
            inputs: inputs.clone(),
            outputs: outputs.clone(),
            fee: c::Value::Coin(b.fee),
            mint: mint.clone(),
            certificates: certificates.clone(),
            withdrawals: withdrawals.clone(),
            valid_range: valid_range.clone(),
            signatories: signatories.clone(),
            data: datums.clone().into_iter().collect(),
            redeemers: redeemer_pairs.clone().into(),
            id,
        }
        .to_plutus_data(),
        c::Language::PlutusV2 => V2TxInfo {
            inputs: inputs.clone(),
            reference_inputs: reference_inputs.clone(),
            outputs: outputs.clone(),
            fee: c::Value::Coin(b.fee),
            mint: mint.clone(),
            certificates: certificates.clone(),
            withdrawals: withdrawals.clone().into(),
            valid_range: valid_range.clone(),
            signatories: signatories.clone(),
            redeemers: redeemer_pairs.clone().into(),
            data: datums.clone().into_iter().collect::<Vec<_>>().into(),
            id,
        }
        .to_plutus_data(),
        c::Language::PlutusV3 => V3TxInfo {
            inputs: inputs.clone(),
            reference_inputs: reference_inputs.clone(),
            outputs: outputs.clone(),
            fee: b.fee,
            mint: mint.clone(),
            certificates: certificates.clone(),
            withdrawals: withdrawals.clone().into(),
            valid_range: valid_range.clone(),
            signatories: signatories.clone(),
            redeemers: redeemer_pairs.clone().into(),
            data: datums.clone().into_iter().collect::<Vec<_>>().into(),
            id,
            votes: get_votes_info(&b.voting_procedures),
            proposal_procedures: proposals.clone(),
            current_treasury_amount: b.treasury_value,
            treasury_donation: b.donation,
        }
        .to_plutus_data_with_protocol(12),
    };
    let costs = &pp.cost_models_for_script_languages;
    let cost_model = |language: c::Language| {
        match language {
            c::Language::PlutusV1 => costs.plutus_v1.as_ref(),
            c::Language::PlutusV2 => costs.plutus_v2.as_ref(),
            c::Language::PlutusV3 => costs.plutus_v3.as_ref(),
        }
        .ok_or(Error::CostModelNotFound(language))
    };
    if !estimate {
        let mut total_mem = 0u64;
        let mut total_steps = 0u64;
        for (_, _, r) in &purposes {
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
        .map(|(key, purpose, r)| {
            let Some(Provided::Plutus(language, bytes)) = scripts.get(&expected[key]) else {
                return Err(Error::MissingRequiredScript {
                    hash: expected[key].to_string(),
                });
            };
            let datum = spending_datums.get(key);
            let context = match language {
                c::Language::PlutusV3 => v3_script_context_data(
                    info(c::Language::PlutusV3),
                    &r.data,
                    &purpose.clone().into_script_info(datum.cloned()),
                    12,
                ),
                c::Language::PlutusV1 | c::Language::PlutusV2 => {
                    v1v2_script_context_data(info(language.clone()), purpose)
                }
            };
            // A V3 script takes the context alone, a V1 or V2 script takes the datum it spends, the redeemer and the context.
            let args: Vec<&c::PlutusData> = match language {
                c::Language::PlutusV3 => vec![&context],
                c::Language::PlutusV1 | c::Language::PlutusV2 => {
                    datum.into_iter().chain([&r.data, &context]).collect()
                }
            };
            let (result, calls) = evaluator::eval_native(
                language.clone(),
                bytes,
                &args,
                cost_model(language.clone())?,
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
