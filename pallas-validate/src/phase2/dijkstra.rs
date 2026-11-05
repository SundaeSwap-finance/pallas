//! Native protocol-12 evaluation of the Plutus scripts the top level and the sub transactions of a Dijkstra transaction run.
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
    tx::MultiEraTxEvalResult,
};
use crate::phase1::dijkstra_ledger::{Level, redeemer_scripts};
use crate::utils::{
    DijkstraTimeContext, EraTime, ForecastHorizon, MultiEraProtocolParameters,
    PostAlonzoError::{InputDecoding, InputNotInUTxO},
    TxoRef, UtxoMap,
    ValidationError::PostAlonzo,
    dijkstra_context::{check_sub_transaction, check_translatable},
};
use pallas_addresses::Address;
use pallas_codec::{minicbor, utils::CborWrap};
use pallas_crypto::hash::{Hash, Hasher};
use pallas_primitives::{conway as c, dijkstra as n};
use pallas_traverse::{ComputeHash, MultiEraOutput, MultiEraScriptRef, MultiEraTx, OriginalHash};
use std::collections::{BTreeMap, BTreeSet};

#[path = "dijkstra_v4_context.rs"]
mod v4_context;
use v4_context::Reach;

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
    let script = output.multi_era_script_ref().map(|s| s.hash());
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
    Plutus(n::Language, Vec<u8>),
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
            n::ScriptRef::PlutusV1Script(x) => plutus(n::Language::PlutusV1, x.as_ref()),
            n::ScriptRef::PlutusV2Script(x) => plutus(n::Language::PlutusV2, x.as_ref()),
            n::ScriptRef::PlutusV3Script(x) => plutus(n::Language::PlutusV3, x.as_ref()),
            n::ScriptRef::PlutusV4Script(x) => plutus(n::Language::PlutusV4, x.as_ref()),
        },
        MultiEraScriptRef::Conway(s) => match s.as_ref() {
            c::ScriptRef::NativeScript(_) => Provided::Native,
            c::ScriptRef::PlutusV1Script(x) => plutus(n::Language::PlutusV1, x.as_ref()),
            c::ScriptRef::PlutusV2Script(x) => plutus(n::Language::PlutusV2, x.as_ref()),
            c::ScriptRef::PlutusV3Script(x) => plutus(n::Language::PlutusV3, x.as_ref()),
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
        let v4 = w.plutus_v4_script.iter().flatten();
        for (hash, language, bytes) in v1
            .map(|x| (x.compute_hash(), n::Language::PlutusV1, x.as_ref()))
            .chain(v2.map(|x| (x.compute_hash(), n::Language::PlutusV2, x.as_ref())))
            .chain(v3.map(|x| (x.compute_hash(), n::Language::PlutusV3, x.as_ref())))
            .chain(v4.map(|x| (x.compute_hash(), n::Language::PlutusV4, x.as_ref())))
        {
            super::native_evaluator::check_plutus_script(&language, bytes)?;
            provided.insert(hash, Provided::Plutus(language, bytes.to_vec()));
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
) -> Result<Vec<MultiEraTxEvalResult>, Error> {
    let results = eval_tx_with_mode(tx, pparams, utxos, &linear_time(slots)?, false)?;
    Ok(results.into_iter().map(|(result, _)| result).collect())
}

pub(super) fn estimate_tx(
    tx: &MultiEraTx,
    pparams: &MultiEraProtocolParameters,
    utxos: &UtxoMap,
    slots: &SlotConfig,
) -> Result<Vec<(MultiEraTxEvalResult, Vec<Builtin>)>, Error> {
    eval_tx_with_mode(tx, pparams, utxos, &linear_time(slots)?, true)
}

pub(super) fn linear_time(slots: &SlotConfig) -> Result<DijkstraTimeContext, Error> {
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
) -> Result<Vec<(MultiEraTxEvalResult, Vec<Builtin>)>, Error> {
    runs(tx, pparams, utxos, time, estimate)?
        .into_iter()
        .map(|run| {
            let args: Vec<_> = run.args.iter().collect();
            let (result, calls) =
                evaluator::eval_native(run.language, &run.script, &args, &run.costs, run.budget)?;
            let result = MultiEraTxEvalResult {
                sub_transaction: run.sub,
                tag: run.tag.into(),
                index: run.index,
                units: result.units,
                success: result.success,
                logs: result.logs,
                failure_message: result.failure.map(|f| f.message),
            };
            Ok((result, calls))
        })
        .collect()
}

/// The script purpose of a redeemer.
#[allow(clippy::large_enum_variant)]
pub(super) enum Purpose {
    Conway(c::RedeemerTag, ScriptPurpose),
    Guarding(u32),
}

impl Purpose {
    /// The Conway tag and script purpose, which a PlutusV1 to V3 script context requires.
    fn conway(&self) -> Result<(c::RedeemerTag, &ScriptPurpose), Error> {
        match self {
            Purpose::Conway(tag, purpose) => Ok((*tag, purpose)),
            Purpose::Guarding(_) => Err(Error::DijkstraInvalid("script guards")),
        }
    }
}

/// The redeemers of a PlutusV1 to V3 transaction info, by script purpose.
fn conway_redeemers(
    purposes: &[(n::RedeemersKey, Purpose, n::RedeemersValue)],
) -> Result<Vec<(ScriptPurpose, c::Redeemer)>, Error> {
    purposes
        .iter()
        .map(|(key, purpose, value)| {
            let (tag, purpose) = purpose.conway()?;
            let redeemer = c::Redeemer {
                tag,
                index: key.index,
                data: value.data.clone(),
                ex_units: value.ex_units,
            };
            Ok((purpose.clone(), redeemer))
        })
        .collect()
}

/// A redeemer's script with the arguments, cost model and budget it runs with.
pub(super) struct Run {
    pub(super) sub: Option<u32>,
    pub(super) tag: n::RedeemerTag,
    pub(super) index: u32,
    pub(super) language: n::Language,
    pub(super) script: Vec<u8>,
    pub(super) args: Vec<c::PlutusData>,
    pub(super) costs: Vec<i64>,
    pub(super) budget: c::ExUnits,
}

/// A level of a batch, the top level transaction or the sub transaction at its index.
#[derive(Clone, Copy)]
enum Part<'a> {
    Top(&'a n::BlockTransaction<'a>),
    Sub(u32, &'a n::SubTransaction<'a>),
}

impl<'a> Part<'a> {
    /// The body fields of the level, with its id.
    fn level(self) -> Level<'a> {
        match self {
            Part::Top(tx) => {
                let b = &tx.transaction_body;
                Level::top(b, Hasher::<256>::hash_cbor(b))
            }
            Part::Sub(index, sub) => {
                let b = &sub.sub_transaction_body;
                Level::sub(b, Hasher::<256>::hash_cbor(b), index)
            }
        }
    }

    /// The witness set of the level.
    fn witnesses(self) -> &'a n::WitnessSet<'a> {
        match self {
            Part::Top(tx) => &tx.transaction_witness_set,
            Part::Sub(_, sub) => &sub.transaction_witness_set,
        }
    }
}

/// The scripts a level runs by redeemer key, their languages, and the redeemers the level declares.
struct Scope<'a> {
    expected: BTreeMap<n::RedeemersKey, Hash<28>>,
    languages: BTreeSet<n::Language>,
    redeemers: Vec<(&'a n::RedeemersKey, &'a n::RedeemersValue)>,
}

/// The scripts, languages and redeemers of the level `part`.
fn scope<'a>(
    part: Part<'a>,
    scripts: &BTreeMap<Hash<28>, Provided>,
    utxos: &UtxoMap,
) -> Result<Scope<'a>, Error> {
    let level = part.level();
    let mut spent = BTreeMap::new();
    for input in ordered(level.inputs)? {
        let output = decode(input, utxos)?;
        output.address()?;
        spent.insert(input, output);
    }
    let mut expected = redeemer_scripts(&level, |x| spent.get(x).ok_or(PostAlonzo(InputNotInUTxO)))
        .map_err(|x| match x {
            PostAlonzo(InputDecoding) => Error::DijkstraInvalid("input address"),
            _ => Error::BadWithdrawalAddress,
        })?;
    expected.retain(|_, hash| !matches!(scripts.get(hash), Some(Provided::Native)));
    let mut languages = BTreeSet::new();
    for hash in expected.values() {
        match scripts.get(hash) {
            Some(Provided::Plutus(language, _)) => {
                languages.insert(language.clone());
            }
            Some(Provided::Native) | None => {
                return Err(Error::MissingRequiredScript {
                    hash: hash.to_string(),
                });
            }
        }
    }
    let redeemers = part
        .witnesses()
        .redeemer
        .iter()
        .flat_map(|x| x.iter())
        .collect();
    Ok(Scope {
        expected,
        languages,
        redeemers,
    })
}

/// The parts of one level of a batch its script contexts hold.
struct Context<'a> {
    level: Level<'a>,
    inputs: Vec<ContextInput>,
    reference_inputs: Vec<ContextInput>,
    outputs: Vec<ContextOutput>,
    valid_range: TimeRange,
    datums: BTreeMap<Hash<32>, c::PlutusData>,
    spending_datums: BTreeMap<n::RedeemersKey, c::PlutusData>,
    certificates: Vec<c::Certificate>,
    proposals: Vec<c::ProposalProcedure>,
    redeemers: Vec<(n::RedeemersKey, Purpose, n::RedeemersValue)>,
    scripts: BTreeMap<n::RedeemersKey, Hash<28>>,
}

/// The script context parts of the level `part`, whose scripts in `scope` run in contexts of `languages`.
fn level_context<'a>(
    part: Part<'a>,
    scope: &Scope<'_>,
    languages: &BTreeSet<n::Language>,
    utxos: &UtxoMap,
    time: &DijkstraTimeContext,
) -> Result<Context<'a>, Error> {
    let level = part.level();
    let expected = &scope.expected;
    let inputs = ordered(level.inputs)?;
    let references: Vec<_> = level
        .reference_inputs
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    let spent = inputs
        .iter()
        .map(|x| decode(x, utxos))
        .collect::<Result<Vec<_>, _>>()?;
    let referenced = references
        .iter()
        .map(|x| decode(x, utxos))
        .collect::<Result<Vec<_>, _>>()?;
    for language in languages {
        check_translatable(
            language,
            &level,
            &spent.iter().collect::<Vec<_>>(),
            &referenced.iter().collect::<Vec<_>>(),
        )
        .map_err(|x| Error::DijkstraInvalid(x.0))?;
    }
    let certificates: Vec<_> = level
        .certificates
        .into_iter()
        .flatten()
        .map(conway_certificate)
        .collect();
    let proposals = level
        .proposals
        .into_iter()
        .flatten()
        .map(conway_proposal)
        .collect::<Result<Vec<_>, _>>()?;
    let policies: Vec<_> = level.mint.into_iter().flat_map(|x| x.keys()).collect();
    let voters: Vec<_> = level.votes.into_iter().flat_map(|x| x.keys()).collect();
    let mut purposes = Vec::new();
    let mut seen = BTreeSet::new();
    for (key, value) in scope.redeemers.iter().copied() {
        let index = key.index as usize;
        if !expected.contains_key(key) || !seen.insert(key.clone()) {
            return Err(Error::ExtraneousRedeemer);
        }
        let purpose = match key.tag {
            n::RedeemerTag::Spend => Purpose::Conway(
                c::RedeemerTag::Spend,
                ScriptPurpose::Spending(inputs[index].clone(), ()),
            ),
            n::RedeemerTag::Mint => Purpose::Conway(
                c::RedeemerTag::Mint,
                ScriptPurpose::Minting(*policies[index]),
            ),
            n::RedeemerTag::Cert => Purpose::Conway(
                c::RedeemerTag::Cert,
                ScriptPurpose::Certifying(index, certificates[index].clone()),
            ),
            n::RedeemerTag::Reward => Purpose::Conway(
                c::RedeemerTag::Reward,
                ScriptPurpose::Rewarding(n::StakeCredential::ScriptHash(expected[key])),
            ),
            n::RedeemerTag::Vote => Purpose::Conway(
                c::RedeemerTag::Vote,
                ScriptPurpose::Voting(voters[index].clone()),
            ),
            n::RedeemerTag::Propose => Purpose::Conway(
                c::RedeemerTag::Propose,
                ScriptPurpose::Proposing(index, proposals[index].clone()),
            ),
            n::RedeemerTag::Guarding => Purpose::Guarding(key.index),
        };
        purposes.push((key.clone(), purpose, value.clone()));
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
    let (lower_bound, upper_bound) =
        time.validity_bounds(level.validity_interval_start, level.ttl)?;
    let valid_range = TimeRange {
        lower_bound,
        upper_bound,
    };
    let datums: BTreeMap<_, _> = part
        .witnesses()
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
    Ok(Context {
        level,
        inputs: resolve(level.inputs, utxos, false)?,
        reference_inputs: resolve(&references, utxos, true)?,
        outputs: level
            .outputs
            .iter()
            .map(|o| context_output(&MultiEraOutput::from_dijkstra(o), false))
            .collect::<Result<Vec<_>, _>>()?,
        valid_range,
        datums,
        spending_datums,
        certificates,
        proposals,
        redeemers: purposes,
        scripts: expected.clone(),
    })
}

/// The fields of a PlutusV1 to V3 transaction info of the top level body `b` beyond those of its level context.
struct Legacy {
    mint: MintValue,
    withdrawals: Vec<(Address, u64)>,
    signatories: Vec<Hash<28>>,
    data: Vec<(Hash<32>, c::PlutusData)>,
    redeemers: Vec<(ScriptPurpose, c::Redeemer)>,
}

impl Legacy {
    fn new(b: &n::TransactionBody<'_>, context: &Context<'_>) -> Result<Self, Error> {
        let withdrawals = context
            .level
            .ordered_withdrawals()
            .into_iter()
            .map(|(raw, amount)| match Address::from_bytes(raw)? {
                address @ Address::Stake(_) => Ok((address, amount)),
                _ => Err(Error::BadWithdrawalAddress),
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let mut signatories: Vec<_> = match &b.guards {
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
        signatories.sort();
        signatories.dedup();
        Ok(Legacy {
            mint: MintValue {
                mint_value: b.mint.clone().unwrap_or_default(),
            },
            withdrawals,
            signatories,
            data: context.datums.clone().into_iter().collect(),
            redeemers: conway_redeemers(&context.redeemers)?,
        })
    }
}

/// The sub transaction levels of a batch, as PlutusV4 contexts, and the validity interval its levels share.
fn batch<'a>(
    parts: &[Part<'a>],
    scopes: &[Scope<'_>],
    utxos: &UtxoMap,
    time: &DijkstraTimeContext,
) -> Result<v4_context::Batch<'a>, Error> {
    let v4 = BTreeSet::from([n::Language::PlutusV4]);
    let mut subs = Vec::new();
    let (mut start, mut ttl) = (None, None);
    for (part, scope) in parts.iter().zip(scopes) {
        let level = part.level();
        start = start.max(level.validity_interval_start);
        ttl = match (ttl, level.ttl) {
            (Some(x), Some(y)) => Some(u64::min(x, y)),
            (x, y) => x.or(y),
        };
        if let Part::Sub(..) = part {
            subs.push(level_context(*part, scope, &v4, utxos, time)?);
        }
    }
    let (lower_bound, upper_bound) = time.validity_bounds(start, ttl)?;
    Ok(v4_context::Batch {
        subs,
        valid_range: TimeRange {
            lower_bound,
            upper_bound,
        },
    })
}

/// The script runs of the redeemers of every level of `tx`, its sub transactions in order and then its top level.
pub(super) fn runs(
    tx: &MultiEraTx,
    pparams: &MultiEraProtocolParameters,
    utxos: &UtxoMap,
    time: &DijkstraTimeContext,
    estimate: bool,
) -> Result<Vec<Run>, Error> {
    let native = tx.as_dijkstra().ok_or(Error::WrongEra())?;
    let MultiEraProtocolParameters::Dijkstra(pp) = pparams else {
        return unsupported("protocol parameters require Dijkstra");
    };
    if pp.protocol_version != (12, 0) {
        return unsupported("protocol version (requires 12.0)");
    }
    let scripts = provided_scripts(native, utxos)?;
    let parts: Vec<_> = (0..)
        .zip(native.transaction_body.sub_transactions.iter().flatten())
        .map(|(index, sub)| Part::Sub(index, sub))
        .chain([Part::Top(native)])
        .collect();
    let scopes = parts
        .iter()
        .map(|part| scope(*part, &scripts, utxos))
        .collect::<Result<Vec<_>, _>>()?;
    let batch = || batch(&parts, &scopes, utxos, time);
    let costs = &pp.cost_models_for_script_languages;
    let execution_limit = pp.max_tx_ex_units;
    let mut runs = Vec::new();
    for (part, scope) in parts.iter().copied().zip(&scopes) {
        if scope.expected.is_empty() && scope.redeemers.is_empty() {
            continue;
        }
        let context = level_context(part, scope, &scope.languages, utxos, time)?;
        if estimate
            && (execution_limit.mem > i64::MAX as u64 || execution_limit.steps > i64::MAX as u64)
        {
            return Err(Error::DijkstraInvalid(
                "transaction execution limit overflow",
            ));
        }
        for (key, purpose, r) in &context.redeemers {
            let hash = &context.scripts[key];
            let Some(Provided::Plutus(language, bytes)) = scripts.get(hash) else {
                return Err(Error::MissingRequiredScript {
                    hash: hash.to_string(),
                });
            };
            let datum = context.spending_datums.get(key);
            // A V1 or V2 script takes the datum it spends, the redeemer and the context, a V3 or V4 script takes the context alone.
            let legacy = |info: c::PlutusData| -> Vec<c::PlutusData> {
                datum
                    .cloned()
                    .into_iter()
                    .chain([r.data.clone(), info])
                    .collect()
            };
            let args = match (language, part) {
                (_, Part::Sub(..)) => {
                    let v4 =
                        check_sub_transaction(language).map_err(|x| Error::DijkstraInvalid(x.0))?;
                    vec![context.script_context(key, purpose, &r.data, datum, Reach::Sub(v4))?]
                }
                (n::Language::PlutusV1, Part::Top(tx)) => {
                    let b = &tx.transaction_body;
                    let x = Legacy::new(b, &context)?;
                    let info = V1TxInfo {
                        inputs: context.inputs.clone(),
                        outputs: context.outputs.clone(),
                        fee: c::Value::Coin(b.fee),
                        mint: x.mint,
                        certificates: context.certificates.clone(),
                        withdrawals: x.withdrawals,
                        valid_range: context.valid_range.clone(),
                        signatories: x.signatories,
                        data: x.data,
                        redeemers: x.redeemers.into(),
                        id: context.level.id,
                    };
                    legacy(v1v2_script_context_data(
                        info.to_plutus_data(),
                        purpose.conway()?.1,
                    ))
                }
                (n::Language::PlutusV2, Part::Top(tx)) => {
                    let b = &tx.transaction_body;
                    let x = Legacy::new(b, &context)?;
                    let info = V2TxInfo {
                        inputs: context.inputs.clone(),
                        reference_inputs: context.reference_inputs.clone(),
                        outputs: context.outputs.clone(),
                        fee: c::Value::Coin(b.fee),
                        mint: x.mint,
                        certificates: context.certificates.clone(),
                        withdrawals: x.withdrawals.into(),
                        valid_range: context.valid_range.clone(),
                        signatories: x.signatories,
                        redeemers: x.redeemers.into(),
                        data: x.data.into(),
                        id: context.level.id,
                    };
                    legacy(v1v2_script_context_data(
                        info.to_plutus_data(),
                        purpose.conway()?.1,
                    ))
                }
                (n::Language::PlutusV3, Part::Top(tx)) => {
                    let b = &tx.transaction_body;
                    let x = Legacy::new(b, &context)?;
                    let info = V3TxInfo {
                        inputs: context.inputs.clone(),
                        reference_inputs: context.reference_inputs.clone(),
                        outputs: context.outputs.clone(),
                        fee: b.fee,
                        mint: x.mint,
                        certificates: context.certificates.clone(),
                        withdrawals: x.withdrawals.into(),
                        valid_range: context.valid_range.clone(),
                        signatories: x.signatories,
                        redeemers: x.redeemers.into(),
                        data: x.data.into(),
                        id: context.level.id,
                        votes: get_votes_info(&b.voting_procedures),
                        proposal_procedures: context.proposals.clone(),
                        current_treasury_amount: b.treasury_value,
                        treasury_donation: b.donation,
                    };
                    vec![v3_script_context_data(
                        info.to_plutus_data_with_protocol(12),
                        &r.data,
                        &purpose.conway()?.1.clone().into_script_info(datum.cloned()),
                        12,
                    )]
                }
                (n::Language::PlutusV4, Part::Top(_)) => {
                    vec![context.script_context(
                        key,
                        purpose,
                        &r.data,
                        datum,
                        Reach::Top(&batch),
                    )?]
                }
            };
            let model = match language {
                n::Language::PlutusV1 => costs.plutus_v1.as_ref(),
                n::Language::PlutusV2 => costs.plutus_v2.as_ref(),
                n::Language::PlutusV3 => costs.plutus_v3.as_ref(),
                n::Language::PlutusV4 => costs.plutus_v4.as_ref(),
            };
            let model = model.ok_or_else(|| Error::DijkstraCostModelNotFound(language.clone()))?;
            runs.push(Run {
                sub: context.level.sub,
                tag: key.tag,
                index: key.index,
                language: language.clone(),
                script: bytes.clone(),
                args,
                costs: model.clone(),
                budget: if estimate {
                    execution_limit
                } else {
                    r.ex_units
                },
            });
        }
    }
    Ok(runs)
}
#[cfg(test)]
#[path = "dijkstra_native_context_tests.rs"]
mod native_context_tests;
