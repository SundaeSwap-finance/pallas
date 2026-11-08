//! Native protocol-12 phase one for transfers, batches, account and governance state, and Plutus V1 to V3.
//! Rules and evidence boundaries: test_data/musashi-dijkstra-validation/README.md.
use super::dijkstra_ledger::{self as ledger, Flows, Level, WithdrawalRule};
use crate::utils::{
    ContextFailure, DijkstraProtParams, MalformedField, ParameterFailure, PostAlonzoError,
    PostAlonzoError::*,
    UTxOs, UnsupportedFeature, ValidationError,
    ValidationError::*,
    ValidationResult, WithdrawalFailure,
    dijkstra_context::check_translatable,
    dijkstra_state::{DijkstraLedgerDelta, DijkstraLedgerOverlay, DijkstraLedgerState},
    verify_signature,
};
use pallas_addresses::{
    Address, Network, ShelleyDelegationPart, ShelleyPaymentPart, byron::ByronAddress,
};
use pallas_codec::{
    minicbor,
    utils::{KeepRaw, Nullable, decode_bytes_def_or_indef},
};
use pallas_crypto::hash::{Hash, Hasher};
use pallas_primitives::{conway::LanguageViews, dijkstra::*};
use pallas_traverse::{
    ComputeHash, MultiEraInput, MultiEraNativeScript, MultiEraOutput, MultiEraScriptRef,
    OriginalHash,
};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashSet},
};

type Keys = HashSet<Hash<28>>;
const MALFORMED_VALUE: ValidationError = DijkstraMalformed(MalformedField::MultiAssetValue);
type Spent = HashSet<(Hash<32>, u64)>;

/// Validates native phase one against `state` and returns the changes the transaction makes to it.
pub fn validate_dijkstra_tx<S: DijkstraLedgerState + ?Sized>(
    tx: &BlockTransaction<'_>,
    utxos: &UTxOs<'_>,
    pp: &DijkstraProtParams,
    block_slot: &u64,
    network_id: &u8,
    state: &S,
) -> Result<DijkstraLedgerDelta, ValidationError> {
    validate_dijkstra_tx_inner(tx, utxos, pp, block_slot, network_id, state, None)
}

/// Native phase one with the historical time context required by bounded Plutus.
pub fn validate_dijkstra_tx_with_time<S: DijkstraLedgerState + ?Sized>(
    tx: &BlockTransaction<'_>,
    utxos: &UTxOs<'_>,
    pp: &DijkstraProtParams,
    block_slot: &u64,
    network_id: &u8,
    state: &S,
    time: &crate::utils::DijkstraTimeContext,
) -> Result<DijkstraLedgerDelta, ValidationError> {
    validate_dijkstra_tx_inner(tx, utxos, pp, block_slot, network_id, state, Some(time))
}

pub(super) fn validate_dijkstra_tx_inner<S: DijkstraLedgerState + ?Sized>(
    tx: &BlockTransaction<'_>,
    utxos: &UTxOs<'_>,
    pp: &DijkstraProtParams,
    block_slot: &u64,
    network_id: &u8,
    state: &S,
    time: Option<&crate::utils::DijkstraTimeContext>,
) -> Result<DijkstraLedgerDelta, ValidationError> {
    if pp.protocol_version != (12, 0) {
        return Err(DijkstraUnsupported(UnsupportedFeature::ProtocolVersion));
    }
    check_supported(tx)?;
    let b = &tx.transaction_body;
    for sub in b.sub_transactions.iter().flatten() {
        check_sub_supported(sub)?;
    }
    let guards = guard_credentials(b.guards.as_ref());
    let mut keys = guard_keys(&guards);
    let top_guards: BTreeSet<_> = guards.iter().cloned().collect();
    check_required_guards(b.required_top_level_guards.as_ref(), &top_guards)?;
    let level = Level::top(b, Hasher::<256>::hash(b.raw_cbor()));
    keys.extend(ledger::needs(&level)?.keys);
    let scripts = ledger::redeemer_scripts(&level, |x| spent(x, utxos))?;
    check_interval(
        level.validity_interval_start,
        level.ttl,
        b.network_id,
        *block_slot,
        *network_id,
    )?;
    if tx_size(tx)? > u64::from(pp.max_transaction_size) {
        return Err(PostAlonzo(MaxTxSizeExceeded));
    }
    let subs = sub_scripts(b, utxos)?;
    let provided = check_scripts(tx, utxos, pp, &scripts, &subs, &mut keys, *network_id, time)?;
    check_guard_datums(b.required_top_level_guards.as_ref(), &provided)?;
    let rule = withdrawal_rule(&provided.languages);
    let legacy = rule == WithdrawalRule::Legacy;
    let (flows, top_flows, delta) = ledger_rules(tx, pp, *network_id, rule, state)?;
    if b.fee < dijkstra_min_fee(tx, utxos, pp)? {
        return Err(PostAlonzo(FeeBelowMin));
    }
    let mut spent = Spent::new();
    let mut consumed = flows.consumed;
    let mut output_coin = 0;
    for (index, sub) in (0..).zip(b.sub_transactions.iter().flat_map(|x| x.iter())) {
        let sb = &sub.sub_transaction_body;
        let w = &sub.transaction_witness_set;
        let level = Level::sub(sb, Hasher::<256>::hash(sb.raw_cbor()), index);
        check_auxiliary(sb.auxiliary_data_hash, &sub.auxiliary_data)?;
        check_required_guards(sb.required_top_level_guards.as_ref(), &top_guards)?;
        check_guard_datums(sb.required_top_level_guards.as_ref(), &provided)?;
        check_interval(
            level.validity_interval_start,
            level.ttl,
            sb.network_id,
            *block_slot,
            *network_id,
        )?;
        let mut sub_keys = guard_keys(&guard_credentials(sb.guards.as_ref()));
        sub_keys.extend(ledger::needs(&level)?.keys);
        let spending = check_inputs(&sb.inputs, utxos, &mut spent, &mut sub_keys)?;
        consumed = add(consumed, spending)?;
        let scripts = &subs.levels[index as usize];
        let languages = check_level(
            &level,
            w,
            sb.script_data_hash,
            scripts,
            &provided,
            utxos,
            pp,
            time,
        )?;
        check_contexts(&level, &languages, utxos)?;
        output_coin = add(output_coin, check_outputs(&sb.outputs, pp, network_id)?)?;
        check_signatures(w, &encode(&sub.sub_transaction_body)?, sub_keys)?;
    }
    let spending = check_inputs(&b.inputs, utxos, &mut spent, &mut keys)?;
    consumed = add(consumed, spending)?;
    let top_output_coin = check_outputs(&b.outputs, pp, network_id)?;
    output_coin = add(output_coin, top_output_coin)?;
    if add(add(output_coin, b.fee)?, flows.produced)? != consumed {
        return Err(PostAlonzo(PreservationOfValue));
    }
    let sub_bodies = || {
        b.sub_transactions
            .iter()
            .flatten()
            .map(|s| &s.sub_transaction_body)
    };
    check_assets(
        b.inputs
            .iter()
            .chain(sub_bodies().flat_map(|s| s.inputs.iter())),
        b.outputs
            .iter()
            .chain(sub_bodies().flat_map(|s| s.outputs.iter())),
        b.mint
            .iter()
            .chain(sub_bodies().flat_map(|s| s.mint.iter())),
        utxos,
    )?;
    // In legacy mode the top level balances on its own, with deposits judged after the sub transactions.
    if legacy {
        if add(add(top_output_coin, b.fee)?, top_flows.produced)?
            != add(spending, top_flows.consumed)?
        {
            return Err(PostAlonzo(PreservationOfValue));
        }
        check_assets(b.inputs.iter(), b.outputs.iter(), b.mint.iter(), utxos)?;
    }
    check_signatures(&tx.transaction_witness_set, &encode(b)?, keys)?;
    check_contexts(&level, &provided.languages, utxos)?;
    Ok(delta)
}

/// Checks that the script context of each of `languages` can hold the level `b`.
fn check_contexts(
    b: &Level<'_>,
    languages: &BTreeSet<Language>,
    utxos: &UTxOs<'_>,
) -> ValidationResult {
    let inputs = resolve(b.inputs.iter(), utxos, InputNotInUTxO)?;
    let references = resolve(
        b.reference_inputs.into_iter().flatten(),
        utxos,
        ReferenceInputNotInUTxO,
    )?;
    for language in languages {
        check_translatable(language, b, &inputs, &references)
            .map_err(|x| DijkstraScriptContext(x.0))?;
    }
    Ok(())
}

/// The outputs `inputs` name in `utxos`, or `missing` for the first one absent.
fn resolve<'a, 'b>(
    inputs: impl Iterator<Item = &'a TransactionInput>,
    utxos: &'a UTxOs<'b>,
    missing: PostAlonzoError,
) -> Result<Vec<&'a MultiEraOutput<'b>>, ValidationError> {
    inputs
        .map(|x| {
            utxos
                .get(&MultiEraInput::from_alonzo_compatible(x))
                .ok_or(PostAlonzo(missing.clone()))
        })
        .collect()
}

/// The output the spent `input` resolves to in `utxos`.
fn spent<'a, 'b>(
    input: &TransactionInput,
    utxos: &'a UTxOs<'b>,
) -> Result<&'a MultiEraOutput<'b>, ValidationError> {
    utxos
        .get(&MultiEraInput::AlonzoCompatible(Box::new(Cow::Owned(
            input.clone(),
        ))))
        .ok_or(PostAlonzo(InputNotInUTxO))
}

/// The ledger state changes of a transaction the ledger has accepted, computed against `state`.
pub fn dijkstra_ledger_effects<S: DijkstraLedgerState + ?Sized>(
    tx: &BlockTransaction<'_>,
    pp: &DijkstraProtParams,
    network_id: u8,
    state: &S,
) -> Result<DijkstraLedgerDelta, ValidationError> {
    if !tx.success {
        return Ok(DijkstraLedgerDelta::default());
    }
    Ok(ledger_rules(tx, pp, network_id, WithdrawalRule::Accepted, state)?.2)
}

/// The treasury, account and governance rules of each sub transaction in order, then of the top level transaction, with the flows of the batch and of the top level.
fn ledger_rules<S: DijkstraLedgerState + ?Sized>(
    tx: &BlockTransaction<'_>,
    pp: &DijkstraProtParams,
    network: u8,
    rule: WithdrawalRule,
    state: &S,
) -> Result<(Flows, Flows, DijkstraLedgerDelta), ValidationError> {
    let b = &tx.transaction_body;
    let mut current = DijkstraLedgerOverlay::new(state);
    let mut flows = Flows::default();
    for (index, sub) in (0..).zip(b.sub_transactions.iter().flatten()) {
        let sb = &sub.sub_transaction_body;
        let level = Level::sub(sb, Hasher::<256>::hash(sb.raw_cbor()), index);
        ledger::check_treasury(&level, state)?;
        flows.add(ledger::entities(
            &level,
            None,
            pp,
            network,
            state,
            &mut current,
        )?)?;
        flows.add(ledger::governance(&level, pp, network, &mut current)?)?;
    }
    let level = Level::top(b, Hasher::<256>::hash(b.raw_cbor()));
    ledger::check_treasury(&level, state)?;
    let subs = ledger::sub_withdrawals(tx)?;
    let mut top = ledger::entities(
        &level,
        Some((rule, &subs)),
        pp,
        network,
        state,
        &mut current,
    )?;
    top.add(ledger::governance(&level, pp, network, &mut current)?)?;
    flows.add(top)?;
    Ok((flows, top, current.delta))
}

/// The minimum fee of a transaction whose inputs resolve in `utxos`, pricing the redeemers of its top level and sub transactions together.
pub fn dijkstra_min_fee(
    tx: &BlockTransaction<'_>,
    utxos: &UTxOs<'_>,
    pp: &DijkstraProtParams,
) -> Result<u64, ValidationError> {
    let size_fee = u64::from(pp.minfee_a)
        .checked_mul(tx_size(tx)?)
        .and_then(|x| x.checked_add(u64::from(pp.minfee_b)))
        .ok_or(PostAlonzo(NegativeValue))?;
    let (mem, steps) = declared_units(tx)?;
    let fee = add(size_fee, execution_fee(mem, steps, pp)?)?;
    add(
        fee,
        reference_fee(reference_script_size(&tx.transaction_body, utxos)?, pp)?,
    )
}

/// The size the ledger counts for a transaction, its body, witnesses and auxiliary data without the block validity flag.
fn tx_size(tx: &BlockTransaction<'_>) -> Result<u64, ValidationError> {
    Ok(encode(tx.to_mempool_transaction())?.len() as u64)
}

/// The memory and steps the redeemers of the transaction and its sub transactions declare, summed.
fn declared_units(tx: &BlockTransaction<'_>) -> Result<(u64, u64), ValidationError> {
    let subs = tx
        .transaction_body
        .sub_transactions
        .iter()
        .flat_map(|x| x.iter())
        .map(|sub| &sub.transaction_witness_set);
    let mut units = (0, 0);
    for (_, value) in std::iter::once(&tx.transaction_witness_set)
        .chain(subs)
        .flat_map(|w| w.redeemer.iter())
        .flat_map(|x| x.iter())
    {
        units = (
            add(units.0, value.ex_units.mem)?,
            add(units.1, value.ex_units.steps)?,
        );
    }
    Ok(units)
}

/// The bytes of the reference scripts held by the outputs the transaction's inputs and reference inputs resolve to, each input once.
fn reference_script_size(
    b: &TransactionBody<'_>,
    utxos: &UTxOs<'_>,
) -> Result<u64, ValidationError> {
    let inputs: BTreeSet<_> = b
        .reference_inputs
        .iter()
        .flat_map(|x| x.iter())
        .chain(b.inputs.iter())
        .collect();
    let mut bytes = 0;
    for input in inputs {
        let script = utxos
            .get(&MultiEraInput::from_alonzo_compatible(input))
            .and_then(|output| output.multi_era_script_ref());
        let size = match &script {
            None => 0,
            Some(script) => match script.native_script() {
                Some(native) => native.encode().len(),
                None => script.plutus_bytes().map_or(0, <[u8]>::len),
            },
        };
        bytes = add(bytes, size as u64)?;
    }
    Ok(bytes)
}

fn encode<T: minicbor::Encode<()>>(value: T) -> Result<Vec<u8>, ValidationError> {
    minicbor::to_vec(value).map_err(|_| PostAlonzo(UnknownTxSize))
}
fn add(a: u64, b: u64) -> Result<u64, ValidationError> {
    a.checked_add(b).ok_or(PostAlonzo(NegativeValue))
}
fn check_interval(
    lo: Option<u64>,
    hi: Option<u64>,
    net: Option<NetworkId>,
    slot: u64,
    network: u8,
) -> ValidationResult {
    if lo.is_some_and(|x| slot < x) {
        return Err(PostAlonzo(BlockPrecedesValInt));
    }
    // Allegra inInterval inherited by Dijkstra: upper bound is exclusive.
    if hi.is_some_and(|x| slot >= x) {
        return Err(PostAlonzo(BlockExceedsValInt));
    }
    if net.is_some_and(|x| u8::from(x) != network) {
        return Err(PostAlonzo(TxWrongNetworkID));
    }
    Ok(())
}
fn guard_credentials(guards: Option<&Guards>) -> Vec<StakeCredential> {
    match guards {
        None => vec![],
        Some(Guards::AddrKeyhashes(xs)) => xs
            .iter()
            .map(|x| StakeCredential::AddrKeyhash(*x))
            .collect(),
        Some(Guards::Credentials(xs)) => xs.to_vec(),
    }
}
fn guard_keys(guards: &[StakeCredential]) -> Keys {
    guards
        .iter()
        .filter_map(|x| match x {
            StakeCredential::AddrKeyhash(key) => Some(*key),
            StakeCredential::ScriptHash(_) => None,
        })
        .collect()
}
fn check_required_guards(
    required: Option<&RequiredTopLevelGuards>,
    top: &BTreeSet<StakeCredential>,
) -> ValidationResult {
    for credential in required.into_iter().flat_map(|x| x.keys()) {
        if !top.contains(credential) {
            return Err(PostAlonzo(ReqSignerMissing));
        }
    }
    Ok(())
}
/// Checks that each required top-level guard whose credential is a key or a provided script has a datum exactly when that script is Plutus.
fn check_guard_datums(
    required: Option<&RequiredTopLevelGuards>,
    provided: &Provided,
) -> ValidationResult {
    for (credential, datum) in required.into_iter().flatten() {
        let takes = match credential {
            StakeCredential::AddrKeyhash(_) => Some(false),
            StakeCredential::ScriptHash(x) if provided.natives.contains_key(x) => Some(false),
            StakeCredential::ScriptHash(x) => provided.plutus.get(x).map(|_| true),
        };
        if takes.is_some_and(|x| x == matches!(datum, Nullable::Null)) {
            return Err(DijkstraMalformedGuardDatum);
        }
    }
    Ok(())
}
/// Checks one level's spending inputs, adding the key of each key locked input to `keys`, and returns their coin.
fn check_inputs(
    inputs: &[TransactionInput],
    utxos: &UTxOs<'_>,
    spent: &mut Spent,
    keys: &mut Keys,
) -> Result<u64, ValidationError> {
    if inputs.is_empty() {
        return Err(PostAlonzo(TxInsEmpty));
    }
    let mut local = Spent::new();
    let mut coin = 0;
    for input in inputs {
        let id = (input.transaction_id, input.index);
        if !local.insert(id) {
            return Err(DijkstraUnsupported(UnsupportedFeature::DuplicateInputs));
        }
        // SUBUTXO requires membership in both original and evolving UTxO.
        let output = utxos
            .get(&MultiEraInput::from_alonzo_compatible(input))
            .ok_or(PostAlonzo(InputNotInUTxO))?;
        if !spent.insert(id) {
            return Err(DijkstraInputAlreadySpent);
        }
        coin = add(coin, output.value().coin())?;
        if let Spender::Key(key) = spender(output)? {
            keys.insert(key);
        }
    }
    Ok(coin)
}
pub(crate) enum Spender {
    Key(Hash<28>),
    Script(Hash<28>),
}
/// Pointer delegation plays no part in spending, so pointer addresses pass.
pub(crate) fn spender(output: &MultiEraOutput<'_>) -> Result<Spender, ValidationError> {
    match output.address().map_err(|_| PostAlonzo(AddressDecoding))? {
        Address::Shelley(address) => Ok(match address.payment() {
            ShelleyPaymentPart::Key(key) => Spender::Key(*key),
            ShelleyPaymentPart::Script(hash) => Spender::Script(*hash),
        }),
        Address::Byron(address) => Ok(Spender::Key(
            byron_payload(&address)
                .map_err(|_| PostAlonzo(InputDecoding))?
                .root,
        )),
        Address::Stake(_) => Err(PostAlonzo(InputDecoding)),
    }
}
/// What the ledger reads from a Byron address payload.
struct ByronPayload {
    root: Hash<28>,
    network: u8,
    attributes_size: usize,
}
/// Reads the root, the network and the attribute size of a Byron address, keeping attributes of any key.
fn byron_payload(address: &ByronAddress) -> Result<ByronPayload, minicbor::decode::Error> {
    let mut d = minicbor::Decoder::new(&address.payload.0);
    d.array()?;
    let root = d.decode()?;
    let mut network = Network::Mainnet.value();
    let mut attributes_size = 0;
    let entries = d.map()?;
    let mut read = 0;
    while entries.map_or(d.datatype()? != minicbor::data::Type::Break, |n| read < n) {
        let key = d.u8()?;
        let value = decode_bytes_def_or_indef(&mut d, &mut ())?;
        match key {
            1 => {
                let path = decode_bytes_def_or_indef(&mut minicbor::Decoder::new(&value), &mut ())?;
                attributes_size += path.len();
            }
            2 => network = Network::Testnet.value(),
            _ => attributes_size += value.len(),
        }
        read += 1;
    }
    Ok(ByronPayload {
        root,
        network,
        attributes_size,
    })
}
fn check_signatures(w: &WitnessSet<'_>, body: &[u8], mut required: Keys) -> ValidationResult {
    let hash = Hasher::<256>::hash(body);
    for witness in w.vkeywitness.iter().flat_map(|x| x.iter()) {
        if witness.vkey.len() != 32
            || witness.signature.len() != 64
            || !verify_signature(witness, hash.as_ref())
        {
            return Err(PostAlonzo(VKWrongSignature));
        }
        required.remove(&Hasher::<224>::hash(&witness.vkey));
    }
    for witness in w.bootstrap_witness.iter().flat_map(|x| x.iter()) {
        let signed = VKeyWitness {
            vkey: witness.public_key.clone(),
            signature: witness.signature.clone(),
        };
        if signed.vkey.len() != 32
            || signed.signature.len() != 64
            || !verify_signature(&signed, hash.as_ref())
        {
            return Err(PostAlonzo(VKWrongSignature));
        }
        required.remove(&super::conway::bootstrap_wit_root(witness));
    }
    if !required.is_empty() {
        return Err(PostAlonzo(VKWitnessMissing));
    }
    Ok(())
}
fn witness_keys(w: &WitnessSet<'_>) -> Keys {
    w.vkeywitness
        .iter()
        .flat_map(|x| x.iter())
        .map(|w| Hasher::<224>::hash(&w.vkey))
        .collect()
}
/// The network of the address of `output` and the size of its Byron attributes, zero for a Shelley address.
fn output_address(output: &MultiEraOutput<'_>) -> Result<(u8, usize), ValidationError> {
    match output.address().map_err(|_| PostAlonzo(AddressDecoding))? {
        Address::Shelley(address) => Ok((address.network().value(), 0)),
        Address::Byron(address) => {
            let payload = byron_payload(&address).map_err(|_| PostAlonzo(AddressDecoding))?;
            Ok((payload.network, payload.attributes_size))
        }
        Address::Stake(_) => Err(PostAlonzo(AddressDecoding)),
    }
}
/// Refuses the first of `outputs` whose address the ledger decoder refuses.
fn check_output_addresses<'a, 'b: 'a>(
    outputs: impl Iterator<Item = &'a TransactionOutput<'b>>,
) -> ValidationResult {
    for output in outputs {
        output_address(&MultiEraOutput::from_dijkstra(output))?;
    }
    Ok(())
}
fn check_outputs(
    outputs: &[TransactionOutput<'_>],
    pp: &DijkstraProtParams,
    network_id: &u8,
) -> Result<u64, ValidationError> {
    let mut total = 0;
    for output in outputs {
        let view = MultiEraOutput::from_dijkstra(output);
        let coin = view.value().coin();
        if let Some(script) = view.multi_era_script_ref() {
            check_new_script(&script)?;
        }
        let (network, attributes_size) = output_address(&view)?;
        if attributes_size > 64 {
            return Err(DijkstraBootstrapAttributesTooLarge);
        }
        if network != *network_id {
            return Err(PostAlonzo(OutputWrongNetworkID));
        }
        // Sized TxOut counts the original serialization, not just the value.
        let output_bytes = minicbor::to_vec(output).map_err(|_| PostAlonzo(UnknownTxSize))?;
        match output {
            TransactionOutput::PostAlonzo(_) => {
                check_map_keys(
                    &output_bytes,
                    &[0, 1, 2, 3],
                    UnsupportedFeature::OutputFields,
                )?;
            }
            TransactionOutput::Legacy(_) => {
                let mut decoder = minicbor::Decoder::new(&output_bytes);
                if !matches!(
                    decoder
                        .array()
                        .map_err(|_| DijkstraUnsupported(UnsupportedFeature::OutputFields))?,
                    Some(2 | 3)
                ) {
                    return Err(DijkstraUnsupported(UnsupportedFeature::OutputFields));
                }
            }
        }
        check_output_value_encoding(&output_bytes)?;
        let minimum = pp
            .ada_per_utxo_byte
            .checked_mul(160 + output_bytes.len() as u64)
            .ok_or(PostAlonzo(NegativeValue))?;
        if coin < minimum {
            return Err(PostAlonzo(MinLovelaceUnreached));
        }
        let value_bytes =
            minicbor::to_vec(view.value().into_alonzo()).map_err(|_| PostAlonzo(UnknownTxSize))?;
        if value_bytes.len() > pp.max_value_size as usize {
            return Err(PostAlonzo(MaxValSizeExceeded));
        }
        total = add(total, coin)?;
    }
    Ok(total)
}
fn check_supported(tx: &BlockTransaction<'_>) -> ValidationResult {
    let b = &tx.transaction_body;
    if !tx.success {
        return Err(DijkstraUnsupported(
            UnsupportedFeature::UnsuccessfulBlockTransaction,
        ));
    }
    check_auxiliary(b.auxiliary_data_hash, &tx.auxiliary_data)?;
    let raw = encode(b)?;
    let mut allowed = vec![0, 1, 2, 3, 8, 15];
    for (key, present) in [
        (4, b.certificates.is_some()),
        (5, b.withdrawals.is_some()),
        (7, b.auxiliary_data_hash.is_some()),
        (9, b.mint.is_some()),
        (11, b.script_data_hash.is_some()),
        (13, b.collateral.is_some()),
        (14, holds_value(&raw, 14)),
        (16, b.collateral_return.is_some()),
        (17, b.total_collateral.is_some()),
        (18, b.reference_inputs.is_some()),
        (19, b.voting_procedures.is_some()),
        (20, b.proposal_procedures.is_some()),
        (21, b.treasury_value.is_some()),
        (22, b.donation.is_some()),
        (23, b.sub_transactions.is_some()),
        (24, b.required_top_level_guards.is_some()),
        (25, b.direct_deposits.is_some()),
        (26, b.account_balance_intervals.is_some()),
        (27, b.starting_account_balance_intervals.is_some()),
    ] {
        if present {
            allowed.push(key);
        }
    }
    check_map_keys(&raw, &allowed, UnsupportedFeature::BodyFields)?;
    let fields: pallas_codec::utils::KeyValuePairs<u64, pallas_codec::utils::AnyCbor> =
        minicbor::decode(&raw).map_err(|_| DijkstraUnsupported(UnsupportedFeature::BodyFields))?;
    for (key, value) in fields.iter() {
        check_field_present(*key, value)?;
        if *key == 9 {
            check_asset_encoding(value, true)?;
        }
        if *key == 24 {
            check_required_guard_keys(value)?;
        }
        if *key == 5 {
            check_withdrawal_accounts(value)?;
        }
    }
    check_output_addresses(b.outputs.iter().chain(b.collateral_return.iter()))?;
    check_guards(b.guards.as_ref())?;
    check_witness_fields(&tx.transaction_witness_set)
}
fn check_guards(guards: Option<&Guards>) -> ValidationResult {
    let guards = guard_credentials(guards);
    match guards.iter().collect::<BTreeSet<_>>().len() == guards.len() {
        true => Ok(()),
        false => Err(DijkstraMalformed(MalformedField::DuplicateGuards)),
    }
}
fn check_witness_fields(w: &KeepRaw<'_, WitnessSet<'_>>) -> ValidationResult {
    let mut keys = HashSet::new();
    for x in w.vkeywitness.iter().flat_map(|x| x.iter()) {
        if x.vkey.len() != 32 || x.signature.len() != 64 {
            return Err(DijkstraMalformed(MalformedField::KeyWitness));
        }
        if !keys.insert((x.vkey.to_vec(), x.signature.to_vec())) {
            return Err(DijkstraMalformed(MalformedField::DuplicateKeyWitnesses));
        }
    }
    let mut roots = HashSet::new();
    for x in w.bootstrap_witness.iter().flat_map(|x| x.iter()) {
        if x.public_key.len() != 32 || x.signature.len() != 64 || x.chain_code.len() != 32 {
            return Err(DijkstraMalformed(MalformedField::BootstrapWitness));
        }
        if !roots.insert(super::conway::bootstrap_wit_root(x)) {
            return Err(DijkstraMalformed(
                MalformedField::DuplicateBootstrapWitnesses,
            ));
        }
    }
    let mut datums = HashSet::new();
    if w.plutus_data
        .iter()
        .flat_map(|x| x.iter())
        .any(|x| !datums.insert(x.raw_cbor()))
    {
        return Err(DijkstraMalformed(MalformedField::DuplicateDatums));
    }
    if let Some(redeemers) = &w.redeemer {
        if redeemers.is_empty() {
            return Err(DijkstraMalformed(MalformedField::EmptyRedeemers));
        }
        let limit = i64::MAX as u64;
        if redeemers
            .iter()
            .any(|(_, x)| x.ex_units.mem > limit || x.ex_units.steps > limit)
        {
            return Err(DijkstraMalformed(MalformedField::ExecutionUnits));
        }
    }
    check_map_keys(
        &encode(w)?,
        &[0, 1, 2, 3, 4, 5, 6, 7, 8],
        UnsupportedFeature::WitnessFields,
    )
}
fn check_sub_supported(tx: &SubTransaction<'_>) -> ValidationResult {
    let b = &tx.sub_transaction_body;
    let raw = encode(b)?;
    let mut allowed = vec![0, 1, 3, 8, 15];
    for (key, present) in [
        (4, b.certificates.is_some()),
        (5, b.withdrawals.is_some()),
        (7, b.auxiliary_data_hash.is_some()),
        (9, b.mint.is_some()),
        (11, b.script_data_hash.is_some()),
        (14, holds_value(&raw, 14)),
        (18, b.reference_inputs.is_some()),
        (19, b.voting_procedures.is_some()),
        (20, b.proposal_procedures.is_some()),
        (21, b.treasury_value.is_some()),
        (22, b.donation.is_some()),
        (24, b.required_top_level_guards.is_some()),
        (25, b.direct_deposits.is_some()),
        (26, b.account_balance_intervals.is_some()),
    ] {
        if present {
            allowed.push(key);
        }
    }
    check_map_keys(&raw, &allowed, UnsupportedFeature::SubtransactionBodyFields)?;
    let fields: pallas_codec::utils::KeyValuePairs<u64, pallas_codec::utils::AnyCbor> =
        minicbor::decode(&raw)
            .map_err(|_| DijkstraUnsupported(UnsupportedFeature::SubtransactionBodyFields))?;
    for (key, value) in fields.iter() {
        check_field_present(*key, value)?;
        match key {
            5 => check_withdrawal_accounts(value)?,
            9 => check_asset_encoding(value, true)?,
            24 => check_required_guard_keys(value)?,
            _ => (),
        }
    }
    let mut references = Spent::new();
    for input in b.reference_inputs.iter().flatten() {
        if !references.insert((input.transaction_id, input.index)) {
            return Err(DijkstraUnsupported(
                UnsupportedFeature::DuplicateReferenceInputs,
            ));
        }
    }
    check_output_addresses(b.outputs.iter())?;
    check_guards(b.guards.as_ref())?;
    check_witness_fields(&tx.transaction_witness_set)
}
/// Refuses a withdrawals map that names an account twice, which the ledger decoder refuses.
fn check_withdrawal_accounts(raw: &[u8]) -> ValidationResult {
    let withdrawals: pallas_codec::utils::KeyValuePairs<Bytes, u64> = minicbor::decode(raw)
        .map_err(|_| DijkstraInvalidWithdrawal(WithdrawalFailure::Encoding))?;
    let mut seen = HashSet::new();
    match withdrawals
        .iter()
        .all(|(account, _)| seen.insert(account.to_vec()))
    {
        true => Ok(()),
        false => Err(DijkstraMalformed(
            MalformedField::DuplicateWithdrawalAccounts,
        )),
    }
}
/// Decoding into a BTreeMap would hide duplicate guards, which the ledger rejects.
fn check_required_guard_keys(raw: &[u8]) -> ValidationResult {
    let guards: pallas_codec::utils::KeyValuePairs<StakeCredential, pallas_codec::utils::AnyCbor> =
        minicbor::decode(raw)
            .map_err(|_| DijkstraUnsupported(UnsupportedFeature::RequiredTopLevelGuards))?;
    let mut seen = BTreeSet::new();
    if guards.iter().any(|(key, _)| !seen.insert(key)) {
        return Err(DijkstraMalformed(
            MalformedField::DuplicateRequiredTopLevelGuards,
        ));
    }
    Ok(())
}
/// The body fields refused when present and empty, with the error each gets.
const NON_EMPTY_FIELDS: [(u64, MalformedField); 11] = [
    (4, MalformedField::EmptyCertificates),
    (5, MalformedField::EmptyWithdrawals),
    (13, MalformedField::EmptyCollateralInputs),
    (18, MalformedField::EmptyReferenceInputs),
    (19, MalformedField::EmptyVotingProcedures),
    (20, MalformedField::EmptyProposalProcedures),
    (23, MalformedField::EmptySubtransactions),
    (24, MalformedField::EmptyRequiredTopLevelGuards),
    (25, MalformedField::EmptyDirectDeposits),
    (26, MalformedField::EmptyAccountBalanceIntervals),
    (27, MalformedField::EmptyStartingAccountBalanceIntervals),
];
/// Refuses a body field the ledger decoder refuses for its value, an empty collection or a zero donation.
fn check_field_present(key: u64, value: &[u8]) -> ValidationResult {
    if key == 22 && minicbor::decode::<u64>(value).is_ok_and(|x| x == 0) {
        return Err(DijkstraMalformed(MalformedField::ZeroDonation));
    }
    match NON_EMPTY_FIELDS.iter().find(|(k, _)| *k == key) {
        Some((_, error)) if is_empty_collection(value) => Err(DijkstraMalformed(*error)),
        _ => Ok(()),
    }
}
/// Whether a CBOR value, past any tag, is an array or map with no entries.
fn is_empty_collection(raw: &[u8]) -> bool {
    use minicbor::data::Type;
    let mut d = minicbor::Decoder::new(raw);
    if matches!(d.datatype(), Ok(Type::Tag)) && d.tag().is_err() {
        return false;
    }
    let length = match d.datatype() {
        Ok(Type::Map | Type::MapIndef) => d.map(),
        Ok(Type::Array | Type::ArrayIndef) => d.array(),
        _ => return false,
    };
    match length {
        Ok(Some(n)) => n == 0,
        Ok(None) => matches!(d.datatype(), Ok(Type::Break)),
        Err(_) => false,
    }
}
/// Whether a CBOR map holds the key with a value other than null.
fn holds_value(raw: &[u8], key: u64) -> bool {
    minicbor::decode::<pallas_codec::utils::KeyValuePairs<u64, pallas_codec::utils::AnyCbor>>(raw)
        .is_ok_and(|fields| {
            fields
                .iter()
                .any(|(k, value)| *k == key && value.raw_bytes() != [0xf6])
        })
}
fn check_map_keys(raw: &[u8], allowed: &[u64], feature: UnsupportedFeature) -> ValidationResult {
    let mut d = minicbor::Decoder::new(raw);
    let mut remaining = d.map().map_err(|_| DijkstraUnsupported(feature))?;
    let mut seen = HashSet::new();
    loop {
        match remaining {
            Some(0) => break,
            Some(ref mut n) => *n -= 1,
            None if d.datatype().map_err(|_| DijkstraUnsupported(feature))?
                == minicbor::data::Type::Break =>
            {
                d.skip().map_err(|_| DijkstraUnsupported(feature))?;
                break;
            }
            None => (),
        }
        let key = d.u64().map_err(|_| DijkstraUnsupported(feature))?;
        if !allowed.contains(&key) || !seen.insert(key) {
            return Err(DijkstraUnsupported(feature));
        }
        d.skip().map_err(|_| DijkstraUnsupported(feature))?;
    }
    if d.position() != raw.len() {
        return Err(DijkstraUnsupported(feature));
    }
    Ok(())
}

type Natives = BTreeMap<Hash<28>, NativeScript>;

/// Scripts the sub-transactions need and carry. The ledger checks for missing
/// and unneeded scripts across the whole batch, so a script may be needed at
/// one level and provided at another.
#[derive(Default)]
struct SubScripts {
    levels: Vec<BTreeMap<RedeemersKey, Hash<28>>>,
    needed: HashSet<Hash<28>>,
    witnessed: HashSet<Hash<28>>,
    plutus_witnessed: Vec<(Hash<28>, Language)>,
    referenced: HashSet<Hash<28>>,
    natives: Natives,
    plutus: Plutus,
    reference_bytes: u64,
}
fn sub_scripts(b: &TransactionBody<'_>, utxos: &UTxOs<'_>) -> Result<SubScripts, ValidationError> {
    let mut subs = SubScripts::default();
    for (index, sub) in (0..).zip(b.sub_transactions.iter().flatten()) {
        let sb = &sub.sub_transaction_body;
        let level = Level::sub(sb, Hasher::<256>::hash(sb.raw_cbor()), index);
        let scripts = ledger::redeemer_scripts(&level, |x| spent(x, utxos))?;
        subs.needed.extend(scripts.values());
        subs.levels.push(scripts);
        let mut outputs = Vec::new();
        for input in sb.inputs.iter() {
            outputs.push(
                utxos
                    .get(&MultiEraInput::from_alonzo_compatible(input))
                    .ok_or(PostAlonzo(InputNotInUTxO))?,
            );
        }
        // A UTxO that a sub-transaction both spends and references counts once.
        for input in sb
            .reference_inputs
            .iter()
            .flatten()
            .filter(|x| !sb.inputs.contains(x))
        {
            outputs.push(
                utxos
                    .get(&MultiEraInput::from_alonzo_compatible(input))
                    .ok_or(PostAlonzo(ReferenceInputNotInUTxO))?,
            );
        }
        for script in outputs.iter().filter_map(|x| x.multi_era_script_ref()) {
            subs.referenced.insert(script.hash());
            let size = match reference(&script)? {
                Reference::Native(native) => {
                    let raw = native.encode();
                    let decoded =
                        minicbor::decode(&raw).map_err(|_| PostAlonzo(UnsupportedNativeScript))?;
                    subs.natives.insert(script.hash(), decoded);
                    raw.len()
                }
                Reference::Plutus(language, bytes) => {
                    subs.plutus.insert(script.hash(), language);
                    bytes.len()
                }
            };
            subs.reference_bytes = add(subs.reference_bytes, size as u64)?;
        }
        let w = &sub.transaction_witness_set;
        for script in w.native_script.iter().flatten() {
            subs.witnessed.insert(script.original_hash());
            subs.natives
                .insert(script.original_hash(), (**script).clone());
        }
        for (hash, language, bytes) in plutus_witnesses(w) {
            well_formed_plutus(&language, bytes)?;
            subs.plutus_witnessed.push((hash, language.clone()));
            subs.plutus.insert(hash, language);
        }
    }
    Ok(subs)
}

/// The language of each Plutus script a batch provides, by hash.
type Plutus = BTreeMap<Hash<28>, Language>;

/// The Plutus scripts a witness set carries, with their hash, language and bytes.
fn plutus_witnesses<'a>(
    w: &'a WitnessSet<'_>,
) -> impl Iterator<Item = (Hash<28>, Language, &'a [u8])> {
    let v1 = w.plutus_v1_script.iter().flatten();
    let v2 = w.plutus_v2_script.iter().flatten();
    let v3 = w.plutus_v3_script.iter().flatten();
    let v4 = w.plutus_v4_script.iter().flatten();
    v1.map(|x| (x.compute_hash(), Language::PlutusV1, x.as_ref()))
        .chain(v2.map(|x| (x.compute_hash(), Language::PlutusV2, x.as_ref())))
        .chain(v3.map(|x| (x.compute_hash(), Language::PlutusV3, x.as_ref())))
        .chain(v4.map(|x| (x.compute_hash(), Language::PlutusV4, x.as_ref())))
}

/// The rule the top level withdrawals of a batch whose top level runs Plutus scripts of `languages` are judged by.
pub(super) fn withdrawal_rule(languages: &BTreeSet<Language>) -> WithdrawalRule {
    // A top level Plutus script up to V3 puts the batch in legacy mode, native and V4 scripts do not.
    let legacy = languages.iter().any(|x| match x {
        Language::PlutusV1 | Language::PlutusV2 | Language::PlutusV3 => true,
        Language::PlutusV4 => false,
    });
    match legacy {
        true => WithdrawalRule::Legacy,
        false => WithdrawalRule::Partial,
    }
}

/// The scripts a batch provides and the languages of the Plutus scripts its top level runs.
struct Provided {
    natives: Natives,
    plutus: Plutus,
    languages: BTreeSet<Language>,
}

#[allow(clippy::too_many_arguments)]
fn check_scripts(
    tx: &BlockTransaction<'_>,
    utxos: &UTxOs<'_>,
    pp: &DijkstraProtParams,
    scripts: &BTreeMap<RedeemersKey, Hash<28>>,
    subs: &SubScripts,
    keys: &mut Keys,
    network: u8,
    time: Option<&crate::utils::DijkstraTimeContext>,
) -> Result<Provided, ValidationError> {
    let b = &tx.transaction_body;
    let w = &tx.transaction_witness_set;
    let mut natives = BTreeMap::new();
    let mut plutus = subs.plutus.clone();
    let mut reference_scripts = HashSet::new();
    let mut refs = Spent::new();
    for input in b.reference_inputs.iter().flat_map(|x| x.iter()) {
        if !refs.insert((input.transaction_id, input.index)) {
            return Err(DijkstraUnsupported(
                UnsupportedFeature::DuplicateReferenceInputs,
            ));
        }
    }
    for input in b
        .reference_inputs
        .iter()
        .flat_map(|x| x.iter())
        .chain(b.inputs.iter())
    {
        let output = utxos
            .get(&MultiEraInput::from_alonzo_compatible(input))
            .ok_or(PostAlonzo(ReferenceInputNotInUTxO))?;
        if let Some(script) = output.multi_era_script_ref() {
            reference_scripts.insert(script.hash());
            match reference(&script)? {
                Reference::Native(native) => {
                    let raw = native.encode();
                    let decoded: NativeScript =
                        minicbor::decode(&raw).map_err(|_| PostAlonzo(UnsupportedNativeScript))?;
                    natives.insert(script.hash(), decoded);
                }
                Reference::Plutus(language, _) => {
                    plutus.insert(script.hash(), language);
                }
            }
        }
    }
    let unneeded = |hash: &Hash<28>| {
        !(scripts.values().any(|x| x == hash) || subs.needed.contains(hash))
            || reference_scripts.contains(hash)
            || subs.referenced.contains(hash)
    };
    for script in w.native_script.iter().flat_map(|x| x.iter()) {
        let hash = script.original_hash();
        if unneeded(&hash) {
            return Err(PostAlonzo(UnneededNativeScript));
        }
        natives.insert(hash, (**script).clone());
    }
    if subs.witnessed.iter().any(unneeded) {
        return Err(PostAlonzo(UnneededNativeScript));
    }
    let unneeded_plutus = |language| match language {
        Language::PlutusV1 => PostAlonzo(UnneededPlutusV1Script),
        Language::PlutusV2 => PostAlonzo(UnneededPlutusV2Script),
        Language::PlutusV3 | Language::PlutusV4 => PostAlonzo(UnneededPlutusV3Script),
    };
    for (hash, language, bytes) in plutus_witnesses(w) {
        if unneeded(&hash) {
            return Err(unneeded_plutus(language));
        }
        well_formed_plutus(&language, bytes)?;
        plutus.insert(hash, language);
    }
    if let Some((_, language)) = subs.plutus_witnessed.iter().find(|(x, _)| unneeded(x)) {
        return Err(unneeded_plutus(language.clone()));
    }
    for (hash, script) in &subs.natives {
        natives.entry(*hash).or_insert_with(|| script.clone());
    }
    // The size cap covers the whole batch, and the fee counts top-level references only.
    let bytes = reference_script_size(b, utxos)?;
    if add(bytes, subs.reference_bytes)? > u64::from(pp.max_ref_script_size_per_tx) {
        return Err(DijkstraReferenceScriptsTooLarge);
    }
    let provided = Provided {
        natives,
        plutus,
        languages: BTreeSet::new(),
    };
    let level = Level::top(b, Hasher::<256>::hash(b.raw_cbor()));
    let languages = check_level(
        &level,
        w,
        b.script_data_hash,
        scripts,
        &provided,
        utxos,
        pp,
        time,
    )?;
    let (mem, steps) = declared_units(tx)?;
    if mem > pp.max_tx_ex_units.mem || steps > pp.max_tx_ex_units.steps {
        return Err(PostAlonzo(TxExUnitsExceeded));
    }
    let levels = std::iter::once(w).chain(
        b.sub_transactions
            .iter()
            .flatten()
            .map(|s| &s.transaction_witness_set),
    );
    let redeemers = levels
        .into_iter()
        .any(|w| w.redeemer.as_ref().is_some_and(|x| !x.is_empty()));
    check_collateral(b, utxos, pp, keys, network, redeemers)?;
    Ok(Provided {
        languages,
        ..provided
    })
}

/// Checks the collateral of a batch, with the rules that need redeemers only where some level has `redeemers`, adding the key of each key locked collateral input to `keys`.
fn check_collateral(
    b: &TransactionBody<'_>,
    utxos: &UTxOs<'_>,
    pp: &DijkstraProtParams,
    keys: &mut Keys,
    network: u8,
    redeemers: bool,
) -> ValidationResult {
    let collateral: Vec<_> = b.collateral.iter().flatten().collect();
    if redeemers && collateral.is_empty() {
        return Err(PostAlonzo(CollateralMissing));
    }
    if collateral.len() > pp.max_collateral_inputs as usize {
        return Err(PostAlonzo(TooManyCollaterals));
    }
    let mut collateral_ids = Spent::new();
    let mut collateral_assets = BTreeMap::new();
    let mut total = 0;
    for input in collateral {
        if !collateral_ids.insert((input.transaction_id, input.index)) {
            return Err(DijkstraUnsupported(
                UnsupportedFeature::DuplicateCollateralInputs,
            ));
        }
        let output = utxos
            .get(&MultiEraInput::from_alonzo_compatible(input))
            .ok_or(PostAlonzo(CollateralNotInUTxO))?;
        match spender(output)? {
            Spender::Key(key) => {
                keys.insert(key);
            }
            Spender::Script(_) if redeemers => return Err(PostAlonzo(CollateralNotVKeyLocked)),
            Spender::Script(_) => {}
        }
        if redeemers {
            total = add(total, output.value().coin())?;
            accumulate_assets(&mut collateral_assets, output, 1)?;
        }
    }
    let returned = match &b.collateral_return {
        Some(output) => check_outputs(std::slice::from_ref(output), pp, &network)?,
        None => 0,
    };
    if let Some(output) = &b.collateral_return
        && let Ok(Address::Shelley(address)) = MultiEraOutput::from_dijkstra(output).address()
        && matches!(address.delegation(), ShelleyDelegationPart::Pointer(_))
    {
        return Err(DijkstraPointerInCollateralReturn);
    }
    if !redeemers {
        return Ok(());
    }
    if let Some(output) = &b.collateral_return {
        accumulate_assets(
            &mut collateral_assets,
            &MultiEraOutput::from_dijkstra(output),
            -1,
        )?;
    }
    if collateral_assets.values().any(|x| *x != 0) {
        return Err(PostAlonzo(NonLovelaceCollateral));
    }
    let paid = total
        .checked_sub(returned)
        .ok_or(PostAlonzo(NegativeValue))?;
    if b.total_collateral.is_some_and(|x| x != paid) {
        return Err(PostAlonzo(CollateralAnnotation));
    }
    if u128::from(paid) * 100 < u128::from(b.fee) * u128::from(pp.collateral_percentage) {
        return Err(PostAlonzo(CollateralMinLovelace));
    }
    Ok(())
}

/// Checks the scripts, datums, redeemers and integrity hash of the level `b` with witness set `w`, and returns the languages of the Plutus scripts it runs.
#[allow(clippy::too_many_arguments)]
fn check_level(
    b: &Level<'_>,
    w: &WitnessSet<'_>,
    declared: Option<Hash<32>>,
    scripts: &BTreeMap<RedeemersKey, Hash<28>>,
    provided: &Provided,
    utxos: &UTxOs<'_>,
    pp: &DijkstraProtParams,
    time: Option<&crate::utils::DijkstraTimeContext>,
) -> Result<BTreeSet<Language>, ValidationError> {
    let witnesses = witness_keys(w);
    let guards: BTreeSet<_> = guard_credentials(b.guards).into_iter().collect();
    for (hash, script) in &provided.natives {
        if scripts.values().any(|x| x == hash)
            && !crate::utils::dijkstra_native::evaluate(
                script,
                &witnesses,
                b.validity_interval_start,
                b.ttl,
                &guards,
            )
        {
            return Err(PostAlonzo(NativeScriptDenial));
        }
    }
    // Retain original purpose indices: native scripts need no redeemer or datum.
    let scripts: BTreeMap<_, _> = scripts
        .iter()
        .filter(|(_, hash)| !provided.natives.contains_key(hash))
        .map(|(key, hash)| (key.clone(), *hash))
        .collect();
    let mut languages = BTreeSet::new();
    for hash in scripts.values() {
        let language = provided
            .plutus
            .get(hash)
            .ok_or(PostAlonzo(ScriptWitnessMissing))?;
        languages.insert(language.clone());
    }
    if !scripts.is_empty() {
        match time {
            Some(time) => {
                time.validity_bounds(b.validity_interval_start, b.ttl)?;
            }
            None if b.ttl.is_some() => {
                return Err(DijkstraUnsupported(
                    UnsupportedFeature::PlutusUpperBoundWithoutForecast,
                ));
            }
            None => {}
        }
    }
    check_datums(b, w, utxos, &scripts, &provided.plutus)?;
    if scripts.is_empty() {
        if w.redeemer.as_ref().is_some_and(|x| !x.is_empty()) {
            return Err(PostAlonzo(UnneededRedeemer));
        }
        // An empty redeemer map and language view still participate when datums exist.
        check_integrity(w, declared, None)?;
        return Ok(languages);
    }
    let models = &pp.cost_models_for_script_languages;
    let mut views = BTreeMap::new();
    for language in &languages {
        let (key, model) = match language {
            Language::PlutusV1 => (0, &models.plutus_v1),
            Language::PlutusV2 => (1, &models.plutus_v2),
            Language::PlutusV3 => (2, &models.plutus_v3),
            Language::PlutusV4 => (3, &models.plutus_v4),
        };
        let model = model
            .clone()
            .ok_or(DijkstraScriptContext(ContextFailure::CostModel))?;
        views.insert(key, model);
    }
    let redeemers = w.redeemer.as_ref().ok_or(PostAlonzo(RedeemerMissing))?;
    for index in scripts.keys() {
        if !redeemers.contains_key(index) {
            return Err(PostAlonzo(RedeemerMissing));
        }
    }
    if redeemers.iter().any(|(key, _)| !scripts.contains_key(key)) {
        return Err(PostAlonzo(UnneededRedeemer));
    }
    check_integrity(w, declared, Some(views))?;
    Ok(languages)
}

/// The fee for the declared execution units, rounded up once.
fn execution_fee(mem: u64, steps: u64, pp: &DijkstraProtParams) -> Result<u64, ValidationError> {
    if mem == 0 && steps == 0 {
        return Ok(0);
    }
    let (n, d) = fraction_add(
        fraction_scale(price(&pp.execution_costs.mem_price)?, mem)?,
        fraction_scale(price(&pp.execution_costs.step_price)?, steps)?,
    )?;
    u64::try_from(n / d + u128::from(n % d != 0)).map_err(|_| PostAlonzo(NegativeValue))
}

// Exact nonnegative arithmetic: execution fees round up once; the total tiered
// reference fee rounds down once. Floating point would change boundary results.
type Fraction = (u128, u128);
fn price(x: &RationalNumber) -> Result<Fraction, ValidationError> {
    if x.denominator == 0 {
        return Err(DijkstraMissingParameters(
            ParameterFailure::NonzeroPriceDenominator,
        ));
    }
    Ok((u128::from(x.numerator), u128::from(x.denominator)))
}
fn reduce((n, d): Fraction) -> Fraction {
    let (mut a, mut b) = (n, d);
    while b != 0 {
        (a, b) = (b, a % b);
    }
    (n / a, d / a)
}
fn fraction_scale((n, d): Fraction, x: u64) -> Result<Fraction, ValidationError> {
    Ok(reduce((
        n.checked_mul(u128::from(x))
            .ok_or(PostAlonzo(NegativeValue))?,
        d,
    )))
}
fn fraction_add((a, b): Fraction, (c, d): Fraction) -> Result<Fraction, ValidationError> {
    let n = a
        .checked_mul(d)
        .and_then(|x| c.checked_mul(b).and_then(|y| x.checked_add(y)))
        .ok_or(PostAlonzo(NegativeValue))?;
    Ok(reduce((
        n,
        b.checked_mul(d).ok_or(PostAlonzo(NegativeValue))?,
    )))
}
fn reference_fee(mut bytes: u64, p: &DijkstraProtParams) -> Result<u64, ValidationError> {
    if bytes == 0 {
        return Ok(0);
    }
    if p.ref_script_cost_stride == 0 {
        return Err(DijkstraMissingParameters(
            ParameterFailure::ReferenceFeeStride,
        ));
    }
    let mut rate = price(&p.minfee_refscript_cost_per_byte)?;
    let multiplier = price(&p.ref_script_cost_multiplier)?;
    let mut total = (0, 1);
    while bytes != 0 {
        let count = bytes.min(u64::from(p.ref_script_cost_stride));
        total = fraction_add(total, fraction_scale(rate, count)?)?;
        bytes -= count;
        if bytes != 0 {
            rate = reduce((
                rate.0
                    .checked_mul(multiplier.0)
                    .ok_or(PostAlonzo(NegativeValue))?,
                rate.1
                    .checked_mul(multiplier.1)
                    .ok_or(PostAlonzo(NegativeValue))?,
            ));
        }
    }
    u64::try_from(total.0 / total.1).map_err(|_| PostAlonzo(NegativeValue))
}

fn check_auxiliary(
    hash: Option<Hash<32>>,
    auxiliary: &Nullable<KeepRaw<'_, AuxiliaryData>>,
) -> ValidationResult {
    let data = match auxiliary {
        Nullable::Null if hash.is_none() => return Ok(()),
        Nullable::Some(data) if hash == Some(Hasher::<256>::hash(&encode(data)?)) => data,
        _ => return Err(PostAlonzo(MetadataHash)),
    };
    let metadata = match &**data {
        AuxiliaryData::Shelley(m) => Some(m),
        AuxiliaryData::ShelleyMa(m) => {
            if m.auxiliary_scripts.as_ref().is_some_and(|x| !x.is_empty()) {
                return Err(DijkstraUnsupported(UnsupportedFeature::AuxiliaryScripts));
            }
            Some(&m.transaction_metadata)
        }
        AuxiliaryData::PostAlonzo(m) => {
            if m.native_scripts.is_some()
                || m.plutus_v1_scripts.is_some()
                || m.plutus_v2_scripts.is_some()
                || m.plutus_v3_scripts.is_some()
                || m.plutus_v4_scripts.is_some()
            {
                return Err(DijkstraUnsupported(UnsupportedFeature::AuxiliaryScripts));
            }
            m.metadata.as_ref()
        }
    };
    // Map decoding into BTreeMap must not hide duplicate metadata labels.
    let raw = encode(data)?;
    let mut decoder = minicbor::Decoder::new(&raw);
    let metadata_bytes = match &**data {
        AuxiliaryData::Shelley(_) => Some(raw.clone()),
        AuxiliaryData::ShelleyMa(_) => {
            decoder.array().map_err(|_| DijkstraInvalidMetadata)?;
            let value: pallas_codec::utils::AnyCbor =
                decoder.decode().map_err(|_| DijkstraInvalidMetadata)?;
            Some(value.to_vec())
        }
        AuxiliaryData::PostAlonzo(_) => {
            decoder.tag().map_err(|_| DijkstraInvalidMetadata)?;
            check_map_keys(
                &raw[decoder.position()..],
                &[0],
                UnsupportedFeature::AuxiliaryFields,
            )?;
            let fields: pallas_codec::utils::KeyValuePairs<u64, pallas_codec::utils::AnyCbor> =
                decoder.decode().map_err(|_| DijkstraInvalidMetadata)?;
            fields
                .iter()
                .find(|(key, _)| *key == 0)
                .map(|(_, value)| value.to_vec())
        }
    };
    if let Some(bytes) = metadata_bytes {
        let entries: pallas_codec::utils::KeyValuePairs<u64, Metadatum> =
            minicbor::decode(&bytes).map_err(|_| DijkstraInvalidMetadata)?;
        let mut labels = HashSet::new();
        if entries.iter().any(|(label, _)| !labels.insert(*label)) {
            return Err(DijkstraInvalidMetadata);
        }
    }
    let mut pending: Vec<_> = metadata.into_iter().flat_map(|m| m.values()).collect();
    while let Some(item) = pending.pop() {
        match item {
            Metadatum::Text(x) if x.len() > 64 => return Err(DijkstraInvalidMetadata),
            Metadatum::Bytes(x) if x.len() > 64 => return Err(DijkstraInvalidMetadata),
            Metadatum::Array(xs) => pending.extend(xs),
            Metadatum::Map(xs) => {
                for (k, v) in xs.iter() {
                    pending.extend([k, v]);
                }
            }
            _ => (),
        }
    }
    Ok(())
}

type AssetBalance = BTreeMap<(Hash<28>, Vec<u8>), i128>;
fn accumulate_assets(
    total: &mut AssetBalance,
    output: &MultiEraOutput<'_>,
    sign: i128,
) -> ValidationResult {
    if let pallas_primitives::alonzo::Value::Multiasset(_, assets) = output.value().into_alonzo() {
        for (policy, assets) in assets {
            for (name, quantity) in assets {
                if name.len() > 32 {
                    return Err(PostAlonzo(NegativeValue));
                }
                let entry = total.entry((policy, name.to_vec())).or_default();
                *entry = entry
                    .checked_add(i128::from(quantity) * sign)
                    .ok_or(PostAlonzo(NegativeValue))?;
            }
        }
    }
    Ok(())
}
/// Checks that the assets of `inputs` and `mint` equal the assets of `outputs`.
fn check_assets<'a, 'b: 'a>(
    inputs: impl Iterator<Item = &'a TransactionInput>,
    outputs: impl Iterator<Item = &'a TransactionOutput<'b>>,
    mint: impl Iterator<Item = &'a Mint>,
    utxos: &UTxOs<'_>,
) -> ValidationResult {
    let mut balance = AssetBalance::new();
    for input in inputs {
        let output = utxos
            .get(&MultiEraInput::from_alonzo_compatible(input))
            .ok_or(PostAlonzo(InputNotInUTxO))?;
        accumulate_assets(&mut balance, output, 1)?;
    }
    for output in outputs {
        accumulate_assets(&mut balance, &MultiEraOutput::from_dijkstra(output), -1)?;
    }
    for (policy, assets) in mint.flat_map(|m| m.iter()) {
        for (name, quantity) in assets {
            let entry = balance.entry((*policy, name.to_vec())).or_default();
            *entry = entry
                .checked_add(i128::from(i64::from(quantity)))
                .ok_or(PostAlonzo(NegativeValue))?;
        }
    }
    if balance.values().any(|x| *x != 0) {
        return Err(PostAlonzo(PreservationOfValue));
    }
    Ok(())
}

/// Checks that the level `b` carries in `w` each datum its Plutus spent inputs require, and only datums those inputs, its outputs and its reference inputs name.
fn check_datums(
    b: &Level<'_>,
    w: &WitnessSet<'_>,
    utxos: &UTxOs<'_>,
    scripts: &BTreeMap<RedeemersKey, Hash<28>>,
    plutus: &Plutus,
) -> ValidationResult {
    let mut allowed = HashSet::new();
    let mut required = HashSet::new();
    for (index, input) in b
        .inputs
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .enumerate()
    {
        if let Some(hash) = scripts.get(&RedeemersKey {
            tag: RedeemerTag::Spend,
            index: index as u32,
        }) {
            let output = utxos
                .get(&MultiEraInput::from_alonzo_compatible(input))
                .ok_or(PostAlonzo(InputNotInUTxO))?;
            match output.datum() {
                Some(DatumOption::Hash(hash)) => {
                    required.insert(hash);
                    allowed.insert(hash);
                }
                Some(DatumOption::Data(_)) => (),
                // CIP-0069: only V3 may spend an output without a datum. A
                // present hash still requires its matching witness datum.
                None => {
                    if matches!(
                        plutus.get(hash),
                        Some(Language::PlutusV1 | Language::PlutusV2)
                    ) {
                        return Err(DijkstraInputWithoutDatum);
                    }
                }
            }
        }
    }
    for output in b.outputs.iter().map(MultiEraOutput::from_dijkstra) {
        if let Some(DatumOption::Hash(hash)) = output.datum() {
            allowed.insert(hash);
        }
    }
    for input in b.reference_inputs.into_iter().flatten() {
        let output = utxos
            .get(&MultiEraInput::from_alonzo_compatible(input))
            .ok_or(PostAlonzo(ReferenceInputNotInUTxO))?;
        if let Some(DatumOption::Hash(hash)) = output.datum() {
            allowed.insert(hash);
        }
    }
    for datum in w.plutus_data.iter().flat_map(|x| x.iter()) {
        let hash = Hasher::<256>::hash(&encode(datum)?);
        if !allowed.contains(&hash) {
            return Err(PostAlonzo(UnneededDatum));
        }
        required.remove(&hash);
    }
    if !required.is_empty() {
        return Err(PostAlonzo(DatumMissing));
    }
    Ok(())
}

/// Checks the declared script integrity hash of one level against its redeemers, datums and the language views of the Plutus scripts it runs.
fn check_integrity(
    w: &WitnessSet<'_>,
    declared: Option<Hash<32>>,
    views: Option<BTreeMap<u8, Vec<i64>>>,
) -> ValidationResult {
    let has_data = w.plutus_data.as_ref().is_some_and(|x| !x.is_empty());
    let has_redeemers = w.redeemer.as_ref().is_some_and(|x| !x.is_empty());
    let expected = if views.is_none() && !has_data && !has_redeemers {
        None
    } else {
        let mut bytes = match &w.redeemer {
            Some(r) => encode(r)?,
            None => vec![0xa0],
        };
        if let Some(data) = w.plutus_data.as_ref().filter(|_| has_data) {
            bytes.extend(encode(data)?);
        }
        bytes.extend(encode(LanguageViews(views.unwrap_or_default()))?);
        Some(Hasher::<256>::hash(&bytes))
    };
    if declared != expected {
        return Err(PostAlonzo(ScriptIntegrityHash));
    }
    Ok(())
}

/// A reference script, native or Plutus with its language and bytes.
enum Reference<'a> {
    Native(MultiEraNativeScript<'a>),
    Plutus(Language, &'a [u8]),
}

fn reference<'a>(script: &'a MultiEraScriptRef<'_>) -> Result<Reference<'a>, ValidationError> {
    use pallas_primitives::conway::ScriptRef as C;
    match script {
        MultiEraScriptRef::Dijkstra(x) => match x.as_ref() {
            ScriptRef::NativeScript(s) => {
                Ok(Reference::Native(MultiEraNativeScript::from_dijkstra(s)))
            }
            ScriptRef::PlutusV1Script(s) => Ok(Reference::Plutus(Language::PlutusV1, s.as_ref())),
            ScriptRef::PlutusV2Script(s) => Ok(Reference::Plutus(Language::PlutusV2, s.as_ref())),
            ScriptRef::PlutusV3Script(s) => Ok(Reference::Plutus(Language::PlutusV3, s.as_ref())),
            ScriptRef::PlutusV4Script(s) => Ok(Reference::Plutus(Language::PlutusV4, s.as_ref())),
        },
        MultiEraScriptRef::Conway(x) => match x.as_ref() {
            C::NativeScript(s) => Ok(Reference::Native(
                MultiEraNativeScript::from_alonzo_compatible(s),
            )),
            C::PlutusV1Script(s) => Ok(Reference::Plutus(Language::PlutusV1, s.as_ref())),
            C::PlutusV2Script(s) => Ok(Reference::Plutus(Language::PlutusV2, s.as_ref())),
            C::PlutusV3Script(s) => Ok(Reference::Plutus(Language::PlutusV3, s.as_ref())),
        },
        _ => Err(DijkstraUnsupported(
            UnsupportedFeature::ReferenceScriptLanguage,
        )),
    }
}

fn check_new_script(script: &MultiEraScriptRef<'_>) -> ValidationResult {
    match script {
        MultiEraScriptRef::Dijkstra(s) => match s.as_ref() {
            ScriptRef::NativeScript(_) => Ok(()),
            ScriptRef::PlutusV1Script(s) => well_formed_plutus(&Language::PlutusV1, s.as_ref()),
            ScriptRef::PlutusV2Script(s) => well_formed_plutus(&Language::PlutusV2, s.as_ref()),
            ScriptRef::PlutusV3Script(s) => well_formed_plutus(&Language::PlutusV3, s.as_ref()),
            ScriptRef::PlutusV4Script(s) => well_formed_plutus(&Language::PlutusV4, s.as_ref()),
        },
        _ => Err(DijkstraUnsupported(UnsupportedFeature::NewScriptLanguage)),
    }
}
fn well_formed_plutus(language: &Language, script: &[u8]) -> ValidationResult {
    #[cfg(feature = "phase2")]
    {
        crate::phase2::native_evaluator::check_plutus_script(language, script)
            .map_err(|_| DijkstraMalformedScript)
    }
    #[cfg(not(feature = "phase2"))]
    {
        let _ = (language, script);
        Err(DijkstraUnsupported(UnsupportedFeature::PlutusWithoutPhase2))
    }
}

// Ledger v12 Mary.Value requires nonempty policy/name maps, nonzero quantities,
// <=32-byte names and duplicate-free maps even in the legacy TxOut representation.
fn check_asset_encoding(raw: &[u8], mint: bool) -> ValidationResult {
    use pallas_codec::utils::KeyValuePairs;
    let assets: KeyValuePairs<Hash<28>, KeyValuePairs<Bytes, minicbor::data::Int>> =
        minicbor::decode(raw).map_err(|_| MALFORMED_VALUE)?;
    let mut policies = HashSet::new();
    if assets.is_empty() {
        return Err(MALFORMED_VALUE);
    }
    for (policy, names) in assets.iter() {
        if !policies.insert(*policy) || names.is_empty() {
            return Err(MALFORMED_VALUE);
        }
        let mut seen = HashSet::new();
        for (name, quantity) in names.iter() {
            let quantity = i128::from(*quantity);
            if name.len() > 32
                || !seen.insert(name.to_vec())
                || quantity == 0
                || (mint && i64::try_from(quantity).is_err())
                || (!mint && u64::try_from(quantity).is_err())
            {
                return Err(MALFORMED_VALUE);
            }
        }
    }
    Ok(())
}
fn check_output_value_encoding(raw: &[u8]) -> ValidationResult {
    use pallas_codec::utils::{AnyCbor, KeyValuePairs};
    let mut decoder = minicbor::Decoder::new(raw);
    let value = match decoder.datatype().map_err(|_| MALFORMED_VALUE)? {
        minicbor::data::Type::Map | minicbor::data::Type::MapIndef => {
            let fields: KeyValuePairs<u64, AnyCbor> =
                decoder.decode().map_err(|_| MALFORMED_VALUE)?;
            fields
                .iter()
                .find(|(k, _)| *k == 1)
                .map(|(_, v)| v.clone())
                .ok_or(MALFORMED_VALUE)?
        }
        _ => {
            decoder.array().map_err(|_| MALFORMED_VALUE)?;
            decoder.skip().map_err(|_| MALFORMED_VALUE)?;
            decoder.decode::<AnyCbor>().map_err(|_| MALFORMED_VALUE)?
        }
    };
    let mut d = minicbor::Decoder::new(&value);
    if matches!(
        d.datatype(),
        Ok(minicbor::data::Type::Array | minicbor::data::Type::ArrayIndef)
    ) {
        let values: Vec<AnyCbor> = d.decode().map_err(|_| MALFORMED_VALUE)?;
        if values.len() != 2 {
            return Err(MALFORMED_VALUE);
        }
        check_asset_encoding(&values[1], false)?;
    }
    Ok(())
}
