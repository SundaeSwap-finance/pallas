//! Native protocol-12 phase one for the documented transfer and registration subset.
//! See test_data/musashi-phase1/registration-only.md for rules and boundaries.
use crate::utils::{
    CertState, DijkstraPlutusParams, DijkstraProtParams, DijkstraRegistrationState,
    PostAlonzoError::*, UTxOs, ValidationError, ValidationError::*, ValidationResult,
    add_fee_and_stake_deposits, verify_signature,
};
use pallas_addresses::{Address, ShelleyDelegationPart, ShelleyPaymentPart};
use pallas_codec::{
    minicbor,
    utils::{KeepRaw, Nullable},
};
use pallas_crypto::hash::{Hash, Hasher};
use pallas_primitives::{conway::LanguageViews, dijkstra::*};
use pallas_traverse::{MultiEraInput, MultiEraOutput, MultiEraScriptRef, MultiEraTx};
use std::collections::{BTreeMap, HashSet};

type Keys = HashSet<Hash<28>>;
type Spent = HashSet<(Hash<32>, u64)>;

/// Validate native phase one. Registration updates are provisional until phase two
/// succeeds. Missing credential entries mean unknown state, never unregistered.
pub fn validate_dijkstra_tx(
    tx: &BlockTransaction<'_>,
    utxos: &UTxOs<'_>,
    pp: &DijkstraProtParams,
    block_slot: &u64,
    network_id: &u8,
    cert_state: &mut CertState,
) -> ValidationResult {
    if pp.protocol_version != (12, 0) {
        return Err(DijkstraUnsupported("protocol version (requires 12.0)"));
    }
    check_supported(tx)?;
    let b = &tx.transaction_body;
    let mut state = cert_state.dijkstra_registrations.clone();
    let mut keys = Keys::new();
    let mut scripts = BTreeMap::new();
    for (index, cert) in b.certificates.iter().flat_map(|x| x.iter()).enumerate() {
        let Certificate::Reg(credential, deposit) = cert else {
            return Err(DijkstraUnsupported("certificate kind"));
        };
        match state.get(credential) {
            None => return Err(DijkstraCertificateStateUnavailable),
            Some(DijkstraRegistrationState::Registered) => {
                return Err(DijkstraInvalidCertificate("already registered"));
            }
            Some(DijkstraRegistrationState::Unregistered) => (),
        }
        let expected = pp
            .key_deposit
            .ok_or(DijkstraMissingParameters("key deposit"))?;
        if *deposit != expected {
            return Err(DijkstraInvalidCertificate("registration deposit"));
        }
        match credential {
            StakeCredential::AddrKeyhash(key) => {
                keys.insert(*key);
            }
            StakeCredential::ScriptHash(hash) => {
                scripts.insert(index as u32, *hash);
            }
        }
        state.insert(credential.clone(), DijkstraRegistrationState::Registered);
    }
    check_interval(
        b.validity_interval_start,
        b.ttl,
        b.network_id,
        *block_slot,
        *network_id,
    )?;
    // Dijkstra Tx.hs counts [body, witnesses, auxiliary/null], excluding block success.
    let size = encode(tx.to_mempool_transaction())?.len();
    if size > pp.max_transaction_size as usize {
        return Err(PostAlonzo(MaxTxSizeExceeded));
    }
    let mut minimum_fee = u64::from(pp.minfee_a)
        .checked_mul(size as u64)
        .and_then(|x| x.checked_add(u64::from(pp.minfee_b)))
        .ok_or(PostAlonzo(NegativeValue))?;
    minimum_fee = add(
        minimum_fee,
        check_scripts(tx, utxos, pp, &scripts, &mut keys, *network_id)?,
    )?;
    if b.fee < minimum_fee {
        return Err(PostAlonzo(FeeBelowMin));
    }
    let consumed = check_inputs(&b.inputs, utxos, &mut keys)?;
    let output_coin = check_outputs(&b.outputs, pp, network_id)?;
    // Same explicit Reg deposit semantics as Conway; no transaction/witness conversion.
    let view = MultiEraTx::from_dijkstra(tx);
    let produced = add_fee_and_stake_deposits(
        &Value::Coin(output_coin),
        b.fee,
        &view.certs(),
        pp.key_deposit.unwrap_or(0),
    )?;
    if produced != Value::Coin(consumed) {
        return Err(PostAlonzo(PreservationOfValue));
    }
    check_signatures(&tx.transaction_witness_set, &encode(b)?, keys)?;
    cert_state.dijkstra_registrations = state;
    Ok(())
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
fn check_inputs(
    inputs: &[TransactionInput],
    utxos: &UTxOs<'_>,
    keys: &mut Keys,
) -> Result<u64, ValidationError> {
    if inputs.is_empty() {
        return Err(PostAlonzo(TxInsEmpty));
    }
    let mut local = Spent::new();
    let mut total = 0;
    for input in inputs {
        let id = (input.transaction_id, input.index);
        if !local.insert(id) {
            return Err(DijkstraUnsupported("duplicate inputs"));
        }
        let output = utxos
            .get(&MultiEraInput::from_alonzo_compatible(input))
            .ok_or(PostAlonzo(InputNotInUTxO))?;
        let (coin, key) = key_coin(output)?;
        total = add(total, coin)?;
        keys.insert(key);
    }
    Ok(total)
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
    if !required.is_empty() {
        return Err(PostAlonzo(VKWitnessMissing));
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
        let (coin, _) = key_coin(&view)?;
        let Address::Shelley(address) = view.address().map_err(|_| PostAlonzo(AddressDecoding))?
        else {
            return Err(DijkstraUnsupported("output address"));
        };
        if address.network().value() != *network_id {
            return Err(PostAlonzo(OutputWrongNetworkID));
        }
        // Sized TxOut counts the original serialization, not just the value.
        let output_bytes = minicbor::to_vec(output).map_err(|_| PostAlonzo(UnknownTxSize))?;
        match output {
            TransactionOutput::PostAlonzo(_) => {
                check_map_keys(&output_bytes, &[0, 1], "output fields")?;
            }
            TransactionOutput::Legacy(_) => {
                let mut decoder = minicbor::Decoder::new(&output_bytes);
                if decoder
                    .array()
                    .map_err(|_| DijkstraUnsupported("output fields"))?
                    != Some(2)
                {
                    return Err(DijkstraUnsupported("output fields"));
                }
            }
        }
        let minimum = pp
            .ada_per_utxo_byte
            .checked_mul(160 + output_bytes.len() as u64)
            .ok_or(PostAlonzo(NegativeValue))?;
        if coin < minimum {
            return Err(PostAlonzo(MinLovelaceUnreached));
        }
        let value_bytes = minicbor::to_vec(coin).map_err(|_| PostAlonzo(UnknownTxSize))?;
        if value_bytes.len() > pp.max_value_size as usize {
            return Err(PostAlonzo(MaxValSizeExceeded));
        }
        total = add(total, coin)?;
    }
    Ok(total)
}
fn key_coin(
    output: &MultiEraOutput<'_>,
) -> Result<(u64, pallas_crypto::hash::Hash<28>), ValidationError> {
    if output.datum().is_some() || output.multi_era_script_ref().is_some() {
        return Err(DijkstraUnsupported("output datum or reference script"));
    }
    if !matches!(
        output.value().into_alonzo(),
        pallas_primitives::alonzo::Value::Coin(_)
    ) {
        return Err(DijkstraUnsupported("multiasset value"));
    }
    let Address::Shelley(address) = output.address().map_err(|_| PostAlonzo(AddressDecoding))?
    else {
        return Err(DijkstraUnsupported("bootstrap or reward address"));
    };
    if matches!(address.delegation(), ShelleyDelegationPart::Pointer(_)) {
        return Err(DijkstraUnsupported("pointer address"));
    }
    let ShelleyPaymentPart::Key(key) = address.payment() else {
        return Err(DijkstraUnsupported("script payment credential"));
    };
    Ok((output.value().coin(), *key))
}

fn check_supported(tx: &BlockTransaction<'_>) -> ValidationResult {
    let b = &tx.transaction_body;
    if !tx.success {
        return Err(DijkstraUnsupported("unsuccessful block transaction"));
    }
    if b.sub_transactions.is_some() {
        return Err(DijkstraUnsupported("subtransactions"));
    }
    if b.guards.is_some() || b.required_top_level_guards.is_some() {
        return Err(DijkstraUnsupported("guards"));
    }
    if b.direct_deposits.is_some()
        || b.account_balance_intervals.is_some()
        || b.starting_account_balance_intervals.is_some()
        || b.withdrawals.is_some()
        || b.voting_procedures.is_some()
        || b.proposal_procedures.is_some()
        || b.treasury_value.is_some()
        || b.donation.is_some()
    {
        return Err(DijkstraUnsupported("account or governance state"));
    }
    if b.mint.is_some() {
        return Err(DijkstraUnsupported("mint"));
    }
    if b.auxiliary_data_hash.is_some() || !matches!(tx.auxiliary_data, Nullable::Null) {
        return Err(DijkstraUnsupported("auxiliary data"));
    }
    let mut allowed = vec![0, 1, 2, 3, 8, 15];
    for (key, present) in [
        (4, b.certificates.is_some()),
        (11, b.script_data_hash.is_some()),
        (13, b.collateral.is_some()),
        (16, b.collateral_return.is_some()),
        (17, b.total_collateral.is_some()),
        (18, b.reference_inputs.is_some()),
    ] {
        if present {
            allowed.push(key);
        }
    }
    check_map_keys(&encode(b)?, &allowed, "body fields")?;
    check_witness_fields(&tx.transaction_witness_set)
}
fn check_witness_fields(w: &KeepRaw<'_, WitnessSet<'_>>) -> ValidationResult {
    if w.native_script.is_some()
        || w.bootstrap_witness.is_some()
        || w.plutus_v1_script.is_some()
        || w.plutus_v2_script.is_some()
        || w.plutus_v3_script.is_some()
        || w.plutus_data.is_some()
    {
        return Err(DijkstraUnsupported("non-vkey witnesses"));
    }
    let allowed = if w.redeemer.is_some() {
        &[0, 5][..]
    } else {
        &[0][..]
    };
    check_map_keys(&encode(w)?, allowed, "witness fields")
}
fn check_map_keys(raw: &[u8], allowed: &[u64], feature: &'static str) -> ValidationResult {
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

fn check_scripts(
    tx: &BlockTransaction<'_>,
    utxos: &UTxOs<'_>,
    pp: &DijkstraProtParams,
    scripts: &BTreeMap<u32, Hash<28>>,
    keys: &mut Keys,
    network: u8,
) -> Result<u64, ValidationError> {
    let b = &tx.transaction_body;
    let w = &tx.transaction_witness_set;
    if scripts.is_empty() {
        if w.redeemer.is_some() {
            return Err(PostAlonzo(UnneededRedeemer));
        }
        if b.script_data_hash.is_some()
            || b.reference_inputs.is_some()
            || b.collateral.is_some()
            || b.collateral_return.is_some()
            || b.total_collateral.is_some()
        {
            return Err(DijkstraUnsupported(
                "script fields without script registration",
            ));
        }
        return Ok(0);
    }
    let p = pp
        .plutus
        .as_ref()
        .ok_or(DijkstraMissingParameters("Plutus parameters"))?;
    if b.ttl.is_some() {
        return Err(DijkstraUnsupported(
            "Plutus validity upper bound requires forecast state",
        ));
    }
    let mut available = HashSet::new();
    let mut refs = Spent::new();
    let mut bytes = 0;
    for input in b.reference_inputs.iter().flat_map(|x| x.iter()) {
        if !refs.insert((input.transaction_id, input.index)) {
            return Err(DijkstraUnsupported("duplicate reference inputs"));
        }
        if b.inputs.contains(input) {
            return Err(DijkstraUnsupported(
                "overlapping spending and reference inputs",
            ));
        }
        let output = utxos
            .get(&MultiEraInput::from_alonzo_compatible(input))
            .ok_or(PostAlonzo(ReferenceInputNotInUTxO))?;
        if let Some(script) = output.multi_era_script_ref() {
            // Reference UTxOs are already-admitted ledger outputs. No new script
            // bytes enter the ledger in this subset, and phase two is separate.
            let raw = match &script {
                MultiEraScriptRef::Dijkstra(x) => match x.as_ref() {
                    ScriptRef::PlutusV3Script(s) => s.as_ref(),
                    _ => return Err(PostAlonzo(UnsupportedPlutusLanguage)),
                },
                MultiEraScriptRef::Conway(x) => match x.as_ref() {
                    pallas_primitives::conway::ScriptRef::PlutusV3Script(s) => s.as_ref(),
                    _ => return Err(PostAlonzo(UnsupportedPlutusLanguage)),
                },
                _ => return Err(PostAlonzo(UnsupportedPlutusLanguage)),
            };
            bytes = add(bytes, raw.len() as u64)?;
            let mut payload = vec![3];
            payload.extend_from_slice(raw);
            available.insert(Hasher::<224>::hash(&payload));
        }
    }
    if bytes > u64::from(p.max_ref_script_size_per_tx) {
        return Err(DijkstraReferenceScriptsTooLarge);
    }
    if scripts.values().any(|x| !available.contains(x)) {
        return Err(PostAlonzo(ScriptWitnessMissing));
    }
    let redeemers = w.redeemer.as_ref().ok_or(PostAlonzo(RedeemerMissing))?;
    // BTreeMap decoding could hide duplicate pointers. Inspect original map first.
    let raw = encode(redeemers)?;
    let mut decoder = minicbor::Decoder::new(&raw);
    let mut pointers = HashSet::new();
    for entry in decoder
        .map_iter::<RedeemersKey, RedeemersValue>()
        .map_err(|_| PostAlonzo(ScriptIntegrityHash))?
    {
        let (key, _) = entry.map_err(|_| PostAlonzo(ScriptIntegrityHash))?;
        if !pointers.insert((key.tag as u8, key.index)) {
            return Err(DijkstraUnsupported("duplicate redeemer pointers"));
        }
    }
    for index in scripts.keys() {
        if !redeemers.contains_key(&RedeemersKey {
            tag: RedeemerTag::Cert,
            index: *index,
        }) {
            return Err(PostAlonzo(RedeemerMissing));
        }
    }
    let mut mem = 0;
    let mut steps = 0;
    for (key, value) in redeemers.iter() {
        if key.tag != RedeemerTag::Cert || !scripts.contains_key(&key.index) {
            return Err(PostAlonzo(UnneededRedeemer));
        }
        mem = add(mem, value.ex_units.mem)?;
        steps = add(steps, value.ex_units.steps)?;
    }
    if mem > p.max_tx_ex_units.mem || steps > p.max_tx_ex_units.steps {
        return Err(PostAlonzo(TxExUnitsExceeded));
    }
    // Dijkstra retains Alonzo's memoized redeemer bytes and Conway's V3 language
    // view encoding. No datum set is admitted by this subset.
    let mut integrity = raw;
    integrity.extend(encode(LanguageViews(BTreeMap::from([(
        2,
        p.cost_model_v3.clone(),
    )])))?);
    if b.script_data_hash != Some(Hasher::<256>::hash(&integrity)) {
        return Err(PostAlonzo(ScriptIntegrityHash));
    }
    let collateral = b.collateral.as_ref().ok_or(PostAlonzo(CollateralMissing))?;
    if collateral.is_empty() {
        return Err(PostAlonzo(CollateralMissing));
    }
    if collateral.len() > p.max_collateral_inputs as usize {
        return Err(PostAlonzo(TooManyCollaterals));
    }
    let mut collateral_ids = Spent::new();
    let mut total = 0;
    for input in collateral.iter() {
        if !collateral_ids.insert((input.transaction_id, input.index)) {
            return Err(DijkstraUnsupported("duplicate collateral inputs"));
        }
        let output = utxos
            .get(&MultiEraInput::from_alonzo_compatible(input))
            .ok_or(PostAlonzo(CollateralNotInUTxO))?;
        let (coin, key) = key_coin(output)?;
        keys.insert(key);
        total = add(total, coin)?;
    }
    let returned = match &b.collateral_return {
        Some(output) => check_outputs(std::slice::from_ref(output), pp, &network)?,
        None => 0,
    };
    let paid = total
        .checked_sub(returned)
        .ok_or(PostAlonzo(NegativeValue))?;
    if b.total_collateral.is_some_and(|x| x != paid) {
        return Err(PostAlonzo(CollateralAnnotation));
    }
    if u128::from(paid) * 100 < u128::from(b.fee) * u128::from(p.collateral_percentage) {
        return Err(PostAlonzo(CollateralMinLovelace));
    }
    let execution = fraction_add(
        fraction_scale(price(&p.execution_costs.mem_price)?, mem)?,
        fraction_scale(price(&p.execution_costs.step_price)?, steps)?,
    )?;
    let execution_fee = execution.0 / execution.1 + u128::from(execution.0 % execution.1 != 0);
    add(
        u64::try_from(execution_fee).map_err(|_| PostAlonzo(NegativeValue))?,
        reference_fee(bytes, p)?,
    )
}

// Exact nonnegative arithmetic: execution fees round up once; the total tiered
// reference fee rounds down once. Floating point would change boundary results.
type Fraction = (u128, u128);
fn price(x: &RationalNumber) -> Result<Fraction, ValidationError> {
    if x.denominator == 0 {
        return Err(DijkstraMissingParameters("nonzero price denominator"));
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
fn reference_fee(mut bytes: u64, p: &DijkstraPlutusParams) -> Result<u64, ValidationError> {
    if p.ref_script_cost_stride == 0 {
        return Err(DijkstraMissingParameters("reference fee stride"));
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
