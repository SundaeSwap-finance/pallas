//! Native protocol-12 phase one for transfers, registrations, key batches and Plutus V3.
//! Rules and evidence boundaries: test_data/musashi-dijkstra-validation/README.md.
use crate::utils::{
    CertState, DijkstraPlutusParams, DijkstraProtParams, DijkstraRegistrationState,
    PostAlonzoError::*, UTxOs, ValidationError, ValidationError::*, ValidationResult,
    add_fee_and_stake_deposits, verify_signature,
};
use pallas_addresses::{Address, ShelleyDelegationPart, ShelleyPaymentPart, StakePayload};
use pallas_codec::{
    minicbor,
    utils::{KeepRaw, Nullable},
};
use pallas_crypto::hash::{Hash, Hasher};
use pallas_primitives::{conway::LanguageViews, dijkstra::*};
use pallas_traverse::{
    ComputeHash, MultiEraInput, MultiEraOutput, MultiEraScriptRef, MultiEraTx, OriginalHash,
};
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
    for sub in b.sub_transactions.iter().flatten() {
        check_sub_supported(sub)?;
    }
    let mut state = cert_state.dijkstra_registrations.clone();
    let mut keys = guard_keys(b.guards.as_ref())?;
    let top_guards = keys.clone();
    check_required_guards(b.required_top_level_guards.as_ref(), &top_guards)?;
    let mut scripts = BTreeMap::new();
    let mut accounts = cert_state.dijkstra_account_balances.clone();
    let mut withdrawals = 0;
    let mut ordered_withdrawals: Vec<_> = b.withdrawals.iter().flat_map(|x| x.iter()).collect();
    // Ledger RewardAccount ordering: network, Script credential before Key, hash.
    ordered_withdrawals.sort_by_key(|(raw, _)| {
        (
            raw.first().map(|x| x & 15),
            raw.first().map(|x| 15 - (x >> 4)),
            raw.get(1..),
        )
    });
    for (index, (raw_address, amount)) in ordered_withdrawals.into_iter().enumerate() {
        let Address::Stake(address) =
            Address::from_bytes(raw_address).map_err(|_| PostAlonzo(AddressDecoding))?
        else {
            return Err(PostAlonzo(AddressDecoding));
        };
        if address.network().value() != *network_id {
            return Err(PostAlonzo(TxWrongNetworkID));
        }
        let credential = match address.payload() {
            StakePayload::Stake(key) => {
                keys.insert(*key);
                StakeCredential::AddrKeyhash(*key)
            }
            StakePayload::Script(hash) => {
                scripts.insert(
                    RedeemersKey {
                        tag: RedeemerTag::Reward,
                        index: index as u32,
                    },
                    *hash,
                );
                StakeCredential::ScriptHash(*hash)
            }
        };
        let balance = accounts
            .get_mut(&credential)
            .ok_or_else(|| DijkstraAccountStateUnavailable(hex::encode(raw_address.as_slice())))?;
        let Some(balance) = balance else {
            return Err(DijkstraInvalidWithdrawal("unregistered account"));
        };
        // ENTITIES uses draining withdrawals in legacy mode (any V1-V3 script).
        // Without Plutus, Dijkstra permits partial withdrawals.
        if *amount > *balance {
            return Err(DijkstraInvalidWithdrawal(
                "amount does not match available account balance",
            ));
        }
        *balance -= *amount;
        withdrawals = add(withdrawals, *amount)?;
    }
    for (index, input) in b
        .inputs
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .enumerate()
    {
        let output = utxos
            .get(&MultiEraInput::from_alonzo_compatible(input))
            .ok_or(PostAlonzo(InputNotInUTxO))?;
        if let ShelleyPaymentPart::Script(hash) = payment(output)? {
            scripts.insert(
                RedeemersKey {
                    tag: RedeemerTag::Spend,
                    index: index as u32,
                },
                hash,
            );
        }
    }
    for (index, (hash, assets)) in b.mint.iter().flat_map(|x| x.iter()).enumerate() {
        if assets.is_empty() || assets.keys().any(|x| x.len() > 32) {
            return Err(PostAlonzo(NegativeValue));
        }
        scripts.insert(
            RedeemersKey {
                tag: RedeemerTag::Mint,
                index: index as u32,
            },
            *hash,
        );
    }
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
                scripts.insert(
                    RedeemersKey {
                        tag: RedeemerTag::Cert,
                        index: index as u32,
                    },
                    *hash,
                );
            }
        }
        if accounts
            .get(credential)
            .is_some_and(|balance| balance.is_some())
        {
            return Err(DijkstraInvalidCertificate("inconsistent account prestate"));
        }
        accounts.insert(credential.clone(), Some(0));
        state.insert(credential.clone(), DijkstraRegistrationState::Registered);
    }
    if !scripts.is_empty() && b.sub_transactions.is_some() {
        return Err(DijkstraUnsupported("scripted or stateful batch"));
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
    let (script_fee, has_plutus) = check_scripts(tx, utxos, pp, &scripts, &mut keys, *network_id)?;
    // Native scripts do not activate legacy Plutus withdrawal rules.
    if has_plutus {
        if b.required_top_level_guards
            .as_ref()
            .is_some_and(|x| !x.is_empty())
        {
            return Err(DijkstraUnsupported("Plutus required top-level guards"));
        }
        for (raw, _) in b.withdrawals.iter().flat_map(|x| x.iter()) {
            let Address::Stake(address) =
                Address::from_bytes(raw).map_err(|_| PostAlonzo(AddressDecoding))?
            else {
                unreachable!()
            };
            let credential = match address.payload() {
                StakePayload::Script(h) => StakeCredential::ScriptHash(*h),
                StakePayload::Stake(h) => StakeCredential::AddrKeyhash(*h),
            };
            if accounts.get(&credential) != Some(&Some(0)) {
                return Err(DijkstraInvalidWithdrawal(
                    "legacy Plutus withdrawals must drain the account",
                ));
            }
        }
    }
    let mut minimum_fee = u64::from(pp.minfee_a)
        .checked_mul(size as u64)
        .and_then(|x| x.checked_add(u64::from(pp.minfee_b)))
        .ok_or(PostAlonzo(NegativeValue))?;
    minimum_fee = add(minimum_fee, script_fee)?;
    if b.fee < minimum_fee {
        return Err(PostAlonzo(FeeBelowMin));
    }
    let mut spent = Spent::new();
    let mut consumed = withdrawals;
    let mut output_coin = 0;
    for sub in b.sub_transactions.iter().flat_map(|x| x.iter()) {
        check_sub_supported(sub)?;
        let sb = &sub.sub_transaction_body;
        for output in sb.outputs.iter() {
            key_coin(&MultiEraOutput::from_dijkstra(output))?;
        }
        check_required_guards(sb.required_top_level_guards.as_ref(), &top_guards)?;
        check_interval(
            sb.validity_interval_start,
            sb.ttl,
            sb.network_id,
            *block_slot,
            *network_id,
        )?;
        let mut sub_keys = guard_keys(sb.guards.as_ref())?;
        consumed = add(
            consumed,
            check_inputs(&sb.inputs, utxos, &mut spent, &mut sub_keys, false)?,
        )?;
        output_coin = add(output_coin, check_outputs(&sb.outputs, pp, network_id)?)?;
        check_signatures(
            &sub.transaction_witness_set,
            &encode(&sub.sub_transaction_body)?,
            sub_keys,
        )?;
    }
    consumed = add(
        consumed,
        check_inputs(&b.inputs, utxos, &mut spent, &mut keys, true)?,
    )?;
    output_coin = add(output_coin, check_outputs(&b.outputs, pp, network_id)?)?;
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
    check_assets(tx, utxos)?;
    check_signatures(&tx.transaction_witness_set, &encode(b)?, keys)?;
    cert_state.dijkstra_registrations = state;
    cert_state.dijkstra_account_balances = accounts;
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
fn guard_keys(guards: Option<&Guards>) -> Result<Keys, ValidationError> {
    let mut keys = Keys::new();
    match guards {
        None => (),
        Some(Guards::AddrKeyhashes(xs)) => keys.extend(xs.iter().copied()),
        Some(Guards::Credentials(xs)) => {
            for x in xs.iter() {
                let StakeCredential::AddrKeyhash(key) = x else {
                    return Err(DijkstraUnsupported("script guards"));
                };
                keys.insert(*key);
            }
        }
    }
    Ok(keys)
}
fn check_required_guards(
    required: Option<&RequiredTopLevelGuards>,
    top: &Keys,
) -> ValidationResult {
    for (credential, datum) in required.into_iter().flatten() {
        let StakeCredential::AddrKeyhash(key) = credential else {
            return Err(DijkstraUnsupported("script guards"));
        };
        if !matches!(datum, Nullable::Null) {
            return Err(DijkstraUnsupported("guard datum"));
        }
        if !top.contains(key) {
            return Err(PostAlonzo(ReqSignerMissing));
        }
    }
    Ok(())
}
fn check_inputs(
    inputs: &[TransactionInput],
    utxos: &UTxOs<'_>,
    spent: &mut Spent,
    keys: &mut Keys,
    native: bool,
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
        // SUBUTXO requires membership in both original and evolving UTxO.
        let output = utxos
            .get(&MultiEraInput::from_alonzo_compatible(input))
            .ok_or(PostAlonzo(InputNotInUTxO))?;
        if !spent.insert(id) {
            return Err(DijkstraInputAlreadySpent);
        }
        if native {
            total = add(total, output.value().coin())?;
            if let ShelleyPaymentPart::Key(key) = payment(output)? {
                keys.insert(key);
            }
        } else {
            let (coin, key) = key_coin(output)?;
            total = add(total, coin)?;
            keys.insert(key);
        }
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
        let coin = view.value().coin();
        payment(&view)?;
        if let Some(script) = view.multi_era_script_ref() {
            check_new_script(&script)?;
        }
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
                check_map_keys(&output_bytes, &[0, 1, 2, 3], "output fields")?;
            }
            TransactionOutput::Legacy(_) => {
                let mut decoder = minicbor::Decoder::new(&output_bytes);
                if !matches!(
                    decoder
                        .array()
                        .map_err(|_| DijkstraUnsupported("output fields"))?,
                    Some(2 | 3)
                ) {
                    return Err(DijkstraUnsupported("output fields"));
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
    if b.certificates.is_some() && b.sub_transactions.is_some() {
        return Err(DijkstraUnsupported("registration with subtransactions"));
    }
    if b.direct_deposits.is_some()
        || b.account_balance_intervals.is_some()
        || b.starting_account_balance_intervals.is_some()
        || b.voting_procedures.is_some()
        || b.proposal_procedures.is_some()
        || b.treasury_value.is_some()
        || b.donation.is_some()
    {
        return Err(DijkstraUnsupported("account or governance state"));
    }
    check_auxiliary(b.auxiliary_data_hash, &tx.auxiliary_data)?;
    if b.sub_transactions.is_some()
        && (b.mint.is_some() || b.withdrawals.is_some() || b.script_data_hash.is_some())
    {
        return Err(DijkstraUnsupported("scripted or stateful batch"));
    }
    let mut allowed = vec![0, 1, 2, 3, 8, 15];
    for (key, present) in [
        (4, b.certificates.is_some()),
        (5, b.withdrawals.is_some()),
        (7, b.auxiliary_data_hash.is_some()),
        (9, b.mint.is_some()),
        (11, b.script_data_hash.is_some()),
        (13, b.collateral.is_some()),
        (14, b.guards.is_some()),
        (16, b.collateral_return.is_some()),
        (17, b.total_collateral.is_some()),
        (18, b.reference_inputs.is_some()),
        (23, b.sub_transactions.is_some()),
        (24, b.required_top_level_guards.is_some()),
    ] {
        if present {
            allowed.push(key);
        }
    }
    let raw = encode(b)?;
    check_map_keys(&raw, &allowed, "body fields")?;
    let fields: pallas_codec::utils::KeyValuePairs<u64, pallas_codec::utils::AnyCbor> =
        minicbor::decode(&raw).map_err(|_| DijkstraUnsupported("body fields"))?;
    for (key, value) in fields.iter() {
        if *key == 9 {
            check_asset_encoding(value, true)?;
        }
        if *key == 5 {
            let withdrawals: pallas_codec::utils::KeyValuePairs<Bytes, u64> =
                minicbor::decode(value).map_err(|_| DijkstraInvalidWithdrawal("encoding"))?;
            let mut seen = HashSet::new();
            if withdrawals.iter().any(|(a, _)| !seen.insert(a.to_vec())) {
                return Err(DijkstraInvalidWithdrawal("duplicate account"));
            }
        }
    }
    check_witness_fields(&tx.transaction_witness_set, true)
}
fn check_witness_fields(w: &KeepRaw<'_, WitnessSet<'_>>, redeemers: bool) -> ValidationResult {
    if (!redeemers && w.native_script.is_some())
        || w.bootstrap_witness.is_some()
        || w.plutus_v1_script.is_some()
        || w.plutus_v2_script.is_some()
        || (!redeemers
            && (w.redeemer.is_some() || w.plutus_v3_script.is_some() || w.plutus_data.is_some()))
    {
        return Err(DijkstraUnsupported("non-vkey witnesses"));
    }
    let allowed = if redeemers {
        &[0, 1, 4, 5, 7][..]
    } else {
        &[0][..]
    };
    check_map_keys(&encode(w)?, allowed, "witness fields")
}
fn check_sub_supported(tx: &SubTransaction<'_>) -> ValidationResult {
    let b = &tx.sub_transaction_body;
    if b.certificates.is_some()
        || b.withdrawals.is_some()
        || b.mint.is_some()
        || b.script_data_hash.is_some()
        || b.reference_inputs.is_some()
        || b.voting_procedures.is_some()
        || b.proposal_procedures.is_some()
        || b.treasury_value.is_some()
        || b.donation.is_some()
        || b.direct_deposits.is_some()
        || b.account_balance_intervals.is_some()
    {
        return Err(DijkstraUnsupported("stateful or scripted subtransaction"));
    }
    if b.auxiliary_data_hash.is_some() || !matches!(tx.auxiliary_data, Nullable::Null) {
        return Err(DijkstraUnsupported("auxiliary data"));
    }
    let mut allowed = vec![0, 1, 3, 8, 15];
    if b.guards.is_some() {
        allowed.push(14);
    }
    if b.required_top_level_guards.is_some() {
        allowed.push(24);
    }
    check_map_keys(&encode(b)?, &allowed, "subtransaction body fields")?;
    check_witness_fields(&tx.transaction_witness_set, false)
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
    scripts: &BTreeMap<RedeemersKey, Hash<28>>,
    keys: &mut Keys,
    network: u8,
) -> Result<(u64, bool), ValidationError> {
    let b = &tx.transaction_body;
    let w = &tx.transaction_witness_set;
    let mut natives = BTreeMap::new();
    let mut available = HashSet::new();
    let mut reference_scripts = HashSet::new();
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
            // Reference UTxOs are already-admitted ledger outputs. No new script
            // bytes enter the ledger in this subset, and phase two is separate.
            if let Some(native) = script.native_script() {
                let raw = native.encode();
                let decoded: NativeScript =
                    minicbor::decode(&raw).map_err(|_| PostAlonzo(UnsupportedNativeScript))?;
                crate::utils::dijkstra_native::check_supported(&decoded)?;
                bytes = add(bytes, raw.len() as u64)?;
                reference_scripts.insert(script.hash());
                natives.insert(script.hash(), decoded);
                continue;
            }
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
            let hash = Hasher::<224>::hash(&payload);
            available.insert(hash);
            reference_scripts.insert(hash);
        }
    }
    for script in w.native_script.iter().flat_map(|x| x.iter()) {
        let hash = script.original_hash();
        if !scripts.values().any(|x| *x == hash) || reference_scripts.contains(&hash) {
            return Err(PostAlonzo(UnneededNativeScript));
        }
        natives.insert(hash, (**script).clone());
    }
    let witness_keys = w
        .vkeywitness
        .iter()
        .flat_map(|x| x.iter())
        .map(|w| Hasher::<224>::hash(&w.vkey))
        .collect();
    for (hash, script) in &natives {
        crate::utils::dijkstra_native::check_supported(script)?;
        if scripts.values().any(|x| x == hash)
            && !crate::utils::dijkstra_native::evaluate(
                script,
                &witness_keys,
                b.validity_interval_start,
                b.ttl,
            )
        {
            return Err(PostAlonzo(NativeScriptDenial));
        }
    }
    // Retain original purpose indices: native scripts need no redeemer or datum.
    let scripts: BTreeMap<_, _> = scripts
        .iter()
        .filter(|(_, hash)| !natives.contains_key(hash))
        .map(|(key, hash)| (key.clone(), *hash))
        .collect();
    if !scripts.is_empty() && b.ttl.is_some() {
        return Err(DijkstraUnsupported(
            "Plutus validity upper bound requires forecast state",
        ));
    }
    for script in w.plutus_v3_script.iter().flat_map(|x| x.iter()) {
        let hash = script.compute_hash();
        if !scripts.values().any(|x| *x == hash) || reference_scripts.contains(&hash) {
            return Err(PostAlonzo(UnneededPlutusV3Script));
        }
        well_formed_v3(script.as_ref())?;
        available.insert(hash);
    }
    if scripts.values().any(|x| !available.contains(x)) {
        return Err(PostAlonzo(ScriptWitnessMissing));
    }
    check_datums(tx, utxos, &scripts)?;
    if scripts.is_empty() {
        if b.collateral.is_some() || b.collateral_return.is_some() || b.total_collateral.is_some() {
            return Err(DijkstraUnsupported("collateral without Plutus"));
        }
        if w.redeemer.as_ref().is_some_and(|x| !x.is_empty()) {
            return Err(PostAlonzo(UnneededRedeemer));
        }
        // An empty redeemer map and language view still participate when datums exist.
        check_integrity(tx, None)?;
        if bytes == 0 {
            return Ok((0, false));
        }
        let p = pp
            .plutus
            .as_ref()
            .ok_or(DijkstraMissingParameters("reference script fee parameters"))?;
        if bytes > u64::from(p.max_ref_script_size_per_tx) {
            return Err(DijkstraReferenceScriptsTooLarge);
        }
        return Ok((reference_fee(bytes, p)?, false));
    }
    let p = pp
        .plutus
        .as_ref()
        .ok_or(DijkstraMissingParameters("Plutus parameters"))?;
    if p.cost_model_v3.len() != 350 {
        return Err(DijkstraMissingParameters(
            "protocol-12 V3 cost model requires 350 entries",
        ));
    }
    if bytes > u64::from(p.max_ref_script_size_per_tx) {
        return Err(DijkstraReferenceScriptsTooLarge);
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
        if !redeemers.contains_key(index) {
            return Err(PostAlonzo(RedeemerMissing));
        }
    }
    let mut mem = 0;
    let mut steps = 0;
    for (key, value) in redeemers.iter() {
        if !scripts.contains_key(key) {
            return Err(PostAlonzo(UnneededRedeemer));
        }
        mem = add(mem, value.ex_units.mem)?;
        steps = add(steps, value.ex_units.steps)?;
    }
    if mem > p.max_tx_ex_units.mem || steps > p.max_tx_ex_units.steps {
        return Err(PostAlonzo(TxExUnitsExceeded));
    }
    check_integrity(tx, Some(&p.cost_model_v3))?;
    let collateral = b.collateral.as_ref().ok_or(PostAlonzo(CollateralMissing))?;
    if collateral.is_empty() {
        return Err(PostAlonzo(CollateralMissing));
    }
    if collateral.len() > p.max_collateral_inputs as usize {
        return Err(PostAlonzo(TooManyCollaterals));
    }
    let mut collateral_ids = Spent::new();
    let mut collateral_assets = BTreeMap::new();
    let mut total = 0;
    for input in collateral.iter() {
        if !collateral_ids.insert((input.transaction_id, input.index)) {
            return Err(DijkstraUnsupported("duplicate collateral inputs"));
        }
        let output = utxos
            .get(&MultiEraInput::from_alonzo_compatible(input))
            .ok_or(PostAlonzo(CollateralNotInUTxO))?;
        let ShelleyPaymentPart::Key(key) = payment(output)? else {
            return Err(PostAlonzo(CollateralNotVKeyLocked));
        };
        keys.insert(key);
        total = add(total, output.value().coin())?;
        accumulate_assets(&mut collateral_assets, output, 1)?;
    }
    let returned = match &b.collateral_return {
        Some(output) => check_outputs(std::slice::from_ref(output), pp, &network)?,
        None => 0,
    };
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
    .map(|fee| (fee, true))
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

fn payment(output: &MultiEraOutput<'_>) -> Result<ShelleyPaymentPart, ValidationError> {
    let Address::Shelley(address) = output.address().map_err(|_| PostAlonzo(AddressDecoding))?
    else {
        return Err(DijkstraUnsupported("bootstrap or reward address"));
    };
    if matches!(address.delegation(), ShelleyDelegationPart::Pointer(_)) {
        return Err(DijkstraUnsupported("pointer address"));
    }
    Ok(address.payment().clone())
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
                return Err(DijkstraUnsupported("auxiliary scripts"));
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
                return Err(DijkstraUnsupported("auxiliary scripts"));
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
            check_map_keys(&raw[decoder.position()..], &[0], "auxiliary fields")?;
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
fn check_assets(tx: &BlockTransaction<'_>, utxos: &UTxOs<'_>) -> ValidationResult {
    let b = &tx.transaction_body;
    let mut balance = AssetBalance::new();
    for input in b.inputs.iter().chain(
        b.sub_transactions
            .iter()
            .flatten()
            .flat_map(|s| s.sub_transaction_body.inputs.iter()),
    ) {
        let output = utxos
            .get(&MultiEraInput::from_alonzo_compatible(input))
            .ok_or(PostAlonzo(InputNotInUTxO))?;
        accumulate_assets(&mut balance, output, 1)?;
    }
    for output in b.outputs.iter().chain(
        b.sub_transactions
            .iter()
            .flatten()
            .flat_map(|s| s.sub_transaction_body.outputs.iter()),
    ) {
        accumulate_assets(&mut balance, &MultiEraOutput::from_dijkstra(output), -1)?;
    }
    for (policy, assets) in b.mint.iter().flat_map(|m| m.iter()) {
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

fn check_datums(
    tx: &BlockTransaction<'_>,
    utxos: &UTxOs<'_>,
    scripts: &BTreeMap<RedeemersKey, Hash<28>>,
) -> ValidationResult {
    let mut allowed = HashSet::new();
    let mut required = HashSet::new();
    let b = &tx.transaction_body;
    for (index, input) in b
        .inputs
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .enumerate()
    {
        if scripts.contains_key(&RedeemersKey {
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
                // CIP-0069: V3 may spend an output without a datum. A present
                // hash still requires its matching witness datum.
                None => (),
            }
        }
    }
    for output in b.outputs.iter().map(MultiEraOutput::from_dijkstra) {
        if let Some(DatumOption::Hash(hash)) = output.datum() {
            allowed.insert(hash);
        }
    }
    for input in b.reference_inputs.iter().flatten() {
        let output = utxos
            .get(&MultiEraInput::from_alonzo_compatible(input))
            .ok_or(PostAlonzo(ReferenceInputNotInUTxO))?;
        if let Some(DatumOption::Hash(hash)) = output.datum() {
            allowed.insert(hash);
        }
    }
    for datum in tx
        .transaction_witness_set
        .plutus_data
        .iter()
        .flat_map(|x| x.iter())
    {
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

fn check_integrity(tx: &BlockTransaction<'_>, model: Option<&Vec<i64>>) -> ValidationResult {
    let w = &tx.transaction_witness_set;
    let has_data = w.plutus_data.as_ref().is_some_and(|x| !x.is_empty());
    let has_redeemers = w.redeemer.as_ref().is_some_and(|x| !x.is_empty());
    let expected = if model.is_none() && !has_data && !has_redeemers {
        None
    } else {
        let mut bytes = match &w.redeemer {
            Some(r) => encode(r)?,
            None => vec![0xa0],
        };
        if has_data {
            bytes.extend(encode(w.plutus_data.as_ref().unwrap())?);
        }
        let views = model
            .map(|m| BTreeMap::from([(2, m.clone())]))
            .unwrap_or_default();
        bytes.extend(encode(LanguageViews(views))?);
        Some(Hasher::<256>::hash(&bytes))
    };
    if tx.transaction_body.script_data_hash != expected {
        return Err(PostAlonzo(ScriptIntegrityHash));
    }
    Ok(())
}

fn check_new_script(script: &MultiEraScriptRef<'_>) -> ValidationResult {
    match script {
        MultiEraScriptRef::Dijkstra(s) => match s.as_ref() {
            ScriptRef::NativeScript(s) => crate::utils::dijkstra_native::check_supported(s),
            ScriptRef::PlutusV3Script(s) => well_formed_v3(s.as_ref()),
            _ => Err(PostAlonzo(UnsupportedPlutusLanguage)),
        },
        _ => Err(PostAlonzo(UnsupportedPlutusLanguage)),
    }
}
fn well_formed_v3(script: &[u8]) -> ValidationResult {
    #[cfg(feature = "phase2")]
    {
        crate::phase2::native_evaluator::check_v3_script(script)
            .map_err(|_| DijkstraMalformedScript)
    }
    #[cfg(not(feature = "phase2"))]
    {
        let _ = script;
        Err(DijkstraUnsupported(
            "new Plutus script validation requires phase2 feature",
        ))
    }
}

// Ledger v12 Mary.Value requires nonempty policy/name maps, nonzero quantities,
// <=32-byte names and duplicate-free maps even in the legacy TxOut representation.
fn check_asset_encoding(raw: &[u8], mint: bool) -> ValidationResult {
    use pallas_codec::utils::KeyValuePairs;
    let assets: KeyValuePairs<Hash<28>, KeyValuePairs<Bytes, minicbor::data::Int>> =
        minicbor::decode(raw).map_err(|_| PostAlonzo(NegativeValue))?;
    let mut policies = HashSet::new();
    if assets.is_empty() {
        return Err(PostAlonzo(NegativeValue));
    }
    for (policy, names) in assets.iter() {
        if !policies.insert(*policy) || names.is_empty() {
            return Err(PostAlonzo(NegativeValue));
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
                return Err(PostAlonzo(NegativeValue));
            }
        }
    }
    Ok(())
}
fn check_output_value_encoding(raw: &[u8]) -> ValidationResult {
    use pallas_codec::utils::{AnyCbor, KeyValuePairs};
    let mut decoder = minicbor::Decoder::new(raw);
    let value = match decoder.datatype().map_err(|_| PostAlonzo(NegativeValue))? {
        minicbor::data::Type::Map | minicbor::data::Type::MapIndef => {
            let fields: KeyValuePairs<u64, AnyCbor> =
                decoder.decode().map_err(|_| PostAlonzo(NegativeValue))?;
            fields
                .iter()
                .find(|(k, _)| *k == 1)
                .map(|(_, v)| v.clone())
                .ok_or(PostAlonzo(NegativeValue))?
        }
        _ => {
            decoder.array().map_err(|_| PostAlonzo(NegativeValue))?;
            decoder.skip().map_err(|_| PostAlonzo(NegativeValue))?;
            decoder
                .decode::<AnyCbor>()
                .map_err(|_| PostAlonzo(NegativeValue))?
        }
    };
    let mut d = minicbor::Decoder::new(&value);
    if matches!(
        d.datatype(),
        Ok(minicbor::data::Type::Array | minicbor::data::Type::ArrayIndef)
    ) {
        let values: Vec<AnyCbor> = d.decode().map_err(|_| PostAlonzo(NegativeValue))?;
        if values.len() != 2 {
            return Err(PostAlonzo(NegativeValue));
        }
        check_asset_encoding(&values[1], false)?;
    }
    Ok(())
}
