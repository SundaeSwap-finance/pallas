//! Native protocol-12 phase one for key-authorized ADA transfers.
//!
//! See test_data/musashi-phase1/README.md for the pinned ledger and explicit subset.
//! Stateful and script features fail closed; no Conway transaction is constructed.
use crate::utils::{
    DijkstraProtParams,
    PostAlonzoError::*,
    UTxOs, ValidationError,
    ValidationError::{DijkstraCertificateStateUnavailable, DijkstraUnsupported, PostAlonzo},
    ValidationResult, verify_signature,
};
use pallas_addresses::{Address, ShelleyDelegationPart, ShelleyPaymentPart};
use pallas_codec::{minicbor, utils::Nullable};
use pallas_crypto::hash::Hasher;
use pallas_primitives::dijkstra::{BlockTransaction, TransactionOutput};
use pallas_traverse::{MultiEraInput, MultiEraOutput};
use std::collections::HashSet;

/// Validate the supported native transfer subset. No certificate/account state is
/// assumed: any feature requiring it returns an explicit unsupported-state error.
pub fn validate_dijkstra_tx(
    tx: &BlockTransaction<'_>,
    utxos: &UTxOs<'_>,
    pp: &DijkstraProtParams,
    block_slot: &u64,
    network_id: &u8,
) -> ValidationResult {
    if pp.protocol_version != (12, 0) {
        return Err(DijkstraUnsupported("protocol version (requires 12.0)"));
    }
    check_supported(tx)?;
    let body = &tx.transaction_body;
    if body.inputs.is_empty() {
        return Err(PostAlonzo(TxInsEmpty));
    }
    if body
        .validity_interval_start
        .is_some_and(|lo| *block_slot < lo)
    {
        return Err(PostAlonzo(BlockPrecedesValInt));
    }
    // Allegra inInterval, inherited by Dijkstra: the upper bound is exclusive.
    if body.ttl.is_some_and(|hi| *block_slot >= hi) {
        return Err(PostAlonzo(BlockExceedsValInt));
    }
    if body.network_id.is_some_and(|n| u8::from(n) != *network_id) {
        return Err(PostAlonzo(TxWrongNetworkID));
    }
    // Dijkstra Tx.hs: [body, witnesses, auxiliary/null], never the block flag.
    let size = minicbor::to_vec(tx.to_mempool_transaction())
        .map_err(|_| PostAlonzo(UnknownTxSize))?
        .len();
    if size > pp.max_transaction_size as usize {
        return Err(PostAlonzo(MaxTxSizeExceeded));
    }
    let fee = u64::from(pp.minfee_a)
        .checked_mul(size as u64)
        .and_then(|x| x.checked_add(u64::from(pp.minfee_b)))
        .ok_or(PostAlonzo(NegativeValue))?;
    if body.fee < fee {
        return Err(PostAlonzo(FeeBelowMin));
    }

    let mut consumed = 0u64;
    let mut required_keys = HashSet::new();
    let mut inputs = HashSet::new();
    for input in body.inputs.iter() {
        if !inputs.insert((input.transaction_id, input.index)) {
            return Err(DijkstraUnsupported("duplicate inputs"));
        }
        let output = utxos
            .get(&MultiEraInput::from_alonzo_compatible(input))
            .ok_or(PostAlonzo(InputNotInUTxO))?;
        let (coin, key) = key_coin(output)?;
        consumed = consumed
            .checked_add(coin)
            .ok_or(PostAlonzo(NegativeValue))?;
        required_keys.insert(key);
    }
    let mut produced = body.fee;
    for output in body.outputs.iter() {
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
        produced = produced
            .checked_add(coin)
            .ok_or(PostAlonzo(NegativeValue))?;
    }
    if consumed != produced {
        return Err(PostAlonzo(PreservationOfValue));
    }
    let hash = Hasher::<256>::hash(&minicbor::to_vec(body).map_err(|_| PostAlonzo(UnknownTxSize))?);
    let witnesses = tx
        .transaction_witness_set
        .vkeywitness
        .as_ref()
        .map(|x| x.as_slice())
        .unwrap_or_default();
    for witness in witnesses {
        // The shared verifier expects fixed widths. Reject malformed lengths before it.
        if witness.vkey.len() != 32
            || witness.signature.len() != 64
            || !verify_signature(witness, hash.as_ref())
        {
            return Err(PostAlonzo(VKWrongSignature));
        }
        required_keys.remove(&Hasher::<224>::hash(&witness.vkey));
    }
    if !required_keys.is_empty() {
        return Err(PostAlonzo(VKWitnessMissing));
    }
    Ok(())
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
    if b.certificates.is_some() {
        return Err(DijkstraCertificateStateUnavailable);
    }
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
    if b.mint.is_some()
        || b.script_data_hash.is_some()
        || b.collateral.is_some()
        || b.collateral_return.is_some()
        || b.total_collateral.is_some()
        || b.reference_inputs.is_some()
    {
        return Err(DijkstraUnsupported(
            "scripts, mint, collateral or reference inputs",
        ));
    }
    if b.auxiliary_data_hash.is_some() || !matches!(tx.auxiliary_data, Nullable::Null) {
        return Err(DijkstraUnsupported("auxiliary data"));
    }
    let w = &tx.transaction_witness_set;
    if w.native_script.is_some()
        || w.bootstrap_witness.is_some()
        || w.plutus_v1_script.is_some()
        || w.plutus_v2_script.is_some()
        || w.plutus_v3_script.is_some()
        || w.plutus_data.is_some()
        || w.redeemer.is_some()
    {
        return Err(DijkstraUnsupported("non-vkey witnesses"));
    }
    // Decode derives may ignore unknown map keys. Inspect retained CBOR too, so
    // unfamiliar features (including witness key 8 / V4) cannot disappear.
    check_map_keys(
        &minicbor::to_vec(b).map_err(|_| PostAlonzo(UnknownTxSize))?,
        &[0, 1, 2, 3, 8, 15],
        "body fields",
    )?;
    check_map_keys(
        &minicbor::to_vec(w).map_err(|_| PostAlonzo(UnknownTxSize))?,
        &[0],
        "witness fields",
    )
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
