//! Phase one verdicts on the batches of ledger conformance records, and on batches changed from them.
use crate::utils::{
    CertState, DijkstraTimeContext, DijkstraTimeError, EraTime, ForecastHorizon,
    MultiEraProtocolParameters, PostAlonzoError, UTxOs, ValidationError, ValidationResult,
};
use pallas_codec::minicbor;
use pallas_crypto::hash::Hasher;
use pallas_primitives::dijkstra as n;
use pallas_traverse::{Era, MultiEraInput, MultiEraOutput, MultiEraTx};

/// The slot every record batch is validated at.
const SLOT: u64 = 5179681;

pub(crate) fn read(record: u32) -> serde_json::Value {
    read_in("dijkstra-plutus-v4", record)
}

/// The fixture of `record` in the test data directory `dir`.
pub(crate) fn read_in(dir: &str, record: u32) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../test_data")
        .join(dir)
        .join(format!("{record}.json"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

pub(crate) fn bytes(value: &serde_json::Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

pub(crate) fn params(fixture: &serde_json::Value) -> MultiEraProtocolParameters {
    let mut pp = super::dijkstra_registration_tests::params().prot_params;
    let MultiEraProtocolParameters::Dijkstra(ref mut p) = pp else {
        unreachable!()
    };
    p.cost_models_for_script_languages.plutus_v4 =
        Some(serde_json::from_value(fixture["plutus_v4"].clone()).unwrap());
    pp
}

/// The encoded inputs and outputs of the UTxO set a record names.
fn pairs(fixture: &serde_json::Value) -> Vec<(Vec<u8>, Vec<u8>)> {
    fixture["utxos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| (bytes(&pair[0]), bytes(&pair[1])))
        .collect()
}

fn time(horizon: ForecastHorizon) -> DijkstraTimeContext {
    let era = EraTime {
        start_slot: 0,
        start_time_ms: 1506203091000,
        slot_length_ms: 1000,
    };
    DijkstraTimeContext::new(vec![era], horizon).unwrap()
}

/// Validates `tx` against the UTxO set `pairs`, with each account the batch registers known as unregistered.
fn check(
    tx: &n::BlockTransaction<'_>,
    pairs: &[(Vec<u8>, Vec<u8>)],
    pp: MultiEraProtocolParameters,
    time: &DijkstraTimeContext,
) -> ValidationResult {
    let utxos: UTxOs = pairs
        .iter()
        .map(|(input, output)| {
            let input: n::TransactionInput = minicbor::decode(input).unwrap();
            (
                MultiEraInput::AlonzoCompatible(Box::new(std::borrow::Cow::Owned(input))),
                MultiEraOutput::decode(Era::Dijkstra, output).unwrap(),
            )
        })
        .collect();
    let mut env = super::dijkstra_registration_tests::params();
    env.prot_params = pp;
    env.block_slot = SLOT;
    let b = &tx.transaction_body;
    let subs = b.sub_transactions.iter().flatten();
    let mut state = CertState::default();
    for certificate in std::iter::once(&b.certificates)
        .chain(subs.map(|x| &x.sub_transaction_body.certificates))
        .flatten()
        .flat_map(|x| x.iter())
    {
        if let n::Certificate::Reg(credential, _) = certificate {
            state.dijkstra.accounts.insert(credential.clone(), None);
        }
    }
    super::validate_tx_with_time(
        &MultiEraTx::from_dijkstra(tx),
        0,
        &env,
        &utxos,
        &mut state,
        time,
    )
}

/// Runs `test` on the batch, UTxO set and parameters of `record`.
fn record(
    record: u32,
    test: impl FnOnce(n::BlockTransaction<'_>, Vec<(Vec<u8>, Vec<u8>)>, MultiEraProtocolParameters),
) {
    let fixture = read(record);
    let raw = bytes(&fixture["tx"]);
    let tx: n::MempoolTransaction = minicbor::decode(&raw).unwrap();
    test(tx.into(), pairs(&fixture), params(&fixture));
}

/// The batch `tx` with its first sub transaction changed by `f`.
fn change_sub<'b>(
    tx: &n::BlockTransaction<'b>,
    f: impl FnOnce(&mut n::SubTransaction<'b>),
) -> n::BlockTransaction<'b> {
    let mut tx = tx.clone();
    let mut body = (*tx.transaction_body).clone();
    let mut subs = body.sub_transactions.clone().unwrap().to_vec();
    f(&mut subs[0]);
    body.sub_transactions = n::NonEmptySet::from_vec(subs);
    tx.transaction_body = body.into();
    tx
}

fn accepts(number: u32) {
    record(number, |tx, pairs, pp| {
        let result = check(&tx, &pairs, pp, &time(ForecastHorizon::Unbounded));
        assert!(result.is_ok(), "record {number}: {result:?}");
    });
}

#[test]
fn phase_one_accepts_a_sub_transaction_running_a_plutus_v4_reference_script() {
    accepts(890);
}

#[test]
#[cfg(feature = "phase2")]
fn phase_one_accepts_a_sub_transaction_witnessing_a_plutus_v4_script() {
    accepts(9820);
}

#[test]
#[cfg(feature = "phase2")]
fn phase_one_accepts_a_plutus_guard_required_with_a_datum() {
    accepts(1344);
}

#[test]
#[cfg(feature = "phase2")]
fn phase_one_refuses_a_plutus_guard_required_with_no_datum() {
    record(1344, |tx, pairs, pp| {
        let mut body = (*tx.transaction_body).clone();
        let mut subs = body.sub_transactions.clone().unwrap().to_vec();
        let mut sub_body = (*subs[0].sub_transaction_body).clone();
        let nulled: Option<n::RequiredTopLevelGuards> =
            sub_body.required_top_level_guards.take().map(|x| {
                x.into_keys()
                    .map(|k| (k, pallas_codec::utils::Nullable::Null))
                    .collect()
            });
        for (top, sub) in [(None, nulled.clone()), (nulled, None)] {
            let mut tx = tx.clone();
            let mut sub_body = sub_body.clone();
            sub_body.required_top_level_guards = sub;
            subs[0].sub_transaction_body = sub_body.into();
            body.sub_transactions = n::NonEmptySet::from_vec(subs.clone());
            body.required_top_level_guards = top;
            tx.transaction_body = body.clone().into();
            let result = check(&tx, &pairs, pp.clone(), &time(ForecastHorizon::Unbounded));
            assert!(
                matches!(result, Err(ValidationError::DijkstraMalformedGuardDatum)),
                "{result:?}"
            );
        }
    });
}

#[test]
fn sub_transaction_redeemers_require_batch_collateral() {
    record(890, |tx, pairs, pp| {
        let mut tx = tx.clone();
        let mut body = (*tx.transaction_body).clone();
        body.collateral = None;
        tx.transaction_body = body.into();
        let result = check(&tx, &pairs, pp, &time(ForecastHorizon::Unbounded));
        assert!(
            matches!(
                result,
                Err(ValidationError::PostAlonzo(
                    PostAlonzoError::CollateralMissing
                ))
            ),
            "{result:?}"
        );
    });
}

#[test]
fn batch_execution_units_include_sub_transaction_redeemers() {
    record(890, |tx, pairs, pp| {
        let MultiEraProtocolParameters::Dijkstra(mut p) = pp else {
            unreachable!()
        };
        p.max_tx_ex_units.mem = 10000000;
        p.max_tx_ex_units.steps = 10000000000;
        let result = check(
            &tx,
            &pairs,
            MultiEraProtocolParameters::Dijkstra(p.clone()),
            &time(ForecastHorizon::Unbounded),
        );
        assert!(result.is_ok(), "{result:?}");
        p.max_tx_ex_units.mem = 9999999;
        let result = check(
            &tx,
            &pairs,
            MultiEraProtocolParameters::Dijkstra(p),
            &time(ForecastHorizon::Unbounded),
        );
        assert!(
            matches!(
                result,
                Err(ValidationError::PostAlonzo(
                    PostAlonzoError::TxExUnitsExceeded
                ))
            ),
            "{result:?}"
        );
    });
}

#[test]
fn sub_transaction_spending_a_datum_hash_requires_the_datum() {
    record(890, |tx, mut pairs, pp| {
        let sub = &tx.transaction_body.sub_transactions.as_ref().unwrap()[0];
        let spent = minicbor::to_vec(&sub.sub_transaction_body.inputs[0]).unwrap();
        let (_, output) = pairs.iter_mut().find(|(x, _)| *x == spent).unwrap();
        assert_eq!(output[0], 0x82);
        output[0] = 0x83;
        output.extend([0x58, 0x20]);
        output.extend([7; 32]);
        let result = check(&tx, &pairs, pp, &time(ForecastHorizon::Unbounded));
        assert!(
            matches!(
                result,
                Err(ValidationError::PostAlonzo(PostAlonzoError::DatumMissing))
            ),
            "{result:?}"
        );
    });
}

#[test]
fn sub_transaction_refuses_a_datum_nothing_names() {
    record(890, |tx, pairs, pp| {
        let extra = change_sub(&tx, |sub| {
            let mut w = (*sub.transaction_witness_set).clone();
            w.plutus_data = Some(minicbor::decode(&[0x81, 0x01]).unwrap());
            sub.transaction_witness_set = w.into();
        });
        let result = check(&extra, &pairs, pp, &time(ForecastHorizon::Unbounded));
        assert!(
            matches!(
                result,
                Err(ValidationError::PostAlonzo(PostAlonzoError::UnneededDatum))
            ),
            "{result:?}"
        );
    });
}

#[test]
fn sub_transaction_upper_bound_must_precede_the_forecast_horizon() {
    record(890, |tx, pairs, pp| {
        let horizon = ForecastHorizon::Slot(SLOT + 100);
        let result = check(&tx, &pairs, pp.clone(), &time(horizon));
        assert!(result.is_ok(), "{result:?}");
        let bounded = change_sub(&tx, |sub| {
            let mut body = (*sub.sub_transaction_body).clone();
            body.ttl = Some(SLOT + 200);
            sub.sub_transaction_body = body.into();
        });
        let result = check(&bounded, &pairs, pp.clone(), &time(horizon));
        assert!(
            matches!(
                result,
                Err(ValidationError::DijkstraTime(
                    DijkstraTimeError::PastHorizon { slot, .. }
                )) if slot == SLOT + 200
            ),
            "{result:?}"
        );
        let result = check(&bounded, &pairs, pp, &time(ForecastHorizon::Unbounded));
        assert!(
            matches!(
                result,
                Err(ValidationError::PostAlonzo(
                    PostAlonzoError::VKWrongSignature
                ))
            ),
            "{result:?}"
        );
    });
}

#[test]
fn sub_transaction_integrity_hash_covers_the_views_of_its_languages() {
    record(890, |tx, pairs, pp| {
        let viewless = change_sub(&tx, |sub| {
            let redeemers = sub.transaction_witness_set.redeemer.as_ref().unwrap();
            let mut raw = minicbor::to_vec(redeemers).unwrap();
            raw.push(0xa0);
            let mut body = (*sub.sub_transaction_body).clone();
            body.script_data_hash = Some(Hasher::<256>::hash(&raw));
            sub.sub_transaction_body = body.into();
        });
        let result = check(&viewless, &pairs, pp, &time(ForecastHorizon::Unbounded));
        assert!(
            matches!(
                result,
                Err(ValidationError::PostAlonzo(
                    PostAlonzoError::ScriptIntegrityHash
                ))
            ),
            "{result:?}"
        );
    });
}

/// A testnet reward address, which no output may hold.
const REWARD: [u8; 29] = {
    let mut address = [5; 29];
    address[0] = 0xe0;
    address
};

/// `output` sent to `address`.
fn sent_to<'b>(output: &n::TransactionOutput<'b>, address: &[u8]) -> n::TransactionOutput<'b> {
    match output {
        n::TransactionOutput::PostAlonzo(o) => {
            let mut o = (**o).clone();
            o.address = address.to_vec().into();
            n::TransactionOutput::PostAlonzo(o.into())
        }
        n::TransactionOutput::Legacy(o) => {
            let mut o = (**o).clone();
            o.address = address.to_vec().into();
            n::TransactionOutput::Legacy(o.into())
        }
    }
}

/// The verdict on `record` with no fee, after `f` changes its body.
fn feeless(
    record: u32,
    f: impl for<'b> FnOnce(&mut n::TransactionBody<'b>, &n::TransactionOutput<'b>),
) -> ValidationResult {
    let mut result = None;
    self::record(record, |tx, pairs, pp| {
        let mut tx = tx.clone();
        let mut body = (*tx.transaction_body).clone();
        body.fee = 0;
        let first = body.outputs[0].clone();
        f(&mut body, &first);
        tx.transaction_body = body.into();
        result = Some(check(&tx, &pairs, pp, &time(ForecastHorizon::Unbounded)));
    });
    result.unwrap()
}

#[test]
fn decodable_output_addresses_reach_the_fee_rule() {
    let result = feeless(890, |_, _| ());
    assert!(
        matches!(
            result,
            Err(ValidationError::PostAlonzo(PostAlonzoError::FeeBelowMin))
        ),
        "{result:?}"
    );
}

#[test]
fn an_output_to_a_reward_address_is_refused_before_every_rule() {
    let top = feeless(890, |body, first| {
        body.outputs = pallas_codec::utils::MaybeIndefArray::Def(vec![sent_to(first, &REWARD)]);
    });
    let collateral = feeless(890, |body, first| {
        body.collateral_return = Some(sent_to(first, &REWARD));
    });
    let sub = feeless(890, |body, first| {
        let mut subs = body.sub_transactions.clone().unwrap().to_vec();
        let mut sub_body = (*subs[0].sub_transaction_body).clone();
        sub_body.outputs = pallas_codec::utils::MaybeIndefArray::Def(vec![sent_to(first, &REWARD)]);
        subs[0].sub_transaction_body = sub_body.into();
        body.sub_transactions = n::NonEmptySet::from_vec(subs);
    });
    for (placement, result) in [("top", top), ("collateral", collateral), ("sub", sub)] {
        assert!(
            matches!(
                result,
                Err(ValidationError::PostAlonzo(
                    PostAlonzoError::AddressDecoding
                ))
            ),
            "{placement}: {result:?}"
        );
    }
}
