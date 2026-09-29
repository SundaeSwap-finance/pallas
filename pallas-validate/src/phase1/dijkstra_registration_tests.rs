//! Real native registration acceptance plus explicitly synthetic rejection cases.
use super::{
    dijkstra_tests::{env, error, sign, synthetic},
    *,
};
use crate::utils::{DijkstraPlutusParams, DijkstraRegistrationState};
use pallas_codec::{minicbor, utils::KeepRaw};
use pallas_primitives::dijkstra as n;
use pallas_traverse::{MultiEraBlock, MultiEraInput, MultiEraOutput};

fn read(name: &str) -> Vec<u8> {
    hex::decode(
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../test_data/musashi-registration")
                .join(name),
        )
        .unwrap()
        .trim(),
    )
    .unwrap()
}
fn params() -> Environment {
    let mut e = env();
    e.block_slot = 1401365;
    let p: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test_data/musashi-phase1/registration-epoch64-parameters.json"
    ))
    .unwrap();
    let g: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test_data/musashi-phase1/registration-dijkstra-genesis.json"
    ))
    .unwrap();
    let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
        unreachable!()
    };
    pp.key_deposit = Some(p["key_deposit"].as_str().unwrap().parse().unwrap());
    pp.plutus = Some(DijkstraPlutusParams {
        cost_model_v3: serde_json::from_value(p["cost_models_raw"]["PlutusV3"].clone()).unwrap(),
        // Exact rational representations of the archived decimal prices.
        execution_costs: pallas_primitives::ExUnitPrices {
            mem_price: n::RationalNumber {
                numerator: 577,
                denominator: 10000,
            },
            step_price: n::RationalNumber {
                numerator: 721,
                denominator: 10000000,
            },
        },
        max_tx_ex_units: n::ExUnits {
            mem: p["max_tx_ex_mem"].as_str().unwrap().parse().unwrap(),
            steps: p["max_tx_ex_steps"].as_str().unwrap().parse().unwrap(),
        },
        collateral_percentage: p["collateral_percent"].as_u64().unwrap() as u32,
        max_collateral_inputs: p["max_collateral_inputs"].as_u64().unwrap() as u32,
        minfee_refscript_cost_per_byte: n::RationalNumber {
            numerator: 15,
            denominator: 1,
        },
        max_ref_script_size_per_tx: g["maxRefScriptSizePerTx"].as_u64().unwrap() as u32,
        ref_script_cost_stride: g["refScriptCostStride"].as_u64().unwrap() as u32,
        ref_script_cost_multiplier: n::RationalNumber {
            numerator: 6,
            denominator: 5,
        },
    });
    assert_eq!(p["price_mem"], 0.0577);
    assert_eq!(p["price_step"], 0.0000721);
    assert_eq!(p["min_fee_ref_script_cost_per_byte"], 15.0);
    assert_eq!(g["refScriptCostMultiplier"], 1.2);
    e
}
fn fixture(test: impl FnOnce(n::BlockTransaction<'_>, UTxOs<'_>, CertState)) {
    let raw = read("blocks/1401365.block");
    let block = MultiEraBlock::decode(&raw).unwrap();
    let txs = block.txs();
    let tx = txs[0].as_dijkstra().unwrap().clone();
    assert_eq!(
        txs[0].hash().to_string(),
        "da910a9bfbe657724d64b505099010dd47f86fb573aa1d20b4da0367163e94c6"
    );
    let producer = read("blocks/1401345.block");
    let producer = MultiEraBlock::decode(&producer).unwrap();
    let producers = producer.txs();
    let outputs = producers[0].outputs();
    let utxos = [
        (
            MultiEraInput::from_alonzo_compatible(&tx.transaction_body.inputs[0]),
            outputs[1].clone(),
        ),
        (
            MultiEraInput::from_alonzo_compatible(
                &tx.transaction_body.reference_inputs.as_ref().unwrap()[0],
            ),
            outputs[0].clone(),
        ),
    ]
    .into_iter()
    .map(|(i, o)| {
        assert_eq!(o.era(), Era::Dijkstra);
        (i.to_owned(), o)
    })
    .collect();
    let state_json: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test_data/musashi-phase1/registration-certificate-state.json"
    ))
    .unwrap();
    let record = state_json["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["before_transaction"] == txs[0].hash().to_string())
        .unwrap();
    assert_eq!(record["registered_before"], false);
    assert_eq!(record["before_slot"], 1401365);
    let credential =
        n::StakeCredential::ScriptHash(record["credential"].as_str().unwrap().parse().unwrap());
    let mut state = CertState::default();
    state
        .dijkstra_registrations
        .insert(credential, DijkstraRegistrationState::Unregistered);
    test(tx.clone(), utxos, state);
}
fn run(
    tx: &n::BlockTransaction<'_>,
    utxos: &UTxOs<'_>,
    e: &Environment,
    state: &mut CertState,
) -> crate::utils::ValidationResult {
    validate_txs(&[MultiEraTx::from_dijkstra(tx)], e, utxos, state)
}
fn fail(
    tx: &n::BlockTransaction<'_>,
    utxos: &UTxOs<'_>,
    e: &Environment,
    state: &CertState,
    expected: &str,
) {
    let mut after = state.clone();
    error(run(tx, utxos, e, &mut after), expected);
    assert_eq!(
        after.dijkstra_registrations, state.dijkstra_registrations,
        "failed phase one must not register"
    );
}
#[test]
fn dijkstra_registration_captured_native_dispatch() {
    fixture(|tx, utxos, mut state| {
        assert_eq!(
            minicbor::to_vec(tx.to_mempool_transaction()).unwrap().len(),
            427
        );
        let original = minicbor::to_vec(&tx).unwrap();
        let result = run(&tx, &utxos, &params(), &mut state);
        assert!(result.is_ok(), "{result:?}");
        assert!(
            state
                .dijkstra_registrations
                .values()
                .all(|x| *x == DijkstraRegistrationState::Registered)
        );
        assert_eq!(minicbor::to_vec(&tx).unwrap(), original);
        fail(
            &tx,
            &utxos,
            &params(),
            &state,
            "DijkstraInvalidCertificate(\"already registered\")",
        );
    });
}
#[test]
fn dijkstra_registration_state_deposit_and_parameters() {
    fixture(|tx, utxos, state| {
        fail(
            &tx,
            &utxos,
            &params(),
            &CertState::default(),
            "DijkstraCertificateStateUnavailable",
        );
        let mut e = params();
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.key_deposit = Some(2000001);
        fail(
            &tx,
            &utxos,
            &e,
            &state,
            "DijkstraInvalidCertificate(\"registration deposit\")",
        );
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.key_deposit = None;
        fail(
            &tx,
            &utxos,
            &e,
            &state,
            "DijkstraMissingParameters(\"key deposit\")",
        );
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.key_deposit = Some(2000000);
        pp.plutus = None;
        fail(
            &tx,
            &utxos,
            &e,
            &state,
            "DijkstraMissingParameters(\"Plutus parameters\")",
        );
    });
}
#[test]
fn dijkstra_registration_scripts_redeemers_integrity_and_signatures() {
    fixture(|tx, utxos, state| {
        let mut no_ref = utxos.clone();
        no_ref.retain(|i, _| i.index() == 1);
        fail(
            &tx,
            &no_ref,
            &params(),
            &state,
            "PostAlonzo(ReferenceInputNotInUTxO)",
        );
        let mut changed = tx.clone();
        changed.transaction_body.reference_inputs = None;
        fail(
            &changed,
            &utxos,
            &params(),
            &state,
            "PostAlonzo(ScriptWitnessMissing)",
        );
        changed = tx.clone();
        changed.transaction_witness_set.redeemer = None;
        fail(
            &changed,
            &utxos,
            &params(),
            &state,
            "PostAlonzo(RedeemerMissing)",
        );
        changed = tx.clone();
        let original = changed.transaction_witness_set.redeemer.as_ref().unwrap();
        let value = original.values().next().unwrap().clone();
        let mut map = (**original).clone().0;
        map.insert(
            n::RedeemersKey {
                tag: n::RedeemerTag::Spend,
                index: 0,
            },
            value,
        );
        changed.transaction_witness_set.redeemer = Some(KeepRaw::from(n::Redeemers(map)));
        fail(
            &changed,
            &utxos,
            &params(),
            &state,
            "PostAlonzo(UnneededRedeemer)",
        );
        changed = tx.clone();
        changed.transaction_body.script_data_hash = Some([0; 32].into());
        fail(
            &changed,
            &utxos,
            &params(),
            &state,
            "PostAlonzo(ScriptIntegrityHash)",
        );
        changed = tx.clone();
        let mut witness = changed
            .transaction_witness_set
            .vkeywitness
            .as_ref()
            .unwrap()[0]
            .clone();
        witness.signature = vec![0; 64].into();
        changed.transaction_witness_set.vkeywitness = n::NonEmptySet::from_vec(vec![witness]);
        fail(
            &changed,
            &utxos,
            &params(),
            &state,
            "PostAlonzo(VKWrongSignature)",
        );
        changed.transaction_witness_set.vkeywitness = None;
        fail(
            &changed,
            &utxos,
            &params(),
            &state,
            "PostAlonzo(VKWitnessMissing)",
        );
        changed = tx.clone();
        changed.transaction_body.ttl = Some(1402000);
        fail(
            &changed,
            &utxos,
            &params(),
            &state,
            "DijkstraUnsupported(\"Plutus validity upper bound requires forecast state\")",
        );
    });
}
#[test]
fn dijkstra_registration_collateral_budgets_and_fees() {
    fixture(|tx, utxos, state| {
        let mut e = params();
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.plutus.as_mut().unwrap().max_tx_ex_units.mem = 18484;
        fail(&tx, &utxos, &e, &state, "PostAlonzo(TxExUnitsExceeded)");
        e = params();
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.plutus.as_mut().unwrap().max_ref_script_size_per_tx = 1;
        fail(&tx, &utxos, &e, &state, "DijkstraReferenceScriptsTooLarge");
        let mut changed = tx.clone();
        changed.transaction_body.collateral = None;
        fail(
            &changed,
            &utxos,
            &params(),
            &state,
            "PostAlonzo(CollateralMissing)",
        );
        changed = tx.clone();
        changed.transaction_body.total_collateral = Some(349750);
        fail(
            &changed,
            &utxos,
            &params(),
            &state,
            "PostAlonzo(CollateralAnnotation)",
        );
        e = params();
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.plutus.as_mut().unwrap().collateral_percentage = 151;
        fail(&tx, &utxos, &e, &state, "PostAlonzo(CollateralMinLovelace)");
        e = params();
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.plutus
            .as_mut()
            .unwrap()
            .minfee_refscript_cost_per_byte
            .numerator = 10000;
        fail(&tx, &utxos, &e, &state, "PostAlonzo(FeeBelowMin)");
    });
}
#[test]
fn dijkstra_registration_key_author_and_deposit_balance() {
    synthetic(|mut tx, input| {
        let credential = n::StakeCredential::AddrKeyhash(pallas_crypto::hash::Hasher::<224>::hash(
            pallas_crypto::key::ed25519::SecretKey::from([71; 32])
                .public_key()
                .as_ref(),
        ));
        tx.transaction_body.certificates =
            n::NonEmptySet::from_vec(vec![n::Certificate::Reg(credential.clone(), 2000000)]);
        let mut outputs = tx.transaction_body.outputs.clone().to_vec();
        let n::TransactionOutput::PostAlonzo(ref mut out) = outputs[0] else {
            unreachable!()
        };
        let n::Value::Coin(ref mut coin) = out.value else {
            unreachable!()
        };
        *coin -= 2000000;
        tx.transaction_body.outputs = pallas_codec::utils::MaybeIndefArray::Def(outputs);
        sign(&mut tx);
        let utxos = [(
            MultiEraInput::from_alonzo_compatible(&tx.transaction_body.inputs[0]),
            MultiEraOutput::from_dijkstra(&input),
        )]
        .into_iter()
        .collect();
        let mut state = CertState::default();
        state
            .dijkstra_registrations
            .insert(credential, DijkstraRegistrationState::Unregistered);
        let result = run(&tx, &utxos, &params(), &mut state);
        assert!(result.is_ok(), "{result:?}");
    });
}

#[test]
fn dijkstra_registration_fee_rounding_and_reference_accounting() {
    fixture(|tx, utxos, state| {
        let mut e = params();
        let reference = utxos
            .values()
            .find(|x| x.multi_era_script_ref().is_some())
            .unwrap();
        let pallas_traverse::MultiEraScriptRef::Dijkstra(script) =
            reference.multi_era_script_ref().unwrap()
        else {
            unreachable!()
        };
        let n::ScriptRef::PlutusV3Script(script) = script.as_ref() else {
            unreachable!()
        };
        let bytes = script.as_ref().len() as u64;
        // Independent integer expression: ceil(18485*.0577 + 4805428*.0000721).
        let execution = (18485u64 * 577 * 1000 + 4805428u64 * 721).div_ceil(10000000);
        let minimum = 427 * 44 + 155381 + execution + bytes * 15;
        assert!(minimum <= tx.transaction_body.fee);
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.minfee_b += (tx.transaction_body.fee - minimum) as u32;
        assert!(run(&tx, &utxos, &e, &mut state.clone()).is_ok());
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.minfee_b += 1;
        fail(&tx, &utxos, &e, &state, "PostAlonzo(FeeBelowMin)");
        // Synthetic tier boundary: script extends one byte beyond the first tier.
        e = params();
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.plutus.as_mut().unwrap().ref_script_cost_stride = (bytes - 1) as u32;
        let tiered = (bytes - 1) * 15 + 18;
        pp.minfee_b += (tx.transaction_body.fee - (427 * 44 + 155381 + execution + tiered)) as u32;
        assert!(run(&tx, &utxos, &e, &mut state.clone()).is_ok());
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.minfee_b += 1;
        fail(&tx, &utxos, &e, &state, "PostAlonzo(FeeBelowMin)");
        // An unrelated script UTxO must not enter the fee or language view.
        let mut extra = utxos.clone();
        extra.insert(
            MultiEraInput::AlonzoCompatible(Box::new(std::borrow::Cow::Owned(
                n::TransactionInput {
                    transaction_id: [8; 32].into(),
                    index: 0,
                },
            ))),
            reference.clone(),
        );
        assert!(run(&tx, &extra, &params(), &mut state.clone()).is_ok());
    });
}
#[test]
fn dijkstra_registration_other_certificates_and_script_forms_reject() {
    fixture(|tx, utxos, state| {
        let mut changed = tx.clone();
        let n::Certificate::Reg(credential, _) =
            &tx.transaction_body.certificates.as_ref().unwrap()[0]
        else {
            unreachable!()
        };
        changed.transaction_body.certificates =
            n::NonEmptySet::from_vec(vec![n::Certificate::UnReg(credential.clone(), 2000000)]);
        fail(
            &changed,
            &utxos,
            &params(),
            &state,
            "DijkstraUnsupported(\"certificate kind\")",
        );
        changed = tx.clone();
        changed.transaction_witness_set.plutus_v3_script =
            n::NonEmptySet::from_vec(vec![pallas_primitives::PlutusScript(vec![0].into())]);
        fail(
            &changed,
            &utxos,
            &params(),
            &state,
            "DijkstraUnsupported(\"non-vkey witnesses\")",
        );
        changed = tx.clone();
        changed.transaction_body.validity_interval_start = Some(1401366);
        fail(
            &changed,
            &utxos,
            &params(),
            &state,
            "PostAlonzo(BlockPrecedesValInt)",
        );
        let mut e = params();
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.plutus.as_mut().unwrap().cost_model_v3.truncate(297);
        fail(&tx, &utxos, &e, &state, "PostAlonzo(ScriptIntegrityHash)");
    });
}

#[test]
fn dijkstra_registration_requires_distinct_certificate_author() {
    synthetic(|mut tx, input| {
        let author = pallas_crypto::key::ed25519::SecretKey::from([72; 32]);
        let credential = n::StakeCredential::AddrKeyhash(pallas_crypto::hash::Hasher::<224>::hash(
            author.public_key().as_ref(),
        ));
        tx.transaction_body.certificates =
            n::NonEmptySet::from_vec(vec![n::Certificate::Reg(credential.clone(), 2000000)]);
        let mut outputs = tx.transaction_body.outputs.clone().to_vec();
        let n::TransactionOutput::PostAlonzo(ref mut out) = outputs[0] else {
            unreachable!()
        };
        let n::Value::Coin(ref mut coin) = out.value else {
            unreachable!()
        };
        *coin -= 2000000;
        tx.transaction_body.outputs = pallas_codec::utils::MaybeIndefArray::Def(outputs);
        sign(&mut tx);
        let utxos = [(
            MultiEraInput::AlonzoCompatible(Box::new(std::borrow::Cow::Owned(
                tx.transaction_body.inputs[0].clone(),
            ))),
            MultiEraOutput::from_dijkstra(&input),
        )]
        .into_iter()
        .collect();
        let mut state = CertState::default();
        state
            .dijkstra_registrations
            .insert(credential, DijkstraRegistrationState::Unregistered);
        fail(
            &tx,
            &utxos,
            &params(),
            &state,
            "PostAlonzo(VKWitnessMissing)",
        );
        let hash = pallas_crypto::hash::Hasher::<256>::hash(
            &minicbor::to_vec(&tx.transaction_body).unwrap(),
        );
        let mut witnesses = tx
            .transaction_witness_set
            .vkeywitness
            .as_ref()
            .unwrap()
            .to_vec();
        witnesses.push(n::VKeyWitness {
            vkey: author.public_key().as_ref().to_vec().into(),
            signature: author.sign(hash).as_ref().to_vec().into(),
        });
        tx.transaction_witness_set.vkeywitness = n::NonEmptySet::from_vec(witnesses);
        let result = run(&tx, &utxos, &params(), &mut state);
        assert!(result.is_ok(), "{result:?}");
    });
}
