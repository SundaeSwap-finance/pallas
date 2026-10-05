//! Native-script admission tests. All mutations below are explicitly synthetic.
use super::{dijkstra_tests, *};
use pallas_addresses::{Network, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart};
use pallas_codec::{
    minicbor,
    utils::{CborWrap, KeepRaw},
};
use pallas_crypto::{
    hash::{Hash, Hasher},
    key::ed25519::SecretKey,
};
use pallas_primitives::{conway as c, dijkstra as n};
use pallas_traverse::{MultiEraInput, MultiEraOutput, OriginalHash};
use std::collections::BTreeMap;

type Inputs<'a> = Vec<(n::TransactionInput, n::TransactionOutput<'a>)>;
fn output<'a, 'b>(
    o: &'a mut n::TransactionOutput<'b>,
) -> &'a mut KeepRaw<'b, n::PostAlonzoTransactionOutput<'b>> {
    let n::TransactionOutput::PostAlonzo(o) = o else {
        panic!()
    };
    o
}
fn key_hash() -> Hash<28> {
    Hasher::<224>::hash(SecretKey::from([71; 32]).public_key().as_ref())
}
fn native(script: n::NativeScript) -> KeepRaw<'static, n::NativeScript> {
    let bytes = minicbor::to_vec(script).unwrap();
    minicbor::decode::<KeepRaw<'_, n::NativeScript>>(&bytes)
        .unwrap()
        .to_owned()
}
fn locked_address(hash: Hash<28>) -> Vec<u8> {
    ShelleyAddress::new(
        Network::Testnet,
        ShelleyPaymentPart::Script(hash),
        ShelleyDelegationPart::Null,
    )
    .to_vec()
}
fn run(
    tx: &n::BlockTransaction<'_>,
    inputs: &Inputs<'_>,
    env: &Environment,
    state: &mut CertState,
) -> crate::utils::ValidationResult {
    let utxos = inputs
        .iter()
        .map(|(i, o)| {
            (
                MultiEraInput::from_alonzo_compatible(i),
                MultiEraOutput::from_dijkstra(o),
            )
        })
        .collect();
    // Admission callers decode actual bytes; exercise the original-CBOR path too.
    let raw = minicbor::to_vec(tx.to_mempool_transaction()).unwrap();
    let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &raw).unwrap();
    validate_txs(&[tx], env, &utxos, state)
}
fn spend(
    script: KeepRaw<'static, n::NativeScript>,
    test: impl FnOnce(n::BlockTransaction<'_>, Inputs<'_>),
) {
    dijkstra_tests::synthetic(|mut tx, mut input| {
        output(&mut input).address = locked_address(script.original_hash()).into();
        tx.transaction_witness_set.native_script = n::NonEmptySet::from_vec(vec![script]);
        dijkstra_tests::sign(&mut tx);
        let inputs = vec![(tx.transaction_body.inputs[0].clone(), input)];
        test(tx, inputs)
    });
}
fn accepts(tx: &n::BlockTransaction<'_>, inputs: &Inputs<'_>) {
    let result = run(
        tx,
        inputs,
        &dijkstra_tests::env(),
        &mut CertState::default(),
    );
    assert!(result.is_ok(), "{result:?}");
}
fn rejects(tx: &n::BlockTransaction<'_>, inputs: &Inputs<'_>, expected: &str) {
    dijkstra_tests::error(
        run(
            tx,
            inputs,
            &dijkstra_tests::env(),
            &mut CertState::default(),
        ),
        expected,
    );
}

#[test]
fn dijkstra_native_signatures_and_witness_coverage() {
    spend(
        native(n::NativeScript::ScriptPubkey(key_hash())),
        |mut tx, inputs| {
            accepts(&tx, &inputs);
            let original = tx.clone();
            tx.transaction_witness_set.vkeywitness = None;
            rejects(&tx, &inputs, "PostAlonzo(NativeScriptDenial)");
            tx = original.clone();
            let mut witness = tx.transaction_witness_set.vkeywitness.as_ref().unwrap()[0].clone();
            witness.signature = vec![0; 64].into();
            tx.transaction_witness_set.vkeywitness = n::NonEmptySet::from_vec(vec![witness]);
            rejects(&tx, &inputs, "PostAlonzo(VKWrongSignature)");
            tx = original.clone();
            tx.transaction_witness_set.native_script = None;
            rejects(&tx, &inputs, "PostAlonzo(ScriptWitnessMissing)");
            tx = original;
            tx.transaction_witness_set.native_script =
                n::NonEmptySet::from_vec(vec![native(n::NativeScript::ScriptAll(vec![]))]);
            rejects(&tx, &inputs, "PostAlonzo(UnneededNativeScript)");
        },
    );
}

#[test]
fn dijkstra_native_combinators_and_slot_bounds() {
    use n::NativeScript::*;
    let cases = [
        (ScriptAll(vec![]), true),
        (ScriptAny(vec![]), false),
        (ScriptNOfK(i64::MIN, vec![]), true),
        (ScriptNOfK(0, vec![]), true),
        (ScriptNOfK(i64::MAX, vec![ScriptPubkey(key_hash())]), false),
        (
            ScriptAny(vec![
                ScriptPubkey(Hash::from([1; 28])),
                ScriptPubkey(key_hash()),
            ]),
            true,
        ),
        (
            ScriptNOfK(2, vec![ScriptPubkey(key_hash()), ScriptPubkey(key_hash())]),
            true,
        ),
        (
            ScriptAll(vec![InvalidBefore(1400000), InvalidHereafter(1400010)]),
            true,
        ),
        (InvalidBefore(1400001), false),
        (InvalidHereafter(1400009), false),
    ];
    for (script, valid) in cases {
        spend(native(script), |mut tx, inputs| {
            tx.transaction_body.validity_interval_start = Some(1400000);
            tx.transaction_body.ttl = Some(1400010);
            dijkstra_tests::sign(&mut tx);
            if valid {
                accepts(&tx, &inputs);
            } else {
                rejects(&tx, &inputs, "PostAlonzo(NativeScriptDenial)");
            }
        });
    }
    for script in [InvalidBefore(0), InvalidHereafter(u64::MAX)] {
        spend(native(script), |mut tx, inputs| {
            tx.transaction_body.validity_interval_start = None;
            tx.transaction_body.ttl = None;
            dijkstra_tests::sign(&mut tx);
            rejects(&tx, &inputs, "PostAlonzo(NativeScriptDenial)");
        });
    }
}

#[test]
fn dijkstra_native_guards_reject_even_in_unused_branches() {
    spend(
        native(n::NativeScript::ScriptAny(vec![
            n::NativeScript::ScriptAll(vec![]),
            n::NativeScript::ScriptRequireGuard(n::StakeCredential::AddrKeyhash(key_hash())),
        ])),
        |tx, inputs| {
            rejects(
                &tx,
                &inputs,
                "DijkstraUnsupported(\"native script guards\")",
            );
        },
    );
}

#[test]
fn dijkstra_native_mint_registration_and_partial_withdrawal() {
    let script = native(n::NativeScript::ScriptPubkey(key_hash()));
    let hash = script.original_hash();
    spend(script, |mut tx, inputs| {
        let mut env = dijkstra_tests::env();
        let MultiEraProtocolParameters::Dijkstra(pp) = &mut env.prot_params else {
            panic!()
        };
        pp.key_deposit = Some(2_000_000);
        // One script authorizes four different purposes; none needs a redeemer.
        tx.transaction_body.mint = Some(BTreeMap::from([(
            hash,
            BTreeMap::from([(b"token".to_vec().into(), 1.try_into().unwrap())]),
        )]));
        let coin = MultiEraOutput::from_dijkstra(&tx.transaction_body.outputs[0])
            .value()
            .coin();
        output(first_output(&mut tx)).value = c::Value::Multiasset(
            coin - 1_000_000,
            BTreeMap::from([(
                hash,
                BTreeMap::from([(b"token".to_vec().into(), 1.try_into().unwrap())]),
            )]),
        );
        // Withdrawal precedes registration; use a distinct key registration to keep state coherent.
        tx.transaction_body.certificates = n::NonEmptySet::from_vec(vec![n::Certificate::Reg(
            n::StakeCredential::AddrKeyhash(key_hash()),
            2_000_000,
        )]);
        let mut reward = vec![0xf0];
        reward.extend(hash.as_ref());
        tx.transaction_body.withdrawals = Some(BTreeMap::from([(reward.into(), 1_000_000)]));
        let mut state = CertState::default();
        state.dijkstra_registrations.insert(
            n::StakeCredential::AddrKeyhash(key_hash()),
            crate::utils::DijkstraRegistrationState::Unregistered,
        );
        state
            .dijkstra_account_balances
            .insert(n::StakeCredential::ScriptHash(hash), Some(2_000_000));
        dijkstra_tests::sign(&mut tx);
        let result = run(&tx, &inputs, &env, &mut state);
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            state.dijkstra_account_balances[&n::StakeCredential::ScriptHash(hash)],
            Some(1_000_000)
        );
        // Native certificate script, no withdrawal from the newly registered account.
        tx.transaction_body.withdrawals = None;
        tx.transaction_body.certificates = n::NonEmptySet::from_vec(vec![n::Certificate::Reg(
            n::StakeCredential::ScriptHash(hash),
            2_000_000,
        )]);
        if let c::Value::Multiasset(coin, _) = &mut output(first_output(&mut tx)).value {
            *coin -= 1_000_000;
        }
        let mut state = CertState::default();
        state.dijkstra_registrations.insert(
            n::StakeCredential::ScriptHash(hash),
            crate::utils::DijkstraRegistrationState::Unregistered,
        );
        dijkstra_tests::sign(&mut tx);
        let result = run(&tx, &inputs, &env, &mut state);
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            state.dijkstra_registrations[&n::StakeCredential::ScriptHash(hash)],
            crate::utils::DijkstraRegistrationState::Registered
        );
    });
}

#[test]
fn dijkstra_native_reference_sources_and_original_hash() {
    // Deliberately noncanonical array/int encoding. Hash the captured representation.
    let mut raw = vec![0x98, 0x02, 0x18, 0x00, 0x58, 0x1c];
    raw.extend(key_hash().as_ref());
    let script = minicbor::decode::<KeepRaw<'_, n::NativeScript>>(&raw)
        .unwrap()
        .to_owned();
    assert_ne!(
        script.original_hash(),
        native(n::NativeScript::ScriptPubkey(key_hash())).original_hash()
    );
    for spent in [false, true] {
        spend(script.clone(), |mut tx, mut inputs| {
            tx.transaction_witness_set.native_script = None;
            let env = super::dijkstra_registration_tests::params();
            if spent {
                output(&mut inputs[0].1).script_ref =
                    Some(CborWrap(n::ScriptRef::NativeScript(script.clone())));
            } else {
                let reference = n::TransactionInput {
                    transaction_id: Hash::from([7; 32]),
                    index: 0,
                };
                let mut o = inputs[0].1.clone();
                output(&mut o).script_ref =
                    Some(CborWrap(n::ScriptRef::NativeScript(script.clone())));
                inputs.push((reference.clone(), o));
                tx.transaction_body.reference_inputs = n::NonEmptySet::from_vec(vec![reference]);
            }
            dijkstra_tests::sign(&mut tx);
            let result = run(&tx, &inputs, &env, &mut CertState::default());
            assert!(result.is_ok(), "{result:?}");
            tx.transaction_witness_set.native_script =
                n::NonEmptySet::from_vec(vec![script.clone()]);
            dijkstra_tests::error(
                run(&tx, &inputs, &env, &mut CertState::default()),
                "PostAlonzo(UnneededNativeScript)",
            );
        });
    }
}

#[cfg(feature = "phase2")]
#[test]
fn dijkstra_native_phase_two_has_no_jobs_or_time_translation() {
    spend(
        native(n::NativeScript::InvalidHereafter(1400010)),
        |mut tx, inputs| {
            tx.transaction_body.ttl = Some(1400010);
            dijkstra_tests::sign(&mut tx);
            accepts(&tx, &inputs);
            let utxos = inputs
                .iter()
                .map(|(i, o)| {
                    (
                        crate::utils::TxoRef(i.transaction_id, i.index as u32),
                        crate::utils::EraCbor(Era::Dijkstra, minicbor::to_vec(o).unwrap()),
                    )
                })
                .collect();
            let result = crate::phase2::evaluate_tx(
                &MultiEraTx::from_dijkstra(&tx),
                &dijkstra_tests::env().prot_params,
                &utxos,
                &crate::phase2::script_context::SlotConfig {
                    zero_slot: u64::MAX,
                    zero_time: u64::MAX,
                    slot_length: u64::MAX,
                },
            );
            assert!(result.unwrap().is_empty());
        },
    );
}

fn first_output<'a, 'b>(tx: &'a mut n::BlockTransaction<'b>) -> &'a mut n::TransactionOutput<'b> {
    match &mut tx.transaction_body.outputs {
        pallas_codec::utils::MaybeIndefArray::Def(xs)
        | pallas_codec::utils::MaybeIndefArray::Indef(xs) => &mut xs[0],
    }
}

#[test]
fn dijkstra_native_captured_mint_admission() {
    let raw =
        hex::decode(include_str!("../../../test_data/dijkstra-native-scripts/mint.tx.hex").trim())
            .unwrap();
    let input = hex::decode(
        include_str!("../../../test_data/dijkstra-native-scripts/mint.input.hex").trim(),
    )
    .unwrap();
    let producer = hex::decode(
        include_str!("../../../test_data/dijkstra-native-scripts/producer.body.hex").trim(),
    )
    .unwrap();
    let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &raw).unwrap();
    assert_eq!(
        tx.hash().to_string(),
        "ca60ffd71d5dc8fa94ad7d0103183511004e0d42efd7b3a07e1aa6bfc19e5f69"
    );
    assert_eq!(*tx.inputs()[0].hash(), Hasher::<256>::hash(&producer));
    let body: n::TransactionBody = minicbor::decode(&producer).unwrap();
    assert_eq!(minicbor::to_vec(&body.outputs[0]).unwrap(), input);
    let utxos = [(
        tx.inputs()[0].to_owned(),
        MultiEraOutput::decode(Era::Dijkstra, &input).unwrap(),
    )]
    .into_iter()
    .collect();
    let mut env = dijkstra_tests::env();
    env.block_slot = 1025002;
    let result = validate_txs(
        std::slice::from_ref(&tx),
        &env,
        &utxos,
        &mut CertState::default(),
    );
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        minicbor::to_vec(tx.as_dijkstra().unwrap().to_mempool_transaction()).unwrap(),
        raw
    );
}

#[test]
fn dijkstra_native_deep_scripts_do_not_use_recursive_evaluation() {
    let mut raw = Vec::new();
    for _ in 0..4096 {
        raw.extend([0x82, 0x01, 0x81]);
    }
    raw.extend([0x82, 0x01, 0x80]);
    let script = minicbor::decode::<KeepRaw<'_, n::NativeScript>>(&raw)
        .unwrap()
        .to_owned();
    spend(script, |tx, inputs| {
        let mut env = dijkstra_tests::env();
        let MultiEraProtocolParameters::Dijkstra(pp) = &mut env.prot_params else {
            panic!()
        };
        pp.minfee_a = 0; // Isolate depth from fee-per-byte; the size limit still applies.
        let result = run(&tx, &inputs, &env, &mut CertState::default());
        assert!(result.is_ok(), "{result:?}");
    });
}

#[test]
fn dijkstra_native_reference_fee_size_and_scope() {
    let script = native(n::NativeScript::ScriptAll(vec![]));
    spend(script.clone(), |mut tx, mut inputs| {
        tx.transaction_witness_set.native_script = None;
        output(&mut inputs[0].1).script_ref =
            Some(CborWrap(n::ScriptRef::NativeScript(script.clone())));
        let mut env = super::dijkstra_registration_tests::params();
        let MultiEraProtocolParameters::Dijkstra(pp) = &mut env.prot_params else {
            panic!()
        };
        // Two UTxOs containing the same script count twice for reference fees/size.
        let reference = n::TransactionInput {
            transaction_id: Hash::from([9; 32]),
            index: 0,
        };
        inputs.push((reference.clone(), inputs[0].1.clone()));
        tx.transaction_body.reference_inputs = n::NonEmptySet::from_vec(vec![reference.clone()]);
        let p = pp.plutus.as_mut().unwrap();
        p.cost_model_v3.clear(); // Native reference scripts need fee parameters, not a cost model.
        p.max_ref_script_size_per_tx = 6;
        pp.minfee_a = 0;
        pp.minfee_b = tx.transaction_body.fee as u32 - 90; // six bytes * 15 lovelace
        dijkstra_tests::sign(&mut tx);
        let result = run(&tx, &inputs, &env, &mut CertState::default());
        assert!(result.is_ok(), "{result:?}");
        let mut bad = Environment {
            prot_params: env.prot_params.clone(),
            ..dijkstra_tests::env()
        };
        let MultiEraProtocolParameters::Dijkstra(pp) = &mut bad.prot_params else {
            panic!()
        };
        pp.minfee_b += 1;
        dijkstra_tests::error(
            run(&tx, &inputs, &bad, &mut CertState::default()),
            "PostAlonzo(FeeBelowMin)",
        );
        let MultiEraProtocolParameters::Dijkstra(pp) = &mut bad.prot_params else {
            panic!()
        };
        pp.minfee_b -= 1;
        pp.plutus.as_mut().unwrap().max_ref_script_size_per_tx = 5;
        dijkstra_tests::error(
            run(&tx, &inputs, &bad, &mut CertState::default()),
            "DijkstraReferenceScriptsTooLarge",
        );
        // An unrelated UTxO may not supply the required native script.
        output(&mut inputs[0].1).script_ref = None;
        tx.transaction_body.reference_inputs = None;
        dijkstra_tests::sign(&mut tx);
        dijkstra_tests::error(
            run(&tx, &inputs, &env, &mut CertState::default()),
            "PostAlonzo(ScriptWitnessMissing)",
        );
    });
}

#[test]
fn dijkstra_native_earlier_era_reference_and_new_output() {
    let script = native(n::NativeScript::ScriptPubkey(key_hash()));
    let raw = minicbor::to_vec(&script).unwrap();
    spend(script, |mut tx, mut inputs| {
        let reference = n::TransactionInput {
            transaction_id: Hash::from([10; 32]),
            index: 0,
        };
        let earlier: KeepRaw<'_, c::NativeScript> = minicbor::decode(&raw).unwrap();
        let reference_output = c::TransactionOutput::PostAlonzo(
            c::PostAlonzoTransactionOutput {
                address: locked_address(Hash::from([1; 28])).into(),
                value: c::Value::Coin(10_000_000),
                datum_option: None,
                script_ref: Some(CborWrap(c::ScriptRef::NativeScript(earlier))),
            }
            .into(),
        );
        tx.transaction_witness_set.native_script = None;
        tx.transaction_body.reference_inputs = n::NonEmptySet::from_vec(vec![reference.clone()]);
        dijkstra_tests::sign(&mut tx);
        let utxos = [
            (
                MultiEraInput::from_alonzo_compatible(&inputs[0].0),
                MultiEraOutput::from_dijkstra(&inputs[0].1),
            ),
            (
                MultiEraInput::from_alonzo_compatible(&reference),
                MultiEraOutput::from_conway(&reference_output),
            ),
        ]
        .into_iter()
        .collect();
        let env = super::dijkstra_registration_tests::params();
        let result = validate_txs(
            &[MultiEraTx::from_dijkstra(&tx)],
            &env,
            &utxos,
            &mut CertState::default(),
        );
        assert!(result.is_ok(), "{result:?}");
        // Publish a native reference script without executing it or enabling phase2.
        tx.transaction_body.reference_inputs = None;
        tx.transaction_witness_set.native_script =
            n::NonEmptySet::from_vec(vec![native(n::NativeScript::ScriptPubkey(key_hash()))]);
        output(first_output(&mut tx)).script_ref = Some(CborWrap(n::ScriptRef::NativeScript(
            native(n::NativeScript::ScriptAny(vec![])),
        )));
        dijkstra_tests::sign(&mut tx);
        accepts(&tx, &inputs);
        // Collateral is not a script source, even if callers supply it in the map.
        let mut extra = inputs[0].1.clone();
        output(&mut extra).script_ref = Some(CborWrap(n::ScriptRef::NativeScript(native(
            n::NativeScript::ScriptPubkey(key_hash()),
        ))));
        inputs.push((reference.clone(), extra));
        tx.transaction_body.collateral = n::NonEmptySet::from_vec(vec![reference]);
        tx.transaction_witness_set.native_script = None;
        dijkstra_tests::sign(&mut tx);
        rejects(&tx, &inputs, "PostAlonzo(ScriptWitnessMissing)");
    });
}
