//! Unchanged native capture and synthetic phase-two boundaries; no submission.
use super::*;
use crate::utils::{EraCbor, TxoRef};
use pallas_codec::minicbor;
use pallas_primitives::{conway as c, dijkstra as n};
use pallas_traverse::{Era, MultiEraBlock, MultiEraRedeemerTag, MultiEraTx};

fn slots() -> SlotConfig {
    SlotConfig {
        zero_slot: 0,
        zero_time: 1788739200000,
        slot_length: 1000,
    }
}
fn params() -> MultiEraProtocolParameters {
    crate::phase1::dijkstra_registration_tests::params().prot_params
}
fn fixture(test: impl FnOnce(n::BlockTransaction<'_>, UtxoMap)) {
    let read = |name| {
        hex::decode(
            std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../test_data/musashi-registration/blocks")
                    .join(name),
            )
            .unwrap()
            .trim(),
        )
        .unwrap()
    };
    let raw = read("1401365.block");
    let raw_producer = read("1401345.block");
    let block = MultiEraBlock::decode(&raw).unwrap();
    let producer = MultiEraBlock::decode(&raw_producer).unwrap();
    let txs = block.txs();
    let producers = producer.txs();
    assert_eq!(
        txs[0].hash().to_string(),
        "da910a9bfbe657724d64b505099010dd47f86fb573aa1d20b4da0367163e94c6"
    );
    let tx = txs[0].as_dijkstra().unwrap();
    assert!(tx.success);
    let outputs = producers[0].outputs();
    let utxos = outputs
        .iter()
        .enumerate()
        .map(|(i, o)| {
            assert_eq!(o.era(), Era::Dijkstra);
            (
                TxoRef(producers[0].hash(), i as u32),
                EraCbor(o.era(), o.encode()),
            )
        })
        .collect();
    test(tx.clone(), utxos);
}
fn run(tx: &n::BlockTransaction<'_>, u: &UtxoMap) -> Result<EvalReport, Error> {
    evaluate_tx(&MultiEraTx::from_dijkstra(tx), &params(), u, &slots())
}
#[test]
fn native_registration_executes_with_historical_budget() {
    fixture(|tx, u| {
        let original = minicbor::to_vec(&tx).unwrap();
        let r = run(&tx, &u).expect("native protocol-12 registration must evaluate");
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].tag, r[0].index), (MultiEraRedeemerTag::Cert, 0));
        assert!(r[0].success, "{r:?}");
        let view = MultiEraTx::from_dijkstra(&tx);
        let budgets = view.redeemers();
        let budget = budgets[0].ex_units();
        assert!(r[0].units.mem > 0 && r[0].units.mem <= budget.mem, "{r:?}");
        assert!(
            r[0].units.steps > 0 && r[0].units.steps <= budget.steps,
            "{r:?}"
        );
        assert!(r[0].failure_message.is_none());
        assert_eq!(minicbor::to_vec(&tx).unwrap(), original);
        println!("native historical result: {r:?}; declared {budget:?}");
    });
}

fn change_redeemer(
    tx: &mut n::BlockTransaction<'_>,
    f: impl FnOnce(&mut n::RedeemersKey, &mut n::RedeemersValue),
) {
    let mut w = (*tx.transaction_witness_set).clone();
    let mut redeemers = w.redeemer.as_ref().unwrap().0.clone();
    let (mut key, mut value) = redeemers.pop_first().unwrap();
    f(&mut key, &mut value);
    redeemers.insert(key, value);
    w.redeemer = Some(n::Redeemers(redeemers).into());
    tx.transaction_witness_set = w.into();
}
fn error(result: Result<EvalReport, Error>, expected: &str) {
    let actual = format!("{:?}", result.expect_err(expected));
    assert!(
        actual.contains(expected),
        "expected {expected}, got {actual}"
    );
}
#[test]
fn native_registration_accepts_a_guard_native_witness() {
    fixture(|mut tx, u| {
        let guard =
            n::NativeScript::ScriptRequireGuard(n::StakeCredential::AddrKeyhash([2; 28].into()));
        let raw = minicbor::to_vec(&guard).unwrap();
        let native = minicbor::decode::<pallas_codec::utils::KeepRaw<'_, n::NativeScript>>(&raw)
            .unwrap()
            .to_owned();
        let mut w = (*tx.transaction_witness_set).clone();
        w.native_script = n::NonEmptySet::from_vec(vec![native]);
        tx.transaction_witness_set = w.into();
        let r = run(&tx, &u).expect("a guard in a native witness must not stop evaluation");
        assert!(r[0].success, "{r:?}");
    });
}
// Synthetic carrier mutations of the unchanged registration capture. Merely
// carrying a native guard script does not execute it or require a guard witness.
#[test]
fn native_registration_guard_reference_context() {
    use pallas_codec::utils::{CborWrap, KeepRaw};
    for nested in [false, true] {
        for carrier in ["spending", "reference", "output"] {
            fixture(|mut tx, mut u| {
                let guard = n::NativeScript::ScriptRequireGuard(n::StakeCredential::AddrKeyhash(
                    [2; 28].into(),
                ));
                let script = if nested {
                    n::NativeScript::ScriptAll(vec![guard])
                } else {
                    guard
                };
                let bytes = minicbor::to_vec(script).unwrap();
                let native: KeepRaw<'_, n::NativeScript> = minicbor::decode(&bytes).unwrap();
                let input = &tx.transaction_body.inputs[0];
                let key = TxoRef(input.transaction_id, input.index as u32);
                let output: n::TransactionOutput<'_> = minicbor::decode(&u[&key].1).unwrap();
                let with_reference = |output: &n::TransactionOutput<'_>| {
                    let view = pallas_traverse::MultiEraOutput::from_dijkstra(output);
                    n::TransactionOutput::PostAlonzo(
                        n::PostAlonzoTransactionOutput {
                            address: view.address().unwrap().to_vec().into(),
                            value: view.value().into_conway(),
                            datum_option: view.datum().map(|d| {
                                match d {
                                    c::DatumOption::Hash(h) => c::DatumOption::Hash(h),
                                    c::DatumOption::Data(d) => {
                                        c::DatumOption::Data(CborWrap(d.0.unwrap().into()))
                                    }
                                }
                                .into()
                            }),
                            script_ref: Some(CborWrap(n::ScriptRef::NativeScript(
                                native.clone().to_owned(),
                            ))),
                        }
                        .into(),
                    )
                };
                let encoded = minicbor::to_vec(with_reference(&output)).unwrap();
                match carrier {
                    "spending" => {
                        u.insert(key, EraCbor(Era::Dijkstra, encoded));
                    }
                    "reference" => {
                        let extra = n::TransactionInput {
                            transaction_id: [7; 32].into(),
                            index: 0,
                        };
                        let mut body = (*tx.transaction_body).clone();
                        let mut refs = body.reference_inputs.as_ref().unwrap().to_vec();
                        refs.push(extra.clone());
                        body.reference_inputs = n::NonEmptySet::from_vec(refs);
                        tx.transaction_body = body.into();
                        u.insert(
                            TxoRef(extra.transaction_id, 0),
                            EraCbor(Era::Dijkstra, encoded),
                        );
                    }
                    _ => {
                        let mut body = (*tx.transaction_body).clone();
                        let mut outputs = body.outputs.to_vec();
                        outputs[0] = with_reference(&outputs[0]);
                        body.outputs = pallas_codec::utils::MaybeIndefArray::Def(outputs);
                        tx.transaction_body = body.into();
                    }
                }
                let report = run(&tx, &u)
                    .expect("ledger permits guard-bearing native reference hashes in V3");
                assert_eq!(report.len(), 1);
                assert!(report[0].success, "{carrier} nested={nested}: {report:?}");
                assert_eq!(
                    report[0].units,
                    n::ExUnits {
                        mem: 18485,
                        steps: 4805428
                    }
                );
                let estimate =
                    estimate_tx(&MultiEraTx::from_dijkstra(&tx), &params(), &u, &slots()).unwrap();
                assert_eq!(estimate[0].units, report[0].units);
            });
        }
    }
}

#[test]
fn native_registration_missing_inputs_and_unrelated_utxos() {
    fixture(|tx, u| {
        for input in [
            &tx.transaction_body.inputs[0],
            &tx.transaction_body.reference_inputs.as_ref().unwrap()[0],
        ] {
            let mut missing = u.clone();
            missing.remove(&TxoRef(input.transaction_id, input.index as u32));
            error(run(&tx, &missing), "ResolvedInputNotFound");
        }
        let mut extra = u.clone();
        extra.insert(
            TxoRef([0; 32].into(), 0),
            EraCbor(Era::Dijkstra, vec![0xff]),
        );
        assert!(run(&tx, &extra).unwrap()[0].success);
    });
}
#[test]
fn native_registration_redeemer_presence_purpose_and_position() {
    fixture(|tx, u| {
        let mut missing = tx.clone();
        let mut w = (*missing.transaction_witness_set).clone();
        w.redeemer = None;
        missing.transaction_witness_set = w.into();
        error(run(&missing, &u), "RequiredRedeemersMismatch");
        for index in [1, u32::MAX] {
            let mut bad = tx.clone();
            change_redeemer(&mut bad, |k, _| k.index = index);
            error(run(&bad, &u), "ExtraneousRedeemer");
        }
        for tag in [
            n::RedeemerTag::Spend,
            n::RedeemerTag::Mint,
            n::RedeemerTag::Reward,
            n::RedeemerTag::Vote,
            n::RedeemerTag::Propose,
            n::RedeemerTag::Guarding,
        ] {
            let mut bad = tx.clone();
            change_redeemer(&mut bad, |k, _| k.tag = tag);
            error(run(&bad, &u), "ExtraneousRedeemer");
        }
        let mut shifted = tx.clone();
        let mut b = (*shifted.transaction_body).clone();
        let mut certificates = b.certificates.as_ref().unwrap().to_vec();
        certificates.insert(
            0,
            n::Certificate::Reg(n::StakeCredential::AddrKeyhash([0; 28].into()), 2000000),
        );
        b.certificates = Some(certificates.try_into().unwrap());
        shifted.transaction_body = b.into();
        change_redeemer(&mut shifted, |k, _| k.index = 1);
        let result = run(&shifted, &u).unwrap();
        assert!(result[0].success);
        assert_eq!(result[0].index, 1);
        change_redeemer(&mut shifted, |k, _| k.index = 0);
        error(run(&shifted, &u), "ExtraneousRedeemer");
    });
}
#[test]
fn native_registration_invalid_redeemer_and_budget() {
    fixture(|tx, u| {
        let mut bad = tx.clone();
        change_redeemer(&mut bad, |_, v| {
            v.data = super::data::Data::bytestring(vec![])
        });
        let result = run(&bad, &u).unwrap();
        assert!(
            result[0].success,
            "captured registration ignores redeemer data: {result:?}"
        );
        for (mem, remaining) in [(true, 0), (false, 0), (true, 18484), (false, 4805427)] {
            let mut exhausted = tx.clone();
            change_redeemer(&mut exhausted, |_, v| {
                if mem {
                    v.ex_units.mem = remaining
                } else {
                    v.ex_units.steps = remaining
                }
            });
            let result = run(&exhausted, &u).unwrap();
            assert!(!result[0].success, "{result:?}");
            assert!(result[0].failure_message.is_some());
        }
        let mut excess = tx.clone();
        change_redeemer(&mut excess, |_, v| v.ex_units.steps = u64::MAX);
        error(
            run(&excess, &u),
            "declared transaction budget exceeds maximum",
        );
    });
}
#[test]
fn native_registration_cost_model_is_applied_by_position() {
    fixture(|tx, u| {
        let original = run(&tx, &u).unwrap();
        let mut pp = params();
        let MultiEraProtocolParameters::Dijkstra(p) = &mut pp else {
            unreachable!()
        };
        let costs = p
            .cost_models_for_script_languages
            .plutus_v3
            .as_mut()
            .unwrap();
        assert_eq!(costs.len(), 350);
        costs[29] += 1000; // V3 cekStartupCost-exBudgetCPU, a used historical coefficient.
        let changed = evaluate_tx(&MultiEraTx::from_dijkstra(&tx), &pp, &u, &slots()).unwrap();
        assert_eq!(changed[0].units.steps, original[0].units.steps + 1000);
        assert!(
            !changed[0].success,
            "higher historical cost exceeds unchanged declared budget"
        );
        for len in [351, 369] {
            let mut pp = params();
            let MultiEraProtocolParameters::Dijkstra(p) = &mut pp else {
                unreachable!()
            };
            p.cost_models_for_script_languages
                .plutus_v3
                .as_mut()
                .unwrap()
                .resize(len, 7);
            let result = evaluate_tx(&MultiEraTx::from_dijkstra(&tx), &pp, &u, &slots()).unwrap();
            assert_eq!(result[0].units, original[0].units, "{len}");
            assert!(result[0].success, "{len}: {result:?}");
        }
        for len in [0, 29] {
            let mut pp = params();
            let MultiEraProtocolParameters::Dijkstra(p) = &mut pp else {
                unreachable!()
            };
            p.cost_models_for_script_languages
                .plutus_v3
                .as_mut()
                .unwrap()
                .truncate(len);
            let result = evaluate_tx(&MultiEraTx::from_dijkstra(&tx), &pp, &u, &slots()).unwrap();
            assert!(!result[0].success, "{len}: {result:?}");
        }
        let mut pp = params();
        let MultiEraProtocolParameters::Dijkstra(p) = &mut pp else {
            unreachable!()
        };
        p.cost_models_for_script_languages.plutus_v3 = None;
        error(
            evaluate_tx(&MultiEraTx::from_dijkstra(&tx), &pp, &u, &slots()),
            "CostModelNotFound",
        );
    });
}

#[test]
fn native_registration_builtin_inventory() {
    use amaru_uplc_native::{arena::Arena, binder::DeBruijn, flat, program::Program, term::Term};
    fixture(|tx, u| {
        let i = &tx.transaction_body.reference_inputs.as_ref().unwrap()[0];
        let raw = &u[&TxoRef(i.transaction_id, i.index as u32)].1;
        let output: n::TransactionOutput = minicbor::decode(raw).unwrap();
        let n::TransactionOutput::PostAlonzo(o) = output else {
            panic!()
        };
        let n::ScriptRef::PlutusV3Script(s) = &o.script_ref.as_ref().unwrap().0 else {
            panic!()
        };
        let bytes: pallas_codec::minicbor::bytes::ByteVec = minicbor::decode(s.as_ref()).unwrap();
        let arena = Arena::new();
        let program: &Program<DeBruijn> = flat::decode(
            &arena,
            &bytes,
            amaru_kernel::PlutusVersion::V3,
            amaru_kernel::ProtocolVersion::new(12, 0),
        )
        .unwrap()
        .0;
        let mut pending = vec![program.term];
        let mut names = std::collections::BTreeSet::new();
        while let Some(t) = pending.pop() {
            match t {
                Term::Builtin(f) => {
                    names.insert(format!("{f:?}"));
                }
                Term::Lambda { body, .. } | Term::Delay(body) | Term::Force(body) => {
                    pending.push(body)
                }
                Term::Apply { function, argument } => {
                    pending.push(function);
                    pending.push(argument);
                }
                Term::Constr { fields, .. } => pending.extend(*fields),
                Term::Case { constr, branches } => {
                    pending.push(constr);
                    pending.extend(*branches);
                }
                _ => (),
            }
        }
        println!("captured builtin inventory: {names:?}");
    });
}

fn script(source: &str) -> n::PlutusScript<3> {
    use amaru_uplc_native::{arena::Arena, flat, syn::parse_program};
    let arena = Arena::new();
    let p = parse_program(&arena, source, amaru_kernel::ProtocolVersion::new(12, 0))
        .into_result()
        .unwrap();
    n::PlutusScript(
        minicbor::to_vec(pallas_codec::minicbor::bytes::ByteVec::from(
            flat::encode(p).unwrap(),
        ))
        .unwrap()
        .into(),
    )
}
fn replace_script(
    tx: &mut n::BlockTransaction<'_>,
    u: &mut UtxoMap,
    script: Option<n::ScriptRef<'_>>,
    update_author: bool,
) {
    use pallas_traverse::ComputeHash;
    let i = &tx.transaction_body.reference_inputs.as_ref().unwrap()[0];
    let entry = u
        .get_mut(&TxoRef(i.transaction_id, i.index as u32))
        .unwrap();
    let mut o: n::TransactionOutput = minicbor::decode(&entry.1).unwrap();
    if update_author {
        let hash = match &script {
            Some(n::ScriptRef::PlutusV1Script(s)) => s.compute_hash(),
            Some(n::ScriptRef::PlutusV2Script(s)) => s.compute_hash(),
            Some(n::ScriptRef::PlutusV3Script(s)) => s.compute_hash(),
            Some(n::ScriptRef::PlutusV4Script(s)) => s.compute_hash(),
            _ => panic!(),
        };
        let mut b = (*tx.transaction_body).clone();
        b.certificates = Some(
            vec![n::Certificate::Reg(
                n::StakeCredential::ScriptHash(hash),
                2000000,
            )]
            .try_into()
            .unwrap(),
        );
        tx.transaction_body = b.into();
    }
    let n::TransactionOutput::PostAlonzo(ref mut output) = o else {
        panic!()
    };
    output.script_ref = script.map(pallas_codec::utils::CborWrap);
    entry.1 = minicbor::to_vec(o).unwrap();
}
#[test]
fn native_registration_script_presence_language_and_machine_failures() {
    fixture(|tx, u| {
        for s in [
            None,
            Some(n::ScriptRef::PlutusV3Script(script(
                "(program 1.1.0 (lam ctx (con unit ())))",
            ))),
        ] {
            let mut tx = tx.clone();
            let mut u = u.clone();
            replace_script(&mut tx, &mut u, s, false);
            error(run(&tx, &u), "MissingRequiredScript");
        }
        for s in [
            n::ScriptRef::PlutusV1Script(n::PlutusScript(vec![0].into())),
            n::ScriptRef::PlutusV2Script(n::PlutusScript(vec![0].into())),
        ] {
            let mut tx = tx.clone();
            let mut u = u.clone();
            replace_script(&mut tx, &mut u, Some(s.clone()), false);
            error(run(&tx, &u), "MissingRequiredScript");
            replace_script(&mut tx, &mut u, Some(s), true);
            error(run(&tx, &u), "CostModelNotFound");
        }
        let mut v4 = tx.clone();
        let mut v4_utxos = u.clone();
        replace_script(
            &mut v4,
            &mut v4_utxos,
            Some(v4_script("(program 1.1.0 (lam ctx (con unit ())))")),
            true,
        );
        error(run(&v4, &v4_utxos), "DijkstraCostModelNotFound(PlutusV4)");
        for source in [
            "(program 1.1.0 (lam ctx (error)))",
            "(program 1.1.0 (lam ctx (con integer 1)))",
        ] {
            let mut tx = tx.clone();
            let mut u = u.clone();
            replace_script(
                &mut tx,
                &mut u,
                Some(n::ScriptRef::PlutusV3Script(script(source))),
                true,
            );
            assert!(!run(&tx, &u).unwrap()[0].success);
        }
        let mut tx = tx.clone();
        let mut u = u.clone();
        replace_script(
            &mut tx,
            &mut u,
            Some(n::ScriptRef::PlutusV3Script(script(
                "(program 1.1.0 (lam ctx [(lam ignore (con unit ())) [(builtin complementByteString) (con bytestring #00)]]))",
            ))),
            true,
        );
        error(
            run(&tx, &u),
            "V3 builtin outside audited protocol-12 subset",
        );
    });
}
fn v4_script(source: &str) -> n::ScriptRef<'static> {
    n::ScriptRef::PlutusV4Script(n::PlutusScript(script(source).0))
}
fn v4_params() -> MultiEraProtocolParameters {
    let mut pp = params();
    let MultiEraProtocolParameters::Dijkstra(p) = &mut pp else {
        unreachable!()
    };
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test_data/dijkstra-plutus-v4/1896.json"
    ))
    .unwrap();
    p.cost_models_for_script_languages.plutus_v4 =
        Some(serde_json::from_value(fixture["plutus_v4"].clone()).unwrap());
    pp
}
#[test]
fn native_registration_runs_a_v4_script_on_the_v4_context() {
    // Unit when ctx is a list of at least four elements, which the V4 context is and the V3 context is not.
    let four = "(program 1.1.0 (lam ctx [(lam ignore (con unit ())) [(force (builtin headList)) [(force (builtin tailList)) [(force (builtin tailList)) [(force (builtin tailList)) [(builtin unListData) ctx]]]]]]))";
    fixture(|tx, u| {
        let run = |script: n::ScriptRef<'static>| {
            let mut tx = tx.clone();
            let mut u = u.clone();
            replace_script(&mut tx, &mut u, Some(script), true);
            evaluate_tx(&MultiEraTx::from_dijkstra(&tx), &v4_params(), &u, &slots())
        };
        let unit = run(v4_script("(program 1.1.0 (lam ctx (con unit ())))")).unwrap();
        assert!(unit[0].success, "{unit:?}");
        let failing = run(v4_script("(program 1.1.0 (lam ctx (error)))")).unwrap();
        assert!(!failing[0].success, "{failing:?}");
        let v4 = run(v4_script(four)).unwrap();
        assert!(v4[0].success, "{v4:?}");
        let v3 = run(n::ScriptRef::PlutusV3Script(script(four))).unwrap();
        assert!(!v3[0].success, "{v3:?}");
    });
}
#[test]
fn native_registration_refuses_a_pointer_output_in_a_v4_context_only() {
    use crate::utils::dijkstra_context::{Untranslatable, check_translatable};
    use pallas_addresses::{
        Network, Pointer, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart,
    };
    fixture(|tx, u| {
        let unit = "(program 1.1.0 (lam ctx (con unit ())))";
        let run = |script: n::ScriptRef<'static>| {
            let mut tx = tx.clone();
            let mut u = u.clone();
            replace_script(&mut tx, &mut u, Some(script), true);
            let mut b = (*tx.transaction_body).clone();
            let mut outputs = b.outputs.to_vec();
            let address = ShelleyAddress::new(
                Network::Testnet,
                ShelleyPaymentPart::Key([0; 28].into()),
                ShelleyDelegationPart::Pointer(Pointer::new(1, 2, 3)),
            );
            outputs.push(n::TransactionOutput::PostAlonzo(
                n::PostAlonzoTransactionOutput {
                    address: address.to_vec().into(),
                    value: c::Value::Coin(1),
                    datum_option: None,
                    script_ref: None,
                }
                .into(),
            ));
            b.outputs = pallas_codec::utils::MaybeIndefArray::Def(outputs);
            let held = |language| check_translatable(&language, &b, &[], &[]);
            let held = (held(n::Language::PlutusV3), held(n::Language::PlutusV4));
            tx.transaction_body = b.into();
            let report = evaluate_tx(&MultiEraTx::from_dijkstra(&tx), &v4_params(), &u, &slots());
            (report, held)
        };
        let (v3, held) = run(n::ScriptRef::PlutusV3Script(script(unit)));
        let v3 = v3.unwrap();
        assert!(v3[0].success, "{v3:?}");
        assert_eq!(held, (Ok(()), Err(Untranslatable("pointer address"))));
        error(run(v4_script(unit)).0, "pointer address");
    });
}
#[test]
fn native_registration_refuses_a_v4_guarding_redeemer() {
    fixture(|mut tx, mut u| {
        use pallas_traverse::ComputeHash;
        let n::ScriptRef::PlutusV4Script(script) =
            v4_script("(program 1.1.0 (lam ctx (con unit ())))")
        else {
            unreachable!()
        };
        let hash = script.compute_hash();
        replace_script(
            &mut tx,
            &mut u,
            Some(n::ScriptRef::PlutusV4Script(script)),
            true,
        );
        let mut b = (*tx.transaction_body).clone();
        b.guards = Some(n::Guards::Credentials(
            vec![n::StakeCredential::ScriptHash(hash)]
                .try_into()
                .unwrap(),
        ));
        tx.transaction_body = b.into();
        let evaluate = |tx: &n::BlockTransaction<'_>| {
            evaluate_tx(&MultiEraTx::from_dijkstra(tx), &v4_params(), &u, &slots())
        };
        error(evaluate(&tx), "RequiredRedeemersMismatch");
        let mut w = (*tx.transaction_witness_set).clone();
        let mut redeemers = w.redeemer.as_ref().unwrap().0.clone();
        let value = redeemers.values().next().unwrap().clone();
        let key = n::RedeemersKey {
            tag: n::RedeemerTag::Guarding,
            index: 0,
        };
        redeemers.insert(key, value);
        w.redeemer = Some(n::Redeemers(redeemers).into());
        tx.transaction_witness_set = w.into();
        error(evaluate(&tx), "redeemer purpose");
    });
}
#[test]
fn native_registration_runs_beside_a_v1_or_v2_script_it_does_not_need() {
    fixture(|tx, u| {
        for s in [
            n::ScriptRef::PlutusV1Script(n::PlutusScript(vec![0].into())),
            n::ScriptRef::PlutusV2Script(n::PlutusScript(vec![0].into())),
        ] {
            let mut u = u.clone();
            let i = tx.transaction_body.inputs.iter().next().unwrap();
            let entry = u
                .get_mut(&TxoRef(i.transaction_id, i.index as u32))
                .unwrap();
            let o: n::TransactionOutput = minicbor::decode(&entry.1).unwrap();
            let n::TransactionOutput::Legacy(legacy) = o else {
                panic!()
            };
            let pallas_primitives::alonzo::Value::Coin(coin) = legacy.amount else {
                panic!()
            };
            let o = n::TransactionOutput::PostAlonzo(
                n::PostAlonzoTransactionOutput {
                    address: legacy.address.clone(),
                    value: c::Value::Coin(coin),
                    datum_option: None,
                    script_ref: Some(pallas_codec::utils::CborWrap(s)),
                }
                .into(),
            );
            entry.1 = minicbor::to_vec(o).unwrap();
            let r = run(&tx, &u).unwrap();
            assert!(r[0].success, "{r:?}");
        }
    });
}
#[test]
fn native_registration_synthetic_validator_reads_redeemer() {
    fixture(|mut tx, mut u| {
        // ctx is Constr 0 [txInfo, redeemer, scriptInfo]. Require integer 42.
        let s = integer_validator(&field("ctx", 1), 42);
        replace_script(&mut tx, &mut u, Some(n::ScriptRef::PlutusV3Script(s)), true);
        for value in [42, 41] {
            change_redeemer(&mut tx, |_, v| {
                v.data = super::data::Data::integer(n::BigInt::Int(value.into()))
            });
            let r = run(&tx, &u).unwrap();
            assert_eq!(r[0].success, value == 42, "{r:?}");
        }
    });
}
#[test]
fn native_registration_features_and_protocols() {
    fixture(|tx, u| {
        for version in [(9, 0), (11, 0), (12, 1), (13, 0)] {
            let mut pp = params();
            let MultiEraProtocolParameters::Dijkstra(p) = &mut pp else {
                unreachable!()
            };
            p.protocol_version = version;
            error(
                evaluate_tx(&MultiEraTx::from_dijkstra(&tx), &pp, &u, &slots()),
                "protocol version (requires 12.0)",
            );
        }
        for feature in 1..15 {
            let mut changed = tx.clone();
            let mut b = (*changed.transaction_body).clone();
            let expected = match feature {
                1 => {
                    b.direct_deposits = Some(Default::default());
                    "evaluates"
                }
                2 => {
                    b.account_balance_intervals = Some(Default::default());
                    "evaluates"
                }
                3 => {
                    b.starting_account_balance_intervals = Some(Default::default());
                    "evaluates"
                }
                4 => {
                    let n::Certificate::Reg(registered, _) = &b.certificates.as_ref().unwrap()[0]
                    else {
                        unreachable!()
                    };
                    b.guards = Some(n::Guards::Credentials(
                        vec![registered.clone()].try_into().unwrap(),
                    ));
                    "script guards"
                }
                5 => {
                    b.treasury_value = Some(1);
                    "evaluates"
                }
                6 => {
                    b.donation = Some(1.try_into().unwrap());
                    "evaluates"
                }
                7 => {
                    b.certificates = Some(
                        vec![n::Certificate::UnReg(
                            n::StakeCredential::ScriptHash([0; 28].into()),
                            2000000,
                        )]
                        .try_into()
                        .unwrap(),
                    );
                    "MissingRequiredScript"
                }
                8 => {
                    let mut references = b.reference_inputs.clone().unwrap().to_vec();
                    references.push(b.inputs[0].clone());
                    b.reference_inputs = Some(references.try_into().unwrap());
                    "inputs that are also reference inputs"
                }
                9 => {
                    b.required_top_level_guards = Some(Default::default());
                    "evaluates"
                }
                10 => {
                    b.mint = Some(Default::default());
                    "evaluates"
                }
                11 => {
                    b.withdrawals = Some(Default::default());
                    "evaluates"
                }
                12 => {
                    b.voting_procedures = Some(Default::default());
                    "evaluates"
                }
                13 => {
                    b.validity_interval_start = Some(u64::MAX);
                    "Overflow"
                }
                _ => {
                    b.inputs = vec![b.inputs[0].clone(), b.inputs[0].clone()].into();
                    "duplicate input"
                }
            };
            changed.transaction_body = b.into();
            if expected == "evaluates" {
                assert!(run(&changed, &u).unwrap()[0].success);
            } else {
                error(run(&changed, &u), expected);
            }
        }
        let bytes =
            hex::decode(include_str!("../../../test_data/dijkstra-subtx.tx").trim()).unwrap();
        let batch = MultiEraTx::decode_for_era(Era::Dijkstra, &bytes).unwrap();
        error(
            evaluate_tx(&batch, &params(), &u, &slots()),
            "subtransaction redeemers",
        );
    });
}

// UPLC helpers are only for synthetic context-sensitive validators.
fn field(value: &str, index: usize) -> String {
    let mut list = format!("[(force (force (builtin sndPair))) [(builtin unConstrData) {value}]]");
    for _ in 0..index {
        list = format!("[(force (builtin tailList)) {list}]");
    }
    format!("[(force (builtin headList)) {list}]")
}
fn integer_validator(data: &str, expected: u64) -> n::PlutusScript<3> {
    let condition =
        format!("[[(builtin equalsInteger) [(builtin unIData) {data}]] (con integer {expected})]");
    script(&format!(
        "(program 1.1.0 (lam ctx (force [[[(force (builtin ifThenElse)) {condition}] (delay (con unit ()))] (delay (error))])))"
    ))
}
#[test]
fn native_guard_reference_hash_reaches_v3_script() {
    use pallas_codec::utils::{CborWrap, KeepRaw};
    use pallas_traverse::OriginalHash;
    // Nonminimal native CBOR, intentionally distinct from semantic re-encoding.
    let bytes = hex::decode(format!("980218068200581c{}", "02".repeat(28))).unwrap();
    let native: KeepRaw<'_, n::NativeScript> = minicbor::decode(&bytes).unwrap();
    let original_hash = native.original_hash();
    let canonical = minicbor::to_vec(&*native).unwrap();
    let canonical_hash = minicbor::decode::<KeepRaw<'_, n::NativeScript>>(&canonical)
        .unwrap()
        .original_hash();
    assert_ne!(original_hash, canonical_hash);
    for (expected, accepts) in [(original_hash, true), (canonical_hash, false)] {
        fixture(|mut tx, mut u| {
            let mut body = (*tx.transaction_body).clone();
            let view = pallas_traverse::MultiEraOutput::from_dijkstra(&body.outputs[0]);
            let carried = n::TransactionOutput::PostAlonzo(
                n::PostAlonzoTransactionOutput {
                    address: view.address().unwrap().to_vec().into(),
                    value: view.value().into_conway(),
                    datum_option: None,
                    script_ref: Some(CborWrap(n::ScriptRef::NativeScript(
                        native.clone().to_owned(),
                    ))),
                }
                .into(),
            );
            assert!(view.datum().is_none());
            let mut outputs = body.outputs.to_vec();
            outputs[0] = carried;
            body.outputs = pallas_codec::utils::MaybeIndefArray::Def(outputs);
            tx.transaction_body = body.into();
            let outputs = field(&field("ctx", 0), 2);
            let first = format!("[(force (builtin headList)) [(builtin unListData) {outputs}]]");
            let hash = field(&field(&first, 3), 0);
            let condition = format!(
                "[[(builtin equalsByteString) [(builtin unBData) {hash}]] (con bytestring #{expected})]"
            );
            let validator = script(&format!(
                "(program 1.1.0 (lam ctx (force [[[(force (builtin ifThenElse)) {condition}] (delay (con unit ()))] (delay (error))])))"
            ));
            replace_script(
                &mut tx,
                &mut u,
                Some(n::ScriptRef::PlutusV3Script(validator)),
                true,
            );
            assert_eq!(run(&tx, &u).unwrap()[0].success, accepts);
        });
    }
}

#[test]
fn native_post_bootstrap_context_reaches_script() {
    fixture(|mut tx, mut u| {
        // Active Certifying[1] -> Reg[1] -> Just[0] -> 2,000,000.
        let amount = field(&field(&field(&field("ctx", 2), 1), 1), 0);
        replace_script(
            &mut tx,
            &mut u,
            Some(n::ScriptRef::PlutusV3Script(integer_validator(
                &amount, 2000000,
            ))),
            true,
        );
        assert!(run(&tx, &u).unwrap()[0].success);
    });
}
#[test]
fn native_registration_resolves_synthetic_earlier_era_outputs() {
    use pallas_primitives::{alonzo, babbage};
    // Fresh synthetic outputs, not native captured CBOR with altered era
    // labels.
    let output = alonzo::TransactionOutput {
        address: [vec![0x60], vec![0x55; 28]].concat().into(),
        amount: alonzo::Value::Coin(50),
        datum_hash: None,
    };
    let earlier = [
        EraCbor(Era::Alonzo, minicbor::to_vec(&output).unwrap()),
        EraCbor(
            Era::Babbage,
            minicbor::to_vec(babbage::TransactionOutput::Legacy(output.clone().into())).unwrap(),
        ),
        EraCbor(
            Era::Conway,
            minicbor::to_vec(c::TransactionOutput::Legacy(output.into())).unwrap(),
        ),
    ];
    fixture(|mut tx, mut u| {
        // Synthetic phase-two-only transaction; signatures and balance are not
        // claims.
        replace_script(
            &mut tx,
            &mut u,
            Some(n::ScriptRef::PlutusV3Script(script(
                "(program 1.1.0 (lam ctx (con unit ())))",
            ))),
            true,
        );
        let key = TxoRef([0x77; 32].into(), 0);
        let mut body = (*tx.transaction_body).clone();
        body.inputs = vec![n::TransactionInput {
            transaction_id: key.0,
            index: 0,
        }]
        .try_into()
        .unwrap();
        tx.transaction_body = body.into();
        for output in earlier {
            let era = output.0;
            let bytes = output.1.clone();
            u.insert(key.clone(), output);
            assert!(run(&tx, &u).unwrap()[0].success);
            assert_eq!(u[&key].0, era);
            assert_eq!(u[&key].1, bytes);
        }
    });
}

#[test]
fn native_registration_excludes_collateral_and_unrelated_script_sources() {
    fixture(|mut tx, u| {
        let mut b = (*tx.transaction_body).clone();
        b.collateral = b.reference_inputs.take();
        tx.transaction_body = b.into();
        // The original script output is still in UTxO and is now collateral
        // only.
        error(run(&tx, &u), "MissingRequiredScript");
    });
}
#[test]
fn native_registration_invalid_script_encoding_and_witness_scripts() {
    fixture(|tx, u| {
        for (bytes, expected) in [(vec![1], "DecodeError"), (vec![0x41, 0xff], "FlatDecode")] {
            let mut tx = tx.clone();
            let mut u = u.clone();
            replace_script(
                &mut tx,
                &mut u,
                Some(n::ScriptRef::PlutusV3Script(n::PlutusScript(bytes.into()))),
                true,
            );
            error(run(&tx, &u), expected);
        }
        for language in [1, 2, 3] {
            let mut tx = tx.clone();
            let mut w = (*tx.transaction_witness_set).clone();
            match language {
                1 => {
                    w.plutus_v1_script =
                        Some(vec![n::PlutusScript(vec![0].into())].try_into().unwrap())
                }
                2 => {
                    w.plutus_v2_script =
                        Some(vec![n::PlutusScript(vec![0].into())].try_into().unwrap())
                }
                _ => {
                    w.plutus_v3_script =
                        Some(vec![n::PlutusScript(vec![0].into())].try_into().unwrap())
                }
            };
            tx.transaction_witness_set = w.into();
            error(run(&tx, &u), "DecodeError");
        }
    });
}

#[test]
fn native_registration_protocol12_bytestring_operand_boundary() {
    fixture(|mut tx, mut u| {
        // Build 131,072 bytes inside a small script. Protocol-12 semantics E
        // rejects this argument to blake2b_256 (limit 65,536 bytes).
        let mut body = "[(builtin blake2b_256) bytes]".to_string();
        for _ in 0..17 {
            body = format!("[(lam bytes {body}) [[(builtin appendByteString) bytes] bytes]]");
        }
        let source = format!(
            "(program 1.1.0 (lam ctx [(lam ignored (con unit ())) [(lam bytes {body}) (con bytestring #00)]]))"
        );
        replace_script(
            &mut tx,
            &mut u,
            Some(n::ScriptRef::PlutusV3Script(script(&source))),
            true,
        );
        change_redeemer(&mut tx, |_, v| {
            v.ex_units = n::ExUnits {
                mem: 1000000,
                steps: 1000000000,
            }
        });
        let r = run(&tx, &u).unwrap();
        assert!(
            !r[0].success,
            "protocol-12 must reject oversized builtin operand: {r:?}"
        );
    });
}

#[test]
#[ignore = "exports public extracted CLI comparison artifacts to MUSASHI_EVAL_EXPORT"]
fn export_registration_cli_comparison() {
    fixture(|mut tx, mut u| {
        let root = std::path::PathBuf::from(std::env::var("MUSASHI_EVAL_EXPORT").unwrap());
        if let Ok(source) = std::env::var("MUSASHI_EVAL_SCRIPT") {
            replace_script(
                &mut tx,
                &mut u,
                Some(n::ScriptRef::PlutusV3Script(script(&source))),
                true,
            );
            change_redeemer(&mut tx, |_, v| {
                v.ex_units = n::ExUnits {
                    mem: 16_500_000,
                    steps: 10_000_000_000,
                }
            });
        }
        let directory = root;
        std::fs::create_dir_all(&directory).unwrap();
        let write = |name: &str, value: serde_json::Value| {
            std::fs::write(
                directory.join(name),
                serde_json::to_vec_pretty(&value).unwrap(),
            )
            .unwrap();
        };
        assert!(tx.transaction_body.validity_interval_start.is_none());
        assert!(tx.transaction_body.ttl.is_none());
        println!(
            "original validity: {:?} {:?}",
            tx.transaction_body.validity_interval_start, tx.transaction_body.ttl
        );
        let body = &tx.transaction_body;
        let witnesses = &tx.transaction_witness_set;
        // The node mempool envelope has four elements; the captured block form
        // omits null auxiliary data. Original body and witness CBOR are
        // retained.
        let bytes = minicbor::to_vec((body, witnesses, tx.success, None::<u8>)).unwrap();
        write(
            "settings.tx.json",
            serde_json::json!({"type":"Tx DijkstraEra","description":"Extracted original settings registration; no submission","cborHex":hex::encode(bytes)}),
        );
        let mut outputs = serde_json::Map::new();
        for (reference, raw) in &u {
            let output = pallas_traverse::MultiEraOutput::decode(raw.0, &raw.1).unwrap();
            let script = match output.multi_era_script_ref() {
                Some(pallas_traverse::MultiEraScriptRef::Dijkstra(s)) => match &*s {
                    n::ScriptRef::PlutusV3Script(s) => {
                        serde_json::json!({"scriptLanguage":"PlutusScriptV3","script":{"type":"PlutusScriptV3","description":"Original captured script","cborHex":hex::encode(s.as_ref())}})
                    }
                    _ => panic!(),
                },
                None => serde_json::Value::Null,
                _ => panic!(),
            };
            outputs.insert(
                format!("{}#{}", reference.0, reference.1),
                serde_json::json!({
                    "address":output.address().unwrap().to_bech32().unwrap(),
                    "value":{"lovelace":output.value().coin()},"datum":null,"datumhash":null,
                    "inlineDatum":null,"inlineDatumhash":null,"referenceScript":script
                }),
            );
        }
        write("settings.utxos.json", outputs.into());
        let result = match run(&tx, &u) {
            Ok(report) => {
                serde_json::json!({"success":report[0].success,"memory":report[0].units.mem,"steps":report[0].units.steps,"failure":report[0].failure_message})
            }
            Err(error) => serde_json::json!({"error":format!("{error:?}")}),
        };
        write("pallas-result.json", result);
    });
}

#[path = "dijkstra_estimation_tests.rs"]
mod estimation_tests;

#[test]
fn native_builtin_reports_preserve_historical_time() {
    fixture(|tx, utxos| {
        let tx = MultiEraTx::from_dijkstra(&tx);
        let slots = slots();
        let time = crate::utils::DijkstraTimeContext::new(
            vec![crate::utils::EraTime {
                start_slot: slots.zero_slot,
                start_time_ms: slots.zero_time,
                slot_length_ms: slots.slot_length,
            }],
            crate::utils::ForecastHorizon::Unbounded,
        )
        .unwrap();
        let ordinary = estimate_tx_calls(&tx, &params(), &utxos, &slots).unwrap();
        let historical = estimate_tx_calls_with_time(&tx, &params(), &utxos, &time).unwrap();
        assert!(!ordinary.is_empty());
        assert_eq!(ordinary.len(), historical.len());
        for ((expected, calls), (actual, historical_calls)) in ordinary.iter().zip(&historical) {
            assert!(expected.success && actual.success);
            assert_eq!(expected.units, actual.units);
            assert!(!calls.is_empty());
            assert_eq!(calls, historical_calls);
        }
    });
}
