//! Synthetic derivatives of the unchanged registration capture; phase two only.
use super::*;

fn estimate(tx: &n::BlockTransaction<'_>, u: &UtxoMap) -> Result<EvalReport, Error> {
    estimate_tx(&MultiEraTx::from_dijkstra(tx), &params(), u, &slots())
}
fn unsigned(tx: &mut n::BlockTransaction<'_>) {
    let mut w = (*tx.transaction_witness_set).clone();
    w.vkeywitness = None;
    tx.transaction_witness_set = w.into();
}
fn exact(r: &EvalReport) {
    assert_eq!(r.len(), 1);
    assert_eq!((r[0].tag, r[0].index), (c::RedeemerTag::Cert, 0));
    assert!(r[0].success, "{r:?}");
    assert_eq!(
        r[0].units,
        n::ExUnits {
            mem: 18_485,
            steps: 4_805_428
        }
    );
    assert!(r[0].failure_message.is_none());
    assert!(r[0].logs.is_empty());
}
fn preserved(tx: &n::BlockTransaction<'_>, u: &UtxoMap) {
    let bytes = minicbor::to_vec(tx).unwrap();
    let hash = MultiEraTx::from_dijkstra(tx).hash();
    let inputs: Vec<_> = u
        .iter()
        .map(|(k, v)| (k.clone(), v.0, v.1.clone()))
        .collect();
    exact(&estimate(tx, u).unwrap());
    assert_eq!(bytes, minicbor::to_vec(tx).unwrap());
    assert_eq!(hash, MultiEraTx::from_dijkstra(tx).hash());
    for (k, era, bytes) in inputs {
        assert_eq!(u[&k].0, era);
        assert_eq!(u[&k].1, bytes);
    }
}
#[test]
fn estimation_unchanged_capture() {
    fixture(|tx, u| {
        exact(&run(&tx, &u).unwrap());
        preserved(&tx, &u);
    });
}
#[test]
fn estimation_unsigned_capture() {
    fixture(|mut tx, u| {
        unsigned(&mut tx);
        exact(&run(&tx, &u).unwrap());
        preserved(&tx, &u);
    });
}
#[test]
fn estimation_zero_budgets() {
    fixture(|mut tx, u| {
        change_redeemer(&mut tx, |_, v| v.ex_units = n::ExUnits { mem: 0, steps: 0 });
        let enforced = run(&tx, &u).unwrap();
        assert!(!enforced[0].success);
        assert!(
            enforced[0]
                .failure_message
                .as_ref()
                .unwrap()
                .contains("Out of budget")
        );
        preserved(&tx, &u);
    });
}
#[test]
fn estimation_insufficient_budgets() {
    fixture(|tx, u| {
        for budget in [
            n::ExUnits {
                mem: 18_484,
                steps: 4_805_428,
            },
            n::ExUnits {
                mem: 18_485,
                steps: 4_805_427,
            },
        ] {
            let mut tx = tx.clone();
            change_redeemer(&mut tx, |_, v| v.ex_units = budget);
            assert!(!run(&tx, &u).unwrap()[0].success);
            preserved(&tx, &u);
        }
    });
}
#[test]
fn estimation_unsigned_zero_budgets() {
    fixture(|mut tx, u| {
        unsigned(&mut tx);
        change_redeemer(&mut tx, |_, v| v.ex_units = n::ExUnits { mem: 0, steps: 0 });
        preserved(&tx, &u);
    });
}
#[test]
fn estimation_ignores_excessive_declared_budgets() {
    fixture(|mut tx, u| {
        change_redeemer(&mut tx, |_, v| {
            v.ex_units = n::ExUnits {
                mem: u64::MAX,
                steps: u64::MAX,
            }
        });
        error(run(&tx, &u), "declared transaction budget exceeds maximum");
        preserved(&tx, &u);
    });
}
fn with_limit(
    tx: &n::BlockTransaction<'_>,
    u: &UtxoMap,
    limit: n::ExUnits,
) -> Result<EvalReport, Error> {
    let mut pp = params();
    let MultiEraProtocolParameters::Dijkstra(p) = &mut pp else {
        unreachable!()
    };
    p.plutus.as_mut().unwrap().max_tx_ex_units = limit;
    estimate_tx(&MultiEraTx::from_dijkstra(tx), &pp, u, &slots())
}
#[test]
fn estimation_execution_limits() {
    fixture(|mut tx, u| {
        change_redeemer(&mut tx, |_, v| v.ex_units = n::ExUnits { mem: 0, steps: 0 });
        exact(
            &with_limit(
                &tx,
                &u,
                n::ExUnits {
                    mem: 18_485,
                    steps: 4_805_428,
                },
            )
            .unwrap(),
        );
        for limit in [
            n::ExUnits {
                mem: 18_484,
                steps: 4_805_428,
            },
            n::ExUnits {
                mem: 18_485,
                steps: 4_805_427,
            },
            n::ExUnits { mem: 0, steps: 0 },
        ] {
            let r = with_limit(&tx, &u, limit).unwrap();
            assert!(!r[0].success, "{r:?}");
            assert!(
                r[0].failure_message
                    .as_ref()
                    .unwrap()
                    .contains("Out of budget")
            );
            assert!(r[0].units.mem > limit.mem || r[0].units.steps > limit.steps);
        }
        error(
            with_limit(
                &tx,
                &u,
                n::ExUnits {
                    mem: u64::MAX,
                    steps: 1,
                },
            ),
            "execution limit overflow",
        );
        error(
            with_limit(
                &tx,
                &u,
                n::ExUnits {
                    mem: 1,
                    steps: u64::MAX,
                },
            ),
            "execution limit overflow",
        );
    });
}
#[test]
fn estimation_aggregate_boundaries_and_indices() {
    fixture(|mut tx, mut u| {
        replace_script(
            &mut tx,
            &mut u,
            Some(n::ScriptRef::PlutusV3Script(script(
                "(program 1.1.0 (lam ctx (con unit ())))",
            ))),
            true,
        );
        change_redeemer(&mut tx, |_, v| v.ex_units = n::ExUnits { mem: 0, steps: 0 });
        let single = estimate(&tx, &u).unwrap();
        assert!(single[0].success, "{single:?}");
        let units = single[0].units;
        let mut b = (*tx.transaction_body).clone();
        let cert = b.certificates.as_ref().unwrap()[0].clone();
        b.certificates = Some(
            vec![
                n::Certificate::Reg(n::StakeCredential::AddrKeyhash([0; 28].into()), 2_000_000),
                cert.clone(),
                cert,
            ]
            .try_into()
            .unwrap(),
        );
        tx.transaction_body = b.into();
        let mut w = (*tx.transaction_witness_set).clone();
        let value = w
            .redeemer
            .as_ref()
            .unwrap()
            .0
            .values()
            .next()
            .unwrap()
            .clone();
        w.redeemer = Some(
            n::Redeemers(
                [1, 2]
                    .into_iter()
                    .map(|index| {
                        (
                            n::RedeemersKey {
                                tag: n::RedeemerTag::Cert,
                                index,
                            },
                            value.clone(),
                        )
                    })
                    .collect(),
            )
            .into(),
        );
        tx.transaction_witness_set = w.into();
        let max = n::ExUnits {
            mem: units.mem * 2,
            steps: units.steps * 2,
        };
        for (limit, succeeds) in [
            (max, true),
            (
                n::ExUnits {
                    mem: max.mem - 1,
                    ..max
                },
                false,
            ),
            (
                n::ExUnits {
                    steps: max.steps - 1,
                    ..max
                },
                false,
            ),
        ] {
            let r = with_limit(&tx, &u, limit).unwrap();
            assert_eq!(r.len(), 2);
            for (i, entry) in r.iter().enumerate() {
                assert_eq!(
                    (entry.tag, entry.index),
                    (c::RedeemerTag::Cert, i as u32 + 1)
                );
            }
            assert!(r[0].success, "{r:?}");
            assert_eq!(r[0].units, units);
            assert_eq!(r[1].success, succeeds, "{r:?}");
            if succeeds {
                assert_eq!(r[1].units, units);
            } else {
                assert!(
                    r[1].failure_message
                        .as_ref()
                        .unwrap()
                        .contains("Out of budget")
                );
            }
        }
        let r = with_limit(&tx, &u, n::ExUnits { mem: 0, steps: 0 }).unwrap();
        assert!(r.iter().all(|x| {
            !x.success
                && x.failure_message
                    .as_ref()
                    .unwrap()
                    .contains("Out of budget")
        }));
    });
}
#[test]
fn estimation_missing_inputs_scripts_redeemers() {
    fixture(|tx, u| {
        for input in [
            &tx.transaction_body.inputs[0],
            &tx.transaction_body.reference_inputs.as_ref().unwrap()[0],
        ] {
            let mut u = u.clone();
            u.remove(&TxoRef(input.transaction_id, input.index as u32));
            error(estimate(&tx, &u), "ResolvedInputNotFound");
        }
        let mut missing = tx.clone();
        let mut w = (*missing.transaction_witness_set).clone();
        w.redeemer = None;
        missing.transaction_witness_set = w.into();
        error(estimate(&missing, &u), "RequiredRedeemersMismatch");
        let mut extra = tx.clone();
        change_redeemer(&mut extra, |k, _| k.index = 1);
        error(estimate(&extra, &u), "ExtraneousRedeemer");
        let mut tx = tx.clone();
        let mut u = u.clone();
        replace_script(&mut tx, &mut u, None, false);
        error(estimate(&tx, &u), "MissingRequiredScript");
    });
}
#[test]
fn estimation_script_failures_and_unsupported() {
    fixture(|tx, u| {
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
            let r = estimate(&tx, &u).unwrap();
            assert!(!r[0].success);
            assert!(r[0].failure_message.is_some(), "{r:?}");
            assert!(r[0].units.mem > 0 && r[0].units.steps > 0);
            assert!(r[0].logs.is_empty());
        }
        let mut tx = tx.clone();
        let mut u = u.clone();
        replace_script(
            &mut tx,
            &mut u,
            Some(n::ScriptRef::PlutusV3Script(script(
                "(program 1.1.0 (lam ctx [(builtin complementByteString) (con bytestring #00)]))",
            ))),
            true,
        );
        error(estimate(&tx, &u), "outside audited protocol-12 subset");
        let mut pp = params();
        let MultiEraProtocolParameters::Dijkstra(p) = &mut pp else {
            unreachable!()
        };
        p.protocol_version = (11, 0);
        error(
            estimate_tx(&MultiEraTx::from_dijkstra(&tx), &pp, &u, &slots()),
            "protocol version",
        );
    });
}

#[test]
fn estimation_preserves_context_hash_and_redeemer_data() {
    fixture(|mut tx, mut u| {
        // Compare the original body's hash in TxInfo with the hash in redeemer
        // data. The redeemer is outside the body, avoiding a self-reference.
        let txid = field(&field("ctx", 0), 11);
        let redeemer = field("ctx", 1);
        let source = format!(
            "(program 1.1.0 (lam ctx (force [[[(force (builtin ifThenElse)) [[(builtin equalsData) {txid}] {redeemer}]] (delay (con unit ()))] (delay (error))])))"
        );
        replace_script(
            &mut tx,
            &mut u,
            Some(n::ScriptRef::PlutusV3Script(script(&source))),
            true,
        );
        // Re-decode the synthetic body so OriginalHash has real preserved CBOR.
        let raw = minicbor::to_vec(&tx).unwrap();
        let mut tx: n::BlockTransaction<'_> = minicbor::decode(&raw).unwrap();
        let hash = MultiEraTx::from_dijkstra(&tx).hash();
        change_redeemer(&mut tx, |_, v| {
            v.data = n::PlutusData::BoundedBytes(hash.to_vec().into());
            v.ex_units = n::ExUnits { mem: 0, steps: 0 };
        });
        unsigned(&mut tx);
        let bytes = minicbor::to_vec(&tx).unwrap();
        let r = estimate(&tx, &u).unwrap();
        assert!(r[0].success, "{r:?}");
        assert_eq!(minicbor::to_vec(&tx).unwrap(), bytes);
        change_redeemer(&mut tx, |_, v| {
            v.data = n::PlutusData::BoundedBytes(vec![0; 32].into())
        });
        let r = estimate(&tx, &u).unwrap();
        assert!(!r[0].success);
        assert!(r[0].failure_message.is_some());
    });
}

#[test]
fn estimation_earlier_era_is_explicitly_unsupported() {
    let bytes = hex::decode(include_str!("../../../test_data/conway1.tx").trim()).unwrap();
    let tx = MultiEraTx::decode_for_era(Era::Conway, &bytes).unwrap();
    error(
        estimate_tx(&tx, &params(), &UtxoMap::new(), &slots()),
        "WrongEra",
    );
}
