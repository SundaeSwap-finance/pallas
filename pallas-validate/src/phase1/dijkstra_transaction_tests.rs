use super::*;
#[test]
fn dijkstra_observed_metadata_reaches_input_validation() {
    let raw = hex::decode(
        include_str!("../../../test_data/musashi-dijkstra-validation/order.tx.hex").trim(),
    )
    .unwrap();
    let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &raw).unwrap();
    assert_eq!(
        tx.hash().to_string(),
        "11ef408b2575189a212b9048472fe445e303f5f0d1382769aae086f3728dc656"
    );
    // Deliberately missing state isolates the unsupported-feature gate, not acceptance.
    let result = validate_txs(
        std::slice::from_ref(&tx),
        &dijkstra_tests::env(),
        &UTxOs::new(),
        &mut CertState::default(),
    );
    assert_eq!(format!("{result:?}"), "Err(PostAlonzo(InputNotInUTxO))");
}

#[test]
fn dijkstra_observed_order_valid_context() {
    let raw = hex::decode(
        include_str!("../../../test_data/musashi-dijkstra-validation/order.tx.hex").trim(),
    )
    .unwrap();
    let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &raw).unwrap();
    let producer = hex::decode(
        include_str!("../../../test_data/musashi-dijkstra-validation/order-producer.body.hex")
            .trim(),
    )
    .unwrap();
    let body: pallas_primitives::dijkstra::TransactionBody =
        pallas_codec::minicbor::decode(&producer).unwrap();
    assert_eq!(
        pallas_crypto::hash::Hasher::<256>::hash(&producer),
        tx.inputs()[0].hash().to_owned()
    );
    let input = hex::decode(
        include_str!("../../../test_data/musashi-dijkstra-validation/order.input.hex").trim(),
    )
    .unwrap();
    assert_eq!(
        pallas_codec::minicbor::to_vec(&body.outputs[2]).unwrap(),
        input
    );
    let utxos = [(
        tx.inputs()[0].to_owned(),
        pallas_traverse::MultiEraOutput::decode(Era::Dijkstra, &input).unwrap(),
    )]
    .into_iter()
    .collect();
    // Constructed replay context: historical parameters and a stipulated later slot.
    // No historical/current acceptance is claimed; no time bounds or certificates used.
    // The producer proves the input bytes, not its current unspent status.
    let mut env = dijkstra_tests::env();
    env.block_slot = 2_100_000;
    let result = validate_txs(
        std::slice::from_ref(&tx),
        &env,
        &utxos,
        &mut CertState::default(),
    );
    assert!(result.is_ok(), "{result:?}");
}

use pallas_codec::{
    minicbor,
    utils::{CborWrap, KeepRaw, Nullable},
};
use pallas_crypto::hash::{Hash, Hasher};
use pallas_primitives::{conway as c, dijkstra as n};
use pallas_traverse::{MultiEraInput, MultiEraOutput};
use std::collections::BTreeMap;

fn run(
    tx: &n::BlockTransaction<'_>,
    inputs: &[(n::TransactionInput, n::TransactionOutput<'_>)],
    env: &Environment,
    state: &CertState,
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
    validate_txs(
        &[MultiEraTx::from_dijkstra(tx)],
        env,
        &utxos,
        &mut state.clone(),
    )
}
fn output_mut<'a, 'b>(
    o: &'a mut n::TransactionOutput<'b>,
) -> &'a mut KeepRaw<'b, n::PostAlonzoTransactionOutput<'b>> {
    let n::TransactionOutput::PostAlonzo(o) = o else {
        panic!()
    };
    o
}
fn auxiliary(tx: &mut n::BlockTransaction<'_>, text: &str) {
    tx.auxiliary_data = Nullable::Some(
        n::AuxiliaryData::Shelley(BTreeMap::from([(674, n::Metadatum::Text(text.into()))])).into(),
    );
    let Nullable::Some(aux) = &tx.auxiliary_data else {
        panic!()
    };
    tx.transaction_body.auxiliary_data_hash =
        Some(Hasher::<256>::hash(&minicbor::to_vec(aux).unwrap()));
    dijkstra_tests::sign(tx);
}
#[test]
fn dijkstra_metadata_commitment_and_limits() {
    dijkstra_tests::synthetic(|mut tx, input| {
        let inputs = vec![(tx.transaction_body.inputs[0].clone(), input)];
        let check = |tx: &n::BlockTransaction<'_>| {
            run(tx, &inputs, &dijkstra_tests::env(), &CertState::default())
        };
        auxiliary(&mut tx, "metadata test");
        assert!(check(&tx).is_ok());
        let valid = tx.clone();
        tx.transaction_body.auxiliary_data_hash = None;
        dijkstra_tests::sign(&mut tx);
        dijkstra_tests::error(check(&tx), "PostAlonzo(MetadataHash)");
        tx = valid.clone();
        tx.auxiliary_data = Nullable::Null;
        dijkstra_tests::error(check(&tx), "PostAlonzo(MetadataHash)");
        tx = valid.clone();
        tx.transaction_body.auxiliary_data_hash = Some(Hash::from([0; 32]));
        dijkstra_tests::sign(&mut tx);
        dijkstra_tests::error(check(&tx), "PostAlonzo(MetadataHash)");
        tx = valid;
        auxiliary(&mut tx, &"x".repeat(64));
        assert!(check(&tx).is_ok());
        auxiliary(&mut tx, &"x".repeat(65));
        dijkstra_tests::error(check(&tx), "DijkstraInvalidMetadata");
    });
}
fn value(coin: u64, policy: Hash<28>, quantity: u64) -> c::Value {
    c::Value::Multiasset(
        coin,
        BTreeMap::from([(
            policy,
            BTreeMap::from([(b"token".to_vec().into(), quantity.try_into().unwrap())]),
        )]),
    )
}
#[test]
fn dijkstra_multiasset_conservation_and_script_output() {
    dijkstra_tests::synthetic(|mut tx, mut input| {
        let policy = Hash::from([8; 28]);
        let coin = MultiEraOutput::from_dijkstra(&input).value().coin();
        output_mut(&mut input).value = value(coin, policy, 7);
        let fee = tx.transaction_body.fee;
        let output = output_mut(first_output(&mut tx));
        output.value = value(coin - fee, policy, 7);
        output.address = pallas_addresses::ShelleyAddress::new(
            pallas_addresses::Network::Testnet,
            pallas_addresses::ShelleyPaymentPart::Script(Hash::from([9; 28])),
            pallas_addresses::ShelleyDelegationPart::Null,
        )
        .to_vec()
        .into();
        output.datum_option = Some(
            c::DatumOption::Data(CborWrap(
                n::PlutusData::BigInt(n::BigInt::Int(42.into())).into(),
            ))
            .into(),
        );
        dijkstra_tests::sign(&mut tx);
        let inputs = vec![(tx.transaction_body.inputs[0].clone(), input)];
        assert!(
            run(&tx, &inputs, &dijkstra_tests::env(), &CertState::default()).is_ok(),
            "script-locked output must not execute a script"
        );
        output_mut(first_output(&mut tx)).value = value(coin - fee, policy, 8);
        dijkstra_tests::sign(&mut tx);
        dijkstra_tests::error(
            run(&tx, &inputs, &dijkstra_tests::env(), &CertState::default()),
            "PostAlonzo(PreservationOfValue)",
        );
    });
}

#[cfg(feature = "phase2")]
mod scripts {
    use super::*;
    use crate::utils::{EraCbor, TxoRef, UtxoMap};
    use pallas_addresses::Address;
    use pallas_traverse::ComputeHash;
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
    fn environment() -> Environment {
        super::super::dijkstra_registration_tests::params()
    }
    fn seal(tx: &mut n::BlockTransaction<'_>, env: &Environment) {
        let MultiEraProtocolParameters::Dijkstra(pp) = &env.prot_params else {
            panic!()
        };
        let mut raw =
            minicbor::to_vec(tx.transaction_witness_set.redeemer.as_ref().unwrap()).unwrap();
        if let Some(datums) = &tx.transaction_witness_set.plutus_data {
            raw.extend(minicbor::to_vec(datums).unwrap());
        }
        raw.extend(
            minicbor::to_vec(c::LanguageViews(BTreeMap::from([(
                2,
                pp.plutus.as_ref().unwrap().cost_model_v3.clone(),
            )])))
            .unwrap(),
        );
        tx.transaction_body.script_data_hash = Some(Hasher::<256>::hash(&raw));
        dijkstra_tests::sign(tx);
    }
    fn evaluate(
        tx: &n::BlockTransaction<'_>,
        inputs: &[(n::TransactionInput, n::TransactionOutput<'_>)],
        env: &Environment,
    ) -> Result<crate::phase2::EvalReport, crate::phase2::error::Error> {
        let map: UtxoMap = inputs
            .iter()
            .map(|(i, o)| {
                (
                    TxoRef(i.transaction_id, i.index as u32),
                    EraCbor(Era::Dijkstra, minicbor::to_vec(o).unwrap()),
                )
            })
            .collect();
        crate::phase2::evaluate_tx(
            &MultiEraTx::from_dijkstra(tx),
            &env.prot_params,
            &map,
            &crate::phase2::script_context::SlotConfig {
                zero_slot: 0,
                zero_time: 1788739200000,
                slot_length: 1000,
            },
        )
    }
    fn case(
        reference: bool,
        source: &str,
        test: impl FnOnce(
            n::BlockTransaction<'_>,
            Vec<(n::TransactionInput, n::TransactionOutput<'_>)>,
            Environment,
            CertState,
        ),
    ) {
        dijkstra_tests::synthetic(|mut tx, input| {
            let env = environment();
            let s = script(source);
            let hash = s.compute_hash();
            let original = tx.transaction_body.inputs[0].clone();
            let coin = MultiEraOutput::from_dijkstra(&input).value().coin();
            let script_input = n::TransactionInput {
                transaction_id: Hash::from([255; 32]),
                index: 1,
            };
            let mut locked = input.clone();
            let o = output_mut(&mut locked);
            o.address = pallas_addresses::ShelleyAddress::new(
                pallas_addresses::Network::Testnet,
                pallas_addresses::ShelleyPaymentPart::Script(hash),
                pallas_addresses::ShelleyDelegationPart::Null,
            )
            .to_vec()
            .into();
            o.value = value(5_000_000, hash, 7);
            o.datum_option = Some(
                c::DatumOption::Data(CborWrap(
                    n::PlutusData::BigInt(n::BigInt::Int(42.into())).into(),
                ))
                .into(),
            );
            tx.transaction_body.inputs = vec![script_input.clone(), original.clone()].into();
            tx.transaction_body.fee = 1_000_000;
            tx.transaction_body.ttl = None;
            output_mut(first_output(&mut tx)).value = value(coin + 4_000_000, hash, 12);
            tx.transaction_body.mint = Some(BTreeMap::from([(
                hash,
                BTreeMap::from([(b"token".to_vec().into(), 5i64.try_into().unwrap())]),
            )]));
            tx.transaction_body.withdrawals = Some(BTreeMap::from([(
                pallas_addresses::StakeAddress::new(
                    pallas_addresses::Network::Testnet,
                    pallas_addresses::StakePayload::Script(hash),
                )
                .to_vec()
                .into(),
                0,
            )]));
            tx.transaction_body.collateral = n::NonEmptySet::from_vec(vec![original.clone()]);
            let mut inputs = vec![(original, input.clone()), (script_input, locked)];
            if reference {
                let reference = n::TransactionInput {
                    transaction_id: Hash::from([2; 32]),
                    index: 0,
                };
                let mut output = input.clone();
                output_mut(&mut output).script_ref =
                    Some(CborWrap(n::ScriptRef::PlutusV3Script(s)));
                tx.transaction_body.reference_inputs =
                    n::NonEmptySet::from_vec(vec![reference.clone()]);
                inputs.push((reference, output));
            } else {
                tx.transaction_witness_set.plutus_v3_script = n::NonEmptySet::from_vec(vec![s]);
            }
            tx.transaction_witness_set.redeemer = Some(
                n::Redeemers(BTreeMap::from([
                    (
                        n::RedeemersKey {
                            tag: n::RedeemerTag::Spend,
                            index: 1,
                        },
                        n::RedeemersValue {
                            data: n::PlutusData::BigInt(n::BigInt::Int(0.into())),
                            ex_units: n::ExUnits {
                                mem: 50_000,
                                steps: 5_000_000,
                            },
                        },
                    ),
                    (
                        n::RedeemersKey {
                            tag: n::RedeemerTag::Mint,
                            index: 0,
                        },
                        n::RedeemersValue {
                            data: n::PlutusData::BigInt(n::BigInt::Int(0.into())),
                            ex_units: n::ExUnits {
                                mem: 50_000,
                                steps: 5_000_000,
                            },
                        },
                    ),
                    (
                        n::RedeemersKey {
                            tag: n::RedeemerTag::Reward,
                            index: 0,
                        },
                        n::RedeemersValue {
                            data: n::PlutusData::BigInt(n::BigInt::Int(0.into())),
                            ex_units: n::ExUnits {
                                mem: 50_000,
                                steps: 5_000_000,
                            },
                        },
                    ),
                ]))
                .into(),
            );
            let mut state = CertState::default();
            state
                .dijkstra_account_balances
                .insert(n::StakeCredential::ScriptHash(hash), Some(0));
            seal(&mut tx, &env);
            test(tx, inputs, env, state);
        });
    }
    const PASS: &str = "(program 1.1.0 (lam ctx (con unit ())))";
    #[test]
    fn dijkstra_spend_mint_reward_both_script_sources() {
        for reference in [false, true] {
            case(reference, PASS, |mut tx, inputs, env, state| {
                let result = run(&tx, &inputs, &env, &state);
                assert!(result.is_ok(), "{result:?}");
                let report = evaluate(&tx, &inputs, &env).unwrap();
                assert_eq!(report.len(), 3);
                assert!(report.iter().all(|r| r.success), "{report:?}");
                let policy = *tx
                    .transaction_body
                    .mint
                    .as_ref()
                    .unwrap()
                    .keys()
                    .next()
                    .unwrap();
                tx.transaction_body.mint = Some(BTreeMap::from([(
                    policy,
                    BTreeMap::from([(b"token".to_vec().into(), (-5i64).try_into().unwrap())]),
                )]));
                let coin = MultiEraOutput::from_dijkstra(&tx.transaction_body.outputs[0])
                    .value()
                    .coin();
                output_mut(first_output(&mut tx)).value = value(coin, policy, 2);
                seal(&mut tx, &env);
                let result = run(&tx, &inputs, &env, &state);
                assert!(result.is_ok(), "burn: {result:?}");
                assert!(
                    evaluate(&tx, &inputs, &env)
                        .unwrap()
                        .iter()
                        .all(|r| r.success)
                );
            });
        }
    }
    #[test]
    fn dijkstra_missing_state_and_script_authorization() {
        case(false, PASS, |tx, inputs, env, state| {
            assert!(
                format!("{:?}", run(&tx, &inputs, &env, &CertState::default()))
                    .contains("DijkstraAccountStateUnavailable")
            );
            let mut changed = tx.clone();
            changed.transaction_witness_set.plutus_v3_script = None;
            dijkstra_tests::error(
                run(&changed, &inputs, &env, &state),
                "PostAlonzo(ScriptWitnessMissing)",
            );
            assert!(evaluate(&changed, &inputs, &env).is_err());
            let mut changed = tx.clone();
            changed.transaction_witness_set.vkeywitness = None;
            dijkstra_tests::error(
                run(&changed, &inputs, &env, &state),
                "PostAlonzo(VKWitnessMissing)",
            );
            let mut changed = tx.clone();
            changed.transaction_body.collateral = None;
            seal(&mut changed, &env);
            dijkstra_tests::error(
                run(&changed, &inputs, &env, &state),
                "PostAlonzo(CollateralMissing)",
            );
            let mut changed = tx.clone();
            changed.transaction_body.script_data_hash = None;
            dijkstra_tests::sign(&mut changed);
            dijkstra_tests::error(
                run(&changed, &inputs, &env, &state),
                "PostAlonzo(ScriptIntegrityHash)",
            );
        });
    }
    #[test]
    fn dijkstra_exact_redeemer_pointers() {
        case(false, PASS, |tx, inputs, env, state| {
            for tag in [
                n::RedeemerTag::Spend,
                n::RedeemerTag::Mint,
                n::RedeemerTag::Reward,
            ] {
                let mut changed = tx.clone();
                let key = n::RedeemersKey {
                    tag,
                    index: if tag == n::RedeemerTag::Spend { 1 } else { 0 },
                };
                let mut rs = (**changed.transaction_witness_set.redeemer.as_ref().unwrap()).clone();
                rs.0.remove(&key);
                changed.transaction_witness_set.redeemer = Some(rs.into());
                seal(&mut changed, &env);
                dijkstra_tests::error(
                    run(&changed, &inputs, &env, &state),
                    "PostAlonzo(RedeemerMissing)",
                );
                assert!(evaluate(&changed, &inputs, &env).is_err());
            }
            let mut changed = tx.clone();
            let mut rs = (**changed.transaction_witness_set.redeemer.as_ref().unwrap()).clone();
            let value = rs.0.values().next().unwrap().clone();
            rs.0.insert(
                n::RedeemersKey {
                    tag: n::RedeemerTag::Spend,
                    index: 0,
                },
                value,
            );
            changed.transaction_witness_set.redeemer = Some(rs.into());
            seal(&mut changed, &env);
            dijkstra_tests::error(
                run(&changed, &inputs, &env, &state),
                "PostAlonzo(UnneededRedeemer)",
            );
            assert!(evaluate(&changed, &inputs, &env).is_err());
        });
    }
    #[test]
    fn dijkstra_budget_and_failing_scripts() {
        case(
            false,
            "(program 1.1.0 (lam ctx (error)))",
            |tx, inputs, env, state| {
                assert!(run(&tx, &inputs, &env, &state).is_ok());
                assert!(
                    evaluate(&tx, &inputs, &env)
                        .unwrap()
                        .iter()
                        .all(|r| !r.success)
                );
            },
        );
        case(false, PASS, |mut tx, inputs, env, state| {
            let mut rs = (**tx.transaction_witness_set.redeemer.as_ref().unwrap()).clone();
            for r in rs.0.values_mut() {
                r.ex_units = n::ExUnits { mem: 0, steps: 0 };
            }
            tx.transaction_witness_set.redeemer = Some(rs.into());
            seal(&mut tx, &env);
            assert!(run(&tx, &inputs, &env, &state).is_ok());
            assert!(
                evaluate(&tx, &inputs, &env)
                    .unwrap()
                    .iter()
                    .all(|r| !r.success)
            );
            let mut rs = (**tx.transaction_witness_set.redeemer.as_ref().unwrap()).clone();
            for r in rs.0.values_mut() {
                r.ex_units = n::ExUnits {
                    mem: u64::MAX,
                    steps: 0,
                };
            }
            tx.transaction_witness_set.redeemer = Some(rs.into());
            seal(&mut tx, &env);
            assert!(run(&tx, &inputs, &env, &state).is_err());
            assert!(evaluate(&tx, &inputs, &env).is_err());
        });
    }
    #[test]
    fn dijkstra_datums_and_integrity_are_independent() {
        case(false, PASS, |mut tx, mut inputs, env, state| {
            let datum = n::PlutusData::BigInt(n::BigInt::Int(42.into()));
            let hash = Hasher::<256>::hash(&minicbor::to_vec(&datum).unwrap());
            output_mut(&mut inputs[1].1).datum_option = Some(c::DatumOption::Hash(hash).into());
            dijkstra_tests::error(run(&tx, &inputs, &env, &state), "PostAlonzo(DatumMissing)");
            assert!(evaluate(&tx, &inputs, &env).is_err());
            tx.transaction_witness_set.plutus_data = Some(
                n::NonEmptySet::from_vec(vec![datum.clone().into()])
                    .unwrap()
                    .into(),
            );
            seal(&mut tx, &env);
            assert!(run(&tx, &inputs, &env, &state).is_ok());
            assert!(
                evaluate(&tx, &inputs, &env)
                    .unwrap()
                    .iter()
                    .all(|r| r.success)
            );
            let valid = tx.clone();
            tx.transaction_body.script_data_hash = Some(Hash::from([3; 32]));
            dijkstra_tests::sign(&mut tx);
            dijkstra_tests::error(
                run(&tx, &inputs, &env, &state),
                "PostAlonzo(ScriptIntegrityHash)",
            );
            tx = valid;
            tx.transaction_witness_set.plutus_data = Some(
                n::NonEmptySet::from_vec(vec![
                    n::PlutusData::BigInt(n::BigInt::Int(43.into())).into(),
                ])
                .unwrap()
                .into(),
            );
            seal(&mut tx, &env);
            dijkstra_tests::error(run(&tx, &inputs, &env, &state), "PostAlonzo(UnneededDatum)");
        });
    }
    #[test]
    fn dijkstra_reward_order_and_explicit_account_balance() {
        case(false, PASS, |mut tx, inputs, env, mut state| {
            let Address::Shelley(address) = MultiEraOutput::from_dijkstra(&inputs[0].1)
                .address()
                .unwrap()
            else {
                panic!()
            };
            let pallas_addresses::ShelleyPaymentPart::Key(hash) = address.payment() else {
                panic!()
            };
            let account = pallas_addresses::StakeAddress::new(
                pallas_addresses::Network::Testnet,
                pallas_addresses::StakePayload::Stake(*hash),
            )
            .to_vec();
            tx.transaction_body
                .withdrawals
                .as_mut()
                .unwrap()
                .insert(account.into(), 0);
            state
                .dijkstra_account_balances
                .insert(n::StakeCredential::AddrKeyhash(*hash), Some(0));
            seal(&mut tx, &env);
            assert!(run(&tx, &inputs, &env, &state).is_ok());
            assert!(
                evaluate(&tx, &inputs, &env)
                    .unwrap()
                    .iter()
                    .all(|r| r.success)
            );
            // Raw address bytes sort the key first; ledger ordering keeps Reward[0] on the script.
            let mut rs = (**tx.transaction_witness_set.redeemer.as_ref().unwrap()).clone();
            let r =
                rs.0.remove(&n::RedeemersKey {
                    tag: n::RedeemerTag::Reward,
                    index: 0,
                })
                .unwrap();
            rs.0.insert(
                n::RedeemersKey {
                    tag: n::RedeemerTag::Reward,
                    index: 1,
                },
                r,
            );
            tx.transaction_witness_set.redeemer = Some(rs.into());
            seal(&mut tx, &env);
            dijkstra_tests::error(
                run(&tx, &inputs, &env, &state),
                "PostAlonzo(RedeemerMissing)",
            );
            assert!(evaluate(&tx, &inputs, &env).is_err());
        });
        case(false, PASS, |tx, inputs, env, mut state| {
            for balance in [None, Some(1)] {
                *state.dijkstra_account_balances.values_mut().next().unwrap() = balance;
                assert!(
                    format!("{:?}", run(&tx, &inputs, &env, &state))
                        .contains("DijkstraInvalidWithdrawal")
                );
            }
        });
    }
    #[test]
    fn dijkstra_collateral_assets_and_annotations() {
        case(false, PASS, |mut tx, mut inputs, env, state| {
            let id = n::TransactionInput {
                transaction_id: Hash::from([12; 32]),
                index: 0,
            };
            let mut collateral = inputs[0].1.clone();
            output_mut(&mut collateral).value = value(3_000_000, Hash::from([10; 28]), 3);
            let returned = n::TransactionOutput::PostAlonzo(
                n::PostAlonzoTransactionOutput {
                    address: MultiEraOutput::from_dijkstra(&collateral)
                        .address()
                        .unwrap()
                        .to_vec()
                        .into(),
                    value: value(1_500_000, Hash::from([10; 28]), 3),
                    datum_option: None,
                    script_ref: None,
                }
                .into(),
            );
            inputs.push((id.clone(), collateral));
            tx.transaction_body.collateral = n::NonEmptySet::from_vec(vec![id]);
            tx.transaction_body.collateral_return = Some(returned);
            tx.transaction_body.total_collateral = Some(1_500_000);
            seal(&mut tx, &env);
            let result = run(&tx, &inputs, &env, &state);
            assert!(result.is_ok(), "{result:?}");
            let valid = tx.clone();
            tx.transaction_body.total_collateral = Some(1_499_999);
            seal(&mut tx, &env);
            dijkstra_tests::error(
                run(&tx, &inputs, &env, &state),
                "PostAlonzo(CollateralAnnotation)",
            );
            tx = valid.clone();
            output_mut(tx.transaction_body.collateral_return.as_mut().unwrap()).value =
                value(1_500_000, Hash::from([10; 28]), 4);
            seal(&mut tx, &env);
            dijkstra_tests::error(
                run(&tx, &inputs, &env, &state),
                "PostAlonzo(NonLovelaceCollateral)",
            );
            tx = valid;
            output_mut(tx.transaction_body.collateral_return.as_mut().unwrap()).value =
                value(1_500_001, Hash::from([10; 28]), 3);
            tx.transaction_body.total_collateral = Some(1_499_999);
            seal(&mut tx, &env);
            dijkstra_tests::error(
                run(&tx, &inputs, &env, &state),
                "PostAlonzo(CollateralMinLovelace)",
            );
        });
    }
    #[test]
    fn dijkstra_fee_budget_and_reference_boundaries() {
        case(false, PASS, |mut tx, inputs, env, state| {
            let MultiEraProtocolParameters::Dijkstra(pp) = &env.prot_params else {
                panic!()
            };
            let coin = MultiEraOutput::from_dijkstra(&tx.transaction_body.outputs[0])
                .value()
                .coin()
                + tx.transaction_body.fee;
            let policy = *tx
                .transaction_body
                .mint
                .as_ref()
                .unwrap()
                .keys()
                .next()
                .unwrap();
            for _ in 0..3 {
                let size = minicbor::to_vec(tx.to_mempool_transaction()).unwrap().len() as u64;
                tx.transaction_body.fee =
                    size * u64::from(pp.minfee_a) + u64::from(pp.minfee_b) + 9737;
                let out_coin = coin - tx.transaction_body.fee;
                output_mut(first_output(&mut tx)).value = value(out_coin, policy, 12);
                seal(&mut tx, &env);
            }
            let result = run(&tx, &inputs, &env, &state);
            assert!(result.is_ok(), "fee boundary: {result:?}");
            tx.transaction_body.fee -= 1;
            let out_coin = coin - tx.transaction_body.fee;
            output_mut(first_output(&mut tx)).value = value(out_coin, policy, 12);
            seal(&mut tx, &env);
            dijkstra_tests::error(run(&tx, &inputs, &env, &state), "PostAlonzo(FeeBelowMin)");
        });
        case(true, PASS, |tx, mut inputs, mut env, state| {
            inputs.pop();
            dijkstra_tests::error(
                run(&tx, &inputs, &env, &state),
                "PostAlonzo(ReferenceInputNotInUTxO)",
            );
            assert!(evaluate(&tx, &inputs, &env).is_err());
            let MultiEraProtocolParameters::Dijkstra(pp) = &mut env.prot_params else {
                panic!()
            };
            pp.plutus = None;
            // Missing reference still takes precedence over fee parameters.
            assert!(run(&tx, &inputs, &env, &state).is_err());
        });
    }
    #[test]
    fn dijkstra_mint_without_policy_rejects() {
        dijkstra_tests::synthetic(|mut tx, input| {
            let policy = Hash::from([8; 28]);
            let coin = MultiEraOutput::from_dijkstra(&tx.transaction_body.outputs[0])
                .value()
                .coin();
            output_mut(first_output(&mut tx)).value = value(coin, policy, 7);
            tx.transaction_body.mint = Some(BTreeMap::from([(
                policy,
                BTreeMap::from([(b"token".to_vec().into(), 7i64.try_into().unwrap())]),
            )]));
            dijkstra_tests::sign(&mut tx);
            let inputs = vec![(tx.transaction_body.inputs[0].clone(), input)];
            dijkstra_tests::error(
                run(&tx, &inputs, &environment(), &CertState::default()),
                "PostAlonzo(ScriptWitnessMissing)",
            );
        });
    }

    fn captured_batch(
        test: impl FnOnce(
            n::BlockTransaction<'_>,
            Vec<(n::TransactionInput, n::TransactionOutput<'_>)>,
            Environment,
            CertState,
        ),
    ) {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../test_data/musashi-dijkstra-validation");
        let raw = hex::decode(
            std::fs::read_to_string(base.join("mint-batch.tx.hex"))
                .unwrap()
                .trim(),
        )
        .unwrap();
        let view = MultiEraTx::decode_for_era(Era::Dijkstra, &raw).unwrap();
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(base.join("mint-batch-inputs.json")).unwrap(),
        )
        .unwrap();
        let raws: Vec<_> = manifest
            .as_object()
            .unwrap()
            .keys()
            .map(|name| {
                (
                    name,
                    hex::decode(
                        std::fs::read_to_string(base.join("batch-inputs").join(name))
                            .unwrap()
                            .trim(),
                    )
                    .unwrap(),
                )
            })
            .collect();
        let inputs = raws
            .iter()
            .map(|(name, raw)| {
                let parts: Vec<_> = name.split('.').collect();
                (
                    n::TransactionInput {
                        transaction_id: parts[0].parse().unwrap(),
                        index: parts[1].parse().unwrap(),
                    },
                    minicbor::decode::<n::TransactionOutput>(raw).unwrap(),
                )
            })
            .collect();
        let tx = view.as_dijkstra().unwrap();
        let mut state = CertState::default();
        {
            let prestate: serde_json::Value = serde_json::from_str(include_str!(
                "../../../test_data/musashi-dijkstra-validation/account-state.json"
            ))
            .unwrap();
            for (hash, account) in prestate["accounts"].as_object().unwrap() {
                assert_eq!(account["registered"], true);
                state.dijkstra_account_balances.insert(
                    n::StakeCredential::ScriptHash(hash.parse().unwrap()),
                    Some(account["balance"].as_u64().unwrap()),
                );
            }
        }
        let mut env = environment();
        env.block_slot = 1404987;
        test(tx.clone(), inputs, env, state);
    }
    #[test]
    fn dijkstra_captured_mint_batch_phase_one() {
        captured_batch(|tx, inputs, env, state| {
            let one = run(&tx, &inputs, &env, &state);
            assert!(one.is_ok(), "phase one: {one:?}");
        });
    }
    #[test]
    fn dijkstra_captured_mint_batch_phase_two() {
        captured_batch(|tx, inputs, env, _| {
            let report = evaluate(&tx, &inputs, &env).expect("native Plutus V3 evaluation");
            println!("captured Dijkstra transaction: {report:?}");
            let redeemers = tx.transaction_witness_set.redeemer.as_ref().unwrap();
            assert_eq!(report.len(), redeemers.len());
            for r in report {
                assert!(r.success, "{r:?}");
                let (key, declared) = redeemers
                    .iter()
                    .find(|(key, _)| key.tag as u8 == r.tag as u8 && key.index == r.index)
                    .unwrap();
                assert_eq!(
                    r.units, declared.ex_units,
                    "exact original builder budget for {key:?}"
                );
            }
        });
    }
    #[test]
    #[ignore = "exports public offline CLI comparison inputs to DIJKSTRA_FIXTURE_EXPORT"]
    fn export_dijkstra_cli_comparison() {
        use pallas_primitives::ToCanonicalJson;
        use serde_json::json;
        let dir = std::path::PathBuf::from(std::env::var("DIJKSTRA_FIXTURE_EXPORT").unwrap());
        std::fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, value: serde_json::Value| {
            std::fs::write(dir.join(name), serde_json::to_vec_pretty(&value).unwrap()).unwrap()
        };
        captured_batch(|tx, inputs, env, _| {
            assert!(
                tx.transaction_body.ttl.is_none()
                    && tx.transaction_body.validity_interval_start.is_none()
            );
            write(
                "mint-batch.tx.json",
                json!({"type":"Tx DijkstraEra","description":"Unchanged captured native transaction; offline evaluation only","cborHex":hex::encode(minicbor::to_vec(tx.to_mempool_transaction()).unwrap())}),
            );
            let mut outputs = serde_json::Map::new();
            for (reference, raw) in &inputs {
                let output = MultiEraOutput::from_dijkstra(raw);
                let script = match output.multi_era_script_ref() {
                    Some(pallas_traverse::MultiEraScriptRef::Dijkstra(s)) => match s.as_ref() {
                        n::ScriptRef::PlutusV3Script(s) => {
                            json!({"scriptLanguage":"PlutusScriptV3","script":{"type":"PlutusScriptV3","description":"Captured public reference script","cborHex":hex::encode(s.as_ref())}})
                        }
                        _ => panic!(),
                    },
                    None => serde_json::Value::Null,
                    _ => panic!(),
                };
                let mut value = serde_json::Map::new();
                value.insert("lovelace".into(), json!(output.value().coin()));
                if let pallas_primitives::alonzo::Value::Multiasset(_, assets) =
                    output.value().into_alonzo()
                {
                    for (policy, names) in assets {
                        value.insert(
                            policy.to_string(),
                            names
                                .into_iter()
                                .map(|(name, amount)| (hex::encode(name.as_slice()), json!(amount)))
                                .collect::<serde_json::Map<_, _>>()
                                .into(),
                        );
                    }
                }
                let (inline, hash, inline_hash) = match output.datum() {
                    Some(c::DatumOption::Data(d)) => (
                        d.0.to_json(),
                        serde_json::Value::Null,
                        json!(Hasher::<256>::hash_cbor(&d.0).to_string()),
                    ),
                    Some(c::DatumOption::Hash(h)) => (
                        serde_json::Value::Null,
                        json!(h.to_string()),
                        serde_json::Value::Null,
                    ),
                    None => (
                        serde_json::Value::Null,
                        serde_json::Value::Null,
                        serde_json::Value::Null,
                    ),
                };
                outputs.insert(format!("{}#{}",reference.transaction_id,reference.index),json!({"address":output.address().unwrap().to_bech32().unwrap(),"value":value,"datum":null,"datumhash":hash,"inlineDatum":inline,"inlineDatumhash":inline_hash,"referenceScript":script}));
            }
            write("mint-batch.utxos.json", outputs.into());
            write("pallas-result.json",evaluate(&tx,&inputs,&env).unwrap().iter().map(|r|json!({"tag":format!("{:?}",r.tag),"index":r.index,"memory":r.units.mem,"steps":r.units.steps,"success":r.success})).collect::<Vec<_>>().into());
        });
    }

    #[test]
    fn dijkstra_v3_purpose_and_optional_datum_context() {
        // The script reads its own ScriptInfo constructor and compares it with the
        // redeemer. This catches wrong purpose construction despite matching pointers.
        let field = |value: &str, index: usize| {
            let mut list =
                format!("[(force (force (builtin sndPair))) [(builtin unConstrData) {value}]]");
            for _ in 0..index {
                list = format!("[(force (builtin tailList)) {list}]");
            }
            format!("[(force (builtin headList)) {list}]")
        };
        let script_info = field("ctx", 2);
        let redeemer = field("ctx", 1);
        let condition = format!(
            "[[(builtin equalsInteger) [(force (force (builtin fstPair))) [(builtin unConstrData) {script_info}]]] [(builtin unIData) {redeemer}]]"
        );
        let source = format!(
            "(program 1.1.0 (lam ctx (force [[[(force (builtin ifThenElse)) {condition}] (delay (con unit ()))] (delay (error))])))"
        );
        case(false, &source, |mut tx, mut inputs, env, state| {
            let mut rs = (**tx.transaction_witness_set.redeemer.as_ref().unwrap()).clone();
            for (key, r) in &mut rs.0 {
                let index = match key.tag {
                    n::RedeemerTag::Spend => 1,
                    n::RedeemerTag::Mint => 0,
                    n::RedeemerTag::Reward => 2,
                    _ => panic!(),
                };
                r.data = n::PlutusData::BigInt(n::BigInt::Int(index.into()));
            }
            tx.transaction_witness_set.redeemer = Some(rs.clone().into());
            seal(&mut tx, &env);
            assert!(run(&tx, &inputs, &env, &state).is_ok());
            assert!(
                evaluate(&tx, &inputs, &env)
                    .unwrap()
                    .iter()
                    .all(|r| r.success)
            );
            // CIP-0069 permits V3 spending without a datum; hashed missing datums are
            // separately rejected by dijkstra_datums_and_integrity_are_independent.
            output_mut(&mut inputs[1].1).datum_option = None;
            assert!(run(&tx, &inputs, &env, &state).is_ok());
            assert!(
                evaluate(&tx, &inputs, &env)
                    .unwrap()
                    .iter()
                    .all(|r| r.success)
            );
            rs.0.get_mut(&n::RedeemersKey {
                tag: n::RedeemerTag::Mint,
                index: 0,
            })
            .unwrap()
            .data = n::PlutusData::BigInt(n::BigInt::Int(9.into()));
            tx.transaction_witness_set.redeemer = Some(rs.into());
            seal(&mut tx, &env);
            assert!(run(&tx, &inputs, &env, &state).is_ok());
            let report = evaluate(&tx, &inputs, &env).unwrap();
            assert!(
                !report
                    .iter()
                    .find(|r| r.tag == c::RedeemerTag::Mint)
                    .unwrap()
                    .success
            );
        });
    }
    #[test]
    fn dijkstra_new_scripts_are_checked() {
        dijkstra_tests::synthetic(|mut tx, input| {
            let inputs = vec![(tx.transaction_body.inputs[0].clone(), input)];
            for bytes in [vec![0], vec![0x41, 0xff]] {
                output_mut(first_output(&mut tx)).script_ref = Some(CborWrap(
                    n::ScriptRef::PlutusV3Script(n::PlutusScript(bytes.into())),
                ));
                dijkstra_tests::sign(&mut tx);
                dijkstra_tests::error(
                    run(&tx, &inputs, &environment(), &CertState::default()),
                    "DijkstraMalformedScript",
                );
            }
            output_mut(first_output(&mut tx)).script_ref =
                Some(CborWrap(n::ScriptRef::PlutusV3Script(script(PASS))));
            dijkstra_tests::sign(&mut tx);
            assert!(run(&tx, &inputs, &environment(), &CertState::default()).is_ok());
        });
    }
}

fn first_output<'a, 'b>(tx: &'a mut n::BlockTransaction<'b>) -> &'a mut n::TransactionOutput<'b> {
    match &mut tx.transaction_body.outputs {
        pallas_codec::utils::MaybeIndefArray::Def(xs)
        | pallas_codec::utils::MaybeIndefArray::Indef(xs) => &mut xs[0],
    }
}

#[test]
fn dijkstra_preserves_original_auxiliary_bytes() {
    dijkstra_tests::synthetic(|mut tx, input| {
        // Indefinite metadata map: same value, different committed bytes.
        let bytes = hex::decode("bf1902a26474657374ff").unwrap();
        let aux: KeepRaw<n::AuxiliaryData> = minicbor::decode(&bytes).unwrap();
        assert_ne!(minicbor::to_vec(&*aux).unwrap(), bytes);
        tx.auxiliary_data = Nullable::Some(aux.to_owned());
        tx.transaction_body.auxiliary_data_hash = Some(Hasher::<256>::hash(&bytes));
        dijkstra_tests::sign(&mut tx);
        let inputs = vec![(tx.transaction_body.inputs[0].clone(), input)];
        assert!(run(&tx, &inputs, &dijkstra_tests::env(), &CertState::default()).is_ok());
        let Nullable::Some(aux) = &tx.auxiliary_data else {
            panic!()
        };
        tx.transaction_body.auxiliary_data_hash =
            Some(Hasher::<256>::hash(&minicbor::to_vec(&**aux).unwrap()));
        dijkstra_tests::sign(&mut tx);
        dijkstra_tests::error(
            run(&tx, &inputs, &dijkstra_tests::env(), &CertState::default()),
            "PostAlonzo(MetadataHash)",
        );
    });
}
#[test]
fn dijkstra_invalid_multiasset_encodings() {
    dijkstra_tests::synthetic(|mut tx, input| {
        let coin = MultiEraOutput::from_dijkstra(&input).value().coin() - tx.transaction_body.fee;
        let address = MultiEraOutput::from_dijkstra(&input)
            .address()
            .unwrap()
            .to_vec();
        for (name, amount, duplicate, empty) in [
            (vec![1], 0u64, false, false),
            (vec![1; 33], 1, false, false),
            (vec![1], 1, true, false),
            (vec![1], 1, false, true),
        ] {
            let mut e = minicbor::Encoder::new(Vec::new());
            e.array(2)
                .unwrap()
                .bytes(&address)
                .unwrap()
                .array(2)
                .unwrap()
                .u64(coin)
                .unwrap()
                .map(if empty { 0 } else { 1 })
                .unwrap();
            if !empty {
                e.bytes(&[8; 28])
                    .unwrap()
                    .map(if duplicate { 2 } else { 1 })
                    .unwrap()
                    .bytes(&name)
                    .unwrap()
                    .u64(amount)
                    .unwrap();
                if duplicate {
                    e.bytes(&name).unwrap().u64(amount).unwrap();
                }
            }
            let raw = e.into_writer();
            let decoded: n::TransactionOutput = minicbor::decode(&raw).unwrap();
            let n::TransactionOutput::Legacy(decoded) = decoded else {
                panic!()
            };
            tx.transaction_body.outputs =
                pallas_codec::utils::MaybeIndefArray::Def(vec![n::TransactionOutput::Legacy(
                    decoded.to_owned(),
                )]);
            dijkstra_tests::sign(&mut tx);
            let inputs = vec![(tx.transaction_body.inputs[0].clone(), input.clone())];
            dijkstra_tests::error(
                run(&tx, &inputs, &dijkstra_tests::env(), &CertState::default()),
                "PostAlonzo(NegativeValue)",
            );
        }
    });
}
