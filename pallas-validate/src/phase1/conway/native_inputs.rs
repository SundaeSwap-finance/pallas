//! Native input inspection with an explicitly scoped Conway transaction view.
//! No input-era relabeling or phase-two evaluation.
use super::*;
use pallas_codec::{minicbor, utils::Nullable};
use pallas_crypto::hash::Hasher;

fn captured_settings(test: impl FnOnce(Tx<'_>, UTxOs<'_>)) {
    use pallas_traverse::{Era, MultiEraBlock};
    let read = |name: &str| {
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
    let block_bytes = read("1401365.block");
    let producer_bytes = read("1401345.block");
    let block = MultiEraBlock::decode(&block_bytes).unwrap();
    let producer = MultiEraBlock::decode(&producer_bytes).unwrap();
    let txs = block.txs();
    let original = &txs[0];
    assert_eq!(original.era(), Era::Dijkstra);
    assert_eq!(
        original.hash().to_string(),
        "da910a9bfbe657724d64b505099010dd47f86fb573aa1d20b4da0367163e94c6"
    );
    let native = original.as_dijkstra().unwrap();
    assert!(native.success);
    let evidence: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../test_data/musashi-registration/certificate-witnesses-provenance.json"
    ))
    .unwrap();
    assert_eq!(
        Hasher::<256>::hash(native.transaction_witness_set.raw_cbor()).to_string(),
        evidence["settings"]["witness_blake2b_256"]
            .as_str()
            .unwrap()
    );
    let tx = Tx {
        transaction_body: minicbor::decode(native.transaction_body.raw_cbor()).unwrap(),
        transaction_witness_set: minicbor::decode(native.transaction_witness_set.raw_cbor())
            .unwrap(),
        success: true,
        auxiliary_data: Nullable::Null,
    };
    assert_eq!(tx.transaction_body.original_hash(), original.hash());
    let producers = producer.txs();
    assert_eq!(
        producers[0].hash(),
        tx.transaction_body.inputs[0].transaction_id
    );
    assert!(producers[0].as_dijkstra().unwrap().success);
    let outputs = producers[0].outputs();
    let raw: Vec<_> = outputs.iter().map(|x| x.encode()).collect();
    assert_eq!(
        Hasher::<256>::hash(&raw[0]).to_string(),
        evidence["settings"]["reference_output"]["blake2b_256"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        native.transaction_body.reference_inputs.as_ref().unwrap()[0].transaction_id,
        producers[0].hash()
    );
    assert_eq!(
        native.transaction_body.reference_inputs.as_ref().unwrap()[0].index,
        0
    );
    assert_eq!(native.transaction_body.inputs[0].index, 1);
    assert_eq!(
        raw[1],
        hex::decode(include_str!(
            "../../../../test_data/musashi-registration/settings.input.hex"
        ))
        .unwrap()
    );
    assert_eq!(
        Hasher::<256>::hash(&raw[1]).to_string(),
        "43a13abb726ae46fed05f96efc1d9cf07e81398a1551089670d35a7aa03b468c"
    );
    let reference = MultiEraOutput::decode(Era::Dijkstra, &raw[0]).unwrap();
    let spending = MultiEraOutput::decode(Era::Dijkstra, &raw[1]).unwrap();
    let body = tx.transaction_body.clone();
    let utxos = UTxOs::from([
        (
            MultiEraInput::from_alonzo_compatible(&body.inputs[0]),
            spending,
        ),
        (
            MultiEraInput::from_alonzo_compatible(&body.reference_inputs.as_ref().unwrap()[0]),
            reference,
        ),
    ]);
    assert_eq!(
        native.transaction_body.collateral.as_ref().unwrap()[0],
        native.transaction_body.inputs[0]
    );
    for output in utxos.values() {
        assert_eq!(output.era(), Era::Dijkstra);
        assert!(output.as_conway().is_none());
    }
    let before: Vec<_> = utxos.values().map(|o| (o.era(), o.encode())).collect();
    test(tx, utxos.clone());
    assert_eq!(
        before,
        utxos
            .values()
            .map(|o| (o.era(), o.encode()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn captured_native_input_checks_original_payment_witness() {
    captured_settings(|tx, utxos| {
        let wits = tx
            .transaction_witness_set
            .vkeywitness
            .as_ref()
            .map(|w| w.clone().to_vec());
        let result = check_vkey_input_wits(&tx, &wits, &utxos);
        assert!(
            result.is_ok(),
            "expected original payment signature to pass: {result:?}"
        );
    });
}

#[test]
fn captured_native_inputs_pass_witness_and_balance_rules() {
    captured_settings(|tx, utxos| {
        let result = check_witness_set(&tx, &utxos);
        assert!(
            result.is_ok(),
            "expected captured witnesses/reference to pass: {result:?}"
        );
        assert!(check_preservation_of_value(&tx, &utxos, 2_000_000).is_ok());
    });
}

#[test]
fn captured_native_collateral_address_and_value() {
    captured_settings(|tx, utxos| {
        assert!(
            check_collaterals_address(tx.transaction_body.collateral.as_ref().unwrap(), &utxos)
                .is_ok()
        );
        let input = utxos
            .get(&MultiEraInput::from_alonzo_compatible(
                &tx.transaction_body.inputs[0],
            ))
            .unwrap();
        assert_eq!(
            val_from_multi_era_output(input),
            get_consumed(&tx.transaction_body, &utxos).unwrap()
        );
        assert!(check_preservation_of_value(&tx, &utxos, 2_000_000).is_ok());
    });
}

fn expect(actual: ValidationResult, expected: &str) {
    assert_eq!(format!("{actual:?}"), expected);
}

#[test]
fn captured_native_inputs_reject_missing_and_invalid_payment_witnesses() {
    captured_settings(|tx, utxos| {
        expect(
            check_vkey_input_wits(&tx, &Some(vec![]), &utxos),
            "Err(PostAlonzo(VKWitnessMissing))",
        );
        let mut wits = tx
            .transaction_witness_set
            .vkeywitness
            .clone()
            .unwrap()
            .to_vec();
        wits[0].signature = vec![0; 64].into();
        expect(
            check_vkey_input_wits(&tx, &Some(wits), &utxos),
            "Err(PostAlonzo(VKWrongSignature))",
        );
    });
}

fn synthetic_output<'a>(
    address: Vec<u8>,
    datum: Option<DatumOption<'a>>,
    script: Option<pallas_primitives::dijkstra::ScriptRef<'a>>,
) -> MultiEraOutput<'a> {
    use pallas_codec::utils::CborWrap;
    use pallas_primitives::dijkstra::{PostAlonzoTransactionOutput, TransactionOutput};
    MultiEraOutput::Dijkstra(Box::new(std::borrow::Cow::Owned(
        TransactionOutput::PostAlonzo(
            PostAlonzoTransactionOutput {
                address: address.into(),
                value: Value::Coin(5_000_000),
                datum_option: datum.map(Into::into),
                script_ref: script.map(CborWrap),
            }
            .into(),
        ),
    )))
}

#[test]
fn native_collateral_rejects_script_and_malformed_addresses() {
    captured_settings(|tx, mut utxos| {
        let input = tx.transaction_body.inputs[0].clone();
        for (address, expected) in [
            (vec![0x70; 29], "Err(PostAlonzo(CollateralNotVKeyLocked))"),
            (vec![], "Err(PostAlonzo(InputDecoding))"),
            (vec![0xe0; 29], "Err(PostAlonzo(InputDecoding))"),
        ] {
            *utxos.get_mut(&owned_input(&input)).unwrap() = synthetic_output(address, None, None);
            expect(
                check_collaterals_address(std::slice::from_ref(&input), &utxos),
                expected,
            );
        }
        utxos.remove(&owned_input(&input));
        expect(
            check_collaterals_address(&[input], &utxos),
            "Err(PostAlonzo(CollateralNotInUTxO))",
        );
    });
}

#[test]
fn native_reference_script_requires_correct_hash_and_input_role() {
    captured_settings(|mut tx, mut utxos| {
        let reference = tx.transaction_body.reference_inputs.as_ref().unwrap()[0].clone();
        let original = utxos.get(&owned_input(&reference)).unwrap().clone();
        for script in [
            None,
            Some(pallas_primitives::dijkstra::ScriptRef::PlutusV3Script(
                PlutusScript(vec![0].into()),
            )),
        ] {
            *utxos.get_mut(&owned_input(&reference)).unwrap() =
                synthetic_output(vec![0x60; 29], None, script);
            expect(
                check_witness_set(&tx, &utxos),
                "Err(PostAlonzo(ScriptWitnessMissing))",
            );
        }
        *utxos.get_mut(&owned_input(&reference)).unwrap() = original;
        // The UTxO map may contain outputs unrelated to this transaction. Even
        // a collateral input must not supply a reference script.
        tx.transaction_body.reference_inputs = None;
        tx.transaction_body.collateral = Some(vec![reference].try_into().unwrap());
        expect(
            check_witness_set(&tx, &utxos),
            "Err(PostAlonzo(ScriptWitnessMissing))",
        );
    });
}

#[test]
fn native_reference_scripts_reject_v4_and_nested_guards_explicitly() {
    use pallas_primitives::dijkstra::{NativeScript, ScriptRef};
    captured_settings(|tx, mut utxos| {
        let reference = tx.transaction_body.reference_inputs.as_ref().unwrap()[0].clone();
        for (script, expected) in [
            (
                ScriptRef::PlutusV4Script(PlutusScript(vec![0].into())),
                "Err(PostAlonzo(UnsupportedPlutusLanguage))",
            ),
            (
                ScriptRef::NativeScript(
                    NativeScript::ScriptRequireGuard(StakeCredential::AddrKeyhash([1; 28].into()))
                        .into(),
                ),
                "Err(PostAlonzo(UnsupportedNativeScript))",
            ),
            (
                ScriptRef::NativeScript(
                    NativeScript::ScriptAll(vec![NativeScript::ScriptRequireGuard(
                        StakeCredential::ScriptHash([2; 28].into()),
                    )])
                    .into(),
                ),
                "Err(PostAlonzo(UnsupportedNativeScript))",
            ),
        ] {
            *utxos.get_mut(&owned_input(&reference)).unwrap() =
                synthetic_output(vec![0x60; 29], None, Some(script));
            expect(check_witness_set(&tx, &utxos), expected);
        }
    });
}

#[test]
fn native_reference_timelocks_keep_original_hash_and_need_no_redeemer() {
    use pallas_primitives::dijkstra::{NativeScript, ScriptRef};
    use pallas_traverse::ComputeHash;
    captured_settings(|mut tx, mut utxos| {
        let reference = tx.transaction_body.reference_inputs.as_ref().unwrap()[0].clone();
        for (tag, expected) in [(1, "Ok(())"), (2, "Err(PostAlonzo(NativeScriptDenial))")] {
            // Noncanonical [all/any, []]; the tag has an extra byte.
            let raw = [0x82, 0x18, tag, 0x80];
            let native: KeepRaw<NativeScript> = minicbor::decode(&raw).unwrap();
            let hash = native.original_hash();
            assert_ne!(hash, native.compute_hash());
            *utxos.get_mut(&owned_input(&reference)).unwrap() = synthetic_output(
                vec![0x60; 29],
                None,
                Some(ScriptRef::NativeScript(native.to_owned())),
            );
            tx.transaction_body.certificates = Some(
                vec![Certificate::Reg(
                    StakeCredential::ScriptHash(hash),
                    2_000_000,
                )]
                .try_into()
                .unwrap(),
            );
            expect(check_certificate_native_scripts(&tx, &utxos), expected);
            if tag == 1 {
                // Re-sign the derived body using a public deterministic test key.
                // Only this synthetic case changes the original body/witnesses.
                let key = pallas_crypto::key::ed25519::SecretKey::from([42; 32]);
                let hash = Hasher::<224>::hash(key.public_key().as_ref());
                let mut address = vec![0x60];
                address.extend(hash.as_ref());
                let spending = tx.transaction_body.inputs[0].clone();
                *utxos.get_mut(&owned_input(&spending)).unwrap() =
                    synthetic_output(address, None, None);
                let body_bytes = minicbor::to_vec(&tx.transaction_body).unwrap();
                let body: KeepRaw<TransactionBody> = minicbor::decode(&body_bytes).unwrap();
                // Keep raw body alive while checking the synthetic signature.
                let mut signed = tx.clone();
                signed.transaction_body = body;
                signed.transaction_witness_set.redeemer = None;
                signed.transaction_witness_set.vkeywitness = Some(
                    vec![VKeyWitness {
                        vkey: key.public_key().as_ref().to_vec().into(),
                        signature: key
                            .sign(signed.transaction_body.original_hash())
                            .as_ref()
                            .to_vec()
                            .into(),
                    }]
                    .try_into()
                    .unwrap(),
                );
                expect(check_witness_set(&signed, &utxos), "Ok(())");
            }
        }
    });
}

#[test]
fn native_input_and_reference_datums_are_visible() {
    captured_settings(|tx, mut utxos| {
        let spending = tx.transaction_body.inputs[0].clone();
        let reference = tx.transaction_body.reference_inputs.as_ref().unwrap()[0].clone();
        let datum: KeepRaw<PlutusData> = minicbor::decode(&[0x01]).unwrap();
        let hash = datum.original_hash();
        let witnesses = Some(NonEmptySet::from_vec(vec![datum]).unwrap().into());
        *utxos.get_mut(&owned_input(&spending)).unwrap() =
            synthetic_output(vec![0x70; 29], Some(DatumOption::Hash(hash)), None);
        expect(
            check_datums(&tx.transaction_body, &utxos, &None),
            "Err(PostAlonzo(DatumMissing))",
        );
        expect(
            check_datums(&tx.transaction_body, &utxos, &witnesses),
            "Ok(())",
        );
        *utxos.get_mut(&owned_input(&spending)).unwrap() =
            synthetic_output(vec![0x70; 29], None, None);
        *utxos.get_mut(&owned_input(&reference)).unwrap() =
            synthetic_output(vec![0x60; 29], Some(DatumOption::Hash(hash)), None);
        expect(
            check_datums(&tx.transaction_body, &utxos, &witnesses),
            "Ok(())",
        );
        *utxos.get_mut(&owned_input(&reference)).unwrap() =
            synthetic_output(vec![0x60; 29], None, None);
        expect(
            check_datums(&tx.transaction_body, &utxos, &witnesses),
            "Err(PostAlonzo(UnneededDatum))",
        );
        let inline = DatumOption::Data(pallas_codec::utils::CborWrap(
            minicbor::decode::<KeepRaw<PlutusData>>(&[0x01])
                .unwrap()
                .to_owned(),
        ));
        *utxos.get_mut(&owned_input(&spending)).unwrap() =
            synthetic_output(vec![0x70; 29], Some(inline), None);
        expect(check_datums(&tx.transaction_body, &utxos, &None), "Ok(())");
    });
}

#[test]
fn native_inline_datum_and_reference_script_restrict_v1_inputs() {
    captured_settings(|mut tx, mut utxos| {
        tx.transaction_body.reference_inputs = None;
        let spending = tx.transaction_body.inputs[0].clone();
        for (datum, script) in [
            (
                Some(DatumOption::Data(pallas_codec::utils::CborWrap(
                    minicbor::decode::<KeepRaw<PlutusData>>(&[1])
                        .unwrap()
                        .to_owned(),
                ))),
                None,
            ),
            (
                None,
                Some(pallas_primitives::dijkstra::ScriptRef::PlutusV2Script(
                    PlutusScript(vec![0].into()),
                )),
            ),
        ] {
            *utxos.get_mut(&owned_input(&spending)).unwrap() =
                synthetic_output(vec![0x60; 29], datum, script);
            assert_eq!(
                allowed_tx_langs(&tx, &utxos),
                vec![Language::PlutusV2, Language::PlutusV3]
            );
        }
    });
}

fn owned_input<'a>(input: &TransactionInput) -> MultiEraInput<'a> {
    MultiEraInput::AlonzoCompatible(Box::new(std::borrow::Cow::Owned(input.clone())))
}

#[test]
fn earlier_era_and_native_outputs_share_input_inspection() {
    use pallas_traverse::Era;
    captured_settings(|tx, _| {
        for era in [
            Era::Shelley,
            Era::Allegra,
            Era::Mary,
            Era::Alonzo,
            Era::Babbage,
            Era::Conway,
            Era::Dijkstra,
        ] {
            for legacy in [true, false] {
                if !legacy && matches!(era, Era::Shelley | Era::Allegra | Era::Mary | Era::Alonzo) {
                    continue;
                }
                let address = vec![0x70; 29];
                let hash = Hash::from([3; 32]);
                let amount = babbage::Value::Multiasset(
                    5_000_000,
                    [(Hash::from([4; 28]), [(Bytes::from(vec![5]), 7)].into())].into(),
                );
                let amount = if matches!(era, Era::Shelley | Era::Allegra) {
                    babbage::Value::Coin(5_000_000)
                } else {
                    amount
                };
                let datum_hash = if matches!(era, Era::Shelley | Era::Allegra | Era::Mary) {
                    None
                } else {
                    Some(hash)
                };
                let output = if legacy {
                    TransactionOutput::Legacy(
                        pallas_primitives::conway::LegacyTransactionOutput {
                            address: address.into(),
                            amount: amount.clone(),
                            datum_hash,
                        }
                        .into(),
                    )
                } else {
                    TransactionOutput::PostAlonzo(
                        pallas_primitives::conway::PostAlonzoTransactionOutput {
                            address: address.into(),
                            value: pallas_traverse::MultiEraValue::AlonzoCompatible(
                                std::borrow::Cow::Borrowed(&amount),
                            )
                            .into_conway(),
                            datum_option: Some(DatumOption::Hash(hash).into()),
                            script_ref: None,
                        }
                        .into(),
                    )
                };
                // Synthetic equivalent encodings, independently decoded by era.
                let bytes = minicbor::to_vec(output).unwrap();
                let output = MultiEraOutput::decode(era, &bytes).unwrap();
                assert_eq!(output.era(), era);
                assert_eq!(output.datum(), datum_hash.map(DatumOption::Hash));
                let utxos = UTxOs::from([(owned_input(&tx.transaction_body.inputs[0]), output)]);
                let actual = get_script_hash_from_input(&tx.transaction_body.inputs[0], &utxos);
                assert_eq!(
                    actual,
                    Some(Hash::from([0x70; 28])),
                    "{era:?} legacy={legacy}"
                );
                let mut datum_wits = [(false, hash)];
                expect(
                    check_input_datum_hash_in_witness_set(
                        &tx.transaction_body,
                        &utxos,
                        &mut datum_wits,
                    ),
                    "Ok(())",
                );
                assert_eq!(datum_wits[0].0, datum_hash.is_some());
                assert_eq!(
                    get_consumed(&tx.transaction_body, &utxos).unwrap(),
                    pallas_traverse::MultiEraValue::AlonzoCompatible(std::borrow::Cow::Borrowed(
                        &amount
                    ))
                    .into_conway()
                );
                expect(
                    check_collaterals_address(&[tx.transaction_body.inputs[0].clone()], &utxos),
                    "Err(PostAlonzo(CollateralNotVKeyLocked))",
                );
            }
        }
    });
}

#[test]
fn native_reference_v1_v2_v3_scripts_supply_mint_from_spending_or_reference_inputs() {
    use pallas_primitives::dijkstra::ScriptRef;
    use pallas_traverse::MultiEraScriptRef;
    captured_settings(|mut tx, mut utxos| {
        for script in [
            ScriptRef::PlutusV1Script(PlutusScript(vec![1].into())),
            ScriptRef::PlutusV2Script(PlutusScript(vec![2].into())),
            ScriptRef::PlutusV3Script(PlutusScript(vec![3].into())),
        ] {
            let hash = MultiEraScriptRef::from_dijkstra(&script).hash();
            tx.transaction_body.mint = Some(
                [(
                    hash,
                    [(Bytes::from(vec![0]), 1i64.try_into().unwrap())].into(),
                )]
                .into(),
            );
            for input in [
                tx.transaction_body.inputs[0].clone(),
                tx.transaction_body.reference_inputs.as_ref().unwrap()[0].clone(),
            ] {
                *utxos.get_mut(&owned_input(&input)).unwrap() =
                    synthetic_output(vec![0x60; 29], None, Some(script.clone()));
                expect(check_minting(&tx.transaction_body, &tx, &utxos), "Ok(())");
                *utxos.get_mut(&owned_input(&input)).unwrap() =
                    synthetic_output(vec![0x60; 29], None, None);
                assert!(
                    matches!(check_minting(&tx.transaction_body, &tx, &utxos), Err(PostAlonzo(MintingLacksPolicy(h))) if h == hash)
                );
            }
        }
    });
}

// Synthetic parameters for collateral arithmetic only, adapted from the Conway tests.
fn synthetic_params() -> ConwayProtParams {
    ConwayProtParams {
        system_start: chrono::DateTime::parse_from_rfc3339("2017-09-23T21:44:51Z").unwrap(),
        epoch_length: 432000,
        slot_length: 1,
        minfee_a: 44,
        minfee_b: 155381,
        max_block_body_size: 90112,
        max_transaction_size: 16384,
        max_block_header_size: 1100,
        key_deposit: 2000000,
        pool_deposit: 500000000,
        maximum_epoch: 18,
        desired_number_of_stake_pools: 500,
        pool_pledge_influence: pallas_primitives::RationalNumber {
            numerator: 3,
            denominator: 10,
        },
        expansion_rate: pallas_primitives::RationalNumber {
            numerator: 3,
            denominator: 1000,
        },
        treasury_growth_rate: pallas_primitives::RationalNumber {
            numerator: 2,
            denominator: 10,
        },
        protocol_version: (7, 0),
        min_pool_cost: 340000000,
        ada_per_utxo_byte: 4310,
        cost_models_for_script_languages: pallas_primitives::conway::CostModels {
            plutus_v1: None,
            plutus_v2: None,
            plutus_v3: None,
            unknown: Default::default(),
        },
        execution_costs: pallas_primitives::ExUnitPrices {
            mem_price: pallas_primitives::RationalNumber {
                numerator: 577,
                denominator: 10000,
            },
            step_price: pallas_primitives::RationalNumber {
                numerator: 721,
                denominator: 10000000,
            },
        },
        max_tx_ex_units: pallas_primitives::ExUnits {
            mem: 14000000,
            steps: 10000000000,
        },
        max_block_ex_units: pallas_primitives::ExUnits {
            mem: 62000000,
            steps: 40000000000,
        },
        max_value_size: 5000,
        collateral_percentage: 150,
        max_collateral_inputs: 3,
        pool_voting_thresholds: pallas_primitives::conway::PoolVotingThresholds {
            motion_no_confidence: pallas_primitives::RationalNumber {
                numerator: 50,
                denominator: 100,
            },
            committee_normal: pallas_primitives::RationalNumber {
                numerator: 60,
                denominator: 100,
            },
            committee_no_confidence: pallas_primitives::RationalNumber {
                numerator: 40,
                denominator: 100,
            },
            hard_fork_initiation: pallas_primitives::RationalNumber {
                numerator: 75,
                denominator: 100,
            },
            security_voting_threshold: pallas_primitives::RationalNumber {
                numerator: 80,
                denominator: 100,
            },
        },
        drep_voting_thresholds: pallas_primitives::conway::DRepVotingThresholds {
            motion_no_confidence: pallas_primitives::RationalNumber {
                numerator: 10,
                denominator: 100,
            },
            committee_normal: pallas_primitives::RationalNumber {
                numerator: 25,
                denominator: 100,
            },
            committee_no_confidence: pallas_primitives::RationalNumber {
                numerator: 15,
                denominator: 100,
            },
            update_constitution: pallas_primitives::RationalNumber {
                numerator: 50,
                denominator: 100,
            },
            hard_fork_initiation: pallas_primitives::RationalNumber {
                numerator: 60,
                denominator: 100,
            },
            pp_network_group: pallas_primitives::RationalNumber {
                numerator: 55,
                denominator: 100,
            },
            pp_economic_group: pallas_primitives::RationalNumber {
                numerator: 65,
                denominator: 100,
            },
            pp_technical_group: pallas_primitives::RationalNumber {
                numerator: 70,
                denominator: 100,
            },
            pp_governance_group: pallas_primitives::RationalNumber {
                numerator: 85,
                denominator: 100,
            },
            treasury_withdrawal: pallas_primitives::RationalNumber {
                numerator: 90,
                denominator: 100,
            },
        },
        min_committee_size: 10,
        committee_term_limit: 5,
        governance_action_validity_period: 3600, // in seconds
        governance_action_deposit: 1000,         // arbitrary value
        drep_deposit: 2000,                      // arbitrary value
        drep_inactivity_period: 60,              // in seconds
        minfee_refscript_cost_per_byte: pallas_primitives::RationalNumber {
            numerator: 10,
            denominator: 100,
        },
    }
}

#[test]
fn captured_native_collateral_accounting_and_reference_only_trigger() {
    captured_settings(|mut tx, utxos| {
        let mut params = synthetic_params();
        params.collateral_percentage = 150; // synthetic boundary parameter
        expect(
            check_collaterals(&tx.transaction_body, &utxos, &params),
            "Ok(())",
        );
        // Original transaction carries its only Plutus script by reference.
        assert!(tx.transaction_witness_set.plutus_v3_script.is_none());
        tx.transaction_body.collateral = None;
        expect(
            check_fee(&tx.transaction_body, &0, &tx, &utxos, &params),
            "Err(PostAlonzo(CollateralMissing))",
        );
    });
}

#[test]
fn native_collateral_assets_and_annotations_are_checked() {
    captured_settings(|mut tx, mut utxos| {
        let params = synthetic_params();
        let input = tx.transaction_body.inputs[0].clone();
        *utxos.get_mut(&owned_input(&input)).unwrap() =
            synthetic_output(vec![0x60; 29], None, None);
        tx.transaction_body.collateral_return = None;
        tx.transaction_body.total_collateral = Some(5_000_000);
        expect(
            check_collaterals(&tx.transaction_body, &utxos, &params),
            "Ok(())",
        );
        tx.transaction_body.total_collateral = Some(4_999_999);
        expect(
            check_collaterals(&tx.transaction_body, &utxos, &params),
            "Err(PostAlonzo(CollateralAnnotation))",
        );
        tx.transaction_body.total_collateral = None;
        tx.transaction_body.fee = 10_000_000;
        expect(
            check_collaterals(&tx.transaction_body, &utxos, &params),
            "Err(PostAlonzo(CollateralMinLovelace))",
        );
        tx.transaction_body.fee = 200_000;
        let mut output = synthetic_output(vec![0x60; 29], None, None);
        let MultiEraOutput::Dijkstra(ref mut boxed) = output else {
            unreachable!()
        };
        let pallas_primitives::dijkstra::TransactionOutput::PostAlonzo(inner) = boxed.to_mut()
        else {
            unreachable!()
        };
        inner.value = Value::Multiasset(
            5_000_000,
            [(
                Hash::from([4; 28]),
                [(Bytes::from(vec![5]), 7u64.try_into().unwrap())].into(),
            )]
            .into(),
        );
        let value = inner.value.clone();
        *utxos.get_mut(&owned_input(&input)).unwrap() = output;
        expect(
            check_collaterals(&tx.transaction_body, &utxos, &params),
            "Err(PostAlonzo(NonLovelaceCollateral))",
        );
        let Value::Multiasset(_, assets) = value else {
            unreachable!()
        };
        tx.transaction_body.collateral_return = Some(TransactionOutput::PostAlonzo(
            pallas_primitives::conway::PostAlonzoTransactionOutput {
                address: vec![0x60; 29].into(),
                value: Value::Multiasset(4_000_000, assets),
                datum_option: None,
                script_ref: None,
            }
            .into(),
        ));
        tx.transaction_body.total_collateral = Some(1_000_000);
        expect(
            check_collaterals(&tx.transaction_body, &utxos, &params),
            "Ok(())",
        );
    });
}

#[test]
fn native_reference_languages_reach_integrity_hash_check() {
    use pallas_primitives::dijkstra::ScriptRef;
    captured_settings(|mut tx, mut utxos| {
        tx.transaction_body.script_data_hash = None;
        let reference = tx.transaction_body.reference_inputs.as_ref().unwrap()[0].clone();
        *utxos.get_mut(&owned_input(&reference)).unwrap() =
            synthetic_output(vec![0x60; 29], None, None);
        for script in [
            ScriptRef::PlutusV1Script(PlutusScript(vec![1].into())),
            ScriptRef::PlutusV2Script(PlutusScript(vec![2].into())),
            ScriptRef::PlutusV3Script(PlutusScript(vec![3].into())),
        ] {
            for input in [tx.transaction_body.inputs[0].clone(), reference.clone()] {
                *utxos.get_mut(&owned_input(&input)).unwrap() =
                    synthetic_output(vec![0x60; 29], None, Some(script.clone()));
                expect(
                    check_script_data_hash(&tx.transaction_body, &tx, &utxos, &synthetic_params()),
                    "Err(PostAlonzo(ScriptIntegrityHash))",
                );
                *utxos.get_mut(&owned_input(&input)).unwrap() =
                    synthetic_output(vec![0x60; 29], None, None);
            }
        }
    });
}

#[test]
fn earlier_era_key_inputs_still_verify_signatures() {
    use pallas_traverse::Era;
    captured_settings(|tx, original_utxos| {
        let input = &tx.transaction_body.inputs[0];
        let address = original_utxos
            .get(&owned_input(input))
            .unwrap()
            .address()
            .unwrap()
            .to_vec();
        let output = pallas_primitives::alonzo::TransactionOutput {
            address: address.into(),
            amount: babbage::Value::Coin(5_000_000),
            datum_hash: None,
        };
        let raw = minicbor::to_vec(output).unwrap();
        let wits = tx
            .transaction_witness_set
            .vkeywitness
            .clone()
            .map(|w| w.to_vec());
        for era in [
            Era::Shelley,
            Era::Allegra,
            Era::Mary,
            Era::Alonzo,
            Era::Babbage,
            Era::Conway,
        ] {
            // A synthetic legacy UTxO with the captured payment credential;
            // no historical earlier-era producer is claimed.
            let utxos = UTxOs::from([(
                owned_input(input),
                MultiEraOutput::decode(era, &raw).unwrap(),
            )]);
            expect(check_vkey_input_wits(&tx, &wits, &utxos), "Ok(())");
            expect(
                check_collaterals_address(std::slice::from_ref(input), &utxos),
                "Ok(())",
            );
        }
    });
}

#[test]
fn byron_output_inspection_preserves_existing_witness_boundary() {
    captured_settings(|tx, _| {
        // Synthetic output using an address from pallas-addresses' public vectors.
        let address = pallas_addresses::ByronAddress::from_base58(
            "Ae2tdPwUPEZLs4HtbuNey7tK4hTKrwNwYtGqp7bDfCy2WdR3P6735W5Yfpe",
        )
        .unwrap()
        .to_vec();
        let output = pallas_primitives::byron::TxOut {
            address: minicbor::decode(&address).unwrap(),
            amount: 5_000_000,
        };
        let utxos = UTxOs::from([(
            owned_input(&tx.transaction_body.inputs[0]),
            MultiEraOutput::from_byron(&output),
        )]);
        expect(
            check_collaterals_address(&[tx.transaction_body.inputs[0].clone()], &utxos),
            "Ok(())",
        );
        assert_eq!(
            get_consumed(&tx.transaction_body, &utxos).unwrap(),
            Value::Coin(5_000_000)
        );
        let wits = tx
            .transaction_witness_set
            .vkeywitness
            .clone()
            .map(|w| w.to_vec());
        // Bootstrap witness validation in this Conway consumer remains unsupported.
        expect(
            check_vkey_input_wits(&tx, &wits, &utxos),
            "Err(PostAlonzo(InputDecoding))",
        );
    });
}
