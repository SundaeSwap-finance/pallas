use super::*;
use pallas_addresses::ShelleyDelegationPart;
use pallas_codec::{minicbor, utils::KeepRaw};
use pallas_traverse::OriginalHash;

#[test]
fn dijkstra_native_reference_hash_survives_v3_projection() {
    // Deliberately nonminimal CBOR: hashing a semantic re-encoding is wrong.
    // Include direct and all three recursive constructors, with both credentials.
    let raw_scripts = [
        "9802180180".to_owned(),
        format!("980218068200581c{}", "02".repeat(28)),
        format!("8201818202818303018182068201581c{}", "03".repeat(28)),
    ];
    for hex in raw_scripts {
        let raw = hex::decode(hex).unwrap();
        let native: KeepRaw<'_, n::NativeScript> = minicbor::decode(&raw).unwrap();
        let expected = native.original_hash();
        let output = n::TransactionOutput::PostAlonzo(
            n::PostAlonzoTransactionOutput {
                address: pallas_addresses::ShelleyAddress::new(
                    pallas_addresses::Network::Testnet,
                    ShelleyPaymentPart::Key([1; 28].into()),
                    ShelleyDelegationPart::Null,
                )
                .to_vec()
                .into(),
                value: c::Value::Coin(5_000_000),
                datum_option: None,
                script_ref: Some(CborWrap(n::ScriptRef::NativeScript(native.clone()))),
            }
            .into(),
        );
        let original = minicbor::to_vec(&output).unwrap();
        for reference in [false, true] {
            let projected =
                context_output(&MultiEraOutput::from_dijkstra(&output), reference).unwrap();
            assert_eq!(projected.script, Some(expected));
            let c::PlutusData::Constr(data) = projected.to_plutus_data() else {
                panic!()
            };
            assert_eq!(data.fields[3], Some(expected).to_plutus_data());
            assert_ne!(
                data.fields[3],
                Some(n::ScriptHash::from([0; 28])).to_plutus_data()
            );
            let c::PlutusData::Constr(v2) = projected.to_plutus_data_v2() else {
                panic!()
            };
            assert_eq!(v2.fields[3], data.fields[3]);
        }
        assert_eq!(minicbor::to_vec(&output).unwrap(), original);
        assert_eq!(minicbor::to_vec(&native).unwrap(), raw);
    }
    // The compatible Conway carrier still exposes exactly the same original hash.
    let raw = [0x98, 0x02, 0x18, 0x01, 0x80];
    let native: KeepRaw<'_, c::NativeScript> = minicbor::decode(&raw).unwrap();
    let expected = native.original_hash();
    let output = c::TransactionOutput::PostAlonzo(
        c::PostAlonzoTransactionOutput {
            address: [vec![0x60], vec![1; 28]].concat().into(),
            value: c::Value::Coin(1),
            datum_option: None,
            script_ref: Some(CborWrap(c::ScriptRef::NativeScript(native))),
        }
        .into(),
    );
    let projected = context_output(&MultiEraOutput::from_conway(&output), true).unwrap();
    assert_eq!(projected.script, Some(expected));
}

#[test]
fn dijkstra_plutus_reference_hash_carries_its_language_tag() {
    let bytes = [0x4d, 0x01, 0x00];
    let scripts = [
        (
            n::ScriptRef::PlutusV3Script(n::PlutusScript(bytes.to_vec().into())),
            3,
        ),
        (
            n::ScriptRef::PlutusV4Script(n::PlutusScript(bytes.to_vec().into())),
            4,
        ),
    ];
    for (script, tag) in scripts {
        let output = n::TransactionOutput::PostAlonzo(
            n::PostAlonzoTransactionOutput {
                address: [vec![0x60], vec![1; 28]].concat().into(),
                value: c::Value::Coin(5_000_000),
                datum_option: None,
                script_ref: Some(CborWrap(script)),
            }
            .into(),
        );
        let projected = context_output(&MultiEraOutput::from_dijkstra(&output), true).unwrap();
        assert_eq!(
            projected.script,
            Some(Hasher::<224>::hash_tagged(&bytes, tag))
        );
    }
}

#[test]
fn dijkstra_pointer_output_keeps_its_pointer_in_a_context() {
    use super::super::to_plutus_data::ToPlutusData;
    let output = |delegation| {
        let address = pallas_addresses::ShelleyAddress::new(
            pallas_addresses::Network::Testnet,
            ShelleyPaymentPart::Key([1; 28].into()),
            delegation,
        )
        .to_vec();
        n::TransactionOutput::PostAlonzo(
            n::PostAlonzoTransactionOutput {
                address: address.into(),
                value: c::Value::Coin(5_000_000),
                datum_option: None,
                script_ref: None,
            }
            .into(),
        )
    };
    let address = |output: &ContextOutput| output.address.to_plutus_data();
    let base = output(ShelleyDelegationPart::Null);
    let projected = context_output(&MultiEraOutput::from_dijkstra(&base), false).unwrap();
    let payment =
        super::super::data::Data::constr(0, vec![Hash::<28>::from([1; 28]).to_plutus_data()]);
    assert_eq!(
        address(&projected),
        super::super::data::Data::constr(0, vec![payment.clone(), None::<u64>.to_plutus_data()])
    );
    let pointer = output(ShelleyDelegationPart::Pointer(
        pallas_addresses::Pointer::new(1, 2, 3),
    ));
    let projected = context_output(&MultiEraOutput::from_dijkstra(&pointer), false).unwrap();
    let staking = super::super::data::Data::constr(
        1,
        vec![
            1u64.to_plutus_data(),
            2u64.to_plutus_data(),
            3u64.to_plutus_data(),
        ],
    );
    assert_eq!(
        address(&projected),
        super::super::data::Data::constr(0, vec![payment, Some(staking).to_plutus_data()])
    );
}

#[test]
fn ttl_validator_detects_an_inclusive_upper_bound() {
    use crate::phase2::to_plutus_data::ToPlutusData;
    use pallas_codec::utils::MaybeIndefArray;
    use pallas_primitives::{Constr, PlutusData};
    let construct = |index: u64, fields: Vec<PlutusData>| {
        PlutusData::Constr(Constr {
            tag: 121 + index,
            any_constructor: None,
            fields: MaybeIndefArray::Def(fields),
        })
    };
    let raw = hex::decode(
        include_str!("../../../test_data/musashi-ttl/confirmed-ttl/transaction.hex").trim(),
    )
    .unwrap();
    let tx = MultiEraTx::decode_for_era(pallas_traverse::Era::Dijkstra, &raw).unwrap();
    let tx = tx.as_dijkstra().unwrap();
    let script = &tx
        .transaction_witness_set
        .plutus_v3_script
        .as_ref()
        .unwrap()[0];
    let key = &tx.transaction_witness_set.vkeywitness.as_ref().unwrap()[0].vkey;
    let owner = pallas_crypto::hash::Hasher::<224>::hash(key.as_slice());
    let expected = &tx
        .transaction_witness_set
        .redeemer
        .as_ref()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .data;
    let metadata: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test_data/musashi-ttl/confirmed-ttl/replay.json"
    ))
    .unwrap();
    let upper = metadata["expected_upper_posix_ms"].as_u64().unwrap();
    let parameters: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test_data/musashi-ttl/confirmed-ttl/parameters.json"
    ))
    .unwrap();
    let costs: Vec<i64> = parameters["values"]["cardano"]["costModels"]["plutusV3"]["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().parse().unwrap())
        .collect();
    for inclusive in [false, true] {
        let mut range = TimeRange {
            lower_bound: None,
            upper_bound: Some(upper),
        }
        .to_plutus_data();
        if inclusive {
            let PlutusData::Constr(range) = &mut range else {
                unreachable!()
            };
            let mut bounds = range.fields.clone().to_vec();
            let PlutusData::Constr(upper) = &mut bounds[1] else {
                unreachable!()
            };
            let mut fields = upper.fields.clone().to_vec();
            fields[1] = true.to_plutus_data();
            upper.fields = MaybeIndefArray::Def(fields);
            range.fields = MaybeIndefArray::Def(bounds);
        }
        // Explicitly synthetic context: only the two fields read by this tiny
        // validator matter; this is not another captured ledger transaction.
        let mut fields = vec![construct(0, vec![]); 16];
        fields[7] = range;
        fields[8] = vec![owner].to_plutus_data();
        let context = construct(
            0,
            vec![construct(0, fields), expected.clone(), construct(1, vec![])],
        );
        let (result, _) = crate::phase2::native_evaluator::eval_native(
            pallas_primitives::dijkstra::Language::PlutusV3,
            script.as_ref(),
            &[&context],
            &costs,
            n::ExUnits {
                mem: 1_000_000,
                steps: 100_000_000,
            },
        )
        .unwrap();
        assert_eq!(result.success, !inclusive, "upper closure was not checked");
    }
}

// Constructed scripts have no raw bytes; mutating a decoded script clears them.
// Both must expose the same hash before and after serialization.
macro_rules! reference_without_raw {
    ($test:ident, $era:ident, $view:ident) => {
        #[test]
        fn $test() {
            let raw = [0x98, 0x02, 0x18, 0x01, 0x80];
            let mut mutated: KeepRaw<'_, $era::NativeScript> = minicbor::decode(&raw).unwrap();
            *mutated = $era::NativeScript::ScriptAny(vec![]);
            for native in [$era::NativeScript::ScriptAll(vec![]).into(), mutated] {
                assert!(native.raw_cbor().is_empty());
                let expected = native.compute_hash();
                let output = $era::TransactionOutput::PostAlonzo(
                    $era::PostAlonzoTransactionOutput {
                        address: [vec![0x60], vec![1; 28]].concat().into(),
                        value: c::Value::Coin(1),
                        datum_option: None,
                        script_ref: Some(CborWrap($era::ScriptRef::NativeScript(native))),
                    }
                    .into(),
                );
                let encoded = minicbor::to_vec(&output).unwrap();
                let decoded: $era::TransactionOutput<'_> = minicbor::decode(&encoded).unwrap();
                let roundtrip = context_output(&MultiEraOutput::$view(&decoded), false).unwrap();
                assert_eq!(roundtrip.script, Some(expected));
                let direct = context_output(&MultiEraOutput::$view(&output), false).unwrap();
                assert_eq!(direct.script, Some(expected));
                assert_eq!(direct.to_plutus_data(), roundtrip.to_plutus_data());
            }
        }
    };
}

reference_without_raw!(dijkstra_reference_without_raw, n, from_dijkstra);
reference_without_raw!(conway_reference_without_raw, c, from_conway);
