use super::*;
use pallas_codec::{minicbor, utils::KeepRaw};
use pallas_traverse::OriginalHash;

#[test]
fn dijkstra_native_reference_hash_survives_v3_projection() {
    // Non-minimal array length and tag: semantic re-encoding changes its hash.
    let raw = [0x98, 0x02, 0x18, 0x01, 0x80];
    let native: KeepRaw<'_, n::NativeScript> = minicbor::decode(&raw).unwrap();
    let expected = native.original_hash();
    let address = pallas_addresses::ShelleyAddress::new(
        pallas_addresses::Network::Testnet,
        ShelleyPaymentPart::Key([1; 28].into()),
        ShelleyDelegationPart::Null,
    )
    .to_vec();
    let output = n::TransactionOutput::PostAlonzo(
        n::PostAlonzoTransactionOutput {
            address: address.into(),
            value: c::Value::Coin(5_000_000),
            datum_option: None,
            script_ref: Some(CborWrap(n::ScriptRef::NativeScript(native))),
        }
        .into(),
    );
    let projected = context_output(&MultiEraOutput::from_dijkstra(&output), true).unwrap();
    let view = MultiEraOutput::from_conway(&projected);
    let reference = view.multi_era_script_ref().unwrap();
    assert_eq!(reference.hash(), expected);
    assert_eq!(reference.native_script().unwrap().encode(), raw);
    // Earlier-era reference scripts retain those same original bytes too.
    let second = context_output(&view, true).unwrap();
    assert_eq!(
        MultiEraOutput::from_conway(&second)
            .multi_era_script_ref()
            .unwrap()
            .hash(),
        expected
    );
}

#[test]
fn dijkstra_native_reference_guard_has_no_v3_projection() {
    let guard = n::NativeScript::ScriptAll(vec![n::NativeScript::ScriptRequireGuard(
        n::StakeCredential::AddrKeyhash([2; 28].into()),
    )]);
    let raw = minicbor::to_vec(&guard).unwrap();
    let native: KeepRaw<'_, n::NativeScript> = minicbor::decode(&raw).unwrap();
    let address = pallas_addresses::ShelleyAddress::new(
        pallas_addresses::Network::Testnet,
        ShelleyPaymentPart::Key([1; 28].into()),
        ShelleyDelegationPart::Null,
    )
    .to_vec();
    let output = n::TransactionOutput::PostAlonzo(
        n::PostAlonzoTransactionOutput {
            address: address.into(),
            value: c::Value::Coin(5_000_000),
            datum_option: None,
            script_ref: Some(CborWrap(n::ScriptRef::NativeScript(native))),
        }
        .into(),
    );
    let result = context_output(&MultiEraOutput::from_dijkstra(&output), true);
    assert!(
        matches!(
            result,
            Err(Error::DijkstraUnsupported(Unsupported(
                "native script guards"
            )))
        ),
        "{result:?}"
    );
}

#[test]
fn dijkstra_pointer_output_is_labelled_as_a_v3_context_pointer() {
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
    let base = output(ShelleyDelegationPart::Null);
    assert!(context_output(&MultiEraOutput::from_dijkstra(&base), false).is_ok());
    let pointer = output(ShelleyDelegationPart::Pointer(
        pallas_addresses::Pointer::new(1, 2, 3),
    ));
    let result = context_output(&MultiEraOutput::from_dijkstra(&pointer), false);
    assert!(
        matches!(
            result,
            Err(Error::DijkstraUnsupported(Unsupported(
                "pointer address in a V3 script context"
            )))
        ),
        "{result:?}"
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
        let (result, _) = crate::phase2::native_evaluator::eval_native_v3(
            script.as_ref(),
            &context,
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
