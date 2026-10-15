//! Native capture, explicitly adapted to the supported Conway bootstrap context
//! (protocol 9). This is not native Dijkstra or historical protocol-12 replay.
use super::*;
use crate::phase2::{data::Data, to_plutus_data::ToPlutusData, tx::eval_redeemer};
use pallas_codec::{minicbor, utils::Nullable};
use pallas_crypto::hash::Hasher;
use pallas_traverse::{Era, MultiEraBlock, MultiEraRedeemer};

const HASH: &str = "9eb9018892f84064087cfb1559cab8956d6300c47b6f325a7262c3db";

fn captured_settings(test: impl FnOnce(Tx<'_>, Vec<ResolvedInput<'_>>, Redeemer)) {
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
    let bytes = read("1401365.block");
    let producer_bytes = read("1401345.block");
    let block = MultiEraBlock::decode(&bytes).unwrap();
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
    assert_eq!(
        Hasher::<256>::hash(native.transaction_witness_set.raw_cbor()).to_string(),
        "738ff611e74b9952694e98e61360e3e940b86defc75a8ea372ea002fa7e0bda4"
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
    assert_eq!(producers[0].era(), Era::Dijkstra);
    assert!(producers[0].as_dijkstra().unwrap().success);
    assert_eq!(
        producers[0].hash().to_string(),
        "3171608e4d1b0812131e64e40f670ab7cdeef7f8e0cbad096b0d15dc62b76ba9"
    );
    let outputs = producers[0].outputs();
    let raw: Vec<_> = outputs.iter().map(|o| o.encode()).collect();
    assert_eq!(
        Hasher::<256>::hash(&raw[0]).to_string(),
        "20209f58a49b42c671fa8b10bcf3f223edc1b2f3a1123680658e1a7736bd395f"
    );
    let inputs = tx
        .transaction_body
        .inputs
        .iter()
        .chain(
            tx.transaction_body
                .reference_inputs
                .as_ref()
                .unwrap()
                .iter(),
        )
        .map(|input| {
            assert_eq!(input.transaction_id, producers[0].hash());
            ResolvedInput {
                input: input.clone(),
                output: minicbor::decode(&raw[input.index as usize]).unwrap(),
            }
        })
        .collect();
    let view = MultiEraTx::from_conway(&tx);
    let redeemers = view.redeemers();
    assert_eq!(redeemers.len(), 1);
    let redeemer = redeemers[0].into_conway_deprecated().unwrap();
    assert_eq!((redeemer.tag, redeemer.index), (RedeemerTag::Cert, 0));
    test(tx, inputs, redeemer);
}

fn slots() -> SlotConfig {
    SlotConfig {
        zero_slot: 0,
        zero_time: 1788739200000,
        slot_length: 1000,
    }
}

fn evaluate(
    tx: &Tx<'_>,
    inputs: &[ResolvedInput<'_>],
    redeemer: &Redeemer,
) -> Result<crate::phase2::tx::TxEvalResult, Error> {
    let view = MultiEraTx::from_conway(tx);
    eval_redeemer(
        &MultiEraRedeemer::from_conway_deprecated(redeemer),
        &view,
        inputs,
        &DataLookupTable::from_transaction(&view, inputs),
        &slots(),
        9,
    )
}

#[test]
fn captured_registration_executes_reference_script_in_conway_view() {
    captured_settings(|tx, inputs, redeemer| {
        let result = evaluate(&tx, &inputs, &redeemer);
        assert!(
            result.is_ok(),
            "expected successful captured script execution, got {result:?}"
        );
        let result = result.unwrap();
        assert!(result.success, "{result:?}");
        assert!(result.failure_message.is_none(), "{result:?}");
        assert!(result.units.mem > 0 && result.units.steps > 0, "{result:?}");
        assert_eq!((result.tag, result.index), (RedeemerTag::Cert, 0));
        println!("captured execution: {result:?}");
    });
}

#[test]
fn captured_registration_context_has_full_certificate_position() {
    captured_settings(|tx, inputs, redeemer| {
        let info = TxInfoV3::from_transaction(&tx, &inputs, &slots()).unwrap();
        let cert = tx.transaction_body.certificates.as_ref().unwrap()[0].clone();
        assert!(
            matches!(&cert, Certificate::Reg(StakeCredential::ScriptHash(h), 2_000_000) if h.to_string() == HASH)
        );
        let context = info.into_script_context(&redeemer, None).unwrap();
        let ScriptContext::V3 { purpose, .. } = &context else {
            panic!("V3 context")
        };
        assert_eq!(**purpose, ScriptInfo::Certifying(0, cert));
        // Ledger protocol-9 V3 encoding: CertifyingScript 0 (RegStaking hash Nothing).
        let registration = Data::constr(
            0,
            vec![
                Data::constr(1, vec![Data::bytestring(hex::decode(HASH).unwrap())]),
                Data::constr(1, vec![]),
            ],
        );
        let expected = Data::constr(3, vec![0usize.to_plutus_data(), registration]);
        let PlutusData::Constr(encoded) = context.to_plutus_data() else {
            panic!("context constructor")
        };
        assert_eq!(encoded.fields[2], expected);
    });
}

#[test]
fn captured_registration_rejects_bad_indices_and_wrong_purpose() {
    captured_settings(|tx, inputs, mut redeemer| {
        for index in [1, u32::MAX] {
            redeemer.index = index;
            assert!(matches!(
                evaluate(&tx, &inputs, &redeemer),
                Err(Error::MissingScriptForRedeemer)
            ));
        }
        redeemer.index = 0;
        redeemer.tag = RedeemerTag::Mint;
        assert!(matches!(
            evaluate(&tx, &inputs, &redeemer),
            Err(Error::MissingScriptForRedeemer)
        ));
    });
}

#[test]
fn captured_registration_requires_correct_script() {
    captured_settings(|tx, mut inputs, redeemer| {
        for incorrect in [false, true] {
            for input in &mut inputs {
                if let TransactionOutput::PostAlonzo(output) = &mut input.output {
                    let mut changed = (**output).clone();
                    changed.script_ref = if incorrect {
                        Some(pallas_codec::utils::CborWrap(ScriptRef::PlutusV3Script(
                            PlutusScript(vec![0].into()),
                        )))
                    } else {
                        None
                    };
                    *output = changed.into();
                }
            }
            let result = evaluate(&tx, &inputs, &redeemer);
            assert!(
                matches!(&result, Err(Error::MissingRequiredScript { hash }) if hash == HASH),
                "{result:?}"
            );
        }
    });
}

#[test]
fn registration_rejects_key_and_exempt_certificate_targets() {
    captured_settings(|mut tx, inputs, redeemer| {
        for (cert, expected) in [
            (
                Certificate::Reg(StakeCredential::AddrKeyhash(Hash::from([0; 28])), 2_000_000),
                "NonScriptStakeCredential",
            ),
            (
                Certificate::StakeRegistration(StakeCredential::ScriptHash(Hash::from([0; 28]))),
                "UnsupportedCertificateType",
            ),
        ] {
            let mut body = (*tx.transaction_body).clone();
            body.certificates = Some(vec![cert].try_into().unwrap());
            tx.transaction_body = body.into();
            assert_eq!(
                format!("{:?}", evaluate(&tx, &inputs, &redeemer).unwrap_err()),
                expected
            );
        }
    });
}

#[test]
fn registration_position_includes_non_script_certificates() {
    captured_settings(|mut tx, inputs, mut redeemer| {
        let original_cert = tx.transaction_body.certificates.as_ref().unwrap()[0].clone();
        let mut body = (*tx.transaction_body).clone();
        body.certificates = Some(
            vec![
                Certificate::Reg(StakeCredential::AddrKeyhash(Hash::from([0; 28])), 2_000_000),
                original_cert.clone(),
            ]
            .try_into()
            .unwrap(),
        );
        tx.transaction_body = body.into();
        redeemer.index = 1;
        let mut witnesses = (*tx.transaction_witness_set).clone();
        // Synthetic list representation also exercises the list-to-purpose path.
        witnesses.redeemer =
            Some(pallas_primitives::conway::Redeemers::List(vec![redeemer.clone()]).into());
        tx.transaction_witness_set = witnesses.into();
        let view = MultiEraTx::from_conway(&tx);
        let table = DataLookupTable::from_transaction(&view, &inputs);
        let (script, datum) = find_script(&redeemer, &tx, &inputs, &table).unwrap();
        assert!(matches!(script, ScriptVersion::V3(s) if s.compute_hash().to_string() == HASH));
        assert!(datum.is_none());
        let info = TxInfoV3::from_transaction(&tx, &inputs, &slots()).unwrap();
        let ScriptContext::V3 { purpose, .. } = info.into_script_context(&redeemer, None).unwrap()
        else {
            panic!("V3 context")
        };
        assert_eq!(*purpose, ScriptInfo::Certifying(1, original_cert));
        redeemer.index = 0;
        assert!(matches!(
            find_script(&redeemer, &tx, &inputs, &table),
            Err(Error::NonScriptStakeCredential)
        ));
    });
}

#[test]
fn registration_can_execute_same_script_from_witness_set() {
    captured_settings(|mut tx, mut inputs, redeemer| {
        let mut witnesses = (*tx.transaction_witness_set).clone();
        for input in &mut inputs {
            if let TransactionOutput::PostAlonzo(output) = &mut input.output {
                let mut changed = (**output).clone();
                if let Some(script) = changed.script_ref.take() {
                    let ScriptRef::PlutusV3Script(script) = script.0 else {
                        panic!("captured V3")
                    };
                    witnesses.plutus_v3_script = Some(vec![script].try_into().unwrap());
                }
                *output = changed.into();
            }
        }
        tx.transaction_witness_set = witnesses.into();
        let result = evaluate(&tx, &inputs, &redeemer).unwrap();
        assert!(result.success, "{result:?}");
    });
}

#[test]
fn registration_v1_v2_context_uses_legacy_registration_encoding() {
    captured_settings(|mut tx, mut inputs, redeemer| {
        // Synthetic V1/V2 contexts: remove reference inputs/scripts (for V1),
        // retaining the captured Reg solely as a certificate encoding example.
        let mut body = (*tx.transaction_body).clone();
        body.reference_inputs = None;
        tx.transaction_body = body.into();
        inputs.retain(|i| tx.transaction_body.inputs.contains(&i.input));
        let credential = Data::constr(1, vec![Data::bytestring(hex::decode(HASH).unwrap())]);
        let registration = Data::constr(0, vec![Data::constr(0, vec![credential])]);
        for info in [
            TxInfoV1::from_transaction(&tx, &inputs, &slots()).unwrap(),
            TxInfoV2::from_transaction(&tx, &inputs, &slots()).unwrap(),
        ] {
            let context = info
                .into_script_context(&redeemer, None)
                .unwrap()
                .to_plutus_data();
            let PlutusData::Constr(context) = context else {
                panic!("context constructor")
            };
            assert_eq!(
                context.fields[1],
                Data::constr(3, vec![registration.clone()])
            );
            let PlutusData::Constr(info) = &context.fields[0] else {
                panic!("tx info constructor")
            };
            // V1 has no reference-input field; V2 does.
            let cert_index = if info.fields.len() == 10 { 4 } else { 5 };
            assert_eq!(
                info.fields[cert_index],
                Data::list(vec![registration.clone()])
            );
        }
    });
}
