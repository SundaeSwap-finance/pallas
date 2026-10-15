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
