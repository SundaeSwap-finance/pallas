//! Conway input checks over outputs of every era and address type.
use super::*;
use pallas_codec::minicbor;
use pallas_traverse::Era;

fn input() -> TransactionInput {
    TransactionInput {
        transaction_id: Hash::new([0; 32]),
        index: 0,
    }
}

fn legacy_output(address: Vec<u8>) -> Vec<u8> {
    minicbor::to_vec(pallas_primitives::alonzo::TransactionOutput {
        address: address.into(),
        amount: babbage::Value::Coin(5_000_000),
        datum_hash: None,
    })
    .unwrap()
}

fn utxos(era: Era, output: &[u8]) -> UTxOs<'_> {
    UTxOs::from([(
        MultiEraInput::AlonzoCompatible(Box::new(std::borrow::Cow::Owned(input()))),
        MultiEraOutput::decode(era, output).unwrap(),
    )])
}

fn key_address() -> Vec<u8> {
    [vec![0x61], vec![1; 28]].concat()
}

fn script_address() -> Vec<u8> {
    [vec![0x71], vec![2; 28]].concat()
}

fn byron_address() -> Vec<u8> {
    pallas_addresses::ByronAddress::from_base58(
        "Ae2tdPwUPEZLs4HtbuNey7tK4hTKrwNwYtGqp7bDfCy2WdR3P6735W5Yfpe",
    )
    .unwrap()
    .to_vec()
}

#[test]
fn script_collateral_from_an_earlier_era_is_not_key_locked() {
    let raw = legacy_output(script_address());

    let result = check_collaterals_address(&[input()], &utxos(Era::Babbage, &raw));

    assert!(
        matches!(result, Err(PostAlonzo(CollateralNotVKeyLocked))),
        "{result:?}"
    );
}

#[test]
fn key_and_byron_collateral_is_key_locked_in_every_era() {
    for address in [key_address(), byron_address()] {
        let raw = legacy_output(address);
        for era in [Era::Alonzo, Era::Babbage, Era::Conway] {
            let result = check_collaterals_address(&[input()], &utxos(era, &raw));

            assert!(result.is_ok(), "{era:?} {result:?}");
        }
    }
}

const V2_SCRIPT: [u8; 4] = [1, 2, 3, 4];

fn output_with_reference_script() -> Vec<u8> {
    let mut cbor = vec![0xa3, 0x00, 0x58, 0x1d]; // output, a 29 byte address
    cbor.extend(key_address());
    cbor.extend([0x01, 0x1a, 0x00, 0x4c, 0x4b, 0x40]); // five ada
    cbor.extend([0x03, 0xd8, 0x18, 0x47, 0x82, 0x02, 0x44]); // a PlutusV2 reference script
    cbor.extend(V2_SCRIPT);
    cbor
}

fn byron_output() -> Vec<u8> {
    let mut cbor = vec![0x82];
    cbor.extend(byron_address());
    cbor.extend([0x1a, 0x00, 0x4c, 0x4b, 0x40]);
    cbor
}

fn input_cbor() -> Vec<u8> {
    let mut cbor = vec![0x82, 0x58, 0x20];
    cbor.extend([0; 32]);
    cbor.push(0x00);
    cbor
}

fn conway_tx_spending_input() -> Vec<u8> {
    let mut cbor = vec![0x84, 0xa3, 0x00, 0x81]; // transaction, body, one input
    cbor.extend(input_cbor());
    cbor.extend([0x01, 0x80, 0x02, 0x00]); // no outputs, no fee
    cbor.extend([0xa0, 0xf5, 0xf6]); // no witnesses, valid, no auxiliary data
    cbor
}

fn conway_tx_referencing_input() -> Vec<u8> {
    let mut cbor = vec![0x84, 0xa4]; // transaction, body
    cbor.extend([0x00, 0x80, 0x01, 0x80, 0x02, 0x00]); // no inputs, no outputs, no fee
    cbor.extend([0x12, 0x81]); // one reference input
    cbor.extend(input_cbor());
    cbor.extend([0xa0, 0xf5, 0xf6]); // no witnesses, valid, no auxiliary data
    cbor
}

#[test]
fn a_script_address_from_an_earlier_era_names_its_script() {
    for (address, expected) in [
        (script_address(), Some(Hash::from([2; 28]))),
        (key_address(), None),
    ] {
        let raw = legacy_output(address);
        for era in [Era::Alonzo, Era::Babbage, Era::Conway] {
            let actual = get_script_hash_from_input(&input(), &utxos(era, &raw));

            assert_eq!(actual, expected, "{era:?}");
        }
    }
}

#[test]
fn a_reference_script_from_an_earlier_era_is_found() {
    let cbor = conway_tx_spending_input();
    let tx = MultiEraTx::decode_for_era(Era::Conway, &cbor).unwrap();
    let body = &tx.as_conway().unwrap().transaction_body;
    let expected = pallas_crypto::hash::Hasher::<224>::hash_tagged(&V2_SCRIPT, 2);

    let with_script = output_with_reference_script();
    let without_script = legacy_output(key_address());
    for era in [Era::Babbage, Era::Conway] {
        assert_eq!(
            get_reference_script_hashes(body, &utxos(era, &with_script)),
            vec![expected],
            "{era:?}"
        );
        assert!(
            get_reference_script_hashes(body, &utxos(era, &without_script)).is_empty(),
            "{era:?}"
        );
    }
}

#[test]
fn a_datum_hash_on_an_earlier_era_reference_input_is_found() {
    let cbor = conway_tx_referencing_input();
    let tx = MultiEraTx::decode_for_era(Era::Conway, &cbor).unwrap();
    let body = &tx.as_conway().unwrap().transaction_body;
    let hash = Hash::from([3; 32]);
    let raw = minicbor::to_vec(pallas_primitives::alonzo::TransactionOutput {
        address: key_address().into(),
        amount: babbage::Value::Coin(5_000_000),
        datum_hash: Some(hash),
    })
    .unwrap();

    for era in [Era::Alonzo, Era::Babbage, Era::Conway] {
        let utxos = utxos(era, &raw);

        let found = find_datum(&hash, body, &utxos);
        let other = find_datum(&Hash::from([4; 32]), body, &utxos);

        assert!(found.is_ok(), "{era:?} {found:?}");
        assert!(
            matches!(other, Err(PostAlonzo(UnneededDatum))),
            "{era:?} {other:?}"
        );
    }
}

#[test]
fn a_byron_era_input_allows_no_plutus_language() {
    let cbor = conway_tx_spending_input();
    let tx = MultiEraTx::decode_for_era(Era::Conway, &cbor).unwrap();
    let tx = tx.as_conway().unwrap();

    let byron = byron_output();
    let key = legacy_output(key_address());

    assert_eq!(allowed_tx_langs(tx, &utxos(Era::Byron, &byron)), vec![]);
    assert_eq!(
        allowed_tx_langs(tx, &utxos(Era::Alonzo, &key)),
        vec![Language::PlutusV1, Language::PlutusV2, Language::PlutusV3]
    );
}
