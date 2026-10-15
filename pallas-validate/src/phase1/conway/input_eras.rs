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
