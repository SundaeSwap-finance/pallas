//! Synthetic Conway cases isolate balance accounting from signatures and DELEG.
use super::*;
use pallas_codec::minicbor;
use pallas_primitives::{
    StakeCredential,
    conway::{Certificate, DRep, LegacyTransactionOutput, PostAlonzoTransactionOutput},
};

const KEY_DEPOSIT: u64 = 2_000_000;
const INPUT: u64 = 20_000_000;

fn registrations(declared: u64) -> Vec<Certificate> {
    let credential = StakeCredential::AddrKeyhash([1; 28].into());
    let pool = [2; 28].into();
    vec![
        Certificate::StakeRegistration(credential.clone()),
        Certificate::Reg(credential.clone(), declared),
        Certificate::StakeRegDeleg(credential.clone(), pool, declared),
        Certificate::VoteRegDeleg(credential.clone(), DRep::Abstain, declared),
        Certificate::StakeVoteRegDeleg(credential, pool, DRep::Abstain, declared),
    ]
}

fn output(coin: u64, legacy: bool) -> TransactionOutput<'static> {
    let mut address = vec![0x61];
    address.extend([0; 28]);
    if legacy {
        TransactionOutput::Legacy(
            LegacyTransactionOutput {
                address: address.into(),
                amount: babbage::Value::Coin(coin),
                datum_hash: None,
            }
            .into(),
        )
    } else {
        TransactionOutput::PostAlonzo(
            PostAlonzoTransactionOutput {
                address: address.into(),
                value: Value::Coin(coin),
                datum_option: None,
                script_ref: None,
            }
            .into(),
        )
    }
}

fn with_tx(certificates: Vec<Certificate>, reserved: u64, legacy: bool, test: impl FnOnce(Tx<'_>)) {
    // Reuse a native Conway body's structure, with synthetic amounts/certificates.
    let raw = hex::decode(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test_data/conway3.tx"
        ))
        .trim(),
    )
    .unwrap();
    let mut tx: Tx = minicbor::decode(&raw).unwrap();
    let mut body = (*tx.transaction_body).clone();
    assert_eq!(body.inputs.len(), 1);
    body.fee = 200_000;
    body.mint = None;
    body.outputs = vec![output(INPUT - body.fee - reserved, legacy)];
    body.certificates = if certificates.is_empty() {
        None
    } else {
        Some(certificates.try_into().unwrap())
    };
    tx.transaction_body = body.into();
    test(tx);
}

fn balance(tx: &Tx, legacy_input: bool, key_deposit: u64) -> ValidationResult {
    let input = output(INPUT, legacy_input);
    let utxos = UTxOs::from([(
        MultiEraInput::from_alonzo_compatible(&tx.transaction_body.inputs[0]),
        MultiEraOutput::from_conway(&input),
    )]);
    check_preservation_of_value(tx, &utxos, key_deposit)
}

#[test]
fn all_stake_registration_forms_charge_the_protocol_deposit() {
    for key_deposit in [KEY_DEPOSIT, 3_000_000] {
        for certificate in registrations(key_deposit) {
            for legacy_output in [false, true] {
                with_tx(
                    vec![certificate.clone()],
                    key_deposit,
                    legacy_output,
                    |tx| {
                        for legacy_input in [false, true] {
                            balance(&tx, legacy_input, key_deposit).unwrap();
                        }
                    },
                );
            }
        }
    }
}

#[test]
fn absent_or_delegation_only_certificates_do_not_charge_a_deposit() {
    let credential = StakeCredential::AddrKeyhash([1; 28].into());
    for certificates in [
        vec![],
        vec![Certificate::StakeDelegation(
            credential.clone(),
            [2; 28].into(),
        )],
        vec![Certificate::VoteDeleg(credential, DRep::Abstain)],
    ] {
        with_tx(certificates, 0, false, |tx| {
            balance(&tx, false, KEY_DEPOSIT).unwrap()
        });
    }
}

#[test]
fn one_lovelace_imbalance_fails_for_both_encodings() {
    for legacy in [false, true] {
        with_tx(
            vec![registrations(KEY_DEPOSIT).remove(1)],
            KEY_DEPOSIT,
            legacy,
            |tx| {
                for delta in [-1, 1] {
                    let mut changed = tx.clone();
                    let mut body = (*changed.transaction_body).clone();
                    body.fee = body.fee.checked_add_signed(delta).unwrap();
                    changed.transaction_body = body.into();
                    for legacy_input in [false, true] {
                        assert!(matches!(
                            balance(&changed, legacy_input, KEY_DEPOSIT),
                            Err(PostAlonzo(PreservationOfValue))
                        ));
                    }
                }
            },
        );
    }
}

#[test]
fn removing_registration_leaves_unbalanced_value() {
    with_tx(vec![], KEY_DEPOSIT, false, |tx| {
        assert!(matches!(
            balance(&tx, false, KEY_DEPOSIT),
            Err(PostAlonzo(PreservationOfValue))
        ));
    });
}

#[test]
fn declared_deposit_cannot_override_protocol_accounting() {
    for delta in [-1, 1] {
        // Skip the legacy registration: it has no declared amount.
        for certificate in registrations(KEY_DEPOSIT.checked_add_signed(delta).unwrap())
            .into_iter()
            .skip(1)
        {
            with_tx(vec![certificate], KEY_DEPOSIT, false, |mut tx| {
                // Amount validity belongs to DELEG, not this balance rule.
                balance(&tx, false, KEY_DEPOSIT).unwrap();
                let mut body = (*tx.transaction_body).clone();
                body.fee = body.fee.checked_add_signed(-delta).unwrap();
                tx.transaction_body = body.into();
                assert!(matches!(
                    balance(&tx, false, KEY_DEPOSIT),
                    Err(PostAlonzo(PreservationOfValue))
                ));
            });
        }
    }
}
