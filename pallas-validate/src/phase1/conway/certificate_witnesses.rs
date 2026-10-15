//! Certificate authorization only; native Dijkstra captures use an explicit
//! Conway view of their compatible body/witness/output CBOR, never era dispatch.
use super::*;
use pallas_codec::minicbor;
use pallas_primitives::conway::{Certificate, RedeemerTag};

use pallas_crypto::{hash::Hasher, key::ed25519::SecretKey};
use pallas_primitives::{
    StakeCredential,
    alonzo::NativeScript,
    conway::{DRep, ExUnits, Redeemer},
};

fn result(actual: ValidationResult, expected: &str) {
    assert_eq!(format!("{actual:?}"), expected);
}

fn credential_certificates(cred: StakeCredential) -> Vec<Certificate> {
    let pool = [9; 28].into();
    vec![
        Certificate::StakeDeregistration(cred.clone()),
        Certificate::StakeDelegation(cred.clone(), pool),
        Certificate::Reg(cred.clone(), 2_000_000),
        Certificate::UnReg(cred.clone(), 2_000_000),
        Certificate::VoteDeleg(cred.clone(), DRep::Abstain),
        Certificate::StakeVoteDeleg(cred.clone(), pool, DRep::Abstain),
        Certificate::StakeRegDeleg(cred.clone(), pool, 2_000_000),
        Certificate::VoteRegDeleg(cred.clone(), DRep::Abstain, 2_000_000),
        Certificate::StakeVoteRegDeleg(cred.clone(), pool, DRep::Abstain, 2_000_000),
        Certificate::AuthCommitteeHot(cred.clone(), StakeCredential::AddrKeyhash([8; 28].into())),
        Certificate::ResignCommitteeCold(cred.clone(), None),
        Certificate::RegDRepCert(cred.clone(), 500_000_000, None),
        Certificate::UnRegDRepCert(cred.clone(), 500_000_000),
        Certificate::UpdateDRepCert(cred, None),
    ]
}

// Build, encode, then decode a synthetic Conway transaction before signing its
// real body hash. Authorization tests isolate witnesses, not certificate state.
fn synthetic(
    certificates: Vec<Certificate>,
    prepare: impl FnOnce(&mut Tx<'_>),
    keys: &[u8],
    test: impl FnOnce(Tx<'_>),
) {
    let raw = hex::decode(include_str!("../../../../test_data/conway3.tx").trim()).unwrap();
    let mut tx: Tx = minicbor::decode(&raw).unwrap();
    tx.transaction_body.inputs = Vec::new().into();
    tx.transaction_body.collateral = None;
    tx.transaction_body.reference_inputs = None;
    tx.transaction_body.required_signers = None;
    tx.transaction_body.withdrawals = None;
    tx.transaction_body.mint = None;
    tx.transaction_body.certificates = certificates.try_into().ok();
    tx.transaction_witness_set = minicbor::decode::<WitnessSet>(&[0xa0]).unwrap().into();
    prepare(&mut tx);
    let encoded = minicbor::to_vec(tx).unwrap();
    let mut tx: Tx = minicbor::decode(&encoded).unwrap();
    let hash = tx.transaction_body.original_hash();
    let witnesses: Vec<_> = keys
        .iter()
        .map(|id| {
            let key = SecretKey::from([*id; 32]);
            VKeyWitness {
                vkey: key.public_key().as_ref().to_vec().into(),
                signature: key.sign(hash).as_ref().to_vec().into(),
            }
        })
        .collect();
    tx.transaction_witness_set.vkeywitness = witnesses.try_into().ok();
    test(tx);
}

fn key_hash(id: u8) -> AddrKeyhash {
    Hasher::<224>::hash(SecretKey::from([id; 32]).public_key().as_ref())
}

fn plutus() -> PlutusScript<3> {
    PlutusScript(vec![1, 2, 3].into())
}

fn redeemer(index: u32, tag: RedeemerTag) -> Redeemer {
    Redeemer {
        tag,
        index,
        data: PlutusData::BigInt(pallas_primitives::BigInt::Int(0.into())),
        ex_units: ExUnits { mem: 1, steps: 1 },
    }
}

fn add_plutus(tx: &mut Tx<'_>, pointers: &[(u32, RedeemerTag)], map: bool) {
    tx.transaction_witness_set.plutus_v3_script = Some(vec![plutus()].try_into().unwrap());
    let list: Vec<_> = pointers
        .iter()
        .map(|(index, tag)| redeemer(*index, *tag))
        .collect();
    let redeemers = if map {
        Redeemers::Map(
            list.into_iter()
                .map(|r| {
                    (
                        RedeemersKey {
                            tag: r.tag,
                            index: r.index,
                        },
                        pallas_primitives::conway::RedeemersValue {
                            data: r.data,
                            ex_units: r.ex_units,
                        },
                    )
                })
                .collect(),
        )
    } else {
        Redeemers::List(list)
    };
    tx.transaction_witness_set.redeemer = Some(redeemers.into());
}

#[test]
fn every_credential_certificate_requires_its_key_and_valid_signature() {
    for cert in credential_certificates(StakeCredential::AddrKeyhash(key_hash(1))) {
        for (keys, expected) in [
            (&[1][..], "Ok(())"),
            (&[][..], "Err(PostAlonzo(VKWitnessMissing))"),
            (&[2][..], "Err(PostAlonzo(VKWitnessMissing))"),
        ] {
            synthetic(
                vec![cert.clone()],
                |_| {},
                keys,
                |tx| result(check_witness_set(&tx, &UTxOs::new()), expected),
            );
        }
        synthetic(
            vec![cert],
            |_| {},
            &[1],
            |mut tx| {
                let mut vkeys = tx
                    .transaction_witness_set
                    .vkeywitness
                    .clone()
                    .unwrap()
                    .to_vec();
                vkeys[0].signature = vec![0; 64].into();
                tx.transaction_witness_set.vkeywitness = Some(vkeys.try_into().unwrap());
                result(
                    check_witness_set(&tx, &UTxOs::new()),
                    "Err(PostAlonzo(VKWrongSignature))",
                );
            },
        );
    }
}

#[test]
fn every_credential_certificate_requires_script_and_plutus_redeemer() {
    let cred = StakeCredential::ScriptHash(compute_plutus_v3_script_hash(&plutus()));
    for cert in credential_certificates(cred) {
        for map in [false, true] {
            synthetic(
                vec![cert.clone()],
                |tx| add_plutus(tx, &[(0, RedeemerTag::Cert)], map),
                &[],
                |tx| result(check_witness_set(&tx, &UTxOs::new()), "Ok(())"),
            );
        }
        synthetic(
            vec![cert.clone()],
            |_| {},
            &[],
            |tx| {
                result(
                    check_witness_set(&tx, &UTxOs::new()),
                    "Err(PostAlonzo(ScriptWitnessMissing))",
                )
            },
        );
        synthetic(
            vec![cert.clone()],
            |tx| add_plutus(tx, &[], false),
            &[],
            |tx| {
                result(
                    check_witness_set(&tx, &UTxOs::new()),
                    "Err(PostAlonzo(RedeemerMissing))",
                )
            },
        );
        synthetic(
            vec![cert],
            |tx| {
                add_plutus(tx, &[(0, RedeemerTag::Cert)], true);
                tx.transaction_witness_set.plutus_v3_script =
                    Some(vec![PlutusScript(vec![99].into())].try_into().unwrap());
            },
            &[],
            |tx| {
                result(
                    check_witness_set(&tx, &UTxOs::new()),
                    "Err(PostAlonzo(ScriptWitnessMissing))",
                )
            },
        );
    }
}

#[test]
fn legacy_registration_requires_neither_key_script_nor_redeemer() {
    for cred in [
        StakeCredential::AddrKeyhash(key_hash(1)),
        StakeCredential::ScriptHash(compute_plutus_v3_script_hash(&plutus())),
    ] {
        synthetic(
            vec![Certificate::StakeRegistration(cred.clone())],
            |_| {},
            &[],
            |tx| result(check_witness_set(&tx, &UTxOs::new()), "Ok(())"),
        );
        synthetic(
            vec![Certificate::StakeRegistration(cred)],
            |tx| {
                tx.transaction_witness_set.redeemer =
                    Some(Redeemers::List(vec![redeemer(0, RedeemerTag::Cert)]).into());
            },
            &[],
            |tx| {
                result(
                    check_witness_set(&tx, &UTxOs::new()),
                    "Err(PostAlonzo(UnneededRedeemer))",
                )
            },
        );
    }
}

#[test]
fn certificate_pointers_use_full_positions_and_distinct_purposes() {
    let hash = compute_plutus_v3_script_hash(&plutus());
    let certs = vec![
        Certificate::StakeRegistration(StakeCredential::ScriptHash([0; 28].into())),
        Certificate::Reg(StakeCredential::AddrKeyhash(key_hash(1)), 2_000_000),
        Certificate::Reg(StakeCredential::ScriptHash(hash), 2_000_000),
        Certificate::VoteDeleg(StakeCredential::ScriptHash(hash), DRep::Abstain),
    ];
    for map in [false, true] {
        for (pointers, expected) in [
            (
                vec![(2, RedeemerTag::Cert), (3, RedeemerTag::Cert)],
                "Ok(())",
            ),
            (
                vec![(2, RedeemerTag::Cert)],
                "Err(PostAlonzo(RedeemerMissing))",
            ),
            (
                vec![(0, RedeemerTag::Cert), (1, RedeemerTag::Cert)],
                "Err(PostAlonzo(UnneededRedeemer))",
            ),
            (
                vec![(2, RedeemerTag::Spend), (3, RedeemerTag::Cert)],
                "Err(PostAlonzo(UnneededRedeemer))",
            ),
            (
                vec![(2, RedeemerTag::Cert), (4, RedeemerTag::Cert)],
                "Err(PostAlonzo(UnneededRedeemer))",
            ),
        ] {
            synthetic(
                certs.clone(),
                |tx| add_plutus(tx, &pointers, map),
                &[1],
                |tx| result(check_witness_set(&tx, &UTxOs::new()), expected),
            );
        }
    }
}

#[test]
fn native_certificate_checks_authorization_without_redeemers() {
    let script = NativeScript::ScriptPubkey(key_hash(1));
    for cert in credential_certificates(StakeCredential::ScriptHash(compute_native_script_hash(
        &script,
    ))) {
        for (keys, expected) in [
            (&[1][..], "Ok(())"),
            (&[][..], "Err(PostAlonzo(NativeScriptDenial))"),
            (&[2][..], "Err(PostAlonzo(NativeScriptDenial))"),
        ] {
            synthetic(
                vec![cert.clone()],
                |tx| {
                    tx.transaction_witness_set.native_script =
                        Some(vec![script.clone().into()].try_into().unwrap());
                },
                keys,
                |tx| result(check_witness_set(&tx, &UTxOs::new()), expected),
            );
        }
    }
    // A valid unrelated witness must not hide a later invalid script signer.
    synthetic(
        vec![Certificate::Reg(
            StakeCredential::ScriptHash(compute_native_script_hash(&script)),
            2_000_000,
        )],
        |tx| {
            tx.transaction_witness_set.native_script =
                Some(vec![script.into()].try_into().unwrap());
        },
        &[2, 1],
        |mut tx| {
            let mut vkeys = tx
                .transaction_witness_set
                .vkeywitness
                .clone()
                .unwrap()
                .to_vec();
            vkeys[1].signature = vec![0; 64].into();
            tx.transaction_witness_set.vkeywitness = Some(vkeys.try_into().unwrap());
            result(
                check_witness_set(&tx, &UTxOs::new()),
                "Err(PostAlonzo(VKWrongSignature))",
            );
        },
    );
}

#[test]
fn pool_certificates_require_operator_and_registration_owners() {
    let registration = Certificate::PoolRegistration {
        operator: key_hash(1),
        vrf_keyhash: [0; 32].into(),
        pledge: 0,
        cost: 0,
        margin: pallas_primitives::UnitInterval {
            numerator: 0,
            denominator: 1,
        },
        reward_account: vec![0xe1; 29].into(),
        pool_owners: vec![key_hash(2)].into(),
        relays: vec![],
        pool_metadata: None,
    };
    for (cert, keys) in [
        (registration, vec![1, 2]),
        (Certificate::PoolRetirement(key_hash(1), 1), vec![1]),
    ] {
        synthetic(
            vec![cert.clone()],
            |_| {},
            &keys,
            |tx| result(check_witness_set(&tx, &UTxOs::new()), "Ok(())"),
        );
        for missing in 0..keys.len() {
            let mut incomplete = keys.clone();
            incomplete.remove(missing);
            synthetic(
                vec![cert.clone()],
                |_| {},
                &incomplete,
                |tx| {
                    result(
                        check_witness_set(&tx, &UTxOs::new()),
                        "Err(PostAlonzo(VKWitnessMissing))",
                    )
                },
            );
        }
    }
}

#[test]
fn native_certificate_timelocks_and_thresholds_are_evaluated() {
    let script = NativeScript::ScriptAll(vec![
        NativeScript::ScriptNOfK(
            1,
            vec![
                NativeScript::ScriptPubkey(key_hash(1)),
                NativeScript::ScriptPubkey(key_hash(2)),
            ],
        ),
        NativeScript::InvalidBefore(10),
        NativeScript::InvalidHereafter(20),
    ]);
    for (start, end, expected) in [
        (Some(10), Some(20), "Ok(())"),
        (None, Some(20), "Err(PostAlonzo(NativeScriptDenial))"),
        (Some(9), Some(20), "Err(PostAlonzo(NativeScriptDenial))"),
        (Some(10), Some(21), "Err(PostAlonzo(NativeScriptDenial))"),
    ] {
        synthetic(
            vec![Certificate::Reg(
                StakeCredential::ScriptHash(compute_native_script_hash(&script)),
                2_000_000,
            )],
            |tx| {
                tx.transaction_body.validity_interval_start = start;
                tx.transaction_body.ttl = end;
                tx.transaction_witness_set.native_script =
                    Some(vec![script.clone().into()].try_into().unwrap());
            },
            &[2],
            |tx| result(check_witness_set(&tx, &UTxOs::new()), expected),
        );
    }
}

#[test]
fn native_and_key_certificates_reject_unnecessary_redeemers() {
    let script = NativeScript::ScriptAll(vec![]);
    for native in [false, true] {
        let cred = if native {
            StakeCredential::ScriptHash(compute_native_script_hash(&script))
        } else {
            StakeCredential::AddrKeyhash(key_hash(1))
        };
        synthetic(
            vec![Certificate::Reg(cred, 2_000_000)],
            |tx| {
                if native {
                    tx.transaction_witness_set.native_script =
                        Some(vec![script.clone().into()].try_into().unwrap());
                }
                tx.transaction_witness_set.redeemer =
                    Some(Redeemers::List(vec![redeemer(0, RedeemerTag::Cert)]).into());
            },
            &[1],
            |tx| {
                result(
                    check_witness_set(&tx, &UTxOs::new()),
                    "Err(PostAlonzo(UnneededRedeemer))",
                )
            },
        );
    }
}

#[test]
fn all_plutus_versions_can_supply_certificate_scripts() {
    let v1 = PlutusScript::<1>(vec![1, 2].into());
    let v2 = PlutusScript::<2>(vec![1, 2].into());
    let v3 = plutus();
    for (version, hash) in [
        (1, compute_plutus_v1_script_hash(&v1)),
        (2, compute_plutus_v2_script_hash(&v2)),
        (3, compute_plutus_v3_script_hash(&v3)),
    ] {
        synthetic(
            vec![Certificate::Reg(
                StakeCredential::ScriptHash(hash),
                2_000_000,
            )],
            |tx| {
                match version {
                    1 => {
                        tx.transaction_witness_set.plutus_v1_script =
                            Some(vec![v1.clone()].try_into().unwrap())
                    }
                    2 => {
                        tx.transaction_witness_set.plutus_v2_script =
                            Some(vec![v2.clone()].try_into().unwrap())
                    }
                    _ => {
                        tx.transaction_witness_set.plutus_v3_script =
                            Some(vec![v3.clone()].try_into().unwrap())
                    }
                }
                tx.transaction_witness_set.redeemer =
                    Some(Redeemers::List(vec![redeemer(0, RedeemerTag::Cert)]).into());
            },
            &[],
            |tx| result(check_witness_set(&tx, &UTxOs::new()), "Ok(())"),
        );
    }
}
