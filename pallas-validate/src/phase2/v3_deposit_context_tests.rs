//! Synthetic encoding boundaries, independent of captured script success.
use super::{data::Data, script_context::*, to_plutus_data::*};
use pallas_primitives::conway::{
    Certificate, ExUnits, PlutusData, Redeemer, RedeemerTag, StakeCredential,
};

fn fields(data: &PlutusData) -> &[PlutusData] {
    match data {
        PlutusData::Constr(c) => &c.fields,
        _ => panic!("expected constructor: {data:?}"),
    }
}
fn context(cert: Certificate) -> ScriptContext<'static> {
    let r = Redeemer {
        tag: RedeemerTag::Cert,
        index: 2,
        data: Data::list(vec![]),
        ex_units: ExUnits {
            mem: 100,
            steps: 100,
        },
    };
    let purpose = ScriptPurpose::Certifying(2, cert.clone());
    TxInfo::V3(TxInfoV3 {
        inputs: vec![],
        reference_inputs: vec![],
        outputs: vec![],
        fee: 0,
        mint: MintValue {
            mint_value: Default::default(),
        },
        certificates: vec![cert],
        withdrawals: vec![].into(),
        valid_range: TimeRange {
            lower_bound: None,
            upper_bound: None,
        },
        signatories: vec![],
        redeemers: vec![(purpose, r.clone())].into(),
        data: vec![].into(),
        id: [0; 32].into(),
        votes: vec![].into(),
        proposal_procedures: vec![],
        current_treasury_amount: None,
        treasury_donation: None,
    })
    .into_script_context(&r, None)
    .unwrap()
}
#[test]
fn v3_deposit_context_protocol_boundaries_at_every_occurrence() {
    let credential = StakeCredential::ScriptHash([7; 28].into());
    for protocol in [9, 10, 11, 12] {
        for amount in [0, 1, 2000000, u64::MAX] {
            for (tag, cert) in [
                (0, Certificate::Reg(credential.clone(), amount)),
                (1, Certificate::UnReg(credential.clone(), amount)),
            ] {
                let c = context(cert);
                let encoded = c.to_plutus_data_with_protocol(protocol);
                let expected = Data::constr(
                    tag,
                    vec![
                        credential.to_plutus_data(),
                        if protocol == 9 {
                            None::<u64>.to_plutus_data()
                        } else {
                            Some(amount).to_plutus_data()
                        },
                    ],
                );
                let info = fields(&fields(&encoded)[0]);
                assert_eq!(
                    info[5],
                    Data::list(vec![expected.clone()]),
                    "certificate list protocol {protocol}"
                );
                assert_eq!(
                    fields(&fields(&encoded)[2])[1],
                    expected,
                    "active purpose protocol {protocol}"
                );
                let PlutusData::Map(m) = &info[9] else {
                    panic!("redeemer map")
                };
                assert_eq!(
                    fields(&m[0].0)[1],
                    expected,
                    "redeemer purpose protocol {protocol}"
                );
                if protocol == 9 {
                    assert_eq!(encoded, c.to_plutus_data());
                }
            }
        }
    }
}
#[test]
fn v3_deposit_context_legacy_certificates_have_no_explicit_amount() {
    let credential = StakeCredential::AddrKeyhash([3; 28].into());
    for cert in [
        Certificate::StakeRegistration(credential.clone()),
        Certificate::StakeDeregistration(credential),
    ] {
        let c = context(cert);
        assert_eq!(
            c.to_plutus_data_with_protocol(9),
            c.to_plutus_data_with_protocol(12)
        );
    }
}

#[test]
fn v3_deposit_context_protocol_reaches_script_execution() {
    use amaru_uplc::{arena::Arena, flat, syn::parse_program};
    use pallas_codec::minicbor;
    use pallas_primitives::conway::Language;

    fn field(value: &str, index: usize) -> String {
        let mut list =
            format!("[(force (force (builtin sndPair))) [(builtin unConstrData) {value}]]");
        for _ in 0..index {
            list = format!("[(force (builtin tailList)) {list}]");
        }
        format!("[(force (builtin headList)) {list}]")
    }
    // Certifying[1] -> Reg/UnReg[1] -> Just[0] -> explicit amount.
    let amount = field(&field(&field(&field("ctx", 2), 1), 1), 0);
    let condition =
        format!("[[(builtin equalsInteger) [(builtin unIData) {amount}]] (con integer 2000000)]");
    let source = format!(
        "(program 1.1.0 (lam ctx (force [[[(force (builtin ifThenElse)) {condition}] (delay (con unit ()))] (delay (error))])))"
    );
    let arena = Arena::new();
    let program = parse_program(&arena, &source).into_result().unwrap();
    let script = minicbor::to_vec(minicbor::bytes::ByteVec::from(
        flat::encode(program).unwrap(),
    ))
    .unwrap();
    let credential = StakeCredential::ScriptHash([7; 28].into());
    for cert in [
        Certificate::Reg(credential.clone(), 2000000),
        Certificate::UnReg(credential, 2000000),
    ] {
        for protocol in [9, 10, 12] {
            let ScriptContext::V3 { tx_info, .. } = context(cert.clone()) else {
                unreachable!()
            };
            let TxInfo::V3(ref info) = *tx_info else {
                unreachable!()
            };
            let redeemer = info.redeemers[0].1.clone();
            let result = super::tx::execute_script(
                Language::PlutusV3,
                *tx_info,
                &script,
                None,
                &redeemer,
                protocol,
            )
            .unwrap();
            assert_eq!(
                result.success,
                protocol > 9,
                "protocol {protocol}: {result:?}"
            );
        }
    }
}
#[test]
fn v1_certificate_context_wraps_every_staking_credential() {
    let credential = StakeCredential::ScriptHash([7; 28].into());
    let pool: pallas_crypto::hash::Hash<28> = [9; 28].into();
    let staking = Data::constr(0, vec![credential.to_plutus_data()]);
    for (cert, expected) in [
        (
            Certificate::Reg(credential.clone(), 2000000),
            Data::constr(0, vec![staking.clone()]),
        ),
        (
            Certificate::PoolRetirement(pool, 3),
            Data::constr(4, vec![pool.to_plutus_data(), 3u64.to_plutus_data()]),
        ),
        (
            Certificate::StakeRegistration(credential.clone()),
            Data::constr(0, vec![staking.clone()]),
        ),
        (
            Certificate::StakeDeregistration(credential.clone()),
            Data::constr(1, vec![staking.clone()]),
        ),
        (
            Certificate::UnReg(credential.clone(), 2000000),
            Data::constr(1, vec![staking.clone()]),
        ),
        (
            Certificate::StakeDelegation(credential.clone(), pool),
            Data::constr(2, vec![staking.clone(), pool.to_plutus_data()]),
        ),
    ] {
        let r = Redeemer {
            tag: RedeemerTag::Cert,
            index: 0,
            data: Data::list(vec![]),
            ex_units: ExUnits { mem: 1, steps: 1 },
        };
        let encoded = TxInfo::V1(TxInfoV1 {
            inputs: vec![],
            outputs: vec![],
            fee: pallas_primitives::conway::Value::Coin(0),
            mint: MintValue {
                mint_value: Default::default(),
            },
            certificates: vec![cert.clone()],
            withdrawals: vec![],
            valid_range: TimeRange {
                lower_bound: None,
                upper_bound: None,
            },
            signatories: vec![],
            data: vec![],
            redeemers: vec![(ScriptPurpose::Certifying(0, cert.clone()), r.clone())].into(),
            id: [0; 32].into(),
        })
        .into_script_context(&r, None)
        .unwrap()
        .to_plutus_data_with_protocol(12);
        assert_eq!(
            fields(&fields(&encoded)[0])[4],
            Data::list(vec![expected.clone()]),
            "certificate list {cert:?}"
        );
        assert_eq!(
            fields(&fields(&encoded)[1])[0],
            expected,
            "purpose {cert:?}"
        );
    }
}

#[test]
fn parameter_update_cost_models_are_a_map_from_language_to_values() {
    let int = |x: i64| x.to_plutus_data();
    let update = |cbor: &str| {
        let bytes = hex::decode(cbor).unwrap();
        pallas_codec::minicbor::decode::<pallas_primitives::conway::ProtocolParamUpdate>(&bytes)
            .unwrap()
            .to_plutus_data()
    };

    assert_eq!(update("a10001"), Data::map(vec![(int(0), int(1))]));

    let models = Data::map(vec![
        (int(0), Data::list(vec![int(1), int(-2)])),
        (int(2), Data::list(vec![int(3)])),
        (int(5), Data::list(vec![int(7)])),
    ]);
    assert_eq!(
        update("a2000112a300820121028103058107"),
        Data::map(vec![(int(0), int(1)), (int(18), models)])
    );
}
