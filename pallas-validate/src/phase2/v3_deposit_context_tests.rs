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
    let program = parse_program(&arena, &source, amaru_kernel::ProtocolVersion::new(12, 0))
        .into_result()
        .unwrap();
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
