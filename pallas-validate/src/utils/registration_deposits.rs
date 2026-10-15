use super::*;
use pallas_primitives::conway::Certificate;
use std::borrow::Cow;

fn certificates(raw: &[Certificate]) -> Vec<MultiEraCert<'_>> {
    raw.iter()
        .map(|cert| MultiEraCert::Conway(Box::new(Cow::Borrowed(cert))))
        .collect()
}

#[test]
fn stake_deposit_sum_overflow_is_rejected() {
    let raw = [1, 2].map(|id| Certificate::Reg(StakeCredential::AddrKeyhash([id; 28].into()), 0));
    assert!(matches!(
        add_fee_and_stake_deposits(&ConwayValue::Coin(0), 0, &certificates(&raw), u64::MAX),
        Err(ValidationError::PostAlonzo(PostAlonzoError::NegativeValue))
    ));
}

#[test]
fn adding_fees_and_deposits_cannot_overflow_produced_value() {
    let raw = [Certificate::Reg(
        StakeCredential::AddrKeyhash([1; 28].into()),
        1,
    )];
    for (output, fee, deposit) in [(u64::MAX, 1, 0), (u64::MAX - 1, 1, 1)] {
        assert!(matches!(
            add_fee_and_stake_deposits(
                &ConwayValue::Coin(output),
                fee,
                &certificates(&raw),
                deposit
            ),
            Err(ValidationError::PostAlonzo(PostAlonzoError::NegativeValue))
        ));
    }
}

#[test]
fn deposits_preserve_native_assets() {
    let assets: ConwayMultiasset<PositiveCoin> = vec![(
        [1; 28].into(),
        vec![(vec![1].into(), 7u64.try_into().unwrap())]
            .into_iter()
            .collect(),
    )]
    .into_iter()
    .collect();
    let raw = [Certificate::Reg(
        StakeCredential::AddrKeyhash([1; 28].into()),
        2,
    )];
    assert_eq!(
        add_fee_and_stake_deposits(
            &ConwayValue::Multiasset(10, assets.clone()),
            3,
            &certificates(&raw),
            2
        )
        .unwrap(),
        ConwayValue::Multiasset(15, assets)
    );
}

#[test]
fn unrelated_certificate_deposits_are_not_stake_deposits() {
    let credential = StakeCredential::AddrKeyhash([1; 28].into());
    let raw = [
        Certificate::RegDRepCert(credential.clone(), 500_000_000, None),
        Certificate::UnReg(credential, 2_000_000),
    ];
    // This component neither charges DRep deposits nor subtracts refunds.
    assert_eq!(
        add_fee_and_stake_deposits(&ConwayValue::Coin(10), 3, &certificates(&raw), 2).unwrap(),
        ConwayValue::Coin(13)
    );
}

#[cfg(feature = "unstable")]
mod native {
    use super::*;
    use pallas_traverse::{MultiEraBlock, MultiEraTx};
    use std::{fs, path::PathBuf};

    fn read(path: impl AsRef<std::path::Path>) -> Vec<u8> {
        hex::decode(fs::read_to_string(path).unwrap().trim()).unwrap()
    }

    fn captured_registration(case: &str) {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test_data/musashi-registration");
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("provenance.json")).unwrap()).unwrap();
        let key_deposit = manifest["parameters"]["key_deposit"].as_u64().unwrap();
        let case = &manifest["cases"][case];
        let block_file = &manifest["blocks"][case["slot"].to_string()]["file"];
        let bytes = read(root.join(block_file.as_str().unwrap()));
        let block = MultiEraBlock::decode(&bytes).unwrap();
        let txs = block.txs();
        let tx = &txs[case["transaction_index"].as_u64().unwrap() as usize];
        assert_eq!(tx.era(), Era::Dijkstra);
        assert_eq!(
            tx.hash().to_string(),
            case["transaction_id"].as_str().unwrap()
        );
        let native = tx.as_dijkstra().unwrap();
        assert!(native.success);
        let body = &native.transaction_body;
        assert_eq!(
            body.raw_cbor(),
            read(root.join(case["body"].as_str().unwrap()))
        );
        assert!(body.mint.is_none());
        assert!(body.withdrawals.is_none());
        assert!(body.proposal_procedures.is_none());
        assert!(body.donation.is_none());
        assert!(body.sub_transactions.is_none());
        assert!(body.direct_deposits.is_none());
        assert!(body.account_balance_intervals.is_none());
        assert!(body.starting_account_balance_intervals.is_none());
        assert_eq!(body.inputs.len(), 1);
        assert_eq!(body.fee, case["fee"].as_u64().unwrap());
        let input_meta = &case["input"];
        assert_eq!(input_meta["era"], "Dijkstra");
        assert_eq!(
            body.inputs[0].transaction_id.to_string(),
            input_meta["transaction_id"].as_str().unwrap()
        );
        assert_eq!(
            body.inputs[0].index,
            input_meta["output_index"].as_u64().unwrap()
        );
        let input_bytes = read(root.join(input_meta["file"].as_str().unwrap()));
        let input = MultiEraOutput::decode(Era::Dijkstra, &input_bytes).unwrap();
        assert_eq!(input.era(), Era::Dijkstra);
        let certificates = tx.certs();
        assert_eq!(
            certificates.len() as u64,
            case["registration_count"].as_u64().unwrap()
        );
        assert!(
            certificates
                .iter()
                .all(|cert| matches!(cert.kind(), Some(MultiEraCertKind::Reg(..))))
        );
        let outputs = output_value(tx);
        let produced =
            add_fee_and_stake_deposits(&outputs, body.fee, &certificates, key_deposit).unwrap();
        assert_eq!(
            produced,
            input.value().into_conway(),
            "captured registration must preserve value including its deposits"
        );
        assert_eq!(
            input.encode(),
            input_bytes,
            "original input must remain unchanged"
        );
    }

    fn output_value(tx: &MultiEraTx) -> ConwayValue {
        tx.outputs()
            .iter()
            .try_fold(ConwayValue::Coin(0), |total, output| {
                assert_eq!(output.era(), Era::Dijkstra);
                conway_add_values(
                    &total,
                    &output.value().into_conway(),
                    &ValidationError::PostAlonzo(PostAlonzoError::NegativeValue),
                )
            })
            .unwrap()
    }

    #[test]
    fn settings_native_dijkstra_registration_balance() {
        captured_registration("settings");
    }

    #[test]
    fn protocol_native_dijkstra_registration_balance() {
        captured_registration("protocol");
    }
}
