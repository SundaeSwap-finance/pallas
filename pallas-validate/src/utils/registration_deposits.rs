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
