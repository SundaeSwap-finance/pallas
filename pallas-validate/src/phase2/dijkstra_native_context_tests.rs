use super::*;
use pallas_codec::{minicbor, utils::KeepRaw};
use pallas_traverse::OriginalHash;

#[test]
fn dijkstra_native_reference_hash_survives_v3_projection() {
    // Non-minimal array length and tag: semantic re-encoding changes its hash.
    let raw = [0x98, 0x02, 0x18, 0x01, 0x80];
    let native: KeepRaw<'_, n::NativeScript> = minicbor::decode(&raw).unwrap();
    let expected = native.original_hash();
    let address = pallas_addresses::ShelleyAddress::new(
        pallas_addresses::Network::Testnet,
        ShelleyPaymentPart::Key([1; 28].into()),
        ShelleyDelegationPart::Null,
    )
    .to_vec();
    let output = n::TransactionOutput::PostAlonzo(
        n::PostAlonzoTransactionOutput {
            address: address.into(),
            value: c::Value::Coin(5_000_000),
            datum_option: None,
            script_ref: Some(CborWrap(n::ScriptRef::NativeScript(native))),
        }
        .into(),
    );
    let projected = context_output(&MultiEraOutput::from_dijkstra(&output), true).unwrap();
    let view = MultiEraOutput::from_conway(&projected);
    let reference = view.multi_era_script_ref().unwrap();
    assert_eq!(reference.hash(), expected);
    assert_eq!(reference.native_script().unwrap().encode(), raw);
    // Earlier-era reference scripts retain those same original bytes too.
    let second = context_output(&view, true).unwrap();
    assert_eq!(
        MultiEraOutput::from_conway(&second)
            .multi_era_script_ref()
            .unwrap()
            .hash(),
        expected
    );
}

#[test]
fn dijkstra_native_reference_guard_has_no_v3_projection() {
    let guard = n::NativeScript::ScriptAll(vec![n::NativeScript::ScriptRequireGuard(
        n::StakeCredential::AddrKeyhash([2; 28].into()),
    )]);
    let raw = minicbor::to_vec(&guard).unwrap();
    let native: KeepRaw<'_, n::NativeScript> = minicbor::decode(&raw).unwrap();
    let address = pallas_addresses::ShelleyAddress::new(
        pallas_addresses::Network::Testnet,
        ShelleyPaymentPart::Key([1; 28].into()),
        ShelleyDelegationPart::Null,
    )
    .to_vec();
    let output = n::TransactionOutput::PostAlonzo(
        n::PostAlonzoTransactionOutput {
            address: address.into(),
            value: c::Value::Coin(5_000_000),
            datum_option: None,
            script_ref: Some(CborWrap(n::ScriptRef::NativeScript(native))),
        }
        .into(),
    );
    let result = context_output(&MultiEraOutput::from_dijkstra(&output), true);
    assert!(
        matches!(
            result,
            Err(Error::DijkstraUnsupported(Unsupported(
                "native script guards"
            )))
        ),
        "{result:?}"
    );
}

#[test]
fn dijkstra_pointer_output_is_labelled_as_a_v3_context_pointer() {
    let output = |delegation| {
        let address = pallas_addresses::ShelleyAddress::new(
            pallas_addresses::Network::Testnet,
            ShelleyPaymentPart::Key([1; 28].into()),
            delegation,
        )
        .to_vec();
        n::TransactionOutput::PostAlonzo(
            n::PostAlonzoTransactionOutput {
                address: address.into(),
                value: c::Value::Coin(5_000_000),
                datum_option: None,
                script_ref: None,
            }
            .into(),
        )
    };
    let base = output(ShelleyDelegationPart::Null);
    assert!(context_output(&MultiEraOutput::from_dijkstra(&base), false).is_ok());
    let pointer = output(ShelleyDelegationPart::Pointer(
        pallas_addresses::Pointer::new(1, 2, 3),
    ));
    let result = context_output(&MultiEraOutput::from_dijkstra(&pointer), false);
    assert!(
        matches!(
            result,
            Err(Error::DijkstraUnsupported(Unsupported(
                "pointer address in a V3 script context"
            )))
        ),
        "{result:?}"
    );
}
