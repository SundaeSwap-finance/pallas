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
