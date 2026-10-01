//! Native dispatch regressions. Captures are immutable; mutations are synthetic.
use super::*;
use crate::utils::DijkstraProtParams;
use pallas_addresses::{Network, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart};
use pallas_codec::{minicbor, utils::MaybeIndefArray};
use pallas_crypto::{hash::Hasher, key::ed25519::SecretKey};
use pallas_primitives::{conway, dijkstra as native};
use pallas_traverse::{MultiEraBlock, MultiEraInput, MultiEraOutput};

fn read(name: &str) -> Vec<u8> {
    hex::decode(
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../test_data/musashi-phase1")
                .join(name),
        )
        .unwrap()
        .trim(),
    )
    .unwrap()
}
pub(super) fn params() -> DijkstraProtParams {
    let p: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test_data/musashi-phase1/historical-parameters.json"
    ))
    .unwrap();
    DijkstraProtParams {
        key_deposit: None,
        plutus: None,
        system_start: "2026-09-07T00:00:00Z".parse().unwrap(),
        epoch_length: 21600,
        slot_length: 1,
        protocol_version: (
            p["protocol_major_ver"].as_u64().unwrap(),
            p["protocol_minor_ver"].as_u64().unwrap(),
        ),
        minfee_a: p["min_fee_a"].as_u64().unwrap() as u32,
        minfee_b: p["min_fee_b"].as_u64().unwrap() as u32,
        max_transaction_size: p["max_tx_size"].as_u64().unwrap() as u32,
        ada_per_utxo_byte: p["coins_per_utxo_size"].as_str().unwrap().parse().unwrap(),
        max_value_size: p["max_val_size"].as_str().unwrap().parse().unwrap(),
    }
}
pub(super) fn env() -> Environment {
    Environment {
        prot_params: MultiEraProtocolParameters::Dijkstra(params()),
        prot_magic: 164,
        block_slot: 1400007,
        network_id: 0,
        acnt: None,
    }
}
fn dispatch(
    tx: &native::BlockTransaction<'_>,
    output: &MultiEraOutput<'_>,
    env: &Environment,
) -> crate::utils::ValidationResult {
    let input = tx.transaction_body.inputs[0].clone();
    let utxos = [(
        MultiEraInput::AlonzoCompatible(Box::new(std::borrow::Cow::Owned(input))),
        output.clone(),
    )]
    .into_iter()
    .collect();
    validate_txs(
        &[MultiEraTx::from_dijkstra(tx)],
        env,
        &utxos,
        &mut CertState::default(),
    )
}
fn captured(test: impl FnOnce(native::BlockTransaction<'_>, MultiEraOutput<'_>)) {
    let raw = read("control.mempool.hex");
    let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &raw).unwrap();
    let input = read("control.input.hex");
    let output = MultiEraOutput::decode(Era::Dijkstra, &input).unwrap();
    assert_eq!(output.era(), Era::Dijkstra);
    test(tx.as_dijkstra().unwrap().clone(), output);
}
pub(super) fn error(result: crate::utils::ValidationResult, expected: &str) {
    assert_eq!(format!("{:?}", result.unwrap_err()), expected);
}

#[test]
fn dijkstra_captured_control_passes_native_dispatch() {
    captured(|tx, output| {
        assert_eq!(
            MultiEraTx::from_dijkstra(&tx).hash().to_string(),
            "f4ed3784097149431498b0df6ceaf13b3a531df88838d1f8f39df1269eb54b20"
        );
        assert!(
            dispatch(&tx, &output, &env()).is_ok(),
            "{:?}",
            dispatch(&tx, &output, &env())
        );
        let block_raw = read("control.block.hex");
        let block_tx: native::BlockTransaction = minicbor::decode(&block_raw).unwrap();
        assert!(block_tx.success);
        assert_eq!(
            block_tx.transaction_body.raw_cbor(),
            tx.transaction_body.raw_cbor()
        );
        assert_eq!(
            block_tx.transaction_witness_set.raw_cbor(),
            tx.transaction_witness_set.raw_cbor()
        );
        assert!(dispatch(&block_tx, &output, &env()).is_ok());
        // Accepted alternate mempool wrapper is synthetic; bytes inside are unchanged.
        let mut alternate = vec![0x84];
        alternate.extend(tx.transaction_body.raw_cbor());
        alternate.extend(tx.transaction_witness_set.raw_cbor());
        alternate.extend([0xf5, 0xf6]);
        let decoded = MultiEraTx::decode_for_era(Era::Dijkstra, &alternate).unwrap();
        assert!(dispatch(decoded.as_dijkstra().unwrap(), &output, &env()).is_ok());
    });
}
#[test]
fn dijkstra_captured_signatures_are_required_and_all_verified() {
    captured(|mut tx, output| {
        let original = tx.transaction_witness_set.clone();
        tx.transaction_witness_set.vkeywitness = None;
        error(
            dispatch(&tx, &output, &env()),
            "PostAlonzo(VKWitnessMissing)",
        );
        tx.transaction_witness_set = original.clone();
        let mut witness = original.vkeywitness.as_ref().unwrap()[0].clone();
        witness.signature = vec![0; 64].into();
        tx.transaction_witness_set.vkeywitness =
            native::NonEmptySet::from_vec(vec![witness.clone()]);
        error(
            dispatch(&tx, &output, &env()),
            "PostAlonzo(VKWrongSignature)",
        );
        // A valid required witness cannot hide an invalid additional witness.
        tx.transaction_witness_set.vkeywitness = native::NonEmptySet::from_vec(vec![
            original.vkeywitness.as_ref().unwrap()[0].clone(),
            witness.clone(),
        ]);
        error(
            dispatch(&tx, &output, &env()),
            "PostAlonzo(VKWrongSignature)",
        );
        witness.vkey = vec![0; 31].into();
        tx.transaction_witness_set.vkeywitness = native::NonEmptySet::from_vec(vec![witness]);
        error(
            dispatch(&tx, &output, &env()),
            "PostAlonzo(VKWrongSignature)",
        );
    });
}

// Re-sign synthetic body changes with a public deterministic test key, and make
// a synthetic key-locked UTxO with the original coin. Never overwrite captures.
pub(super) fn synthetic(
    test: impl FnOnce(native::BlockTransaction<'_>, native::TransactionOutput<'_>),
) {
    captured(|mut tx, output| {
        let key = SecretKey::from([71; 32]);
        let address = ShelleyAddress::new(
            Network::Testnet,
            ShelleyPaymentPart::Key(Hasher::<224>::hash(key.public_key().as_ref())),
            ShelleyDelegationPart::Null,
        )
        .to_vec();
        tx.transaction_body.outputs =
            MaybeIndefArray::Def(vec![native::TransactionOutput::PostAlonzo(
                native::PostAlonzoTransactionOutput {
                    address: address.clone().into(),
                    value: conway::Value::Coin(output.value().coin() - tx.transaction_body.fee),
                    datum_option: None,
                    script_ref: None,
                }
                .into(),
            )]);
        let input = native::TransactionOutput::PostAlonzo(
            native::PostAlonzoTransactionOutput {
                address: address.into(),
                value: conway::Value::Coin(output.value().coin()),
                datum_option: None,
                script_ref: None,
            }
            .into(),
        );
        sign(&mut tx);
        test(tx, input);
    });
}
pub(super) fn sign(tx: &mut native::BlockTransaction<'_>) {
    let key = SecretKey::from([71; 32]);
    let hash = Hasher::<256>::hash(&minicbor::to_vec(&tx.transaction_body).unwrap());
    tx.transaction_witness_set.vkeywitness =
        native::NonEmptySet::from_vec(vec![native::VKeyWitness {
            vkey: key.public_key().as_ref().to_vec().into(),
            signature: key.sign(hash).as_ref().to_vec().into(),
        }]);
}
#[test]
fn dijkstra_validity_is_half_open() {
    synthetic(|mut tx, input| {
        tx.transaction_body.validity_interval_start = Some(1400000);
        tx.transaction_body.ttl = Some(1400010);
        sign(&mut tx);
        let output = MultiEraOutput::from_dijkstra(&input);
        for slot in [1400000, 1400007, 1400009] {
            let mut e = env();
            e.block_slot = slot;
            assert!(dispatch(&tx, &output, &e).is_ok());
        }
        let mut e = env();
        e.block_slot = 1399999;
        error(
            dispatch(&tx, &output, &e),
            "PostAlonzo(BlockPrecedesValInt)",
        );
        for slot in [1400010, 1400011] {
            e.block_slot = slot;
            error(dispatch(&tx, &output, &e), "PostAlonzo(BlockExceedsValInt)");
        }
    });
}
#[test]
fn dijkstra_size_fee_and_output_boundaries() {
    captured(|tx, output| {
        assert_eq!(read("control.mempool.hex").len(), 196);
        assert_eq!(read("control.block.hex").len(), 197);
        let mut e = env();
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.max_transaction_size = 196;
        pp.minfee_a = 1;
        pp.minfee_b = 200000 - 196;
        assert!(dispatch(&tx, &output, &e).is_ok());
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.minfee_b += 1;
        error(dispatch(&tx, &output, &e), "PostAlonzo(FeeBelowMin)");
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.minfee_b -= 1;
        pp.max_transaction_size = 195;
        error(dispatch(&tx, &output, &e), "PostAlonzo(MaxTxSizeExceeded)");
    });
    synthetic(|tx, input| {
        let output = MultiEraOutput::from_dijkstra(&input);
        let mut e = env();
        let out = MultiEraOutput::from_dijkstra(&tx.transaction_body.outputs[0]);
        let size = minicbor::to_vec(&tx.transaction_body.outputs[0])
            .unwrap()
            .len() as u64;
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.ada_per_utxo_byte = out.value().coin() / (160 + size);
        assert!(dispatch(&tx, &output, &e).is_ok());
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.ada_per_utxo_byte += 1;
        error(
            dispatch(&tx, &output, &e),
            "PostAlonzo(MinLovelaceUnreached)",
        );
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.ada_per_utxo_byte = 4310;
        pp.max_value_size = 4;
        error(dispatch(&tx, &output, &e), "PostAlonzo(MaxValSizeExceeded)");
    });
}
#[test]
fn dijkstra_balance_network_and_input_checks() {
    synthetic(|mut tx, input| {
        let output = MultiEraOutput::from_dijkstra(&input);
        tx.transaction_body.fee += 1;
        error(
            dispatch(&tx, &output, &env()),
            "PostAlonzo(PreservationOfValue)",
        );
        tx.transaction_body.fee -= 1;
        tx.transaction_body.network_id = Some(native::NetworkId::Mainnet);
        error(
            dispatch(&tx, &output, &env()),
            "PostAlonzo(TxWrongNetworkID)",
        );
        tx.transaction_body.network_id = None;
        let mut e = env();
        e.network_id = 1;
        error(
            dispatch(&tx, &output, &e),
            "PostAlonzo(OutputWrongNetworkID)",
        );
        let mut inputs = tx.transaction_body.inputs.to_vec();
        inputs.push(inputs[0].clone());
        tx.transaction_body.inputs = inputs.into();
        error(
            dispatch(&tx, &output, &env()),
            "DijkstraUnsupported(\"duplicate inputs\")",
        );
        tx.transaction_body.inputs = vec![].into();
        error(
            validate_txs(
                &[MultiEraTx::from_dijkstra(&tx)],
                &env(),
                &UTxOs::new(),
                &mut CertState::default(),
            ),
            "PostAlonzo(TxInsEmpty)",
        );
    });
    captured(|tx, _| {
        error(
            validate_txs(
                &[MultiEraTx::from_dijkstra(&tx)],
                &env(),
                &UTxOs::new(),
                &mut CertState::default(),
            ),
            "PostAlonzo(InputNotInUTxO)",
        )
    });
}
#[test]
fn dijkstra_registration_rejects_unavailable_certificate_state() {
    let raw = hex::decode(
        include_str!("../../../test_data/musashi-registration/blocks/1401365.block").trim(),
    )
    .unwrap();
    let block = MultiEraBlock::decode(&raw).unwrap();
    let txs = block.txs();
    assert_eq!(
        txs[0].hash().to_string(),
        "da910a9bfbe657724d64b505099010dd47f86fb573aa1d20b4da0367163e94c6"
    );
    assert!(txs[0].as_dijkstra().unwrap().success);
    let producer_raw = hex::decode(
        include_str!("../../../test_data/musashi-registration/blocks/1401345.block").trim(),
    )
    .unwrap();
    let producer = MultiEraBlock::decode(&producer_raw).unwrap();
    let producers = producer.txs();
    let outputs = producers[0].outputs();
    let tx = txs[0].as_dijkstra().unwrap();
    let inputs = txs[0].inputs();
    let references = txs[0].reference_inputs();
    let utxos = [
        (inputs[0].clone(), outputs[1].clone()),
        (references[0].clone(), outputs[0].clone()),
    ]
    .into_iter()
    .collect();
    let mut e = env();
    e.block_slot = 1401365;
    error(
        validate_txs(&txs, &e, &utxos, &mut CertState::default()),
        "DijkstraCertificateStateUnavailable",
    );
    assert!(tx.transaction_body.certificates.is_some());
}
#[test]
fn dijkstra_unsupported_fields_do_not_disappear_in_decode() {
    captured(|tx, output| {
        // Add each disallowed body key in original CBOR, including unknown future keys.
        // Most known keys use typed synthetic mutations elsewhere; null still must reject.
        for key in [
            4, 5, 7, 9, 11, 13, 14, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 99,
        ] {
            let mut raw = tx.transaction_body.raw_cbor().to_vec();
            raw[0] += 1;
            let mut enc = minicbor::Encoder::new(Vec::new());
            enc.u64(key).unwrap().null().unwrap();
            raw.extend(enc.into_writer());
            // Optional nulls decode as None. The raw whitelist must still reject.
            let body = minicbor::decode(&raw).unwrap();
            let mut changed = tx.clone();
            changed.transaction_body = body;
            error(
                dispatch(&changed, &output, &env()),
                "DijkstraUnsupported(\"body fields\")",
            );
        }
        // A synthetic unknown map field must not disappear in typed decoding.
        let view = MultiEraOutput::from_dijkstra(&tx.transaction_body.outputs[0]);
        let mut enc = minicbor::Encoder::new(Vec::new());
        enc.map(3)
            .unwrap()
            .u8(0)
            .unwrap()
            .bytes(&view.address().unwrap().to_vec())
            .unwrap()
            .u8(1)
            .unwrap()
            .encode(view.value().into_alonzo())
            .unwrap()
            .u8(99)
            .unwrap()
            .null()
            .unwrap();
        let raw_output = enc.into_writer();
        let mut changed = tx.clone();
        changed.transaction_body.outputs =
            MaybeIndefArray::Def(vec![minicbor::decode(&raw_output).unwrap()]);
        error(
            dispatch(&changed, &output, &env()),
            "DijkstraUnsupported(\"output fields\")",
        );
        let raw = [0xa1, 0x08, 0x80]; // witness V4 key currently omitted by the typed model
        let mut changed = tx.clone();
        changed.transaction_witness_set = minicbor::decode(&raw).unwrap();
        error(
            dispatch(&changed, &output, &env()),
            "DijkstraUnsupported(\"witness fields\")",
        );
        changed = tx.clone();
        changed.auxiliary_data = pallas_codec::utils::Nullable::Undefined;
        error(
            dispatch(&changed, &output, &env()),
            "PostAlonzo(MetadataHash)",
        );
        changed = tx.clone();
        changed.success = false;
        error(
            dispatch(&changed, &output, &env()),
            "DijkstraUnsupported(\"unsuccessful block transaction\")",
        );
        let mut e = env();
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.protocol_version = (13, 0);
        error(
            dispatch(&tx, &output, &e),
            "DijkstraUnsupported(\"protocol version (requires 12.0)\")",
        );
    });
}
#[test]
fn dijkstra_earlier_era_inputs_keep_their_eras() {
    captured(|tx, output| {
        let raw = output.encode();
        // Synthetic representation tests, not genuine earlier-era captures.
        for era in [
            Era::Shelley,
            Era::Allegra,
            Era::Mary,
            Era::Alonzo,
            Era::Babbage,
            Era::Conway,
        ] {
            let earlier = MultiEraOutput::decode(era, &raw).unwrap();
            assert_eq!(earlier.era(), era);
            assert!(dispatch(&tx, &earlier, &env()).is_ok());
        }
    });
}

#[test]
fn dijkstra_typed_features_reject_explicitly() {
    captured(|tx, output| {
        for field in 0..10 {
            let mut changed = tx.clone();
            let expected = match field {
                0 => {
                    changed.transaction_body.guards = Some(native::Guards::Credentials(
                        native::NonEmptySet::from_vec(vec![native::StakeCredential::ScriptHash(
                            [1; 28].into(),
                        )])
                        .unwrap(),
                    ));
                    "script guards"
                }
                1 => {
                    changed.transaction_body.required_top_level_guards = Some(
                        [(
                            native::StakeCredential::ScriptHash([1; 28].into()),
                            pallas_codec::utils::Nullable::Null,
                        )]
                        .into_iter()
                        .collect(),
                    );
                    "script guards"
                }
                2 => {
                    changed.transaction_body.direct_deposits = Some(Default::default());
                    "account or governance state"
                }
                3 => {
                    changed.transaction_body.account_balance_intervals = Some(Default::default());
                    "account or governance state"
                }
                4 => {
                    changed.transaction_body.starting_account_balance_intervals =
                        Some(Default::default());
                    "account or governance state"
                }
                5 => {
                    changed.transaction_body.treasury_value = Some(0);
                    "account or governance state"
                }
                6 => {
                    changed.transaction_body.total_collateral = Some(0);
                    "collateral without Plutus"
                }
                7 => {
                    changed.transaction_body.reference_inputs =
                        native::NonEmptySet::from_vec(changed.transaction_body.inputs.to_vec());
                    "overlapping spending and reference inputs"
                }
                8 => {
                    changed.transaction_body.script_data_hash = Some([0; 32].into());
                    "script fields without script registration"
                }
                _ => {
                    changed.transaction_body.auxiliary_data_hash = Some([0; 32].into());
                    "auxiliary data"
                }
            };
            let expected = match field {
                8 => "PostAlonzo(ScriptIntegrityHash)".to_owned(),
                9 => "PostAlonzo(MetadataHash)".to_owned(),
                _ => format!("DijkstraUnsupported({expected:?})"),
            };
            error(dispatch(&changed, &output, &env()), &expected);
        }
        let sub_bytes = hex::decode("83a200800180a0f6").unwrap();
        let sub: native::SubTransaction = minicbor::decode(&sub_bytes).unwrap();
        let mut changed = tx.clone();
        changed.transaction_body.sub_transactions =
            native::NonEmptySet::from_vec(vec![sub.clone()]);
        error(
            dispatch(&changed, &output, &env()),
            "PostAlonzo(TxInsEmpty)",
        );
        error(
            validate_txs(
                &[MultiEraTx::from_dijkstra_sub(&sub, true)],
                &env(),
                &UTxOs::new(),
                &mut CertState::default(),
            ),
            "DijkstraUnsupported(\"subtransactions\")",
        );
    });
    synthetic(|tx, mut input| {
        let native::TransactionOutput::PostAlonzo(ref mut out) = input else {
            unreachable!()
        };
        out.script_ref = Some(pallas_codec::utils::CborWrap(
            native::ScriptRef::PlutusV4Script(pallas_primitives::PlutusScript(vec![1].into())),
        ));
        error(
            dispatch(&tx, &MultiEraOutput::from_dijkstra(&input), &env()),
            "PostAlonzo(UnsupportedPlutusLanguage)",
        );
    });
}

fn elements(raw: &[u8]) -> Vec<&[u8]> {
    let mut d = minicbor::Decoder::new(raw);
    let count = d.array().unwrap().unwrap();
    let parts = (0..count)
        .map(|_| {
            let start = d.position();
            d.skip().unwrap();
            &raw[start..d.position()]
        })
        .collect();
    assert_eq!(d.position(), raw.len());
    parts
}
#[test]
fn dijkstra_capture_integrity_and_certified_original_input() {
    use pallas_codec::utils::KeepRaw;
    use pallas_traverse::OriginalHash;
    let provenance: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test_data/musashi-phase1/payload-provenance.json"
    ))
    .unwrap();
    for (name, meta) in provenance.as_object().unwrap() {
        let bytes = read(name);
        assert_eq!(
            Hasher::<256>::hash(&bytes).to_string(),
            meta["blake2b_256"].as_str().unwrap()
        );
        assert_eq!(bytes.len() as u64, meta["bytes"].as_u64().unwrap());
    }
    for (name, slot, hash) in [
        (
            "control.block",
            1400007,
            "99fe52870c5c180eff940e90c8154d5d1abfaa19c94a4c78ff1bdfe80ac5474b",
        ),
        (
            "producer-announcement.block",
            1391831,
            "30ae10c97ff39bd91fa488b15778f622bf64a5436c7e3471dc99492f53928759",
        ),
        (
            "producer-certification.block",
            1391855,
            "9bc1f11abd20391247270d3ed9c866ed58b379ff5a1957e3df90087965807006",
        ),
    ] {
        let bytes = read(name);
        let block = MultiEraBlock::decode(&bytes).unwrap();
        assert_eq!(block.era(), Era::Dijkstra);
        assert_eq!(block.slot(), slot);
        assert_eq!(block.hash().to_string(), hash);
        let parts = elements(elements(&bytes)[1]);
        let native: native::Block = minicbor::decode(elements(&bytes)[1]).unwrap();
        assert_eq!(
            Hasher::<256>::hash(parts[1]),
            native.header.header_body.block_body_hash
        );
        assert_eq!(
            parts[1].len() as u64,
            native.header.header_body.block_body_size
        );
        if slot == 1400007 {
            let tx = &native.block_body.transactions[0];
            assert!(tx.success);
            assert_eq!(minicbor::to_vec(tx).unwrap(), read("control.block.hex"));
        }
    }
    let a = read("producer-announcement.block");
    let c = read("producer-certification.block");
    let a = MultiEraBlock::decode(&a).unwrap();
    let c = MultiEraBlock::decode(&c).unwrap();
    let ah = a.header();
    let ch = c.header();
    assert_eq!(ch.block_body_contains_leios_cert(), Some(true));
    assert_eq!(ch.previous_hash(), Some(ah.hash()));
    let announcement = ah.eb_announcement().unwrap();
    let commitments = read("producer-commitments.hex");
    let body: KeepRaw<native::EndorserBlock> = minicbor::decode(&commitments).unwrap();
    assert_eq!(body.original_hash(), announcement.eb_hash);
    assert_eq!(body.len(), 2340);
    let wire = read("control-producer.wire.hex");
    let raw = minicbor::Decoder::new(&wire).bytes().unwrap();
    let (hash, size) = body.get(23).unwrap();
    assert_eq!(Hasher::<256>::hash(raw), *hash);
    assert_eq!(raw.len(), *size as usize);
    let producer = MultiEraTx::decode_for_era(Era::Dijkstra, raw).unwrap();
    assert_eq!(
        producer.hash().to_string(),
        "884c9befc41220fbfb2026a79e2a0a293797a0de0f29f6e3ce13977fe7329e6f"
    );
    // Compare an original CBOR output slice, not a reconstructed output.
    let mut d = minicbor::Decoder::new(elements(raw)[0]);
    let mut original = None;
    for _ in 0..d.map().unwrap().unwrap() {
        let key = d.u64().unwrap();
        let start = d.position();
        d.skip().unwrap();
        if key == 1 {
            original = Some(elements(&d.input()[start..d.position()])[1]);
        }
    }
    assert_eq!(original.unwrap(), read("control.input.hex"));
    captured(|tx, output| {
        assert_eq!(
            tx.transaction_body.inputs[0].transaction_id,
            producer.hash()
        );
        assert_eq!(tx.transaction_body.inputs[0].index, 1);
        assert_eq!(output.encode(), original.unwrap());
        assert_eq!(output.era(), Era::Dijkstra);
    });
}

#[test]
fn dijkstra_output_subset_and_checked_arithmetic() {
    synthetic(|tx, input| {
        for feature in 0..4 {
            let mut changed = input.clone();
            let native::TransactionOutput::PostAlonzo(ref mut out) = changed else {
                unreachable!()
            };
            let expected = match feature {
                0 => {
                    out.datum_option = Some(native::DatumOption::Hash([0; 32].into()).into());
                    "output datum or reference script"
                }
                1 => {
                    out.value = conway::Value::Multiasset(
                        1,
                        vec![(
                            [0; 28].into(),
                            vec![(vec![1].into(), 1.try_into().unwrap())]
                                .into_iter()
                                .collect(),
                        )]
                        .into_iter()
                        .collect(),
                    );
                    "multiasset value"
                }
                2 => {
                    out.address = ShelleyAddress::new(
                        Network::Testnet,
                        ShelleyPaymentPart::Script([0; 28].into()),
                        ShelleyDelegationPart::Null,
                    )
                    .to_vec()
                    .into();
                    "script payment credential"
                }
                _ => {
                    out.address = ShelleyAddress::new(
                        Network::Testnet,
                        ShelleyPaymentPart::Key([0; 28].into()),
                        ShelleyDelegationPart::Pointer(pallas_addresses::Pointer::new(1, 2, 3)),
                    )
                    .to_vec()
                    .into();
                    "pointer address"
                }
            };
            let result = dispatch(&tx, &MultiEraOutput::from_dijkstra(&changed), &env());
            match feature {
                0 => assert!(result.is_ok(), "a key input may carry a datum"),
                1 => error(result, "PostAlonzo(PreservationOfValue)"),
                2 => error(result, "DijkstraMissingParameters(\"Plutus parameters\")"),
                _ => error(result, &format!("DijkstraUnsupported({expected:?})")),
            }
        }
        let output = MultiEraOutput::from_dijkstra(&input);
        let mut e = env();
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.ada_per_utxo_byte = u64::MAX;
        error(dispatch(&tx, &output, &e), "PostAlonzo(NegativeValue)");
        let mut changed = tx.clone();
        let mut outputs = changed.transaction_body.outputs.clone().to_vec();
        let native::TransactionOutput::PostAlonzo(ref mut out) = outputs[0] else {
            unreachable!()
        };
        out.value = conway::Value::Coin(u64::MAX);
        changed.transaction_body.outputs = MaybeIndefArray::Def(outputs);
        error(
            dispatch(&changed, &output, &env()),
            "PostAlonzo(NegativeValue)",
        );
        // Supported body/witness fields duplicated in raw CBOR also fail closed.
        let mut raw = tx.transaction_body.raw_cbor().to_vec();
        if raw.is_empty() {
            raw = minicbor::to_vec(&tx.transaction_body).unwrap();
        }
        raw[0] += 1;
        raw.extend([0x02, 0x00]);
        changed = tx.clone();
        changed.transaction_body = minicbor::decode(&raw).unwrap();
        error(
            dispatch(&changed, &output, &env()),
            "DijkstraUnsupported(\"body fields\")",
        );
    });
}
