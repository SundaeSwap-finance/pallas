//! Network evidence for the scoped registration-deposit regression.
#![cfg(feature = "unstable")]

use std::{fs, path::PathBuf};

use pallas_codec::minicbor::{self, Decoder};
use pallas_crypto::hash::Hasher;
use pallas_primitives::dijkstra;
use pallas_traverse::{Era, MultiEraBlock};
use serde_json::Value;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test_data/musashi-registration")
}

fn read(path: &Value) -> Vec<u8> {
    hex::decode(
        fs::read_to_string(root().join(path.as_str().unwrap()))
            .unwrap()
            .trim(),
    )
    .unwrap()
}

// Preserve original CBOR slices; re-encoding is not evidence of byte identity.
fn elements(raw: &[u8]) -> Vec<&[u8]> {
    let mut decoder = Decoder::new(raw);
    let count = decoder.array().unwrap().unwrap();
    let parts = (0..count)
        .map(|_| {
            let start = decoder.position();
            decoder.skip().unwrap();
            &raw[start..decoder.position()]
        })
        .collect();
    assert_eq!(decoder.position(), raw.len());
    parts
}

fn outputs(body: &[u8]) -> Vec<&[u8]> {
    let mut decoder = Decoder::new(body);
    for _ in 0..decoder.map().unwrap().unwrap() {
        let key = decoder.u64().unwrap();
        let start = decoder.position();
        decoder.skip().unwrap();
        if key == 1 {
            return elements(&body[start..decoder.position()]);
        }
    }
    panic!("producer has no outputs")
}

#[test]
fn registration_fixtures_match_successful_network_transactions() {
    let manifest: Value =
        serde_json::from_slice(&fs::read(root().join("provenance.json")).unwrap()).unwrap();
    for (file, hash) in manifest["payload_blake2b_256"].as_object().unwrap() {
        assert_eq!(
            Hasher::<256>::hash(
                &hex::decode(fs::read_to_string(root().join(file)).unwrap().trim()).unwrap(),
            )
            .to_string(),
            hash.as_str().unwrap(),
            "{file}"
        );
    }
    let blocks = manifest["blocks"].as_object().unwrap();
    assert_eq!(blocks.len(), 4);
    for (slot, metadata) in blocks {
        let raw = read(&metadata["file"]);
        let block = MultiEraBlock::decode(&raw).unwrap();
        assert_eq!(block.era(), Era::Dijkstra);
        assert_eq!(block.slot().to_string(), *slot);
        assert_eq!(block.number(), metadata["block_number"].as_u64().unwrap());
        assert_eq!(
            block.hash().to_string(),
            metadata["header_hash"].as_str().unwrap()
        );
        let parts = elements(elements(&raw)[1]);
        let native: dijkstra::Block = minicbor::decode(elements(&raw)[1]).unwrap();
        assert_eq!(
            Hasher::<256>::hash(parts[1]),
            native.header.header_body.block_body_hash
        );
        assert_eq!(
            parts[1].len() as u64,
            native.header.header_body.block_body_size
        );
    }
    let cases = manifest["cases"].as_object().unwrap();
    assert_eq!(cases.len(), 2);
    for case in cases.values() {
        let raw = read(&blocks[&case["slot"].to_string()]["file"]);
        let (_, block): (u16, dijkstra::Block) = minicbor::decode(&raw).unwrap();
        let tx =
            &block.block_body.transactions[case["transaction_index"].as_u64().unwrap() as usize];
        assert!(tx.success);
        let body = tx.transaction_body.raw_cbor();
        assert_eq!(body, read(&case["body"]));
        assert_eq!(
            Hasher::<256>::hash(body).to_string(),
            case["transaction_id"].as_str().unwrap()
        );
        let certs = tx.transaction_body.certificates.as_ref().unwrap();
        assert_eq!(
            certs.len() as u64,
            case["registration_count"].as_u64().unwrap()
        );
        for cert in certs.iter() {
            let dijkstra::Certificate::Reg(_, deposit) = cert else {
                panic!("unexpected certificate")
            };
            assert_eq!(
                *deposit,
                manifest["parameters"]["key_deposit"].as_u64().unwrap()
            );
        }
        let input = &case["input"];
        assert_eq!(tx.transaction_body.inputs.len(), 1);
        assert_eq!(
            tx.transaction_body.inputs[0].transaction_id.to_string(),
            input["transaction_id"].as_str().unwrap()
        );
        assert_eq!(
            tx.transaction_body.inputs[0].index,
            input["output_index"].as_u64().unwrap()
        );
        let raw = read(&blocks[&input["slot"].to_string()]["file"]);
        let (_, block): (u16, dijkstra::Block) = minicbor::decode(&raw).unwrap();
        let producer =
            &block.block_body.transactions[input["transaction_index"].as_u64().unwrap() as usize];
        assert!(producer.success);
        let body = producer.transaction_body.raw_cbor();
        assert_eq!(
            Hasher::<256>::hash(body).to_string(),
            input["transaction_id"].as_str().unwrap()
        );
        assert_eq!(
            outputs(body)[input["output_index"].as_u64().unwrap() as usize],
            read(&input["file"])
        );
    }
}
