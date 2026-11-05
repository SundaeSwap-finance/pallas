//! Top level PlutusV4 redeemers of ledger conformance records, against the contexts the ledger built and the budgets it spent.
use super::*;
use crate::utils::{EraCbor, TxoRef};
use pallas_codec::minicbor;
use pallas_primitives::dijkstra as n;
use pallas_traverse::{Era, MultiEraRedeemerTag, MultiEraTx};

const RECORDS: [u32; 7] = [900, 1896, 2109, 2113, 2165, 2302, 9846];

fn read(record: u32) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../test_data/dijkstra-plutus-v4")
        .join(format!("{record}.json"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn bytes(value: &serde_json::Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn utxos(fixture: &serde_json::Value) -> UtxoMap {
    fixture["utxos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            let input: n::TransactionInput = minicbor::decode(&bytes(&pair[0])).unwrap();
            (
                TxoRef(input.transaction_id, input.index as u32),
                EraCbor(Era::Dijkstra, bytes(&pair[1])),
            )
        })
        .collect()
}

fn params(fixture: &serde_json::Value) -> MultiEraProtocolParameters {
    let mut pp = crate::phase1::dijkstra_registration_tests::params().prot_params;
    let MultiEraProtocolParameters::Dijkstra(ref mut p) = pp else {
        unreachable!()
    };
    p.cost_models_for_script_languages.plutus_v4 =
        Some(serde_json::from_value(fixture["plutus_v4"].clone()).unwrap());
    pp
}

fn slots() -> SlotConfig {
    SlotConfig {
        zero_slot: 0,
        zero_time: 1506203091000,
        slot_length: 1000,
    }
}

/// The redeemer tag and index a fixture purpose names.
fn purpose(redeemer: &serde_json::Value) -> (MultiEraRedeemerTag, u32) {
    let (tag, index): (u8, u32) = minicbor::decode(&bytes(&redeemer["purpose"])).unwrap();
    let tag = match tag {
        0 => MultiEraRedeemerTag::Spend,
        1 => MultiEraRedeemerTag::Mint,
        2 => MultiEraRedeemerTag::Cert,
        3 => MultiEraRedeemerTag::Reward,
        4 => MultiEraRedeemerTag::Vote,
        5 => MultiEraRedeemerTag::Propose,
        6 => MultiEraRedeemerTag::Guarding,
        other => panic!("purpose tag {other}"),
    };
    (tag, index)
}

/// The tree of `data` with its definite and indefinite encodings identified.
fn shape(data: &n::PlutusData) -> String {
    let all = |xs: &[n::PlutusData]| xs.iter().map(shape).collect::<Vec<_>>().join(",");
    match data {
        n::PlutusData::Constr(x) => {
            format!("C{}/{:?}[{}]", x.tag, x.any_constructor, all(&x.fields))
        }
        n::PlutusData::Map(x) => {
            let pairs: Vec<_> = x
                .iter()
                .map(|(k, v)| format!("{}:{}", shape(k), shape(v)))
                .collect();
            format!("M{{{}}}", pairs.join(","))
        }
        n::PlutusData::Array(x) => format!("L[{}]", all(x)),
        n::PlutusData::BigInt(x) => format!("I{x:?}"),
        n::PlutusData::BoundedBytes(x) => format!("B{}", hex::encode(x.as_slice())),
    }
}

#[test]
fn top_level_plutus_v4_contexts_equal_the_ledger_contexts() {
    for record in RECORDS {
        let fixture = read(record);
        let raw = bytes(&fixture["tx"]);
        let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &raw).unwrap();
        let time = dijkstra::linear_time(&slots()).unwrap();
        let runs = dijkstra::runs(&tx, &params(&fixture), &utxos(&fixture), &time, false)
            .unwrap_or_else(|e| panic!("record {record}: {e:?}"));
        let want = fixture["redeemers"].as_array().unwrap();
        assert_eq!(runs.len(), want.len(), "record {record}");
        for redeemer in want {
            let key = purpose(redeemer);
            let run = runs
                .iter()
                .find(|r| (MultiEraRedeemerTag::from(r.tag), r.index) == key)
                .unwrap_or_else(|| panic!("record {record}: no run for {key:?}"));
            assert_eq!(
                run.language,
                n::Language::PlutusV4,
                "record {record} {key:?}"
            );
            let context: n::PlutusData = minicbor::decode(&bytes(&redeemer["context"])).unwrap();
            assert_eq!(run.args.len(), 1, "record {record} {key:?}");
            assert_eq!(
                shape(&run.args[0]),
                shape(&context),
                "record {record} {key:?}"
            );
        }
    }
}

#[test]
fn top_level_plutus_v4_redeemers_spend_the_ledger_budget() {
    for record in RECORDS {
        let fixture = read(record);
        let raw = bytes(&fixture["tx"]);
        let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &raw).unwrap();
        let report = evaluate_tx(&tx, &params(&fixture), &utxos(&fixture), &slots())
            .unwrap_or_else(|e| panic!("record {record}: {e:?}"));
        let want = fixture["redeemers"].as_array().unwrap();
        assert_eq!(report.len(), want.len(), "record {record}: {report:?}");
        for redeemer in want {
            let key = purpose(redeemer);
            let got = report
                .iter()
                .find(|r| (r.tag, r.index) == key)
                .unwrap_or_else(|| panic!("record {record}: no result for {key:?}"));
            assert!(got.success, "record {record}: {got:?}");
            assert_eq!(
                (got.units.mem, got.units.steps),
                (
                    redeemer["mem"].as_u64().unwrap(),
                    redeemer["steps"].as_u64().unwrap()
                ),
                "record {record} {key:?}"
            );
        }
    }
}
