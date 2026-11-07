//! PlutusV3 redeemers of ledger supplement records that call builtins, against the budgets the ledger spent.
use super::dijkstra_v4_tests::{purpose, slots, utxos};
use super::error::{Unsupported, UnsupportedEvaluation};
use super::*;
use crate::phase1::dijkstra_records_tests::{bytes, read_in};
use pallas_traverse::Era;

const DIR: &str = "dijkstra-plutus-v3-builtins";

/// The registration parameters with the PlutusV3 cost model of `fixture`.
fn params(fixture: &serde_json::Value) -> MultiEraProtocolParameters {
    let mut pp = crate::phase1::dijkstra_registration_tests::params().prot_params;
    let MultiEraProtocolParameters::Dijkstra(ref mut p) = pp else {
        unreachable!()
    };
    p.cost_models_for_script_languages.plutus_v3 =
        Some(serde_json::from_value(fixture["plutus_v3"].clone()).unwrap());
    pp
}

/// The fixture of `record` and the native evaluation of its transaction.
fn evaluate(record: u32) -> (serde_json::Value, Result<MultiEraEvalReport, Error>) {
    let fixture = read_in(DIR, record);
    let raw = bytes(&fixture["tx"]);
    let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &raw).unwrap();
    let report = evaluate_multi_era_tx(&tx, &params(&fixture), &utxos(&fixture), &slots());
    (fixture, report)
}

/// Asserts that every redeemer of `record` succeeds with the units the ledger spent.
fn spends_the_ledger_budget(record: u32) {
    let (fixture, report) = evaluate(record);
    let report = report.unwrap_or_else(|e| panic!("record {record}: {e:?}"));
    let want = fixture["redeemers"].as_array().unwrap();
    assert_eq!(report.len(), want.len(), "record {record}: {report:?}");
    for redeemer in want {
        let key = purpose(redeemer);
        let got = report
            .iter()
            .find(|r| (r.sub_transaction, r.tag, r.index) == key)
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

#[test]
fn a_plutus_v3_redeemer_calling_sha2_256_spends_the_ledger_budget() {
    spends_the_ledger_budget(211);
}

#[test]
fn a_plutus_v3_redeemer_calling_mk_nil_data_spends_the_ledger_budget() {
    spends_the_ledger_budget(214);
}

#[test]
fn a_plutus_v3_integer_operand_above_the_registration_range_is_unsupported() {
    let (_, report) = evaluate(217);
    assert!(
        matches!(
            report,
            Err(Error::DijkstraUnsupported(Unsupported(
                UnsupportedEvaluation::IntegerOutsideRegistrationRange
            )))
        ),
        "{report:?}"
    );
}
