use std::collections::HashMap;

use serde_json::json;
use u5c_chain_oracle::compare;
use u5c_chain_oracle::coverage::{Coverage, Location, Tally};
use u5c_chain_oracle::fields::{self, Case, Found, IdVerdict, PoolReport};
use u5c_chain_oracle::ledger::Ledger;
use u5c_chain_oracle::model::Output;

fn case() -> Case {
    Case {
        name: "s0".to_owned(),
        id: [1; 32],
    }
}

const AT: Found = Found {
    block: 7,
    parent: None,
};

fn output(coin: u64) -> Output {
    Output {
        address: vec![0x60; 29],
        coin,
        assets: Default::default(),
        datum_hash: None,
        script: None,
    }
}

#[test]
fn ids_agree_when_every_case_is_carried() {
    let c = case();
    assert!(fields::ids_agree(&[(&c, IdVerdict::Carried(AT))]));
}

#[test]
fn ids_disagree_when_a_case_is_not_carried_or_not_in_source() {
    let c = case();
    assert!(!fields::ids_agree(&[(&c, IdVerdict::NotCarried(AT))]));
    assert!(!fields::ids_agree(&[(&c, IdVerdict::NotInSource)]));
}

#[test]
fn ids_disagree_without_a_case() {
    assert!(!fields::ids_agree(&[]));
}

#[test]
fn pools_agree_when_u5c_holds_every_bls_key() {
    let report = PoolReport {
        registrations: 2,
        with_bls: 1,
        bls_in_u5c: 1,
        ..Default::default()
    };
    assert!(report.agrees());
}

#[test]
fn pools_disagree_when_u5c_drops_a_bls_key() {
    let report = PoolReport {
        registrations: 2,
        with_bls: 1,
        bls_in_u5c: 0,
        ..Default::default()
    };
    assert!(!report.agrees());
}

#[test]
fn pools_disagree_without_a_bls_registration() {
    let report = PoolReport {
        registrations: 3,
        ..Default::default()
    };
    assert!(!report.agrees());
}

fn coverage(tally: Tally) -> Coverage {
    let mut c = Coverage {
        blocks: 1,
        ..Default::default()
    };
    c.tallies.insert(Location::Body(0), tally);
    c
}

#[test]
fn coverage_agrees_when_u5c_holds_every_occurrence() {
    let c = coverage(Tally {
        occurrences: 3,
        ..Default::default()
    });
    assert!(c.agrees());
}

#[test]
fn coverage_disagrees_when_an_occurrence_has_no_counterpart() {
    let c = coverage(Tally {
        occurrences: 3,
        without_counterpart: 1,
        first: Some((7, None)),
        ..Default::default()
    });
    assert!(!c.agrees());
}

#[test]
fn coverage_disagrees_without_a_block() {
    assert!(!Coverage::default().agrees());
}

#[test]
fn state_agrees_when_the_fold_holds_the_node_utxo() {
    let mut fold = Ledger::default();
    fold.utxo.insert(([2; 32], 0), output(5));
    let node = HashMap::from([(([2; 32], 0), output(5))]);
    assert!(compare::state(&fold, &node, &HashMap::new()).agrees());
}

#[test]
fn state_disagrees_when_an_output_differs() {
    let mut fold = Ledger::default();
    fold.utxo.insert(([2; 32], 0), output(5));
    let node = HashMap::from([(([2; 32], 0), output(6))]);
    let report = compare::state(&fold, &node, &HashMap::new());
    assert_eq!(
        report.utxo,
        vec![compare::UtxoMismatch::Differs(([2; 32], 0))]
    );
    assert!(!report.agrees());
}

#[test]
fn state_disagrees_without_a_node_entry() {
    let report = compare::state(&Ledger::default(), &HashMap::new(), &HashMap::new());
    assert!(!report.agrees());
}

#[test]
fn same_agrees_within_one_part_in_a_billion() {
    assert!(fields::same(&json!(0.0577), &json!(577.0 / 10000.0)));
    assert!(fields::same(&json!([1, {"a": 2}]), &json!([1, {"a": 2}])));
}

#[test]
fn same_disagrees_on_a_different_value() {
    assert!(!fields::same(&json!(0.0577), &json!(0.0578)));
    assert!(!fields::same(&json!([1, 2]), &json!([1])));
}

#[test]
fn same_disagrees_when_either_side_is_missing() {
    assert!(!fields::same(&json!(null), &json!(null)));
    assert!(!fields::same(&json!(null), &json!(1)));
}
