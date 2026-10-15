#![cfg(feature = "phase2")]

use pallas_primitives::{ExUnits, conway::RedeemerTag};
use pallas_validate::phase2::{EvalReport, tx::TxEvalResult};

fn purpose(result: &TxEvalResult) -> &'static str {
    match result.tag {
        RedeemerTag::Spend => "spend",
        RedeemerTag::Mint => "mint",
        RedeemerTag::Cert => "cert",
        RedeemerTag::Reward => "reward",
        RedeemerTag::Vote => "vote",
        RedeemerTag::Propose => "propose",
    }
}

#[test]
fn a_crate_outside_pallas_builds_and_reads_an_evaluation_result() {
    let report: EvalReport = vec![TxEvalResult {
        tag: RedeemerTag::Mint,
        index: 1,
        units: ExUnits { mem: 2, steps: 3 },
        success: true,
        logs: vec![],
        failure_message: None,
    }];
    assert_eq!(purpose(&report[0]), "mint");
}
