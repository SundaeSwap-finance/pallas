use std::collections::HashMap;

use pallas_utxorpc::v1beta::spec::cardano as u5c;
use u5c_chain_oracle::compare::{self, AccountMismatch, UtxoMismatch};
use u5c_chain_oracle::effects;
use u5c_chain_oracle::ledger::Ledger;
use u5c_chain_oracle::model::{AccountOp, Credential, Effects, Origin, Output};

const FUNDED: [u8; 32] = [9; 32];
const TOP: [u8; 32] = [1; 32];
const SUB: [u8; 32] = [2; 32];
const HOLDER: Credential = Credential {
    script: false,
    hash: [7; 28],
};

fn coin(v: u64) -> Option<u5c::BigInt> {
    Some(u5c::BigInt {
        big_int: Some(u5c::big_int::BigInt::Int(v as i64)),
    })
}

fn out(v: u64) -> u5c::TxOutput {
    u5c::TxOutput {
        address: vec![0x60; 29].into(),
        coin: coin(v),
        ..Default::default()
    }
}

fn input(id: [u8; 32], index: u32) -> u5c::TxInput {
    u5c::TxInput {
        tx_hash: id.to_vec().into(),
        output_index: index,
        ..Default::default()
    }
}

fn tx(id: [u8; 32], spends: ([u8; 32], u32), successful: bool) -> u5c::Tx {
    u5c::Tx {
        hash: id.to_vec().into(),
        inputs: vec![input(spends.0, spends.1)],
        outputs: vec![out(3)],
        successful,
        collateral: Some(u5c::Collateral {
            collateral: vec![input(FUNDED, 1)],
            collateral_return: Some(out(4)),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn output(v: u64) -> Output {
    effects::output(&out(v))
}

fn funded() -> Ledger {
    let mut ledger = Ledger::default();
    ledger.apply(&Effects {
        origin: Origin {
            block: 0,
            top: [0; 32],
            sub: None,
        },
        spent: vec![],
        produced: vec![
            ((FUNDED, 0), output(10)),
            ((FUNDED, 1), output(5)),
            ((FUNDED, 2), output(6)),
        ],
        accounts: vec![AccountOp::Register(HOLDER)],
    });
    ledger
}

fn reward_account(c: Credential) -> Vec<u8> {
    let mut bytes = vec![0xe0];
    bytes.extend(c.hash);
    bytes
}

/// A top level transaction spending the third funded output, with one sub transaction spending the first and a direct deposit of 2 to the holder.
fn with_sub(successful: bool) -> u5c::Tx {
    u5c::Tx {
        sub_transactions: vec![tx(SUB, (FUNDED, 0), successful)],
        direct_deposits: vec![u5c::DirectDeposit {
            reward_account: reward_account(HOLDER).into(),
            coin: coin(2),
        }],
        ..tx(TOP, (FUNDED, 2), successful)
    }
}

fn fold(top: &u5c::Tx) -> Ledger {
    let mut ledger = funded();
    for fx in effects::applied(top, 1) {
        ledger.apply(&fx);
    }
    ledger
}

#[test]
fn a_successful_top_applies_its_sub_transactions_first() {
    let applied = effects::applied(&with_sub(true), 1);
    let origins: Vec<Option<[u8; 32]>> = applied.iter().map(|fx| fx.origin.sub).collect();
    assert_eq!(origins, vec![Some(SUB), None]);
    assert_eq!(applied[0].produced, vec![((SUB, 0), output(3))]);
    assert_eq!(applied[1].accounts, vec![AccountOp::Deposit(HOLDER, 2)]);
}

#[test]
fn a_failed_top_applies_only_its_collateral() {
    let applied = effects::applied(&with_sub(false), 1);
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].spent, vec![(FUNDED, 1)]);
    assert_eq!(applied[0].produced, vec![((TOP, 1), output(4))]);
    assert!(applied[0].accounts.is_empty());
}

/// The node's UTxO set once the sub transaction has spent the first funded output and the top the third.
fn node_after_sub() -> HashMap<([u8; 32], u32), Output> {
    HashMap::from([
        ((FUNDED, 1), output(5)),
        ((SUB, 0), output(3)),
        ((TOP, 0), output(3)),
    ])
}

#[test]
fn the_fold_of_the_u5c_sub_transactions_and_deposits_agrees_with_the_node() {
    let ledger = fold(&with_sub(true));
    let accounts = HashMap::from([(HOLDER, 2)]);
    let report = compare::state(&ledger, &node_after_sub(), &accounts);
    assert!(report.agrees(), "{report:?} {:?}", ledger.violations);
}

#[test]
fn a_mapping_that_drops_the_sub_transactions_and_deposits_misses_their_effects() {
    let dropped = u5c::Tx {
        sub_transactions: vec![],
        direct_deposits: vec![],
        ..with_sub(true)
    };
    let u5c_only = fold(&dropped);
    let accounts = HashMap::from([(HOLDER, 2)]);
    let report = compare::state(&u5c_only, &node_after_sub(), &accounts);
    assert_eq!(
        report.utxo,
        vec![
            UtxoMismatch::OnlyAtNode((SUB, 0)),
            UtxoMismatch::OnlyInFold((FUNDED, 0)),
        ]
    );
    assert_eq!(
        report.accounts.mismatches,
        vec![AccountMismatch::Balance {
            cred: HOLDER,
            fold: 0,
            node: 2,
            earns_rewards: false,
        }]
    );
    assert!(u5c_only.violations.is_empty());
}

fn account_ops(ops: Vec<AccountOp>) -> Ledger {
    let mut ledger = funded();
    ledger.apply(&Effects {
        origin: Origin {
            block: 1,
            top: TOP,
            sub: None,
        },
        spent: vec![],
        produced: vec![],
        accounts: ops,
    });
    ledger
}

#[test]
fn an_account_delegated_before_it_was_registered_again_may_hold_rewards() {
    let ledger = account_ops(vec![
        AccountOp::Delegate(HOLDER),
        AccountOp::Unregister(HOLDER),
        AccountOp::Register(HOLDER),
    ]);
    let report = compare::accounts(&ledger, &HashMap::from([(HOLDER, 5)]));
    assert_eq!(report.mismatches, vec![]);
    assert_eq!(report.rewarded, 1);
}

#[test]
fn an_account_never_delegated_holds_exactly_its_deposits() {
    let ledger = account_ops(vec![
        AccountOp::Unregister(HOLDER),
        AccountOp::Register(HOLDER),
    ]);
    let report = compare::accounts(&ledger, &HashMap::from([(HOLDER, 5)]));
    assert_eq!(report.exact, 1);
    assert_eq!(report.mismatches.len(), 1);
}

#[test]
fn spending_an_unknown_input_is_a_violation() {
    let ledger = fold(&tx(TOP, ([8; 32], 0), true));
    assert_eq!(ledger.violations.len(), 1);
}
