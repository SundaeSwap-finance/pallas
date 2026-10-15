use std::collections::{BTreeSet, HashMap};

use crate::ledger::Ledger;
use crate::model::{Credential, Output, TxIn};

/// One way a folded UTxO entry disagrees with the node.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum UtxoMismatch {
    OnlyInFold(TxIn),
    OnlyAtNode(TxIn),
    Differs(TxIn),
}

impl UtxoMismatch {
    /// The output reference the mismatch is about.
    pub fn key(&self) -> TxIn {
        match self {
            UtxoMismatch::OnlyInFold(k)
            | UtxoMismatch::OnlyAtNode(k)
            | UtxoMismatch::Differs(k) => *k,
        }
    }
}

/// Lists every output reference whose entry differs between the fold and the node, in key order.
pub fn utxo(fold: &HashMap<TxIn, Output>, node: &HashMap<TxIn, Output>) -> Vec<UtxoMismatch> {
    let keys: BTreeSet<&TxIn> = fold.keys().chain(node.keys()).collect();
    keys.into_iter()
        .filter_map(|k| match (fold.get(k), node.get(k)) {
            (Some(_), None) => Some(UtxoMismatch::OnlyInFold(*k)),
            (None, Some(_)) => Some(UtxoMismatch::OnlyAtNode(*k)),
            (Some(a), Some(b)) if a != b => Some(UtxoMismatch::Differs(*k)),
            _ => None,
        })
        .collect()
}

/// Names the fields in which two outputs differ.
pub fn differing_fields(a: &Output, b: &Output) -> Vec<&'static str> {
    [
        ("address", a.address != b.address),
        ("coin", a.coin != b.coin),
        ("assets", a.assets != b.assets),
        ("datum_hash", a.datum_hash != b.datum_hash),
        ("script", a.script != b.script),
    ]
    .into_iter()
    .filter(|(_, differs)| *differs)
    .map(|(name, _)| name)
    .collect()
}

/// How a fold compares with the node's UTxO set and reward accounts.
#[derive(Clone, Debug)]
pub struct StateReport {
    pub compared: usize,
    pub utxo: Vec<UtxoMismatch>,
    pub accounts: AccountReport,
    pub violations: usize,
}

impl StateReport {
    /// Tells whether the node reported an entry and the fold holds the node's UTxO set and accounts and broke no ledger rule.
    pub fn agrees(&self) -> bool {
        self.compared > 0
            && self.utxo.is_empty()
            && self.accounts.mismatches.is_empty()
            && self.violations == 0
    }
}

/// Compares a fold with the node's UTxO set and reward accounts.
pub fn state(
    fold: &Ledger,
    utxo: &HashMap<TxIn, Output>,
    accounts: &HashMap<Credential, i128>,
) -> StateReport {
    StateReport {
        compared: utxo.len() + accounts.len(),
        utxo: self::utxo(&fold.utxo, utxo),
        accounts: self::accounts(fold, accounts),
        violations: fold.violations.len(),
    }
}

/// One way a folded reward account disagrees with the node.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AccountMismatch {
    OnlyInFold(Credential, i128),
    OnlyAtNode(Credential, i128),
    Balance {
        cred: Credential,
        fold: i128,
        node: i128,
        earns_rewards: bool,
    },
}

/// How the folded accounts compare with the node, split by whether rewards may reach them.
#[derive(Clone, Debug, Default)]
pub struct AccountReport {
    pub exact: usize,
    pub rewarded: usize,
    pub mismatches: Vec<AccountMismatch>,
}

/// Compares every account either side holds, exactly for an account no reward reaches and as a nonnegative reward residual otherwise.
pub fn accounts(fold: &Ledger, node: &HashMap<Credential, i128>) -> AccountReport {
    let keys: BTreeSet<&Credential> = fold.accounts.keys().chain(node.keys()).collect();
    let mut report = AccountReport::default();
    for k in keys {
        let rewards = fold.earns_rewards(k);
        match (fold.accounts.get(k), node.get(k)) {
            (Some(a), None) => report
                .mismatches
                .push(AccountMismatch::OnlyInFold(*k, a.balance)),
            (None, Some(b)) => report.mismatches.push(AccountMismatch::OnlyAtNode(*k, *b)),
            (Some(a), Some(b)) => {
                if rewards {
                    report.rewarded += 1;
                } else {
                    report.exact += 1;
                }
                let agrees = if rewards {
                    *b >= a.balance
                } else {
                    *b == a.balance
                };
                if !agrees {
                    report.mismatches.push(AccountMismatch::Balance {
                        cred: *k,
                        fold: a.balance,
                        node: *b,
                        earns_rewards: rewards,
                    });
                }
            }
            (None, None) => {}
        }
    }
    report
}
