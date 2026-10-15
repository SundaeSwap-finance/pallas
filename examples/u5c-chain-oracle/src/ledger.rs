use std::collections::{HashMap, HashSet};

use crate::model::{AccountOp, Credential, Effects, Origin, Output, TxIn};

/// A rule of the ledger that applying a transaction broke, with the transaction that broke it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Violation {
    UnknownInput(TxIn, Origin),
    DuplicateOutput(TxIn, Origin),
    UnknownAccount(Credential, Origin),
    AlreadyRegistered(Credential, Origin),
    NegativeBalance(Credential, i128, Origin),
    UnregisteredWithBalance(Credential, i128, Origin),
}

/// A registered reward account as the fold sees it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Account {
    pub balance: i128,
}

/// The UTxO set and reward accounts that folding the chain's effects produces.
#[derive(Default)]
pub struct Ledger {
    pub utxo: HashMap<TxIn, Output>,
    pub accounts: HashMap<Credential, Account>,
    pub reward_targets: HashSet<Credential>,
    pub violations: Vec<Violation>,
    pub spent_by_sub: HashMap<TxIn, Origin>,
    pub sub_origins: HashMap<[u8; 32], Origin>,
    pub deposits_to: HashMap<Credential, Vec<Origin>>,
}

impl Ledger {
    /// Tells whether rewards the chain does not show may reach this account, which holds once it has been delegated or named to receive rewards, across later registrations too.
    pub fn earns_rewards(&self, cred: &Credential) -> bool {
        self.reward_targets.contains(cred)
    }

    /// Applies the effects of one transaction.
    pub fn apply(&mut self, fx: &Effects) {
        let origin = fx.origin;
        if let Some(sub) = origin.sub {
            self.sub_origins.insert(sub, origin);
        }
        for i in &fx.spent {
            if self.utxo.remove(i).is_none() {
                self.violations.push(Violation::UnknownInput(*i, origin));
            } else if origin.sub.is_some() {
                self.spent_by_sub.insert(*i, origin);
            }
        }
        for (i, o) in &fx.produced {
            if self.utxo.insert(*i, o.clone()).is_some() {
                self.violations.push(Violation::DuplicateOutput(*i, origin));
            }
        }
        for op in &fx.accounts {
            self.account(op, origin);
        }
    }

    fn account(&mut self, op: &AccountOp, origin: Origin) {
        match op {
            AccountOp::Register(c) => {
                if self.accounts.insert(*c, Account::default()).is_some() {
                    self.violations
                        .push(Violation::AlreadyRegistered(*c, origin));
                }
            }
            AccountOp::Unregister(c) => {
                let rewards = self.earns_rewards(c);
                match self.accounts.remove(c) {
                    None => self.violations.push(Violation::UnknownAccount(*c, origin)),
                    Some(a) if a.balance != 0 && !rewards => self
                        .violations
                        .push(Violation::UnregisteredWithBalance(*c, a.balance, origin)),
                    Some(_) => {}
                }
            }
            AccountOp::Delegate(c) => {
                if self.accounts.contains_key(c) {
                    self.reward_targets.insert(*c);
                } else {
                    self.violations.push(Violation::UnknownAccount(*c, origin));
                }
            }
            AccountOp::Withdraw(c, coin) => {
                let rewards = self.earns_rewards(c);
                match self.accounts.get_mut(c) {
                    None => self.violations.push(Violation::UnknownAccount(*c, origin)),
                    Some(a) => {
                        a.balance -= i128::from(*coin);
                        if a.balance < 0 && !rewards {
                            self.violations
                                .push(Violation::NegativeBalance(*c, a.balance, origin));
                        }
                    }
                }
            }
            AccountOp::Deposit(c, coin) => {
                self.deposits_to.entry(*c).or_default().push(origin);
                match self.accounts.get_mut(c) {
                    None => self.violations.push(Violation::UnknownAccount(*c, origin)),
                    Some(a) => a.balance += i128::from(*coin),
                }
            }
            AccountOp::RewardTarget(c) => {
                self.reward_targets.insert(*c);
            }
        }
    }
}
