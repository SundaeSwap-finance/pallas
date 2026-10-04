use std::collections::BTreeMap;

use pallas_utxorpc::v1beta::spec::cardano as u5c;

use crate::model::{AccountOp, Credential, Effects, Origin, Output, RefScript, TxIn};

/// Reads a u5c integer that holds a coin or a quantity.
pub fn natural(x: Option<&u5c::BigInt>) -> u64 {
    match x.and_then(|x| x.big_int.as_ref()) {
        Some(u5c::big_int::BigInt::Int(v)) => u64::try_from(*v).expect("a negative quantity"),
        Some(u5c::big_int::BigInt::BigUInt(b)) => b
            .iter()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)),
        Some(u5c::big_int::BigInt::BigNInt(_)) => panic!("a negative quantity"),
        None => 0,
    }
}

fn id32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("a 32 byte id")
}

fn input(x: &u5c::TxInput) -> TxIn {
    (id32(&x.tx_hash), x.output_index)
}

fn script(x: &u5c::Script) -> Option<RefScript> {
    match x.script.as_ref()? {
        u5c::script::Script::Native(_) => Some(RefScript::Native),
        u5c::script::Script::PlutusV1(b) => Some(RefScript::Plutus(1, b.to_vec())),
        u5c::script::Script::PlutusV2(b) => Some(RefScript::Plutus(2, b.to_vec())),
        u5c::script::Script::PlutusV3(b) => Some(RefScript::Plutus(3, b.to_vec())),
        u5c::script::Script::PlutusV4(b) => Some(RefScript::Plutus(4, b.to_vec())),
    }
}

/// Reads the ledger content of a u5c output.
pub fn output(x: &u5c::TxOutput) -> Output {
    let mut assets = BTreeMap::new();
    for policy in &x.assets {
        for asset in &policy.assets {
            *assets
                .entry((policy.policy_id.to_vec(), asset.name.to_vec()))
                .or_insert(0) += natural(asset.quantity.as_ref());
        }
    }
    Output {
        address: x.address.to_vec(),
        coin: natural(x.coin.as_ref()),
        assets,
        datum_hash: x
            .datum
            .as_ref()
            .filter(|d| !d.hash.is_empty())
            .map(|d| id32(&d.hash)),
        script: x.script.as_ref().and_then(script),
    }
}

fn credential(x: Option<&u5c::StakeCredential>) -> Credential {
    match x.and_then(|x| x.stake_credential.as_ref()) {
        Some(u5c::stake_credential::StakeCredential::AddrKeyHash(h)) => Credential {
            script: false,
            hash: h.as_ref().try_into().expect("a 28 byte hash"),
        },
        Some(u5c::stake_credential::StakeCredential::ScriptHash(h)) => Credential {
            script: true,
            hash: h.as_ref().try_into().expect("a 28 byte hash"),
        },
        None => panic!("a certificate without a credential"),
    }
}

fn reward_account(bytes: &[u8]) -> Credential {
    Credential::from_reward_account(bytes).expect("a reward account")
}

fn certificate(x: &u5c::Certificate, ops: &mut Vec<AccountOp>) {
    use u5c::certificate::Certificate as C;
    match x.certificate.as_ref() {
        Some(C::StakeRegistration(c)) => ops.push(AccountOp::Register(credential(Some(c)))),
        Some(C::StakeDeregistration(c)) => ops.push(AccountOp::Unregister(credential(Some(c)))),
        Some(C::StakeDelegation(c)) => {
            ops.push(AccountOp::Delegate(credential(c.stake_credential.as_ref())))
        }
        Some(C::PoolRegistration(c)) => {
            ops.push(AccountOp::RewardTarget(reward_account(&c.reward_account)))
        }
        Some(C::RegCert(c)) => {
            ops.push(AccountOp::Register(credential(c.stake_credential.as_ref())))
        }
        Some(C::UnregCert(c)) => ops.push(AccountOp::Unregister(credential(
            c.stake_credential.as_ref(),
        ))),
        Some(C::StakeVoteDelegCert(c)) => {
            ops.push(AccountOp::Delegate(credential(c.stake_credential.as_ref())))
        }
        Some(C::StakeRegDelegCert(c)) => {
            let cred = credential(c.stake_credential.as_ref());
            ops.push(AccountOp::Register(cred));
            ops.push(AccountOp::Delegate(cred));
        }
        Some(C::VoteRegDelegCert(c)) => {
            ops.push(AccountOp::Register(credential(c.stake_credential.as_ref())))
        }
        Some(C::StakeVoteRegDelegCert(c)) => {
            let cred = credential(c.stake_credential.as_ref());
            ops.push(AccountOp::Register(cred));
            ops.push(AccountOp::Delegate(cred));
        }
        _ => {}
    }
}

fn proposal_targets(x: &u5c::GovernanceActionProposal, ops: &mut Vec<AccountOp>) {
    ops.push(AccountOp::RewardTarget(reward_account(&x.reward_account)));
    let action = x
        .gov_action
        .as_ref()
        .and_then(|a| a.governance_action.as_ref());
    if let Some(u5c::governance_action::GovernanceAction::TreasuryWithdrawalsAction(t)) = action {
        for w in &t.withdrawals {
            ops.push(AccountOp::RewardTarget(reward_account(&w.reward_account)));
        }
    }
}

fn applied_one(tx: &u5c::Tx, origin: Origin) -> Effects {
    let id = id32(&tx.hash);
    if !tx.successful {
        let collateral = tx.collateral.clone().unwrap_or_default();
        let index = tx.outputs.len() as u32;
        return Effects {
            origin,
            spent: collateral.collateral.iter().map(input).collect(),
            produced: collateral
                .collateral_return
                .iter()
                .map(|o| ((id, index), output(o)))
                .collect(),
            accounts: vec![],
        };
    }
    let mut accounts = Vec::new();
    for w in &tx.withdrawals {
        accounts.push(AccountOp::Withdraw(
            reward_account(&w.reward_account),
            natural(w.coin.as_ref()),
        ));
    }
    for c in &tx.certificates {
        certificate(c, &mut accounts);
    }
    for d in &tx.direct_deposits {
        accounts.push(AccountOp::Deposit(
            reward_account(&d.reward_account),
            natural(d.coin.as_ref()),
        ));
    }
    for p in &tx.proposals {
        proposal_targets(p, &mut accounts);
    }
    Effects {
        origin,
        spent: tx.inputs.iter().map(input).collect(),
        produced: tx
            .outputs
            .iter()
            .enumerate()
            .map(|(i, o)| ((id, i as u32), output(o)))
            .collect(),
        accounts,
    }
}

/// Lists the effects of one top level transaction in the order the ledger applies them.
pub fn applied(tx: &u5c::Tx, block: u64) -> Vec<Effects> {
    let top = id32(&tx.hash);
    let mut out = Vec::new();
    if tx.successful {
        for sub in &tx.sub_transactions {
            let origin = Origin {
                block,
                top,
                sub: Some(id32(&sub.hash)),
            };
            out.push(applied_one(sub, origin));
        }
    }
    let origin = Origin {
        block,
        top,
        sub: None,
    };
    out.push(applied_one(tx, origin));
    out
}
