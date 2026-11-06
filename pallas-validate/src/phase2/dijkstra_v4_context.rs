//! The PlutusV4 script context of a redeemer of a level of a batch.
use super::{Context, ContextInput, ContextOutput, Purpose, conway_certificate};
use crate::phase1::dijkstra_ledger::reward_account;
use crate::phase2::{
    error::Error,
    script_context::{ScriptInfo, TimeRange, get_votes_info},
    to_plutus_data::{MintValue, ToPlutusData, WithRegistrationDeposit, wrap_multiple_with_constr},
};
use crate::utils::dijkstra_context::v4_stake;
use pallas_addresses::ShelleyPaymentPart;
use pallas_codec::utils::{Int, KeyValuePairs, MaybeIndefArray, Nullable};
use pallas_crypto::hash::Hash;
use pallas_primitives::{
    RewardAccount,
    conway::{self as c, PlutusData, StakeCredential},
    dijkstra as n,
};
use pallas_traverse::withdrawals::cmp_reward_accounts;
use std::collections::{BTreeMap, BTreeSet};

/// The sub transaction levels of a batch and the validity interval of all its levels, which the script info of a top level guard holds.
pub(super) struct Batch<'a> {
    pub(super) subs: Vec<Context<'a>>,
    pub(super) valid_range: TimeRange,
}

/// The fields of a PlutusV4 transaction info, encoded, with the items of its lists apart so the levels of a batch can join them.
struct TxInfo {
    id: PlutusData,
    sub: PlutusData,
    inputs: Vec<PlutusData>,
    reference_inputs: Vec<PlutusData>,
    outputs: Vec<PlutusData>,
    mint: PlutusData,
    certificates: Vec<PlutusData>,
    withdrawals: PlutusData,
    direct_deposits: PlutusData,
    balance_intervals: PlutusData,
    valid_range: PlutusData,
    guards: Vec<PlutusData>,
    required_guards: PlutusData,
    redeemers: PlutusData,
    data: PlutusData,
    votes: PlutusData,
    proposals: Vec<PlutusData>,
    treasury: PlutusData,
    donation: PlutusData,
}

impl TxInfo {
    /// The encoded transaction info, which has no fee.
    fn data(&self) -> PlutusData {
        list(vec![
            self.id.clone(),
            self.sub.clone(),
            list(self.inputs.clone()),
            list(self.reference_inputs.clone()),
            list(self.outputs.clone()),
            self.mint.clone(),
            list(self.certificates.clone()),
            self.withdrawals.clone(),
            self.direct_deposits.clone(),
            self.balance_intervals.clone(),
            self.valid_range.clone(),
            list(self.guards.clone()),
            self.required_guards.clone(),
            self.redeemers.clone(),
            self.data.clone(),
            self.votes.clone(),
            list(self.proposals.clone()),
            self.treasury.clone(),
            self.donation.clone(),
        ])
    }
}

impl<'a> Context<'a> {
    /// The script context of the redeemer at `key`, with the datum it spends, and for a top level guard the view of `batch`.
    pub(super) fn script_context(
        &self,
        key: &n::RedeemersKey,
        purpose: &Purpose,
        redeemer: &PlutusData,
        datum: Option<&PlutusData>,
        batch: &dyn Fn() -> Result<Batch<'a>, Error>,
    ) -> Result<PlutusData, Error> {
        let hash = &self.scripts[key];
        let tx_info = self.tx_info()?;
        let (index, mut fields) = self.fields(purpose)?;
        match purpose {
            Purpose::Conway(_, ScriptInfo::Spending(..)) => {
                fields.push(datum.cloned().to_plutus_data())
            }
            Purpose::Conway(..) => {}
            Purpose::Guarding(_) => {
                let top = match self.level.sub {
                    None => Some(self.top_tx_info(hash, &tx_info, &batch()?)?),
                    Some(_) => None,
                };
                fields.push(top.to_plutus_data())
            }
        }
        Ok(list(vec![
            tx_info.data(),
            redeemer.clone(),
            wrap_multiple_with_constr(index, fields),
            hash.to_plutus_data(),
        ]))
    }

    /// The transaction info fields of the level.
    fn tx_info(&self) -> Result<TxInfo, Error> {
        let level = &self.level;
        let mut redeemers = Vec::new();
        for (key, purpose, redeemer) in &self.redeemers {
            let (index, fields) = self.fields(purpose)?;
            let purpose = std::iter::once(self.scripts[key].to_plutus_data()).chain(fields);
            redeemers.push((
                key,
                wrap_multiple_with_constr(index, purpose.collect()),
                redeemer.data.clone(),
            ));
        }
        redeemers.sort_by(|x, y| x.0.cmp(y.0));
        let guards = match level.guards {
            None => vec![],
            Some(n::Guards::AddrKeyhashes(keys)) => keys
                .iter()
                .map(|key| StakeCredential::AddrKeyhash(*key).to_plutus_data())
                .collect(),
            Some(n::Guards::Credentials(credentials)) => {
                credentials.iter().map(|x| x.to_plutus_data()).collect()
            }
        };
        let mut required: Vec<_> = level
            .required_top_level_guards
            .into_iter()
            .flatten()
            .collect();
        required.sort_by_key(|(credential, _)| credential_order(credential));
        Ok(TxInfo {
            id: level.id.to_plutus_data(),
            sub: level.sub.to_plutus_data(),
            inputs: self.inputs.iter().map(input).collect(),
            reference_inputs: self.reference_inputs.iter().map(input).collect(),
            outputs: self.outputs.iter().map(output).collect(),
            mint: MintValue {
                mint_value: level.mint.cloned().unwrap_or_default(),
            }
            .to_plutus_data(),
            certificates: level
                .certificates
                .into_iter()
                .flatten()
                .map(certificate)
                .collect(),
            withdrawals: map(by_account(level.withdrawals.into_iter().flatten(), |x| {
                x.to_plutus_data()
            })?),
            direct_deposits: map(by_account(
                level.direct_deposits.into_iter().flatten(),
                |x| x.to_plutus_data(),
            )?),
            balance_intervals: map(by_account(
                level.intervals.into_iter().flatten(),
                balance_interval,
            )?),
            valid_range: list(vec![
                self.valid_range.lower_bound.to_plutus_data(),
                self.valid_range.upper_bound.to_plutus_data(),
            ]),
            guards,
            required_guards: map(required
                .into_iter()
                .map(|(credential, datum)| (credential.to_plutus_data(), datum.to_plutus_data()))
                .collect()),
            redeemers: map(redeemers
                .into_iter()
                .map(|(_, purpose, data)| (purpose, data))
                .collect()),
            data: map(self
                .datums
                .iter()
                .map(|(hash, datum)| (hash.to_plutus_data(), datum.clone()))
                .collect()),
            votes: votes(&level.votes.cloned()),
            proposals: self
                .proposals
                .iter()
                .map(proposal)
                .collect::<Result<_, _>>()?,
            treasury: level.treasury_value.to_plutus_data(),
            donation: level.donation.unwrap_or(0).to_plutus_data(),
        })
    }

    /// The constructor index of `purpose` and the fields its script purpose and script info share.
    fn fields(&self, purpose: &Purpose) -> Result<(u64, Vec<PlutusData>), Error> {
        let certificates: Vec<_> = self.level.certificates.into_iter().flatten().collect();
        Ok(match purpose {
            Purpose::Conway(_, ScriptInfo::Minting(policy)) => (0, vec![policy.to_plutus_data()]),
            Purpose::Conway(_, ScriptInfo::Spending(spent, ())) => (1, vec![out_ref(spent)]),
            Purpose::Conway(_, ScriptInfo::Rewarding(credential)) => {
                (2, vec![credential.to_plutus_data()])
            }
            Purpose::Conway(_, ScriptInfo::Certifying(ix, _)) => {
                (3, vec![ix.to_plutus_data(), certificate(certificates[*ix])])
            }
            Purpose::Conway(_, ScriptInfo::Voting(voter)) => (4, vec![voter.to_plutus_data()]),
            Purpose::Conway(_, ScriptInfo::Proposing(ix, procedure)) => {
                (5, vec![ix.to_plutus_data(), proposal(procedure)?])
            }
            Purpose::Guarding(ix) => (6, vec![u64::from(*ix).to_plutus_data()]),
        })
    }

    /// The view of the whole batch in the script info of the guard `hash` of this top level, whose transaction info is `tx_info`.
    fn top_tx_info(
        &self,
        hash: &Hash<28>,
        tx_info: &TxInfo,
        batch: &Batch<'_>,
    ) -> Result<PlutusData, Error> {
        let subs = batch
            .subs
            .iter()
            .map(|x| x.tx_info())
            .collect::<Result<Vec<_>, _>>()?;
        let levels: Vec<(&Context<'_>, &TxInfo)> = batch
            .subs
            .iter()
            .zip(&subs)
            .chain([(self, tx_info)])
            .collect();
        let guard = StakeCredential::ScriptHash(*hash);
        let mut datums = BTreeMap::new();
        for (context, _) in &levels {
            if let Some(Nullable::Some(datum)) = context
                .level
                .required_top_level_guards
                .and_then(|x| x.get(&guard))
            {
                datums.insert(context.level.id, datum.clone());
            }
        }
        let concat = |field: fn(&TxInfo) -> &Vec<PlutusData>| {
            list(levels.iter().flat_map(|(_, x)| field(x).clone()).collect())
        };
        let mints: Vec<_> = levels.iter().filter_map(|(x, _)| x.level.mint).collect();
        let mut withdrawals = BTreeMap::new();
        let mut deposits = BTreeMap::new();
        let mut required = BTreeSet::new();
        let mut redeemer_hashes = BTreeSet::new();
        let mut data = BTreeMap::new();
        let mut voters = BTreeMap::new();
        let mut donation = 0;
        for (context, _) in &levels {
            let level = &context.level;
            for (account, coin) in level.withdrawals.into_iter().flatten() {
                *withdrawals.entry(account.clone()).or_insert(0) += i128::from(*coin);
            }
            for (account, coin) in level.direct_deposits.into_iter().flatten() {
                *deposits.entry(account.clone()).or_insert(0) += i128::from(*coin);
            }
            for (credential, _) in level.required_top_level_guards.into_iter().flatten() {
                required.insert(credential_order(credential));
            }
            redeemer_hashes.extend(
                context
                    .redeemers
                    .iter()
                    .map(|(key, ..)| context.scripts[key]),
            );
            data.extend(context.datums.clone());
            for (voter, actions) in level.votes.into_iter().flatten() {
                let entry: &mut BTreeMap<_, _> = voters.entry(voter.clone()).or_default();
                entry.extend(actions.clone());
            }
            donation += i128::from(level.donation.unwrap_or(0));
        }
        let simplified = list(vec![
            list(levels.iter().map(|(_, x)| x.id.clone()).collect()),
            concat(|x| &x.inputs),
            concat(|x| &x.reference_inputs),
            concat(|x| &x.outputs),
            mint_part(&mints, true),
            mint_part(&mints, false),
            concat(|x| &x.certificates),
            map(by_account(withdrawals.iter(), |x| integer(*x))?),
            map(by_account(deposits.iter(), |x| integer(*x))?),
            list(vec![
                batch.valid_range.lower_bound.to_plutus_data(),
                batch.valid_range.upper_bound.to_plutus_data(),
            ]),
            concat(|x| &x.guards),
            list(
                required
                    .into_iter()
                    .map(|(key, hash)| match key {
                        false => StakeCredential::ScriptHash(hash),
                        true => StakeCredential::AddrKeyhash(hash),
                    })
                    .map(|x| x.to_plutus_data())
                    .collect(),
            ),
            list(redeemer_hashes.iter().map(|x| x.to_plutus_data()).collect()),
            map(data
                .iter()
                .map(|(hash, datum)| (hash.to_plutus_data(), datum.clone()))
                .collect()),
            votes(&Some(voters)),
            concat(|x| &x.proposals),
            levels
                .iter()
                .find_map(|(x, _)| x.level.treasury_value)
                .to_plutus_data(),
            integer(donation),
        ]);
        Ok(list(vec![
            list(subs.iter().map(TxInfo::data).collect()),
            map(datums
                .iter()
                .map(|(id, datum)| (id.to_plutus_data(), datum.clone()))
                .collect()),
            map(by_account(
                self.level.starting_intervals.into_iter().flatten(),
                balance_interval,
            )?),
            simplified,
        ]))
    }
}

/// The votes of `procedures`, by voter and then by governance action.
fn votes(procedures: &Option<c::VotingProcedures>) -> PlutusData {
    map(get_votes_info(procedures)
        .iter()
        .map(|(voter, actions)| {
            let actions = actions
                .iter()
                .map(|(id, procedure)| (gov_action_id(id), procedure.vote.to_plutus_data()))
                .collect();
            (voter.to_plutus_data(), map(actions))
        })
        .collect())
}

/// The entries of the `mints` with positive amounts, or with negative amounts, summed, without the policies left empty.
fn mint_part(mints: &[&c::Mint], positive: bool) -> PlutusData {
    let mut sums: BTreeMap<_, BTreeMap<_, i128>> = BTreeMap::new();
    for (policy, assets) in mints.iter().copied().flatten() {
        for (name, amount) in assets {
            let amount = i64::from(*amount);
            if (amount > 0) == positive {
                *sums
                    .entry(*policy)
                    .or_default()
                    .entry(name.clone())
                    .or_default() += i128::from(amount);
            }
        }
    }
    map(sums
        .into_iter()
        .map(|(policy, assets)| {
            let assets = assets
                .into_iter()
                .map(|(name, amount)| (name.to_plutus_data(), integer(amount)))
                .collect();
            (policy.to_plutus_data(), map(assets))
        })
        .collect())
}

/// An integer, in the data encoding of its size.
fn integer(value: impl Into<i128>) -> PlutusData {
    let value = value.into();
    match Int::try_from(value) {
        Ok(x) => PlutusData::BigInt(c::BigInt::Int(x)),
        Err(_) => {
            let (magnitude, big): (u128, fn(_) -> c::BigInt) = if value < 0 {
                ((!value) as u128, c::BigInt::BigNInt)
            } else {
                (value as u128, c::BigInt::BigUInt)
            };
            let bytes = magnitude.to_be_bytes();
            let first = bytes.iter().position(|x| *x != 0).unwrap_or(bytes.len());
            PlutusData::BigInt(big(bytes[first..].to_vec().into()))
        }
    }
}

/// A record or a list, which PlutusV4 encodes as a data list.
fn list(items: Vec<PlutusData>) -> PlutusData {
    PlutusData::Array(MaybeIndefArray::Def(items))
}

/// A data map with its entries in the given order.
fn map(entries: Vec<(PlutusData, PlutusData)>) -> PlutusData {
    PlutusData::Map(KeyValuePairs::Def(entries))
}

/// The key the ledger orders credentials by, script credentials first.
fn credential_order(credential: &StakeCredential) -> (bool, Hash<28>) {
    match credential {
        StakeCredential::ScriptHash(hash) => (false, *hash),
        StakeCredential::AddrKeyhash(hash) => (true, *hash),
    }
}

/// The entries of a map keyed by reward account, keyed by credential in the order the ledger holds them.
fn by_account<'a, V: 'a>(
    entries: impl Iterator<Item = (&'a RewardAccount, &'a V)>,
    value: impl Fn(&V) -> PlutusData,
) -> Result<Vec<(PlutusData, PlutusData)>, Error> {
    let mut entries: Vec<_> = entries.collect();
    entries.sort_by(|(x, _), (y, _)| cmp_reward_accounts(x, y));
    entries
        .into_iter()
        .map(|(raw, v)| {
            let (_, credential) = reward_account(raw).map_err(|_| Error::BadWithdrawalAddress)?;
            Ok((credential.to_plutus_data(), value(v)))
        })
        .collect()
}

/// An account balance interval, by its lower bound, upper bound, both bounds or exact balance.
fn balance_interval(interval: &n::AccountBalanceInterval) -> PlutusData {
    let (index, bounds) = match interval {
        n::AccountBalanceInterval::LowerBound(lower) => (0, vec![*lower]),
        n::AccountBalanceInterval::UpperBound(upper) => (1, vec![*upper]),
        n::AccountBalanceInterval::Bounded(lower, upper) => (2, vec![*lower, *upper]),
        n::AccountBalanceInterval::Exact(coin) => (3, vec![*coin]),
    };
    wrap_multiple_with_constr(index, bounds.iter().map(|x| x.to_plutus_data()).collect())
}

/// A transaction output reference, as its transaction id and index.
fn out_ref(input: &n::TransactionInput) -> PlutusData {
    list(vec![
        input.transaction_id.to_plutus_data(),
        input.index.to_plutus_data(),
    ])
}

/// An input, as its output reference and the output it resolves to.
fn input(input: &ContextInput) -> PlutusData {
    list(vec![out_ref(&input.out_ref), output(&input.resolved)])
}

/// An output, whose address holds a payment credential and an optional stake credential.
fn output(output: &ContextOutput) -> PlutusData {
    let payment = match output.address.payment() {
        ShelleyPaymentPart::Key(hash) => StakeCredential::AddrKeyhash(*hash),
        ShelleyPaymentPart::Script(hash) => StakeCredential::ScriptHash(*hash),
    };
    let stake = v4_stake(&output.address)
        .unwrap_or_else(|x| unreachable!("unexpected {} in a PlutusV4 script context", x.0));
    list(vec![
        list(vec![payment.to_plutus_data(), stake.to_plutus_data()]),
        output.value.to_plutus_data(),
        output.datum.to_plutus_data(),
        output.script.to_plutus_data(),
    ])
}

/// A certificate, whose registration and unregistration deposits are not optional.
fn certificate(cert: &n::Certificate) -> PlutusData {
    match cert {
        n::Certificate::Reg(credential, deposit) => wrap_multiple_with_constr(
            0,
            vec![credential.to_plutus_data(), deposit.to_plutus_data()],
        ),
        n::Certificate::UnReg(credential, refund) => wrap_multiple_with_constr(
            1,
            vec![credential.to_plutus_data(), refund.to_plutus_data()],
        ),
        other => WithRegistrationDeposit(&conway_certificate(other), true).to_plutus_data(),
    }
}

/// A governance action id, as its transaction id and index.
fn gov_action_id(id: &c::GovActionId) -> PlutusData {
    list(vec![
        id.transaction_id.to_plutus_data(),
        id.action_index.to_plutus_data(),
    ])
}

/// A proposal procedure, whose return account is a credential.
fn proposal(proposal: &c::ProposalProcedure) -> Result<PlutusData, Error> {
    let (_, credential) =
        reward_account(&proposal.reward_account).map_err(|_| Error::BadWithdrawalAddress)?;
    Ok(list(vec![
        proposal.deposit.to_plutus_data(),
        credential.to_plutus_data(),
        gov_action(&proposal.gov_action)?,
    ]))
}

/// A governance action, whose ids, protocol versions, constitutions and quorums are lists.
fn gov_action(action: &c::GovAction) -> Result<PlutusData, Error> {
    let previous = |id: &Option<c::GovActionId>| id.as_ref().map(gov_action_id).to_plutus_data();
    Ok(match action {
        c::GovAction::ParameterChange(id, update, guardrail) => wrap_multiple_with_constr(
            0,
            vec![
                previous(id),
                update.as_ref().to_plutus_data(),
                guardrail.to_plutus_data(),
            ],
        ),
        c::GovAction::HardForkInitiation(id, (major, minor)) => wrap_multiple_with_constr(
            1,
            vec![
                previous(id),
                list(vec![major.to_plutus_data(), minor.to_plutus_data()]),
            ],
        ),
        c::GovAction::TreasuryWithdrawals(withdrawals, guardrail) => wrap_multiple_with_constr(
            2,
            vec![
                map(by_account(withdrawals.iter(), |x| x.to_plutus_data())?),
                guardrail.to_plutus_data(),
            ],
        ),
        c::GovAction::NoConfidence(id) => wrap_multiple_with_constr(3, vec![previous(id)]),
        c::GovAction::UpdateCommittee(id, removed, added, quorum) => {
            let mut removed: Vec<_> = removed.iter().collect();
            removed.sort_by_key(|x| credential_order(x));
            let mut added: Vec<_> = added.iter().collect();
            added.sort_by_key(|(x, _)| credential_order(x));
            wrap_multiple_with_constr(
                4,
                vec![
                    previous(id),
                    list(removed.into_iter().map(|x| x.to_plutus_data()).collect()),
                    map(added
                        .into_iter()
                        .map(|(x, epoch)| (x.to_plutus_data(), epoch.to_plutus_data()))
                        .collect()),
                    list(vec![
                        quorum.numerator.to_plutus_data(),
                        quorum.denominator.to_plutus_data(),
                    ]),
                ],
            )
        }
        c::GovAction::NewConstitution(id, constitution) => wrap_multiple_with_constr(
            5,
            vec![
                previous(id),
                list(vec![constitution.guardrail_script.to_plutus_data()]),
            ],
        ),
        c::GovAction::Information => wrap_multiple_with_constr(6, vec![]),
    })
}
