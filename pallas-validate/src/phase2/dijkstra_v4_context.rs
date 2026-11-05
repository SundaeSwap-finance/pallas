//! The PlutusV4 script context of a top level redeemer.
use super::{ContextInput, ContextOutput, Purpose, conway_certificate, unsupported};
use crate::phase1::dijkstra_ledger::{account_order, reward_account};
use crate::phase2::{
    error::Error,
    script_context::{ScriptInfo, TimeRange, get_votes_info},
    to_plutus_data::{MintValue, ToPlutusData, WithRegistrationDeposit, wrap_multiple_with_constr},
};
use pallas_addresses::{Address, ShelleyDelegationPart, ShelleyPaymentPart};
use pallas_codec::utils::{KeyValuePairs, MaybeIndefArray, Nullable};
use pallas_crypto::hash::Hash;
use pallas_primitives::{
    RewardAccount,
    conway::{self as c, PlutusData, StakeCredential},
    dijkstra as n,
};
use std::collections::{BTreeMap, BTreeSet};

/// The parts of the top level of a transaction its PlutusV4 script contexts hold.
pub(super) struct Top<'a, 'b> {
    pub(super) body: &'a n::TransactionBody<'b>,
    pub(super) id: Hash<32>,
    pub(super) inputs: &'a [ContextInput],
    pub(super) reference_inputs: &'a [ContextInput],
    pub(super) outputs: &'a [ContextOutput],
    pub(super) valid_range: &'a TimeRange,
    pub(super) datums: &'a BTreeMap<Hash<32>, PlutusData>,
    pub(super) proposals: &'a [c::ProposalProcedure],
    pub(super) redeemers: &'a [(n::RedeemersKey, Purpose, n::RedeemersValue)],
    pub(super) scripts: &'a BTreeMap<n::RedeemersKey, Hash<28>>,
}

/// The fields of a PlutusV4 transaction info, encoded.
struct TxInfo {
    id: PlutusData,
    inputs: PlutusData,
    reference_inputs: PlutusData,
    outputs: PlutusData,
    mint: PlutusData,
    certificates: PlutusData,
    withdrawals: PlutusData,
    direct_deposits: PlutusData,
    balance_intervals: PlutusData,
    valid_range: PlutusData,
    guards: PlutusData,
    required_guards: PlutusData,
    redeemers: PlutusData,
    data: PlutusData,
    votes: PlutusData,
    proposals: PlutusData,
    treasury: PlutusData,
    donation: PlutusData,
}

impl TxInfo {
    /// The encoded transaction info of the top level, which has no fee and no sub transaction index.
    fn data(self) -> PlutusData {
        list(vec![
            self.id,
            None::<u64>.to_plutus_data(),
            self.inputs,
            self.reference_inputs,
            self.outputs,
            self.mint,
            self.certificates,
            self.withdrawals,
            self.direct_deposits,
            self.balance_intervals,
            self.valid_range,
            self.guards,
            self.required_guards,
            self.redeemers,
            self.data,
            self.votes,
            self.proposals,
            self.treasury,
            self.donation,
        ])
    }
}

impl Top<'_, '_> {
    /// The script context of the redeemer at `key`, with the datum it spends.
    pub(super) fn script_context(
        &self,
        key: &n::RedeemersKey,
        purpose: &Purpose,
        redeemer: &PlutusData,
        datum: Option<&PlutusData>,
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
                fields.push(Some(self.top_tx_info(hash, &tx_info)?).to_plutus_data())
            }
        }
        Ok(list(vec![
            tx_info.data(),
            redeemer.clone(),
            wrap_multiple_with_constr(index, fields),
            hash.to_plutus_data(),
        ]))
    }

    /// The transaction info fields of the top level.
    fn tx_info(&self) -> Result<TxInfo, Error> {
        let b = self.body;
        let mut redeemers = Vec::new();
        for (key, purpose, redeemer) in self.redeemers {
            let (index, fields) = self.fields(purpose)?;
            let purpose = std::iter::once(self.scripts[key].to_plutus_data()).chain(fields);
            redeemers.push((
                key,
                wrap_multiple_with_constr(index, purpose.collect()),
                redeemer.data.clone(),
            ));
        }
        redeemers.sort_by(|x, y| x.0.cmp(y.0));
        let guards = match &b.guards {
            None => vec![],
            Some(n::Guards::AddrKeyhashes(keys)) => keys
                .iter()
                .map(|key| StakeCredential::AddrKeyhash(*key).to_plutus_data())
                .collect(),
            Some(n::Guards::Credentials(credentials)) => {
                credentials.iter().map(|x| x.to_plutus_data()).collect()
            }
        };
        let mut required: Vec<_> = b.required_top_level_guards.iter().flatten().collect();
        required.sort_by_key(|(credential, _)| credential_order(credential));
        let votes = get_votes_info(&b.voting_procedures)
            .iter()
            .map(|(voter, actions)| {
                let actions = actions
                    .iter()
                    .map(|(id, procedure)| (gov_action_id(id), procedure.vote.to_plutus_data()))
                    .collect();
                (voter.to_plutus_data(), map(actions))
            })
            .collect();
        Ok(TxInfo {
            id: self.id.to_plutus_data(),
            inputs: list(self.inputs.iter().map(input).collect::<Result<_, _>>()?),
            reference_inputs: list(
                self.reference_inputs
                    .iter()
                    .map(input)
                    .collect::<Result<_, _>>()?,
            ),
            outputs: list(self.outputs.iter().map(output).collect::<Result<_, _>>()?),
            mint: MintValue {
                mint_value: b.mint.clone().unwrap_or_default(),
            }
            .to_plutus_data(),
            certificates: list(b.certificates.iter().flatten().map(certificate).collect()),
            withdrawals: map(by_account(b.withdrawals.iter().flatten(), |x| {
                x.to_plutus_data()
            })?),
            direct_deposits: map(by_account(b.direct_deposits.iter().flatten(), |x| {
                x.to_plutus_data()
            })?),
            balance_intervals: map(by_account(
                b.account_balance_intervals.iter().flatten(),
                balance_interval,
            )?),
            valid_range: list(vec![
                self.valid_range.lower_bound.to_plutus_data(),
                self.valid_range.upper_bound.to_plutus_data(),
            ]),
            guards: list(guards),
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
            votes: map(votes),
            proposals: list(
                self.proposals
                    .iter()
                    .map(proposal)
                    .collect::<Result<_, _>>()?,
            ),
            treasury: b.treasury_value.to_plutus_data(),
            donation: b.donation.as_ref().map_or(0, u64::from).to_plutus_data(),
        })
    }

    /// The constructor index of `purpose` and the fields its script purpose and script info share.
    fn fields(&self, purpose: &Purpose) -> Result<(u64, Vec<PlutusData>), Error> {
        let certificates: Vec<_> = self.body.certificates.iter().flatten().collect();
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

    /// The view of the whole transaction in the script info of the guard `hash`.
    fn top_tx_info(&self, hash: &Hash<28>, tx_info: &TxInfo) -> Result<PlutusData, Error> {
        let b = self.body;
        if b.sub_transactions.iter().flatten().next().is_some() {
            return unsupported("guarding redeemer with subtransactions");
        }
        let datums = match b
            .required_top_level_guards
            .as_ref()
            .and_then(|x| x.get(&StakeCredential::ScriptHash(*hash)))
        {
            Some(Nullable::Some(datum)) => vec![(tx_info.id.clone(), datum.clone())],
            _ => vec![],
        };
        let mut required: Vec<_> = b.required_top_level_guards.iter().flatten().collect();
        required.sort_by_key(|(credential, _)| credential_order(credential));
        let redeemer_hashes: BTreeSet<_> = self
            .redeemers
            .iter()
            .map(|(key, ..)| self.scripts[key])
            .collect();
        let simplified = list(vec![
            list(vec![tx_info.id.clone()]),
            tx_info.inputs.clone(),
            tx_info.reference_inputs.clone(),
            tx_info.outputs.clone(),
            mint_part(b.mint.as_ref(), true),
            mint_part(b.mint.as_ref(), false),
            tx_info.certificates.clone(),
            tx_info.withdrawals.clone(),
            tx_info.direct_deposits.clone(),
            tx_info.valid_range.clone(),
            tx_info.guards.clone(),
            list(
                required
                    .into_iter()
                    .map(|(credential, _)| credential.to_plutus_data())
                    .collect(),
            ),
            list(redeemer_hashes.iter().map(|x| x.to_plutus_data()).collect()),
            tx_info.data.clone(),
            tx_info.votes.clone(),
            tx_info.proposals.clone(),
            tx_info.treasury.clone(),
            tx_info.donation.clone(),
        ]);
        Ok(list(vec![
            list(vec![]),
            map(datums),
            map(by_account(
                b.starting_account_balance_intervals.iter().flatten(),
                balance_interval,
            )?),
            simplified,
        ]))
    }
}

/// The entries of `mint` with positive amounts, or with negative amounts, without the policies left empty.
fn mint_part(mint: Option<&c::Mint>, positive: bool) -> PlutusData {
    let mint_value = mint
        .into_iter()
        .flatten()
        .filter_map(|(policy, assets)| {
            let assets: BTreeMap<_, _> = assets
                .iter()
                .filter(|(_, amount)| (i64::from(*amount) > 0) == positive)
                .map(|(name, amount)| (name.clone(), *amount))
                .collect();
            (!assets.is_empty()).then_some((*policy, assets))
        })
        .collect();
    MintValue { mint_value }.to_plutus_data()
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
    entries.sort_by(|(x, _), (y, _)| account_order(x).cmp(&account_order(y)));
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
fn input(input: &ContextInput) -> Result<PlutusData, Error> {
    Ok(list(vec![
        out_ref(&input.out_ref),
        output(&input.resolved)?,
    ]))
}

/// An output, whose address holds a payment credential and an optional stake credential.
fn output(output: &ContextOutput) -> Result<PlutusData, Error> {
    let Address::Shelley(address) = &output.address else {
        return unsupported("output address (requires Shelley)");
    };
    let payment = match address.payment() {
        ShelleyPaymentPart::Key(hash) => StakeCredential::AddrKeyhash(*hash),
        ShelleyPaymentPart::Script(hash) => StakeCredential::ScriptHash(*hash),
    };
    let stake = match address.delegation() {
        ShelleyDelegationPart::Key(hash) => Some(StakeCredential::AddrKeyhash(*hash)),
        ShelleyDelegationPart::Script(hash) => Some(StakeCredential::ScriptHash(*hash)),
        ShelleyDelegationPart::Null => None,
        ShelleyDelegationPart::Pointer(_) => return Err(Error::DijkstraInvalid("pointer address")),
    };
    Ok(list(vec![
        list(vec![payment.to_plutus_data(), stake.to_plutus_data()]),
        output.value.to_plutus_data(),
        output.datum.to_plutus_data(),
        output.script.to_plutus_data(),
    ]))
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
