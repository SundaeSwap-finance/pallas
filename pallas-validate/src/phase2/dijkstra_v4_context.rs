//! The PlutusV4 script context of a top level redeemer.
use super::{ContextInput, ContextOutput, conway_certificate, unsupported};
use crate::phase1::dijkstra_ledger::{account_order, reward_account};
use crate::phase2::{
    error::Error,
    script_context::{ScriptInfo, ScriptPurpose, TimeRange, get_votes_info},
    to_plutus_data::{MintValue, ToPlutusData, WithRegistrationDeposit, wrap_multiple_with_constr},
};
use pallas_addresses::{Address, ShelleyDelegationPart, ShelleyPaymentPart};
use pallas_codec::utils::{KeyValuePairs, MaybeIndefArray};
use pallas_crypto::hash::Hash;
use pallas_primitives::{
    RewardAccount,
    conway::{self as c, PlutusData, StakeCredential},
    dijkstra as n,
};
use std::collections::BTreeMap;

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
    pub(super) redeemers: &'a [(n::RedeemersKey, ScriptPurpose, c::Redeemer)],
    pub(super) scripts: &'a BTreeMap<n::RedeemersKey, Hash<28>>,
}

impl Top<'_, '_> {
    /// The script context of the redeemer at `key`, with the datum it spends.
    pub(super) fn script_context(
        &self,
        key: &n::RedeemersKey,
        purpose: &ScriptPurpose,
        redeemer: &PlutusData,
        datum: Option<&PlutusData>,
    ) -> Result<PlutusData, Error> {
        let hash = &self.scripts[key];
        let (_, info) = self.purpose(purpose, hash, datum)?;
        Ok(list(vec![
            self.tx_info()?,
            redeemer.clone(),
            info,
            hash.to_plutus_data(),
        ]))
    }

    /// The transaction info, with no fee and with the top level marked by an absent sub transaction index.
    fn tx_info(&self) -> Result<PlutusData, Error> {
        let b = self.body;
        let mut redeemers = Vec::new();
        for (key, purpose, redeemer) in self.redeemers {
            let (purpose, _) = self.purpose(purpose, &self.scripts[key], None)?;
            redeemers.push((key, purpose, redeemer.data.clone()));
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
        Ok(list(vec![
            self.id.to_plutus_data(),
            None::<u64>.to_plutus_data(),
            list(self.inputs.iter().map(input).collect::<Result<_, _>>()?),
            list(
                self.reference_inputs
                    .iter()
                    .map(input)
                    .collect::<Result<_, _>>()?,
            ),
            list(self.outputs.iter().map(output).collect::<Result<_, _>>()?),
            MintValue {
                mint_value: b.mint.clone().unwrap_or_default(),
            }
            .to_plutus_data(),
            list(b.certificates.iter().flatten().map(certificate).collect()),
            map(by_account(b.withdrawals.iter().flatten(), |x| {
                x.to_plutus_data()
            })?),
            map(by_account(b.direct_deposits.iter().flatten(), |x| {
                x.to_plutus_data()
            })?),
            map(by_account(
                b.account_balance_intervals.iter().flatten(),
                balance_interval,
            )?),
            list(vec![
                self.valid_range.lower_bound.to_plutus_data(),
                self.valid_range.upper_bound.to_plutus_data(),
            ]),
            list(guards),
            map(required
                .into_iter()
                .map(|(credential, datum)| (credential.to_plutus_data(), datum.to_plutus_data()))
                .collect()),
            map(redeemers
                .into_iter()
                .map(|(_, purpose, data)| (purpose, data))
                .collect()),
            map(self
                .datums
                .iter()
                .map(|(hash, datum)| (hash.to_plutus_data(), datum.clone()))
                .collect()),
            map(votes),
            list(
                self.proposals
                    .iter()
                    .map(proposal)
                    .collect::<Result<_, _>>()?,
            ),
            b.treasury_value.to_plutus_data(),
            b.donation.as_ref().map_or(0, u64::from).to_plutus_data(),
        ]))
    }

    /// The script purpose and the script info of the redeemer that runs `hash` for `purpose`.
    fn purpose(
        &self,
        purpose: &ScriptPurpose,
        hash: &Hash<28>,
        datum: Option<&PlutusData>,
    ) -> Result<(PlutusData, PlutusData), Error> {
        let certificates: Vec<_> = self.body.certificates.iter().flatten().collect();
        let (index, fields) = match purpose {
            ScriptInfo::Minting(policy) => (0, vec![policy.to_plutus_data()]),
            ScriptInfo::Spending(spent, ()) => (1, vec![out_ref(spent)]),
            ScriptInfo::Rewarding(credential) => (2, vec![credential.to_plutus_data()]),
            ScriptInfo::Certifying(ix, _) => {
                (3, vec![ix.to_plutus_data(), certificate(certificates[*ix])])
            }
            ScriptInfo::Voting(voter) => (4, vec![voter.to_plutus_data()]),
            ScriptInfo::Proposing(ix, procedure) => {
                (5, vec![ix.to_plutus_data(), proposal(procedure)?])
            }
        };
        let mut info = fields.clone();
        if let ScriptInfo::Spending(..) = purpose {
            info.push(datum.cloned().to_plutus_data());
        }
        let purpose = std::iter::once(hash.to_plutus_data()).chain(fields);
        Ok((
            wrap_multiple_with_constr(index, purpose.collect()),
            wrap_multiple_with_constr(index, info),
        ))
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
