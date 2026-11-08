//! Dijkstra rules on account, pool, DRep, committee and proposal state.
use super::dijkstra::{Spender, spender};
use crate::utils::{
    AccountFailure, CertificateFailure, DijkstraProtParams, GovernanceFailure, MalformedField,
    PostAlonzoError::*,
    ValidationError,
    ValidationError::*,
    ValidationResult, WithdrawalFailure,
    dijkstra_state::{
        DijkstraAccount, DijkstraCommitteeAuth, DijkstraDRep, DijkstraLedgerOverlay,
        DijkstraLedgerState, DijkstraPool, DijkstraProposal, DijkstraProposalAction,
    },
};
use pallas_addresses::{Address, StakePayload};
use pallas_codec::minicbor;
use pallas_crypto::hash::Hash;
use pallas_primitives::dijkstra::*;
use pallas_traverse::{MultiEraOutput, withdrawals::cmp_reward_accounts};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// The fields a top level and a sub transaction body share, with the position of a sub transaction in its batch.
#[derive(Clone, Copy)]
pub(crate) struct Level<'a> {
    pub id: Hash<32>,
    pub sub: Option<u32>,
    pub inputs: &'a Set<TransactionInput>,
    pub reference_inputs: Option<&'a NonEmptySet<TransactionInput>>,
    pub outputs: &'a [TransactionOutput<'a>],
    pub validity_interval_start: Option<u64>,
    pub ttl: Option<u64>,
    pub mint: Option<&'a Mint>,
    pub guards: Option<&'a Guards>,
    pub required_top_level_guards: Option<&'a RequiredTopLevelGuards>,
    pub withdrawals: Option<&'a Withdrawals>,
    pub certificates: Option<&'a NonEmptySet<Certificate>>,
    pub direct_deposits: Option<&'a DirectDeposits>,
    pub intervals: Option<&'a AccountBalanceIntervals>,
    pub starting_intervals: Option<&'a StartingAccountBalanceIntervals>,
    pub votes: Option<&'a VotingProcedures>,
    pub proposals: Option<&'a NonEmptySet<ProposalProcedure>>,
    pub treasury_value: Option<Coin>,
    pub donation: Option<u64>,
}

impl<'a> Level<'a> {
    pub fn top(b: &'a TransactionBody<'a>, id: Hash<32>) -> Self {
        Level {
            id,
            sub: None,
            inputs: &b.inputs,
            reference_inputs: b.reference_inputs.as_ref(),
            outputs: &b.outputs,
            validity_interval_start: b.validity_interval_start,
            ttl: b.ttl,
            mint: b.mint.as_ref(),
            guards: b.guards.as_ref(),
            required_top_level_guards: b.required_top_level_guards.as_ref(),
            withdrawals: b.withdrawals.as_ref(),
            certificates: b.certificates.as_ref(),
            direct_deposits: b.direct_deposits.as_ref(),
            intervals: b.account_balance_intervals.as_ref(),
            starting_intervals: b.starting_account_balance_intervals.as_ref(),
            votes: b.voting_procedures.as_ref(),
            proposals: b.proposal_procedures.as_ref(),
            treasury_value: b.treasury_value,
            donation: b.donation.as_ref().map(u64::from),
        }
    }

    pub fn sub(b: &'a SubTransactionBody<'a>, id: Hash<32>, index: u32) -> Self {
        Level {
            id,
            sub: Some(index),
            inputs: &b.inputs,
            reference_inputs: b.reference_inputs.as_ref(),
            outputs: &b.outputs,
            validity_interval_start: b.validity_interval_start,
            ttl: b.ttl,
            mint: b.mint.as_ref(),
            guards: b.guards.as_ref(),
            required_top_level_guards: b.required_top_level_guards.as_ref(),
            withdrawals: b.withdrawals.as_ref(),
            certificates: b.certificates.as_ref(),
            direct_deposits: b.direct_deposits.as_ref(),
            intervals: b.account_balance_intervals.as_ref(),
            starting_intervals: None,
            votes: b.voting_procedures.as_ref(),
            proposals: b.proposal_procedures.as_ref(),
            treasury_value: b.treasury_value,
            donation: b.donation.as_ref().map(u64::from),
        }
    }

    /// The withdrawals in the order the ledger indexes their redeemers.
    pub fn ordered_withdrawals(&self) -> Vec<(&'a RewardAccount, Coin)> {
        let mut ordered: Vec<_> = self
            .withdrawals
            .iter()
            .flat_map(|x| x.iter())
            .map(|(a, c)| (a, *c))
            .collect();
        ordered.sort_by(|(x, _), (y, _)| cmp_reward_accounts(x, y));
        ordered
    }
}

/// The key hashes and scripts one level's ledger fields require, by redeemer purpose.
#[derive(Default)]
pub(crate) struct Needs {
    pub keys: HashSet<Hash<28>>,
    pub scripts: BTreeMap<RedeemersKey, Hash<28>>,
}

impl Needs {
    fn credential(&mut self, credential: &StakeCredential, tag: RedeemerTag, index: usize) {
        match credential {
            StakeCredential::AddrKeyhash(key) => {
                self.keys.insert(*key);
            }
            StakeCredential::ScriptHash(hash) => {
                self.scripts.insert(
                    RedeemersKey {
                        tag,
                        index: index as u32,
                    },
                    *hash,
                );
            }
        }
    }
}

/// The network and credential of a reward account.
pub(crate) fn reward_account(raw: &[u8]) -> Result<(u8, StakeCredential), ValidationError> {
    let Address::Stake(address) =
        Address::from_bytes(raw).map_err(|_| PostAlonzo(AddressDecoding))?
    else {
        return Err(PostAlonzo(AddressDecoding));
    };
    let credential = match address.payload() {
        StakePayload::Stake(key) => StakeCredential::AddrKeyhash(*key),
        StakePayload::Script(hash) => StakeCredential::ScriptHash(*hash),
    };
    Ok((address.network().value(), credential))
}

/// The script of each script guard in `guards`, by its Guarding redeemer key.
fn guarding_scripts(guards: Option<&Guards>) -> BTreeMap<RedeemersKey, Hash<28>> {
    let Some(Guards::Credentials(credentials)) = guards else {
        return BTreeMap::new();
    };
    credentials
        .iter()
        .enumerate()
        .filter_map(|(index, credential)| match credential {
            StakeCredential::ScriptHash(hash) => Some((
                RedeemersKey {
                    tag: RedeemerTag::Guarding,
                    index: index as u32,
                },
                *hash,
            )),
            StakeCredential::AddrKeyhash(_) => None,
        })
        .collect()
}

/// The script each redeemer key of the level `b` names, where `spent` gives the output a spent input resolves to.
pub(crate) fn redeemer_scripts<'o, 'x: 'o>(
    b: &Level<'_>,
    mut spent: impl FnMut(&TransactionInput) -> Result<&'o MultiEraOutput<'x>, ValidationError>,
) -> Result<BTreeMap<RedeemersKey, Hash<28>>, ValidationError> {
    let mut scripts = guarding_scripts(b.guards);
    scripts.extend(needs(b)?.scripts);
    for (index, input) in b
        .inputs
        .iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .enumerate()
    {
        if let Spender::Script(hash) = spender(spent(input)?)? {
            let tag = RedeemerTag::Spend;
            scripts.insert(
                RedeemersKey {
                    tag,
                    index: index as u32,
                },
                hash,
            );
        }
    }
    for (index, hash) in b.mint.into_iter().flat_map(|x| x.keys()).enumerate() {
        let tag = RedeemerTag::Mint;
        scripts.insert(
            RedeemersKey {
                tag,
                index: index as u32,
            },
            *hash,
        );
    }
    Ok(scripts)
}

/// The witnesses and scripts the withdrawals, certificates, votes and proposals of a level require.
pub(crate) fn needs(level: &Level<'_>) -> Result<Needs, ValidationError> {
    let mut needs = Needs::default();
    for (index, (raw, _)) in level.ordered_withdrawals().into_iter().enumerate() {
        let (_, credential) = reward_account(raw)?;
        needs.credential(&credential, RedeemerTag::Reward, index);
    }
    for (index, cert) in level.certificates.iter().flat_map(|x| x.iter()).enumerate() {
        match cert {
            Certificate::Reg(c, _)
            | Certificate::UnReg(c, _)
            | Certificate::StakeDelegation(c, _)
            | Certificate::VoteDeleg(c, _)
            | Certificate::StakeVoteDeleg(c, _, _)
            | Certificate::StakeRegDeleg(c, _, _)
            | Certificate::VoteRegDeleg(c, _, _)
            | Certificate::StakeVoteRegDeleg(c, _, _, _)
            | Certificate::AuthCommitteeHot(c, _)
            | Certificate::ResignCommitteeCold(c, _)
            | Certificate::RegDRepCert(c, _, _)
            | Certificate::UnRegDRepCert(c, _)
            | Certificate::UpdateDRepCert(c, _) => needs.credential(c, RedeemerTag::Cert, index),
            Certificate::PoolRegistration {
                operator,
                pool_owners,
                ..
            } => {
                needs.keys.insert(*operator);
                needs.keys.extend(pool_owners.iter().copied());
            }
            Certificate::PoolRetirement(operator, _) => {
                needs.keys.insert(*operator);
            }
        }
    }
    for (index, voter) in level.votes.iter().flat_map(|x| x.keys()).enumerate() {
        let credential = match voter {
            Voter::ConstitutionalCommitteeKey(key)
            | Voter::DRepKey(key)
            | Voter::StakePoolKey(key) => StakeCredential::AddrKeyhash(*key),
            Voter::ConstitutionalCommitteeScript(hash) | Voter::DRepScript(hash) => {
                StakeCredential::ScriptHash(*hash)
            }
        };
        needs.credential(&credential, RedeemerTag::Vote, index);
    }
    for (index, proposal) in level.proposals.iter().flat_map(|x| x.iter()).enumerate() {
        if let GovAction::ParameterChange(_, _, Some(policy))
        | GovAction::TreasuryWithdrawals(_, Some(policy)) = &proposal.gov_action
        {
            needs.scripts.insert(
                RedeemersKey {
                    tag: RedeemerTag::Propose,
                    index: index as u32,
                },
                *policy,
            );
        }
    }
    Ok(needs)
}

/// The coin a level's ledger fields take from accounts and deposits, and the coin they put into them.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Flows {
    pub consumed: u64,
    pub produced: u64,
}

impl Flows {
    fn consume(&mut self, coin: u64) -> ValidationResult {
        self.consumed = self
            .consumed
            .checked_add(coin)
            .ok_or(PostAlonzo(NegativeValue))?;
        Ok(())
    }
    fn produce(&mut self, coin: u64) -> ValidationResult {
        self.produced = self
            .produced
            .checked_add(coin)
            .ok_or(PostAlonzo(NegativeValue))?;
        Ok(())
    }
    pub fn add(&mut self, other: Flows) -> ValidationResult {
        self.consume(other.consumed)?;
        self.produce(other.produced)
    }
}

/// The withdrawals of every sub transaction, summed per account.
pub(crate) fn sub_withdrawals(
    tx: &BlockTransaction<'_>,
) -> Result<BTreeMap<StakeCredential, u128>, ValidationError> {
    let mut total = BTreeMap::new();
    for sub in tx.transaction_body.sub_transactions.iter().flatten() {
        for (raw, amount) in sub.sub_transaction_body.withdrawals.iter().flatten() {
            let (_, credential) = reward_account(raw)?;
            *total.entry(credential).or_default() += u128::from(*amount);
        }
    }
    Ok(total)
}

/// The rule the top level withdrawals of a transaction are judged by.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum WithdrawalRule {
    /// The transaction runs a Plutus V1, V2 or V3 script, so each top level withdrawal drains its account.
    Legacy,
    /// The transaction runs no Plutus V1, V2 or V3 script, so a top level withdrawal may take part of its account.
    Partial,
    /// The transaction was accepted before, so only its changes are computed.
    Accepted,
}

fn interval_contains(balance: Coin, interval: &AccountBalanceInterval) -> bool {
    match interval {
        AccountBalanceInterval::LowerBound(lo) => *lo <= balance,
        AccountBalanceInterval::UpperBound(hi) => balance < *hi,
        AccountBalanceInterval::Bounded(lo, hi) => *lo <= balance && balance < *hi,
        AccountBalanceInterval::Exact(n) => balance == *n,
    }
}

fn check_intervals<S: DijkstraLedgerState + ?Sized>(
    intervals: Option<&AccountBalanceIntervals>,
    network: u8,
    state: &S,
) -> ValidationResult {
    for (raw, interval) in intervals.into_iter().flatten() {
        let (net, credential) = reward_account(raw)?;
        if net != network {
            return Err(PostAlonzo(TxWrongNetworkID));
        }
        let account = state.account(&credential)?.ok_or(DijkstraInvalidAccount(
            AccountFailure::BalanceIntervalUnregistered,
        ))?;
        if !interval_contains(account.balance, interval) {
            return Err(DijkstraInvalidAccount(
                AccountFailure::BalanceOutsideInterval,
            ));
        }
    }
    Ok(())
}

/// ENTITIES and SUBENTITIES: withdrawals, balance intervals, certificates and direct deposits, applied to `current`.
pub(crate) fn entities<O, S>(
    level: &Level<'_>,
    top: Option<(WithdrawalRule, &BTreeMap<StakeCredential, u128>)>,
    pp: &DijkstraProtParams,
    network: u8,
    original: &O,
    current: &mut DijkstraLedgerOverlay<'_, S>,
) -> Result<Flows, ValidationError>
where
    O: DijkstraLedgerState + ?Sized,
    S: DijkstraLedgerState + ?Sized,
{
    let mut flows = Flows::default();
    let withdrawals = level
        .ordered_withdrawals()
        .into_iter()
        .map(|(raw, amount)| Ok((reward_account(raw)?, amount)))
        .collect::<Result<Vec<_>, ValidationError>>()?;
    if withdrawals.iter().any(|((net, _), _)| *net != network) {
        return Err(PostAlonzo(TxWrongNetworkID));
    }
    for (raw, _) in level.direct_deposits.into_iter().flatten() {
        if reward_account(raw)?.0 != network {
            return Err(PostAlonzo(TxWrongNetworkID));
        }
    }
    check_intervals(level.intervals, network, current)?;
    check_intervals(level.starting_intervals, network, original)?;
    match top {
        Some((WithdrawalRule::Accepted, _)) => (),
        Some((rule, subs)) => {
            let legacy = rule == WithdrawalRule::Legacy;
            let mut all = subs.clone();
            if !legacy {
                for ((_, credential), amount) in &withdrawals {
                    if original.account(credential)?.is_none() {
                        return Err(DijkstraInvalidWithdrawal(
                            WithdrawalFailure::AccountMissingFromOriginalState,
                        ));
                    }
                    *all.entry(credential.clone()).or_default() += u128::from(*amount);
                }
            }
            for (credential, amount) in &all {
                if let Some(account) = original.account(credential)?
                    && *amount > u128::from(account.balance)
                {
                    return Err(DijkstraInvalidWithdrawal(
                        WithdrawalFailure::AmountExceedsOriginalBalance,
                    ));
                }
            }
            for ((_, credential), amount) in &withdrawals {
                let account = current
                    .account(credential)?
                    .ok_or(DijkstraInvalidWithdrawal(
                        WithdrawalFailure::UnregisteredAccount,
                    ))?;
                if legacy && account.balance != *amount {
                    return Err(DijkstraInvalidWithdrawal(
                        WithdrawalFailure::LegacyPlutusMustDrain,
                    ));
                }
            }
        }
        None => {
            for ((_, credential), _) in &withdrawals {
                if original.account(credential)?.is_none() {
                    return Err(DijkstraInvalidWithdrawal(
                        WithdrawalFailure::AccountMissingFromOriginalState,
                    ));
                }
                if current.account(credential)?.is_none() {
                    return Err(DijkstraInvalidWithdrawal(
                        WithdrawalFailure::UnregisteredAccount,
                    ));
                }
            }
        }
    }
    for ((_, credential), amount) in &withdrawals {
        withdraw(current, credential, *amount)?;
        flows.consume(*amount)?;
    }
    for cert in level.certificates.iter().flat_map(|x| x.iter()) {
        certificate(cert, pp, network, current, &mut flows)?;
    }
    for (raw, amount) in level.direct_deposits.into_iter().flatten() {
        let (_, credential) = reward_account(raw)?;
        if current.account(&credential)?.is_none() {
            return Err(DijkstraInvalidAccount(
                AccountFailure::DirectDepositUnregistered,
            ));
        }
        flows.produce(*amount)?;
    }
    for (raw, amount) in level.direct_deposits.into_iter().flatten() {
        deposit(current, &reward_account(raw)?.1, *amount)?;
    }
    Ok(flows)
}

fn withdraw<S: DijkstraLedgerState + ?Sized>(
    state: &mut DijkstraLedgerOverlay<'_, S>,
    credential: &StakeCredential,
    amount: Coin,
) -> ValidationResult {
    if let Some(mut account) = state.account(credential)? {
        account.balance = account
            .balance
            .checked_sub(amount)
            .ok_or(DijkstraInvalidWithdrawal(
                WithdrawalFailure::AmountExceedsBalance,
            ))?;
        state
            .delta
            .accounts
            .insert(credential.clone(), Some(account));
    }
    Ok(())
}

fn deposit<S: DijkstraLedgerState + ?Sized>(
    state: &mut DijkstraLedgerOverlay<'_, S>,
    credential: &StakeCredential,
    amount: Coin,
) -> ValidationResult {
    if let Some(mut account) = state.account(credential)? {
        account.balance = account
            .balance
            .checked_add(amount)
            .ok_or(PostAlonzo(NegativeValue))?;
        state
            .delta
            .accounts
            .insert(credential.clone(), Some(account));
    }
    Ok(())
}

fn register<S: DijkstraLedgerState + ?Sized>(
    state: &mut DijkstraLedgerOverlay<'_, S>,
    credential: &StakeCredential,
    amount: Coin,
    pp: &DijkstraProtParams,
    flows: &mut Flows,
) -> ValidationResult {
    if amount != pp.key_deposit {
        return Err(DijkstraInvalidCertificate(
            CertificateFailure::RegistrationDeposit,
        ));
    }
    if state.account(credential)?.is_some() {
        return Err(DijkstraInvalidCertificate(
            CertificateFailure::AlreadyRegistered,
        ));
    }
    state.delta.accounts.insert(
        credential.clone(),
        Some(DijkstraAccount {
            balance: 0,
            deposit: amount,
        }),
    );
    flows.produce(amount)
}

fn registered<S: DijkstraLedgerState + ?Sized>(
    state: &DijkstraLedgerOverlay<'_, S>,
    credential: &StakeCredential,
) -> ValidationResult {
    match state.account(credential)? {
        Some(_) => Ok(()),
        None => Err(DijkstraInvalidAccount(
            AccountFailure::StakeCredentialNotRegistered,
        )),
    }
}

fn delegate_pool<S: DijkstraLedgerState + ?Sized>(
    state: &DijkstraLedgerOverlay<'_, S>,
    pool: &Hash<28>,
) -> ValidationResult {
    match state.pool(pool)? {
        Some(_) => Ok(()),
        None => Err(DijkstraInvalidCertificate(
            CertificateFailure::DelegateePoolNotRegistered,
        )),
    }
}

fn delegate_drep<S: DijkstraLedgerState + ?Sized>(
    state: &DijkstraLedgerOverlay<'_, S>,
    drep: &DRep,
) -> ValidationResult {
    let credential = match drep {
        DRep::Key(key) => StakeCredential::AddrKeyhash(*key),
        DRep::Script(hash) => StakeCredential::ScriptHash(*hash),
        DRep::Abstain | DRep::NoConfidence => return Ok(()),
    };
    match state.drep(&credential)? {
        Some(_) => Ok(()),
        None => Err(DijkstraInvalidCertificate(
            CertificateFailure::DelegateeDRepNotRegistered,
        )),
    }
}

/// The domain separation tag of a BLS proof of possession, which signs the compressed public key.
const BLS_POP_DST: &[u8] = b"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

fn valid_possession_proof(key: &BlsKey) -> bool {
    use blst::min_sig::{PublicKey, Signature};
    let (Ok(public), Ok(proof)) = (
        PublicKey::from_bytes(&key.bls_pubkey),
        Signature::from_bytes(&key.bls_possession_proof),
    ) else {
        return false;
    };
    proof.verify(true, &key.bls_pubkey, BLS_POP_DST, &[], &public, true)
        == blst::BLST_ERROR::BLST_SUCCESS
}

fn certificate<S: DijkstraLedgerState + ?Sized>(
    cert: &Certificate,
    pp: &DijkstraProtParams,
    network: u8,
    state: &mut DijkstraLedgerOverlay<'_, S>,
    flows: &mut Flows,
) -> ValidationResult {
    match cert {
        Certificate::Reg(c, amount) => register(state, c, *amount, pp, flows),
        Certificate::UnReg(c, refund) => {
            let account = state.account(c)?.ok_or(DijkstraInvalidAccount(
                AccountFailure::StakeCredentialNotRegistered,
            ))?;
            if *refund != account.deposit {
                return Err(DijkstraInvalidCertificate(CertificateFailure::Refund));
            }
            if account.balance != 0 {
                return Err(DijkstraInvalidCertificate(
                    CertificateFailure::AccountBalanceNotZero,
                ));
            }
            state.delta.accounts.insert(c.clone(), None);
            flows.consume(*refund)
        }
        Certificate::StakeDelegation(c, pool) => {
            registered(state, c)?;
            delegate_pool(state, pool)
        }
        Certificate::VoteDeleg(c, drep) => {
            registered(state, c)?;
            delegate_drep(state, drep)
        }
        Certificate::StakeVoteDeleg(c, pool, drep) => {
            registered(state, c)?;
            delegate_pool(state, pool)?;
            delegate_drep(state, drep)
        }
        Certificate::StakeRegDeleg(c, pool, amount) => {
            delegate_pool(state, pool)?;
            register(state, c, *amount, pp, flows)
        }
        Certificate::VoteRegDeleg(c, drep, amount) => {
            delegate_drep(state, drep)?;
            register(state, c, *amount, pp, flows)
        }
        Certificate::StakeVoteRegDeleg(c, pool, drep, amount) => {
            delegate_pool(state, pool)?;
            delegate_drep(state, drep)?;
            register(state, c, *amount, pp, flows)
        }
        Certificate::PoolRegistration {
            operator,
            vrf_keyhash,
            bls_key,
            cost,
            reward_account: account,
            pool_metadata,
            ..
        } => {
            if reward_account(account)?.0 != network {
                return Err(PostAlonzo(TxWrongNetworkID));
            }
            if pool_metadata.as_ref().is_some_and(|m| m.hash.len() > 32) {
                return Err(DijkstraInvalidCertificate(
                    CertificateFailure::PoolMetadataHashTooBig,
                ));
            }
            if *cost < pp.min_pool_cost {
                return Err(DijkstraInvalidCertificate(
                    CertificateFailure::PoolCostBelowMinimum,
                ));
            }
            if let Some(pallas_codec::utils::Nullable::Some(key)) = bls_key
                && !valid_possession_proof(key)
            {
                return Err(DijkstraInvalidCertificate(
                    CertificateFailure::BlsProofOfPossession,
                ));
            }
            let count = state.vrf_count(vrf_keyhash)?;
            match state.pool(operator)? {
                None => {
                    if count != 0 {
                        return Err(DijkstraInvalidCertificate(
                            CertificateFailure::VrfKeyHashAlreadyRegistered,
                        ));
                    }
                    state.delta.pools.insert(
                        *operator,
                        DijkstraPool {
                            vrf: *vrf_keyhash,
                            future_vrf: None,
                        },
                    );
                    *state.delta.vrf_counts.entry(*vrf_keyhash).or_default() += 1;
                    flows.produce(pp.pool_deposit)
                }
                Some(pool) => {
                    let own = *vrf_keyhash == pool.vrf || pool.future_vrf == Some(*vrf_keyhash);
                    if count != u64::from(own) {
                        return Err(DijkstraInvalidCertificate(
                            CertificateFailure::VrfKeyHashAlreadyRegistered,
                        ));
                    }
                    if pool.future_vrf != Some(*vrf_keyhash) {
                        if let Some(old) = pool.future_vrf
                            && old != pool.vrf
                        {
                            *state.delta.vrf_counts.entry(old).or_default() -= 1;
                        }
                        if *vrf_keyhash != pool.vrf {
                            *state.delta.vrf_counts.entry(*vrf_keyhash).or_default() += 1;
                        }
                    }
                    state.delta.pools.insert(
                        *operator,
                        DijkstraPool {
                            vrf: pool.vrf,
                            future_vrf: Some(*vrf_keyhash),
                        },
                    );
                    Ok(())
                }
            }
        }
        Certificate::PoolRetirement(operator, epoch) => {
            if state.pool(operator)?.is_none() {
                return Err(DijkstraInvalidCertificate(
                    CertificateFailure::PoolNotRegistered,
                ));
            }
            let current = state.epoch();
            if *epoch <= current || *epoch > current.saturating_add(pp.maximum_epoch) {
                return Err(DijkstraInvalidCertificate(
                    CertificateFailure::PoolRetirementEpoch,
                ));
            }
            Ok(())
        }
        Certificate::AuthCommitteeHot(cold, _) | Certificate::ResignCommitteeCold(cold, _) => {
            let auths = state.committee_auths()?;
            if auths.get(cold) == Some(&DijkstraCommitteeAuth::Resigned) {
                return Err(DijkstraInvalidCertificate(
                    CertificateFailure::CommitteeMemberResigned,
                ));
            }
            let member = state
                .committee()?
                .is_some_and(|members| members.contains_key(cold));
            let proposed = state.proposals()?.iter().any(|(_, proposal)| {
                matches!(&proposal.action, DijkstraProposalAction::UpdateCommittee { added } if added.contains(cold))
            });
            if !member && !proposed {
                return Err(DijkstraInvalidCertificate(
                    CertificateFailure::CommitteeMemberUnknown,
                ));
            }
            let auth = match cert {
                Certificate::AuthCommitteeHot(_, hot) => DijkstraCommitteeAuth::Hot(hot.clone()),
                _ => DijkstraCommitteeAuth::Resigned,
            };
            state.delta.committee_auths.insert(cold.clone(), auth);
            Ok(())
        }
        Certificate::RegDRepCert(c, amount, _) => {
            if state.drep(c)?.is_some() {
                return Err(DijkstraInvalidCertificate(
                    CertificateFailure::DRepAlreadyRegistered,
                ));
            }
            if *amount != pp.drep_deposit {
                return Err(DijkstraInvalidCertificate(CertificateFailure::DRepDeposit));
            }
            state
                .delta
                .dreps
                .insert(c.clone(), Some(DijkstraDRep { deposit: *amount }));
            flows.produce(*amount)
        }
        Certificate::UnRegDRepCert(c, refund) => {
            let drep = state.drep(c)?.ok_or(DijkstraInvalidCertificate(
                CertificateFailure::DRepNotRegistered,
            ))?;
            if *refund != drep.deposit {
                return Err(DijkstraInvalidCertificate(CertificateFailure::DRepRefund));
            }
            state.delta.dreps.insert(c.clone(), None);
            flows.consume(*refund)
        }
        Certificate::UpdateDRepCert(c, _) => match state.drep(c)? {
            Some(_) => Ok(()),
            None => Err(DijkstraInvalidCertificate(
                CertificateFailure::DRepNotRegistered,
            )),
        },
    }
}

/// The CBOR keys of the protocol parameters whose change the stake pools vote on.
const SECURITY_GROUP: [u64; 15] = [0, 1, 2, 3, 4, 17, 21, 22, 30, 33, 34, 35, 36, 37, 40];

/// The CBOR keys of the protocol parameters an update may not set to zero.
const NONZERO: [u64; 13] = [2, 3, 4, 6, 7, 8, 17, 22, 23, 28, 29, 30, 31];

/// The keys an update sets, each with its value when the value is an unsigned integer.
fn update_fields(update: &ProtocolParamUpdate) -> Result<Vec<(u64, Option<u64>)>, ValidationError> {
    let raw = minicbor::to_vec(update).map_err(|_| PostAlonzo(UnknownTxSize))?;
    let fields: pallas_codec::utils::KeyValuePairs<u64, pallas_codec::utils::AnyCbor> =
        minicbor::decode(&raw)
            .map_err(|_| DijkstraMalformed(MalformedField::ProtocolParameterUpdate))?;
    Ok(fields
        .iter()
        .map(|(key, value)| (*key, minicbor::decode::<u64>(value).ok()))
        .collect())
}

/// Whether an update changes a parameter the stake pools vote on.
pub(crate) fn security_relevant(update: &ProtocolParamUpdate) -> Result<bool, ValidationError> {
    Ok(update_fields(update)?
        .iter()
        .any(|(key, _)| SECURITY_GROUP.contains(key) || (41..=56).contains(key)))
}

/// What later proposals and votes read of a governance action.
pub(crate) fn proposal_action(
    action: &GovAction,
) -> Result<DijkstraProposalAction, ValidationError> {
    Ok(match action {
        GovAction::ParameterChange(_, update, _) => DijkstraProposalAction::ParameterChange {
            security_relevant: security_relevant(update)?,
        },
        GovAction::HardForkInitiation(_, version) => {
            DijkstraProposalAction::HardForkInitiation { version: *version }
        }
        GovAction::TreasuryWithdrawals(..) => DijkstraProposalAction::TreasuryWithdrawals,
        GovAction::NoConfidence(_) => DijkstraProposalAction::NoConfidence,
        GovAction::UpdateCommittee(_, _, added, _) => DijkstraProposalAction::UpdateCommittee {
            added: added.keys().cloned().collect(),
        },
        GovAction::NewConstitution(..) => DijkstraProposalAction::NewConstitution,
        GovAction::Information => DijkstraProposalAction::Information,
    })
}

/// The purposes whose actions name a predecessor.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Purpose {
    ParameterChange,
    HardFork,
    Committee,
    Constitution,
}

fn purpose(action: &DijkstraProposalAction) -> Option<Purpose> {
    match action {
        DijkstraProposalAction::ParameterChange { .. } => Some(Purpose::ParameterChange),
        DijkstraProposalAction::HardForkInitiation { .. } => Some(Purpose::HardFork),
        DijkstraProposalAction::NoConfidence | DijkstraProposalAction::UpdateCommittee { .. } => {
            Some(Purpose::Committee)
        }
        DijkstraProposalAction::NewConstitution => Some(Purpose::Constitution),
        DijkstraProposalAction::TreasuryWithdrawals | DijkstraProposalAction::Information => None,
    }
}

fn previous(action: &GovAction) -> Option<&GovActionId> {
    match action {
        GovAction::ParameterChange(prev, _, _)
        | GovAction::HardForkInitiation(prev, _)
        | GovAction::NoConfidence(prev)
        | GovAction::UpdateCommittee(prev, _, _, _)
        | GovAction::NewConstitution(prev, _) => prev.as_ref(),
        GovAction::TreasuryWithdrawals(..) | GovAction::Information => None,
    }
}

fn can_follow(current: (u64, u64), next: (u64, u64)) -> bool {
    next == (current.0.saturating_add(1), 0) || next == (current.0, current.1.saturating_add(1))
}

/// Whether a voter role may vote on an action.
fn allowed(voter: &Voter, action: &DijkstraProposalAction) -> bool {
    use DijkstraProposalAction as A;
    match voter {
        Voter::ConstitutionalCommitteeKey(_) | Voter::ConstitutionalCommitteeScript(_) => {
            !matches!(action, A::NoConfidence | A::UpdateCommittee { .. })
        }
        Voter::DRepKey(_) | Voter::DRepScript(_) => true,
        Voter::StakePoolKey(_) => match action {
            A::ParameterChange { security_relevant } => *security_relevant,
            A::NewConstitution | A::TreasuryWithdrawals => false,
            _ => true,
        },
    }
}

/// GOV and SUBGOV: proposals then votes, with new proposals added to `current`.
pub(crate) fn governance<S: DijkstraLedgerState + ?Sized>(
    level: &Level<'_>,
    pp: &DijkstraProtParams,
    network: u8,
    current: &mut DijkstraLedgerOverlay<'_, S>,
) -> Result<Flows, ValidationError> {
    let mut flows = Flows::default();
    let epoch = current.epoch();
    let roots = current.roots()?;
    let guardrail = current.guardrail_script()?;
    for (index, proposal) in level.proposals.iter().flat_map(|x| x.iter()).enumerate() {
        let action = proposal_action(&proposal.gov_action)?;
        match &proposal.gov_action {
            GovAction::ParameterChange(_, update, _) => {
                let fields = update_fields(update)?;
                if fields.is_empty()
                    || fields
                        .iter()
                        .any(|(key, value)| NONZERO.contains(key) && *value == Some(0))
                {
                    return Err(DijkstraInvalidGovernance(
                        GovernanceFailure::MalformedParameterUpdate,
                    ));
                }
            }
            GovAction::UpdateCommittee(_, removed, added, _) => {
                if added.keys().any(|x| removed.contains(x)) {
                    return Err(DijkstraInvalidGovernance(
                        GovernanceFailure::ConflictingCommitteeUpdate,
                    ));
                }
                if added.values().any(|term| *term <= epoch) {
                    return Err(DijkstraInvalidGovernance(
                        GovernanceFailure::CommitteeTermTooSmall,
                    ));
                }
            }
            GovAction::TreasuryWithdrawals(withdrawals, _) => {
                let mut total: u128 = 0;
                for (raw, amount) in withdrawals {
                    let (net, credential) = reward_account(raw)?;
                    if net != network {
                        return Err(PostAlonzo(TxWrongNetworkID));
                    }
                    if current.account(&credential)?.is_none() {
                        return Err(DijkstraInvalidGovernance(
                            GovernanceFailure::TreasuryWithdrawalAccountNotRegistered,
                        ));
                    }
                    total += u128::from(*amount);
                }
                if total == 0 {
                    return Err(DijkstraInvalidGovernance(
                        GovernanceFailure::ZeroTreasuryWithdrawals,
                    ));
                }
            }
            _ => (),
        }
        if let GovAction::ParameterChange(_, _, policy) | GovAction::TreasuryWithdrawals(_, policy) =
            &proposal.gov_action
            && *policy != guardrail
        {
            return Err(DijkstraInvalidGovernance(
                GovernanceFailure::GuardrailsScriptHash,
            ));
        }
        if proposal.deposit != pp.governance_action_deposit {
            return Err(DijkstraInvalidGovernance(
                GovernanceFailure::ProposalDeposit,
            ));
        }
        let (net, credential) = reward_account(&proposal.reward_account)?;
        if net != network {
            return Err(PostAlonzo(TxWrongNetworkID));
        }
        if current.account(&credential)?.is_none() {
            return Err(DijkstraInvalidGovernance(
                GovernanceFailure::ProposalReturnAccountNotRegistered,
            ));
        }
        let proposals = current.proposals()?;
        if let Some(purpose) = purpose(&action) {
            let prev = previous(&proposal.gov_action);
            let root = match purpose {
                Purpose::ParameterChange => &roots.parameter_change,
                Purpose::HardFork => &roots.hard_fork,
                Purpose::Committee => &roots.committee,
                Purpose::Constitution => &roots.constitution,
            };
            let parent = proposals
                .iter()
                .find(|(id, p)| Some(id) == prev && self::purpose(&p.action) == Some(purpose));
            if prev != root.as_ref() && parent.is_none() {
                return Err(DijkstraInvalidGovernance(
                    GovernanceFailure::PreviousActionId,
                ));
            }
            if let DijkstraProposalAction::HardForkInitiation { version } = action {
                let base = match parent {
                    Some((
                        _,
                        DijkstraProposal {
                            action: DijkstraProposalAction::HardForkInitiation { version },
                            ..
                        },
                    )) if prev != root.as_ref() => *version,
                    _ => pp.protocol_version,
                };
                if !can_follow(base, version) {
                    return Err(DijkstraInvalidGovernance(
                        GovernanceFailure::HardForkVersionCannotFollow,
                    ));
                }
            }
        }
        current.delta.proposals.push((
            GovActionId {
                transaction_id: level.id,
                action_index: index as u32,
            },
            DijkstraProposal {
                action,
                expires_after: epoch.saturating_add(pp.governance_action_validity_period),
            },
        ));
        flows.produce(proposal.deposit)?;
    }
    if let Some(votes) = level.votes {
        let auths = current.committee_auths()?;
        let hot: BTreeSet<_> = auths
            .values()
            .filter_map(|x| match x {
                DijkstraCommitteeAuth::Hot(hot) => Some(hot),
                DijkstraCommitteeAuth::Resigned => None,
            })
            .collect();
        let members = current.committee()?.unwrap_or_default();
        let elected: BTreeSet<_> = auths
            .iter()
            .filter(|(cold, _)| members.contains_key(*cold))
            .filter_map(|(_, x)| match x {
                DijkstraCommitteeAuth::Hot(hot) => Some(hot),
                DijkstraCommitteeAuth::Resigned => None,
            })
            .collect();
        let proposals = current.proposals()?;
        for (voter, actions) in votes.iter() {
            let exists = match voter {
                Voter::ConstitutionalCommitteeKey(_) | Voter::ConstitutionalCommitteeScript(_) => {
                    let credential = voter_credential(voter);
                    if hot.contains(&credential) && !elected.contains(&credential) {
                        return Err(DijkstraInvalidGovernance(
                            GovernanceFailure::UnelectedCommitteeVoter,
                        ));
                    }
                    hot.contains(&credential)
                }
                Voter::DRepKey(_) | Voter::DRepScript(_) => {
                    current.drep(&voter_credential(voter))?.is_some()
                }
                Voter::StakePoolKey(pool) => current.pool(pool)?.is_some(),
            };
            if !exists {
                return Err(DijkstraInvalidGovernance(
                    GovernanceFailure::VoterDoesNotExist,
                ));
            }
            for id in actions.keys() {
                let (_, proposal) =
                    proposals
                        .iter()
                        .find(|(x, _)| x == id)
                        .ok_or(DijkstraInvalidGovernance(
                            GovernanceFailure::ActionDoesNotExist,
                        ))?;
                if epoch > proposal.expires_after {
                    return Err(DijkstraInvalidGovernance(
                        GovernanceFailure::VoteOnExpiredAction,
                    ));
                }
                if !allowed(voter, &proposal.action) {
                    return Err(DijkstraInvalidGovernance(
                        GovernanceFailure::VoterMayNotVote,
                    ));
                }
            }
        }
    }
    if let Some(donation) = level.donation {
        flows.produce(donation)?;
    }
    Ok(flows)
}

fn voter_credential(voter: &Voter) -> StakeCredential {
    match voter {
        Voter::ConstitutionalCommitteeKey(key) | Voter::DRepKey(key) | Voter::StakePoolKey(key) => {
            StakeCredential::AddrKeyhash(*key)
        }
        Voter::ConstitutionalCommitteeScript(hash) | Voter::DRepScript(hash) => {
            StakeCredential::ScriptHash(*hash)
        }
    }
}

/// The treasury a level states must equal the ledger treasury.
pub(crate) fn check_treasury<S: DijkstraLedgerState + ?Sized>(
    level: &Level<'_>,
    state: &S,
) -> ValidationResult {
    match level.treasury_value {
        Some(value) if value != state.treasury()? => Err(DijkstraTreasuryValueMismatch),
        _ => Ok(()),
    }
}
