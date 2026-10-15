//! The ledger state a Dijkstra transaction reads, and the changes a transaction makes to it.
use super::ValidationError;
use pallas_crypto::hash::Hash;
use pallas_primitives::{
    Coin, Epoch,
    dijkstra::{GovActionId, StakeCredential},
};
use std::collections::{BTreeMap, HashMap};

/// A registered stake account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DijkstraAccount {
    pub balance: Coin,
    pub deposit: Coin,
}

/// A registered stake pool, by the VRF key hashes of its active and pending parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DijkstraPool {
    pub vrf: Hash<32>,
    pub future_vrf: Option<Hash<32>>,
}

/// A registered DRep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DijkstraDRep {
    pub deposit: Coin,
}

/// The hot credential state of a committee cold credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DijkstraCommitteeAuth {
    Hot(StakeCredential),
    Resigned,
}

/// The part of a governance action that later proposals and votes read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DijkstraProposalAction {
    ParameterChange { security_relevant: bool },
    HardForkInitiation { version: (u64, u64) },
    TreasuryWithdrawals,
    NoConfidence,
    UpdateCommittee { added: Vec<StakeCredential> },
    NewConstitution,
    Information,
}

/// A proposal in the governance state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DijkstraProposal {
    pub action: DijkstraProposalAction,
    pub expires_after: Epoch,
}

/// The last enacted action of each purpose whose proposals name a predecessor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DijkstraGovRoots {
    pub parameter_change: Option<GovActionId>,
    pub hard_fork: Option<GovActionId>,
    pub committee: Option<GovActionId>,
    pub constitution: Option<GovActionId>,
}

/// Read access to the ledger state the Dijkstra rules consult.
pub trait DijkstraLedgerState {
    fn epoch(&self) -> Epoch;
    fn treasury(&self) -> Result<Coin, ValidationError>;
    fn account(
        &self,
        credential: &StakeCredential,
    ) -> Result<Option<DijkstraAccount>, ValidationError>;
    fn pool(&self, operator: &Hash<28>) -> Result<Option<DijkstraPool>, ValidationError>;
    /// The number of registered pools whose active or pending parameters name the VRF key hash.
    fn vrf_count(&self, vrf: &Hash<32>) -> Result<u64, ValidationError>;
    fn drep(&self, credential: &StakeCredential) -> Result<Option<DijkstraDRep>, ValidationError>;
    /// The elected committee members and their expiry epochs, absent after a no confidence motion.
    fn committee(&self) -> Result<Option<BTreeMap<StakeCredential, Epoch>>, ValidationError>;
    fn committee_auths(
        &self,
    ) -> Result<BTreeMap<StakeCredential, DijkstraCommitteeAuth>, ValidationError>;
    fn proposals(&self) -> Result<Vec<(GovActionId, DijkstraProposal)>, ValidationError>;
    fn roots(&self) -> Result<DijkstraGovRoots, ValidationError>;
    fn guardrail_script(&self) -> Result<Option<Hash<28>>, ValidationError>;
}

/// The changes one or more transactions make to the ledger state.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DijkstraLedgerDelta {
    pub accounts: BTreeMap<StakeCredential, Option<DijkstraAccount>>,
    pub pools: BTreeMap<Hash<28>, DijkstraPool>,
    pub vrf_counts: BTreeMap<Hash<32>, i64>,
    pub dreps: BTreeMap<StakeCredential, Option<DijkstraDRep>>,
    pub committee_auths: BTreeMap<StakeCredential, DijkstraCommitteeAuth>,
    pub proposals: Vec<(GovActionId, DijkstraProposal)>,
}

impl DijkstraLedgerDelta {
    /// Adds the changes of a later transaction.
    pub fn extend(&mut self, later: DijkstraLedgerDelta) {
        self.accounts.extend(later.accounts);
        self.pools.extend(later.pools);
        for (vrf, change) in later.vrf_counts {
            *self.vrf_counts.entry(vrf).or_default() += change;
        }
        self.dreps.extend(later.dreps);
        self.committee_auths.extend(later.committee_auths);
        self.proposals.extend(later.proposals);
    }
}

/// A ledger state with changes laid over it.
#[derive(Debug, Clone)]
pub struct DijkstraLedgerOverlay<'a, S: ?Sized> {
    pub base: &'a S,
    pub delta: DijkstraLedgerDelta,
}

impl<'a, S: DijkstraLedgerState + ?Sized> DijkstraLedgerOverlay<'a, S> {
    pub fn new(base: &'a S) -> Self {
        DijkstraLedgerOverlay {
            base,
            delta: DijkstraLedgerDelta::default(),
        }
    }
}

impl<S: DijkstraLedgerState + ?Sized> DijkstraLedgerState for DijkstraLedgerOverlay<'_, S> {
    fn epoch(&self) -> Epoch {
        self.base.epoch()
    }
    fn treasury(&self) -> Result<Coin, ValidationError> {
        self.base.treasury()
    }
    fn account(
        &self,
        credential: &StakeCredential,
    ) -> Result<Option<DijkstraAccount>, ValidationError> {
        match self.delta.accounts.get(credential) {
            Some(account) => Ok(*account),
            None => self.base.account(credential),
        }
    }
    fn pool(&self, operator: &Hash<28>) -> Result<Option<DijkstraPool>, ValidationError> {
        match self.delta.pools.get(operator) {
            Some(pool) => Ok(Some(*pool)),
            None => self.base.pool(operator),
        }
    }
    fn vrf_count(&self, vrf: &Hash<32>) -> Result<u64, ValidationError> {
        let base = i64::try_from(self.base.vrf_count(vrf)?).unwrap_or(i64::MAX);
        let change = self.delta.vrf_counts.get(vrf).copied().unwrap_or(0);
        Ok(u64::try_from(base.saturating_add(change)).unwrap_or(0))
    }
    fn drep(&self, credential: &StakeCredential) -> Result<Option<DijkstraDRep>, ValidationError> {
        match self.delta.dreps.get(credential) {
            Some(drep) => Ok(*drep),
            None => self.base.drep(credential),
        }
    }
    fn committee(&self) -> Result<Option<BTreeMap<StakeCredential, Epoch>>, ValidationError> {
        self.base.committee()
    }
    fn committee_auths(
        &self,
    ) -> Result<BTreeMap<StakeCredential, DijkstraCommitteeAuth>, ValidationError> {
        let mut auths = self.base.committee_auths()?;
        auths.extend(self.delta.committee_auths.clone());
        Ok(auths)
    }
    fn proposals(&self) -> Result<Vec<(GovActionId, DijkstraProposal)>, ValidationError> {
        let mut proposals = self.base.proposals()?;
        proposals.extend(self.delta.proposals.iter().cloned());
        Ok(proposals)
    }
    fn roots(&self) -> Result<DijkstraGovRoots, ValidationError> {
        self.base.roots()
    }
    fn guardrail_script(&self) -> Result<Option<Hash<28>>, ValidationError> {
        self.base.guardrail_script()
    }
}

/// An owned ledger state in which an account absent from `accounts` is unknown.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DijkstraLedgerSnapshot {
    pub epoch: Epoch,
    pub treasury: Coin,
    pub accounts: HashMap<StakeCredential, Option<DijkstraAccount>>,
    pub pools: HashMap<Hash<28>, DijkstraPool>,
    pub vrf_counts: HashMap<Hash<32>, u64>,
    pub dreps: HashMap<StakeCredential, DijkstraDRep>,
    pub committee: Option<BTreeMap<StakeCredential, Epoch>>,
    pub committee_auths: BTreeMap<StakeCredential, DijkstraCommitteeAuth>,
    pub proposals: Vec<(GovActionId, DijkstraProposal)>,
    pub roots: DijkstraGovRoots,
    pub guardrail_script: Option<Hash<28>>,
}

impl DijkstraLedgerSnapshot {
    /// Writes the changes into the snapshot.
    pub fn apply(&mut self, delta: DijkstraLedgerDelta) {
        self.accounts.extend(delta.accounts);
        self.pools.extend(delta.pools);
        for (vrf, change) in delta.vrf_counts {
            let count = self.vrf_counts.entry(vrf).or_default();
            *count = u64::try_from(i64::try_from(*count).unwrap_or(i64::MAX) + change).unwrap_or(0);
        }
        self.vrf_counts.retain(|_, count| *count != 0);
        for (credential, drep) in delta.dreps {
            match drep {
                Some(drep) => self.dreps.insert(credential, drep),
                None => self.dreps.remove(&credential),
            };
        }
        self.committee_auths.extend(delta.committee_auths);
        self.proposals.extend(delta.proposals);
    }
}

impl DijkstraLedgerState for DijkstraLedgerSnapshot {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
    fn treasury(&self) -> Result<Coin, ValidationError> {
        Ok(self.treasury)
    }
    fn account(
        &self,
        credential: &StakeCredential,
    ) -> Result<Option<DijkstraAccount>, ValidationError> {
        self.accounts.get(credential).copied().ok_or_else(|| {
            ValidationError::DijkstraLedgerStateUnavailable(format!("{credential:?}"))
        })
    }
    fn pool(&self, operator: &Hash<28>) -> Result<Option<DijkstraPool>, ValidationError> {
        Ok(self.pools.get(operator).copied())
    }
    fn vrf_count(&self, vrf: &Hash<32>) -> Result<u64, ValidationError> {
        Ok(self.vrf_counts.get(vrf).copied().unwrap_or(0))
    }
    fn drep(&self, credential: &StakeCredential) -> Result<Option<DijkstraDRep>, ValidationError> {
        Ok(self.dreps.get(credential).copied())
    }
    fn committee(&self) -> Result<Option<BTreeMap<StakeCredential, Epoch>>, ValidationError> {
        Ok(self.committee.clone())
    }
    fn committee_auths(
        &self,
    ) -> Result<BTreeMap<StakeCredential, DijkstraCommitteeAuth>, ValidationError> {
        Ok(self.committee_auths.clone())
    }
    fn proposals(&self) -> Result<Vec<(GovActionId, DijkstraProposal)>, ValidationError> {
        Ok(self.proposals.clone())
    }
    fn roots(&self) -> Result<DijkstraGovRoots, ValidationError> {
        Ok(self.roots.clone())
    }
    fn guardrail_script(&self) -> Result<Option<Hash<28>>, ValidationError> {
        Ok(self.guardrail_script)
    }
}
