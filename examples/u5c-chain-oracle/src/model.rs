use std::collections::BTreeMap;

/// An output reference, the producing transaction id and the output index.
pub type TxIn = ([u8; 32], u32);

/// A stake credential, whether it is a script hash and its hash.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Credential {
    pub script: bool,
    pub hash: [u8; 28],
}

impl Credential {
    /// Reads the credential of a reward account, a header byte and a 28 byte hash.
    pub fn from_reward_account(bytes: &[u8]) -> Option<Self> {
        let hash = bytes.get(1..29)?.try_into().ok()?;
        Some(Self {
            script: bytes.first()? & 0x10 != 0,
            hash,
        })
    }

    /// Writes the credential as the ledger state names its account.
    pub fn node_key(&self) -> String {
        let kind = if self.script { "scriptHash" } else { "keyHash" };
        format!("{kind}-{}", hex::encode(self.hash))
    }
}

/// The reference script an output carries.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RefScript {
    Native,
    Plutus(u8, Vec<u8>),
}

/// The ledger content of an output that the node reports.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Output {
    pub address: Vec<u8>,
    pub coin: u64,
    pub assets: BTreeMap<(Vec<u8>, Vec<u8>), u64>,
    pub datum_hash: Option<[u8; 32]>,
    pub script: Option<RefScript>,
}

/// The transaction an effect came from, its block and its top level and sub transaction ids.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Origin {
    pub block: u64,
    pub top: [u8; 32],
    pub sub: Option<[u8; 32]>,
}

impl Origin {
    /// Names the applied transaction in hex.
    pub fn describe(&self) -> String {
        match self.sub {
            Some(sub) => format!(
                "sub {} of {} in block {}",
                hex::encode(sub),
                hex::encode(self.top),
                self.block
            ),
            None => format!("{} in block {}", hex::encode(self.top), self.block),
        }
    }
}

/// A change one applied transaction makes to the reward accounts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AccountOp {
    Register(Credential),
    Unregister(Credential),
    Delegate(Credential),
    Withdraw(Credential, u64),
    Deposit(Credential, u64),
    RewardTarget(Credential),
}

/// Everything one applied transaction does to the UTxO set and the reward accounts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Effects {
    pub origin: Origin,
    pub spent: Vec<TxIn>,
    pub produced: Vec<(TxIn, Output)>,
    pub accounts: Vec<AccountOp>,
}
