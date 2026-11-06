use std::cmp::Ordering;

use pallas_primitives::alonzo;

use crate::MultiEraWithdrawals;

/// The ledger's order of two raw reward accounts: network, then script credentials before key credentials, then hash.
pub fn cmp_reward_accounts(a: &[u8], b: &[u8]) -> Ordering {
    fn key(raw: &[u8]) -> (Option<u8>, Option<u8>, Option<&[u8]>) {
        (
            raw.first().map(|x| x & 15),
            raw.first().map(|x| 15 - (x >> 4)),
            raw.get(1..),
        )
    }

    key(a).cmp(&key(b))
}

impl MultiEraWithdrawals<'_> {
    pub fn as_alonzo(&self) -> Option<&alonzo::Withdrawals> {
        match self {
            Self::AlonzoCompatible(x) => Some(x),
            _ => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            MultiEraWithdrawals::AlonzoCompatible(x) => x.is_empty(),
            _ => true,
        }
    }

    pub fn collect<'a, T>(&'a self) -> T
    where
        T: FromIterator<(&'a [u8], u64)>,
    {
        match self {
            MultiEraWithdrawals::NotApplicable => std::iter::empty().collect(),
            MultiEraWithdrawals::Empty => std::iter::empty().collect(),
            MultiEraWithdrawals::AlonzoCompatible(x) => {
                x.iter().map(|(k, v)| (k.as_slice(), *v)).collect()
            }
            MultiEraWithdrawals::Conway(x) => x.iter().map(|(k, v)| (k.as_slice(), *v)).collect(),
        }
    }
}
