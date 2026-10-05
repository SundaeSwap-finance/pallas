//! Compares the values u5c holds for Dijkstra body fields with the source, body by body.

use std::ops::Deref;

use pallas_codec::utils::Nullable;
use pallas_primitives::dijkstra::{self, AccountBalanceInterval, NativeScript};
use pallas_primitives::{BigInt, PlutusData, StakeCredential};
use pallas_traverse::OriginalHash;
use pallas_utxorpc::v1beta::spec::cardano as u5c;

/// One guard credential, its script flag and its hash, or None for a u5c credential with neither.
pub type Guard = Option<(bool, Vec<u8>)>;

/// One node of a Plutus datum in preorder, with the number of children it has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    Constr {
        tag: u64,
        any_constructor: u64,
        fields: usize,
    },
    Map(usize),
    Array(usize),
    /// The integer n when not negative, and minus one minus n when negative, n big endian with no leading zero byte.
    Integer {
        negative: bool,
        n: Vec<u8>,
    },
    Bytes(Vec<u8>),
    Absent,
}

/// One reward account and its interval, None for a u5c interval the source type has no form for.
pub type Interval = (Vec<u8>, Option<AccountBalanceInterval>);

/// The index and payload tokens of one guarding redeemer.
pub type Redeemer = (u32, Vec<Token>);

/// One credential required of the top level transaction and its datum tokens, None for a nil datum.
pub type TopLevelGuard = (Guard, Option<Vec<Token>>);

/// The credential of a source guard.
pub fn credential(c: &StakeCredential) -> Guard {
    match c {
        StakeCredential::AddrKeyhash(h) => Some((false, h.to_vec())),
        StakeCredential::ScriptHash(h) => Some((true, h.to_vec())),
    }
}

/// The credential of a u5c guard.
pub fn u5c_credential(c: Option<&u5c::StakeCredential>) -> Guard {
    use u5c::stake_credential::StakeCredential as C;
    match c?.stake_credential.as_ref()? {
        C::AddrKeyHash(h) => Some((false, h.to_vec())),
        C::ScriptHash(h) => Some((true, h.to_vec())),
    }
}

fn integer(negative: bool, n: &[u8]) -> Token {
    let start = n.iter().position(|b| *b != 0).unwrap_or(n.len());
    Token::Integer {
        negative,
        n: n[start..].to_vec(),
    }
}

fn small(v: i128) -> Token {
    if v < 0 {
        integer(true, &(-1 - v).to_be_bytes())
    } else {
        integer(false, &v.to_be_bytes())
    }
}

/// The preorder tokens of a source datum.
pub fn source_datum(x: &PlutusData) -> Vec<Token> {
    let mut out = Vec::new();
    let mut stack = vec![x];
    while let Some(x) = stack.pop() {
        match x {
            PlutusData::Constr(c) => {
                out.push(Token::Constr {
                    tag: c.tag,
                    any_constructor: c.any_constructor.unwrap_or(0),
                    fields: c.fields.len(),
                });
                stack.extend(c.fields.iter().rev());
            }
            PlutusData::Map(m) => {
                out.push(Token::Map(m.len()));
                for (k, v) in m.iter().rev() {
                    stack.push(v);
                    stack.push(k);
                }
            }
            PlutusData::Array(a) => {
                out.push(Token::Array(a.len()));
                stack.extend(a.iter().rev());
            }
            PlutusData::BigInt(BigInt::Int(i)) => out.push(small(i128::from(i.0))),
            PlutusData::BigInt(BigInt::BigUInt(n)) => out.push(integer(false, n)),
            PlutusData::BigInt(BigInt::BigNInt(n)) => out.push(integer(true, n)),
            PlutusData::BoundedBytes(b) => out.push(Token::Bytes(b.to_vec())),
        }
    }
    out
}

/// The preorder tokens of a u5c datum.
pub fn u5c_datum(x: &u5c::PlutusData) -> Vec<Token> {
    use u5c::big_int::BigInt as B;
    use u5c::plutus_data::PlutusData as P;
    let mut out = Vec::new();
    let mut stack = vec![Some(x)];
    while let Some(x) = stack.pop() {
        let Some(x) = x.and_then(|x| x.plutus_data.as_ref()) else {
            out.push(Token::Absent);
            continue;
        };
        match x {
            P::Constr(c) => {
                out.push(Token::Constr {
                    tag: c.tag.into(),
                    any_constructor: c.any_constructor,
                    fields: c.fields.len(),
                });
                stack.extend(c.fields.iter().rev().map(Some));
            }
            P::Map(m) => {
                out.push(Token::Map(m.pairs.len()));
                for p in m.pairs.iter().rev() {
                    stack.push(p.value.as_ref());
                    stack.push(p.key.as_ref());
                }
            }
            P::Array(a) => {
                out.push(Token::Array(a.items.len()));
                stack.extend(a.items.iter().rev().map(Some));
            }
            P::BigInt(b) => out.push(match b.big_int.as_ref() {
                Some(B::Int(i)) => small((*i).into()),
                Some(B::BigUInt(n)) => integer(false, n),
                Some(B::BigNInt(n)) => integer(true, n),
                None => Token::Absent,
            }),
            P::BoundedBytes(b) => out.push(Token::Bytes(b.to_vec())),
        }
    }
    out
}

/// The coin a u5c integer holds, or None for one that is negative, absent or above u64.
fn coin(x: &u5c::BigInt) -> Option<u64> {
    use u5c::big_int::BigInt as B;
    match x.big_int.as_ref()? {
        B::Int(i) => u64::try_from(*i).ok(),
        B::BigUInt(n) => {
            let start = n.iter().position(|b| *b != 0).unwrap_or(n.len());
            let n = &n[start..];
            (n.len() <= 8).then(|| n.iter().fold(0, |a, b| (a << 8) | u64::from(*b)))
        }
        B::BigNInt(_) => None,
    }
}

fn source_guards(x: Option<&dijkstra::Guards>) -> Vec<Guard> {
    match x {
        None => vec![],
        Some(dijkstra::Guards::AddrKeyhashes(x)) => {
            x.iter().map(|h| Some((false, h.to_vec()))).collect()
        }
        Some(dijkstra::Guards::Credentials(x)) => x.iter().map(credential).collect(),
    }
}

fn source_intervals(x: Option<&dijkstra::AccountBalanceIntervals>) -> Vec<Interval> {
    x.into_iter()
        .flatten()
        .map(|(a, i)| (a.to_vec(), Some(i.clone())))
        .collect()
}

fn u5c_intervals(x: &[u5c::AccountBalanceInterval]) -> Vec<Interval> {
    use AccountBalanceInterval as A;
    use u5c::account_balance_interval::Interval as I;
    let interval = |x: &u5c::AccountBalanceInterval| match x.interval.as_ref()? {
        I::Exact(c) => coin(c).map(A::Exact),
        I::Range(r) => {
            let lower = r.inclusive_lower_bound.as_ref().map(coin);
            let upper = r.exclusive_upper_bound.as_ref().map(coin);
            match (lower, upper) {
                (Some(Some(l)), None) => Some(A::LowerBound(l)),
                (Some(Some(l)), Some(Some(u))) => Some(A::Bounded(l, u)),
                (None, Some(Some(u))) => Some(A::UpperBound(u)),
                _ => None,
            }
        }
    };
    x.iter()
        .map(|x| (x.reward_account.to_vec(), interval(x)))
        .collect()
}

fn source_clauses(w: &dijkstra::WitnessSet) -> Vec<Guard> {
    let mut out = Vec::new();
    let mut stack: Vec<&NativeScript> = w
        .native_script
        .iter()
        .flat_map(|s| s.iter())
        .map(|s| s.deref())
        .rev()
        .collect();
    while let Some(s) = stack.pop() {
        match s {
            NativeScript::ScriptAll(x)
            | NativeScript::ScriptAny(x)
            | NativeScript::ScriptNOfK(_, x) => stack.extend(x.iter().rev()),
            NativeScript::ScriptRequireGuard(c) => out.push(credential(c)),
            NativeScript::ScriptPubkey(_)
            | NativeScript::InvalidBefore(_)
            | NativeScript::InvalidHereafter(_) => {}
        }
    }
    out
}

fn u5c_clauses(tx: &u5c::Tx) -> Vec<Guard> {
    use u5c::native_script::NativeScript as N;
    use u5c::script::Script as S;
    let mut out = Vec::new();
    let mut stack: Vec<&u5c::NativeScript> = tx
        .witnesses
        .iter()
        .flat_map(|w| &w.script)
        .filter_map(|s| match s.script.as_ref() {
            Some(S::Native(n)) => Some(n),
            _ => None,
        })
        .rev()
        .collect();
    while let Some(s) = stack.pop() {
        match s.native_script.as_ref() {
            Some(N::ScriptAll(l) | N::ScriptAny(l)) => stack.extend(l.items.iter().rev()),
            Some(N::ScriptNOfK(k)) => stack.extend(k.scripts.iter().rev()),
            Some(N::ScriptRequireGuard(c)) => out.push(u5c_credential(Some(c))),
            _ => {}
        }
    }
    out
}

fn source_redeemers(w: &dijkstra::WitnessSet) -> Vec<Redeemer> {
    w.redeemer
        .iter()
        .flat_map(|r| r.iter())
        .filter(|(k, _)| k.tag == dijkstra::RedeemerTag::Guarding)
        .map(|(k, v)| (k.index, source_datum(&v.data)))
        .collect()
}

fn u5c_redeemers(tx: &u5c::Tx) -> Vec<Redeemer> {
    tx.witnesses
        .iter()
        .flat_map(|w| &w.redeemers)
        .filter(|r| r.purpose == u5c::RedeemerPurpose::Guarding as i32)
        .map(|r| {
            let payload = r.payload.as_ref().map_or(vec![Token::Absent], u5c_datum);
            (r.index, payload)
        })
        .collect()
}

fn source_top_level(x: Option<&dijkstra::RequiredTopLevelGuards>) -> Vec<TopLevelGuard> {
    x.into_iter()
        .flatten()
        .map(|(c, d)| {
            let datum = match d {
                Nullable::Some(d) => Some(source_datum(d)),
                Nullable::Null | Nullable::Undefined => None,
            };
            (credential(c), datum)
        })
        .collect()
}

fn u5c_top_level(tx: &u5c::Tx) -> Vec<TopLevelGuard> {
    tx.required_top_level_guards
        .iter()
        .map(|g| {
            let datum = g.datum.as_ref().map(u5c_datum);
            (u5c_credential(g.credential.as_ref()), datum)
        })
        .collect()
}

/// The fields of one source body that check 2 compares by value.
struct Body<'a> {
    guards: Option<&'a dijkstra::Guards>,
    intervals: Option<&'a dijkstra::AccountBalanceIntervals>,
    starting: Option<&'a dijkstra::StartingAccountBalanceIntervals>,
    top_level: Option<&'a dijkstra::RequiredTopLevelGuards>,
}

/// The guard credentials of one u5c transaction, in field order.
pub fn u5c_guards(tx: Option<&u5c::Tx>) -> Vec<Guard> {
    tx.into_iter()
        .flat_map(|t| &t.guards)
        .map(|c| u5c_credential(Some(c)))
        .collect()
}

/// How one body field's values compare with u5c over every body added.
#[derive(Clone, Debug, Default)]
pub struct ValueReport {
    pub bodies: usize,
    pub holding: usize,
    pub values: usize,
    pub differences: Vec<(u64, [u8; 32])>,
}

impl ValueReport {
    /// Tells whether a body held a value and u5c holds the values of every body, none where the source has none.
    pub fn agrees(&self) -> bool {
        self.values > 0 && self.differences.is_empty()
    }

    /// Counts one body's values and notes the body when u5c holds other values than the source.
    pub fn compare<T: PartialEq>(&mut self, at: (u64, [u8; 32]), source: Vec<T>, mapped: Vec<T>) {
        self.bodies += 1;
        if !source.is_empty() {
            self.holding += 1;
        }
        self.values += source.len();
        if source != mapped {
            self.differences.push(at);
        }
    }
}

/// The value reports of the body fields check 2 compares.
#[derive(Clone, Debug, Default)]
pub struct Values {
    pub guards: ValueReport,
    pub intervals: ValueReport,
    pub starting: ValueReport,
    pub guard_clauses: ValueReport,
    pub guarding_redeemers: ValueReport,
    pub top_level_guards: ValueReport,
}

impl Values {
    /// Each report beside the name check 2 prints it under.
    pub fn reports(&self) -> [(&'static str, &ValueReport); 6] {
        [
            ("key 14 guards", &self.guards),
            ("key 26 intervals", &self.intervals),
            ("key 27 starting intervals", &self.starting),
            ("guard native clauses", &self.guard_clauses),
            ("guarding redeemers", &self.guarding_redeemers),
            ("key 24 top level guards", &self.top_level_guards),
        ]
    }

    /// Tells whether every report agrees.
    pub fn agrees(&self) -> bool {
        self.reports().iter().all(|(_, r)| r.agrees())
    }

    /// Compares each body of a Dijkstra block, top level and sub transactions, with the u5c transaction at the same place.
    pub fn add(&mut self, block: &dijkstra::Block, number: u64, mapped: &u5c::Block) {
        let txs = mapped.body.as_ref().map(|b| b.tx.as_slice()).unwrap_or(&[]);
        for (i, tx) in block.block_body.transactions.iter().enumerate() {
            let body = &tx.transaction_body;
            let u5c_tx = txs.get(i);
            let fields = Body {
                guards: body.guards.as_ref(),
                intervals: body.account_balance_intervals.as_ref(),
                starting: body.starting_account_balance_intervals.as_ref(),
                top_level: body.required_top_level_guards.as_ref(),
            };
            let at = (number, *body.original_hash());
            self.body(at, fields, &tx.transaction_witness_set, u5c_tx);
            for (j, sub) in body
                .sub_transactions
                .iter()
                .flat_map(|s| s.iter())
                .enumerate()
            {
                let sub_body = &sub.sub_transaction_body;
                let fields = Body {
                    guards: sub_body.guards.as_ref(),
                    intervals: sub_body.account_balance_intervals.as_ref(),
                    starting: None,
                    top_level: sub_body.required_top_level_guards.as_ref(),
                };
                let at = (number, *sub_body.original_hash());
                let u5c_sub = u5c_tx.and_then(|t| t.sub_transactions.get(j));
                self.body(at, fields, &sub.transaction_witness_set, u5c_sub);
            }
        }
    }

    fn body(
        &mut self,
        at: (u64, [u8; 32]),
        body: Body,
        wits: &dijkstra::WitnessSet,
        tx: Option<&u5c::Tx>,
    ) {
        self.guards
            .compare(at, source_guards(body.guards), u5c_guards(tx));
        self.intervals.compare(
            at,
            source_intervals(body.intervals),
            tx.map(|t| u5c_intervals(&t.account_balance_intervals))
                .unwrap_or_default(),
        );
        self.starting.compare(
            at,
            source_intervals(body.starting),
            tx.map(|t| u5c_intervals(&t.starting_account_balance_intervals))
                .unwrap_or_default(),
        );
        self.guard_clauses.compare(
            at,
            source_clauses(wits),
            tx.map(u5c_clauses).unwrap_or_default(),
        );
        self.guarding_redeemers.compare(
            at,
            source_redeemers(wits),
            tx.map(u5c_redeemers).unwrap_or_default(),
        );
        self.top_level_guards.compare(
            at,
            source_top_level(body.top_level),
            tx.map(u5c_top_level).unwrap_or_default(),
        );
    }
}
