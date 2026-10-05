use std::collections::BTreeMap;

use pallas_codec::minicbor::Decoder;
use pallas_codec::minicbor::data::Type;
use pallas_utxorpc::v1beta::spec::cardano as u5c;

use crate::effects::natural;

/// A map key or array position of a Dijkstra block that the source can hold.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Location {
    HeaderBody(u64),
    BlockBody(u64),
    TxPart(u64),
    Body(u64),
    Wits(u64),
    RedeemerTag(u64),
    NativeClause(u64),
    CertTag(u64),
    PoolBls,
    ParamUpdate(u64),
}

/// What the source holds at one occurrence of a location.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Held {
    Count(u64),
    Uint(u64),
    Bool(bool),
    Other,
}

/// The locations the scope leaves out of u5c, each with its reason.
pub const EXCLUDED: [(Location, &str); 18] = [
    (
        Location::HeaderBody(2),
        "header prev_hash, u5c BlockHeader holds slot, hash and height only",
    ),
    (
        Location::HeaderBody(3),
        "header issuer_vkey, u5c BlockHeader holds slot, hash and height only",
    ),
    (
        Location::HeaderBody(4),
        "header vrf_vkey, u5c BlockHeader holds slot, hash and height only",
    ),
    (
        Location::HeaderBody(5),
        "header vrf_result, u5c BlockHeader holds slot, hash and height only",
    ),
    (
        Location::HeaderBody(6),
        "header block_body_size, u5c BlockHeader holds slot, hash and height only",
    ),
    (
        Location::HeaderBody(7),
        "header block_body_hash, u5c BlockHeader holds slot, hash and height only",
    ),
    (
        Location::HeaderBody(8),
        "header operational_cert, u5c BlockHeader holds slot, hash and height only",
    ),
    (
        Location::HeaderBody(9),
        "header protocol_version, u5c BlockHeader holds slot, hash and height only",
    ),
    (
        Location::HeaderBody(10),
        "header block_body_contains_leios_cert, u5c BlockHeader holds slot, hash and height only",
    ),
    (
        Location::HeaderBody(11),
        "header eb_announcement, u5c BlockHeader names no endorser block",
    ),
    (
        Location::BlockBody(1),
        "block_body leios_certificate, u5c BlockBody holds transactions only",
    ),
    (
        Location::BlockBody(2),
        "block_body peras_certificate, u5c BlockBody holds transactions only",
    ),
    (
        Location::Body(7),
        "body key 7 auxiliary_data_hash, u5c Tx holds the decoded auxiliary data and no hash of it",
    ),
    (
        Location::Body(11),
        "body key 11 script_data_hash, u5c Tx holds no script integrity hash",
    ),
    (
        Location::Body(15),
        "body key 15 network_id, u5c Tx holds no network id",
    ),
    (
        Location::Body(21),
        "body key 21 current treasury value, u5c Tx holds no treasury value",
    ),
    (
        Location::Body(22),
        "body key 22 donation, u5c Tx holds no donation",
    ),
    (
        Location::Body(24),
        "body key 24 required_top_level_guards, u5c Tx holds no guard data",
    ),
];

/// The scope rows u5c is to hold, each with the location the source shows it at.
pub fn in_items() -> Vec<(String, Location)> {
    let mut items = vec![
        ("11 body key 14 guards".to_owned(), Location::Body(14)),
        (
            "12 body key 23 sub_transactions".to_owned(),
            Location::Body(23),
        ),
        (
            "14 body key 25 direct_deposits".to_owned(),
            Location::Body(25),
        ),
        (
            "15 body key 26 account_balance_intervals".to_owned(),
            Location::Body(26),
        ),
        (
            "16 body key 27 starting_account_balance_intervals".to_owned(),
            Location::Body(27),
        ),
        (
            "21 redeemer tag 6 guarding".to_owned(),
            Location::RedeemerTag(6),
        ),
        (
            "27 native clause 6 script_require_guard".to_owned(),
            Location::NativeClause(6),
        ),
        ("30 pool registration bls_key".to_owned(), Location::PoolBls),
    ];
    for k in 34..=48 {
        items.push((
            format!("{k} protocol_param_update key {k}"),
            Location::ParamUpdate(k),
        ));
    }
    items
}

fn excluded(location: &Location) -> bool {
    EXCLUDED.iter().any(|(l, _)| l == location)
}

fn skip_tags(d: &mut Decoder) {
    while d.datatype().expect("a CBOR item") == Type::Tag {
        d.tag().expect("a tag");
    }
}

fn end_indefinite(d: &mut Decoder) -> bool {
    if d.datatype().expect("a CBOR item") == Type::Break {
        d.set_position(d.position() + 1);
        true
    } else {
        false
    }
}

/// Calls `item` on each element of the array at the decoder.
fn each_item<'b>(d: &mut Decoder<'b>, mut item: impl FnMut(&mut Decoder<'b>, u64)) {
    skip_tags(d);
    match d.array().expect("an array") {
        Some(n) => (0..n).for_each(|i| item(d, i)),
        None => {
            let mut i = 0;
            while !end_indefinite(d) {
                item(d, i);
                i += 1;
            }
        }
    }
}

/// Calls `entry` on each key of the map at the decoder, with the decoder at the value.
fn each_entry<'b>(d: &mut Decoder<'b>, mut entry: impl FnMut(&mut Decoder<'b>, Option<u64>)) {
    skip_tags(d);
    let mut one = |d: &mut Decoder<'b>| {
        let key = match d.datatype().expect("a key") {
            Type::U8 | Type::U16 | Type::U32 | Type::U64 => Some(d.u64().expect("a uint key")),
            _ => {
                d.skip().expect("a key");
                None
            }
        };
        entry(d, key);
    };
    match d.map().expect("a map") {
        Some(n) => (0..n).for_each(|_| one(d)),
        None => {
            while !end_indefinite(d) {
                one(d);
            }
        }
    }
}

/// Reads the shape of the item at the decoder and moves past it.
fn held(d: &mut Decoder) -> Held {
    skip_tags(d);
    let start = d.position();
    let out = match d.datatype().expect("a CBOR item") {
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => Held::Uint(d.u64().expect("a uint")),
        Type::Bool => Held::Bool(d.bool().expect("a bool")),
        Type::Array | Type::ArrayIndef => {
            let mut n = 0;
            each_item(d, |d, _| {
                d.skip().expect("an element");
                n += 1;
            });
            Held::Count(n)
        }
        Type::Map | Type::MapIndef => {
            let mut n = 0;
            each_entry(d, |d, _| {
                d.skip().expect("a value");
                n += 1;
            });
            Held::Count(n)
        }
        _ => {
            d.skip().expect("an item");
            Held::Other
        }
    };
    debug_assert!(d.position() > start);
    out
}

fn is_null(d: &Decoder) -> bool {
    d.datatype().expect("a CBOR item") == Type::Null
}

/// What one transaction of a block holds at each location, and what each of its sub transactions holds.
#[derive(Default, Debug)]
pub struct TxScan {
    pub held: Vec<(Location, Held)>,
    pub subs: Vec<TxScan>,
}

impl TxScan {
    fn bump(counts: &mut BTreeMap<Location, u64>, location: Location) {
        *counts.entry(location).or_insert(0) += 1;
    }
}

fn native_clauses(d: &mut Decoder, counts: &mut BTreeMap<Location, u64>) {
    let mut first = true;
    let mut clause = None;
    each_item(d, |d, i| {
        if first {
            first = false;
            let c = d.u64().expect("a native script clause");
            TxScan::bump(counts, Location::NativeClause(c));
            clause = Some(c);
            return;
        }
        match (clause, i) {
            (Some(1) | Some(2), 1) | (Some(3), 2) => {
                each_item(d, |d, _| native_clauses(d, counts));
            }
            _ => d.skip().expect("a clause argument"),
        }
    });
}

fn certificates(d: &mut Decoder, counts: &mut BTreeMap<Location, u64>) {
    each_item(d, |d, _| {
        let mut tag = None;
        each_item(d, |d, i| {
            if i == 0 {
                let t = d.u64().expect("a certificate tag");
                TxScan::bump(counts, Location::CertTag(t));
                tag = Some(t);
                return;
            }
            if tag == Some(3)
                && i == 3
                && matches!(
                    d.datatype().expect("an item"),
                    Type::Array | Type::ArrayIndef
                )
            {
                TxScan::bump(counts, Location::PoolBls);
            }
            d.skip().expect("a certificate field");
        });
    });
}

fn redeemer_tags(d: &mut Decoder, counts: &mut BTreeMap<Location, u64>) {
    skip_tags(d);
    match d.datatype().expect("redeemers") {
        Type::Map | Type::MapIndef => {
            skip_tags(d);
            let mut key = |d: &mut Decoder| {
                each_item(d, |d, i| {
                    if i == 0 {
                        TxScan::bump(counts, Location::RedeemerTag(d.u64().expect("a tag")));
                    } else {
                        d.skip().expect("a redeemer index");
                    }
                });
                d.skip().expect("a redeemer value");
            };
            match d.map().expect("a redeemer map") {
                Some(n) => (0..n).for_each(|_| key(d)),
                None => {
                    while !end_indefinite(d) {
                        key(d);
                    }
                }
            }
        }
        _ => each_item(d, |d, _| {
            each_item(d, |d, i| {
                if i == 0 {
                    TxScan::bump(counts, Location::RedeemerTag(d.u64().expect("a tag")));
                } else {
                    d.skip().expect("a redeemer field");
                }
            })
        }),
    }
}

fn proposals(d: &mut Decoder, counts: &mut BTreeMap<Location, u64>) {
    each_item(d, |d, _| {
        each_item(d, |d, field| {
            if field != 2 {
                d.skip().expect("a proposal field");
                return;
            }
            let mut kind = None;
            each_item(d, |d, j| match (kind, j) {
                (_, 0) => kind = Some(d.u64().expect("a governance action tag")),
                (Some(0), 2) => each_entry(d, |d, key| {
                    if let Some(k) = key {
                        TxScan::bump(counts, Location::ParamUpdate(k));
                    }
                    d.skip().expect("a parameter value");
                }),
                _ => d.skip().expect("a governance action field"),
            });
        });
    });
}

fn scan_tx(d: &mut Decoder) -> TxScan {
    let mut scan = TxScan::default();
    let mut counts = BTreeMap::new();
    each_item(d, |d, part| match part {
        0 => each_entry(d, |d, key| match key {
            Some(k) => {
                let start = d.position();
                let h = held(d);
                scan.held.push((Location::Body(k), h));
                let end = d.position();
                if k == 4 || k == 20 || k == 23 {
                    d.set_position(start);
                    match k {
                        4 => certificates(d, &mut counts),
                        20 => proposals(d, &mut counts),
                        _ => each_item(d, |d, _| scan.subs.push(scan_tx(d))),
                    }
                    assert_eq!(d.position(), end, "a rescan ends where the first did");
                }
            }
            None => d.skip().expect("a value"),
        }),
        1 => each_entry(d, |d, key| match key {
            Some(k) => {
                let start = d.position();
                let h = held(d);
                scan.held.push((Location::Wits(k), h));
                let end = d.position();
                if k == 1 || k == 5 {
                    d.set_position(start);
                    if k == 1 {
                        each_item(d, |d, _| native_clauses(d, &mut counts));
                    } else {
                        redeemer_tags(d, &mut counts);
                    }
                    assert_eq!(d.position(), end, "a rescan ends where the first did");
                }
            }
            None => d.skip().expect("a value"),
        }),
        2 => {
            if is_null(d) {
                d.skip().expect("null");
            } else {
                d.skip().expect("auxiliary data");
                scan.held.push((Location::TxPart(2), Held::Other));
            }
        }
        p => {
            let h = held(d);
            scan.held.push((Location::TxPart(p), h));
        }
    });
    scan.held
        .extend(counts.into_iter().map(|(l, n)| (l, Held::Count(n))));
    scan
}

/// What one Dijkstra block holds at each location, in the block's own and its transactions' terms.
#[derive(Default, Debug)]
pub struct BlockScan {
    pub held: Vec<(Location, Held)>,
    pub txs: Vec<TxScan>,
}

/// Walks the CBOR of a Dijkstra block, the array of header and body, and records every location it holds.
pub fn scan(block: &[u8]) -> BlockScan {
    let mut out = BlockScan::default();
    let d = &mut Decoder::new(block);
    each_item(d, |d, part| match part {
        0 => each_item(d, |d, h| {
            if h == 0 {
                each_item(d, |d, pos| {
                    let held = held(d);
                    out.held.push((Location::HeaderBody(pos), held));
                });
            } else {
                d.skip().expect("a header signature");
            }
        }),
        1 => each_item(d, |d, pos| {
            if pos == 0 {
                let mut n = 0;
                each_item(d, |d, _| {
                    out.txs.push(scan_tx(d));
                    n += 1;
                });
                out.held.push((Location::BlockBody(0), Held::Count(n)));
            } else if is_null(d) {
                d.skip().expect("null");
            } else {
                d.skip().expect("a certificate");
                out.held.push((Location::BlockBody(pos), Held::Other));
            }
        }),
        _ => d.skip().expect("a block part"),
    });
    out
}

fn cert_tag(c: &u5c::certificate::Certificate) -> u64 {
    use u5c::certificate::Certificate as C;
    match c {
        C::StakeRegistration(_) => 0,
        C::StakeDeregistration(_) => 1,
        C::StakeDelegation(_) => 2,
        C::PoolRegistration(_) => 3,
        C::PoolRetirement(_) => 4,
        C::GenesisKeyDelegation(_) => 5,
        C::MirCert(_) => 6,
        C::RegCert(_) => 7,
        C::UnregCert(_) => 8,
        C::VoteDelegCert(_) => 9,
        C::StakeVoteDelegCert(_) => 10,
        C::StakeRegDelegCert(_) => 11,
        C::VoteRegDelegCert(_) => 12,
        C::StakeVoteRegDelegCert(_) => 13,
        C::AuthCommitteeHotCert(_) => 14,
        C::ResignCommitteeColdCert(_) => 15,
        C::RegDrepCert(_) => 16,
        C::UnregDrepCert(_) => 17,
        C::UpdateDrepCert(_) => 18,
    }
}

fn native_counts(x: &u5c::NativeScript, counts: &mut BTreeMap<u64, u64>) {
    use u5c::native_script::NativeScript as N;
    let (clause, children): (u64, &[u5c::NativeScript]) = match x.native_script.as_ref() {
        Some(N::ScriptPubkeyHash(_)) => (0, &[]),
        Some(N::ScriptAll(l)) => (1, &l.items),
        Some(N::ScriptAny(l)) => (2, &l.items),
        Some(N::ScriptNOfK(k)) => (3, &k.scripts),
        Some(N::InvalidBefore(_)) => (4, &[]),
        Some(N::InvalidHereafter(_)) => (5, &[]),
        Some(N::ScriptRequireGuard(_)) => (6, &[]),
        None => return,
    };
    *counts.entry(clause).or_insert(0) += 1;
    children.iter().for_each(|c| native_counts(c, counts));
}

fn scripts_of(tx: &u5c::Tx, pick: &dyn Fn(&u5c::script::Script) -> bool) -> u64 {
    tx.witnesses
        .iter()
        .flat_map(|w| &w.script)
        .filter(|s| s.script.as_ref().is_some_and(pick))
        .count() as u64
}

/// Tells whether a parameter update holds the Conway key, or None for a key u5c has no field for.
pub fn param_set(p: &u5c::PParams, key: u64) -> Option<bool> {
    Some(match key {
        0 => p.min_fee_coefficient.is_some(),
        1 => p.min_fee_constant.is_some(),
        2 => p.max_block_body_size != 0,
        3 => p.max_tx_size != 0,
        4 => p.max_block_header_size != 0,
        5 => p.stake_key_deposit.is_some(),
        6 => p.pool_deposit.is_some(),
        7 => p.pool_retirement_epoch_bound != 0,
        8 => p.desired_number_of_pools != 0,
        9 => p.pool_influence.is_some(),
        10 => p.monetary_expansion.is_some(),
        11 => p.treasury_expansion.is_some(),
        16 => p.min_pool_cost.is_some(),
        17 => p.coins_per_utxo_byte.is_some(),
        18 => p.cost_models.is_some(),
        19 => p.prices.is_some(),
        20 => p.max_execution_units_per_transaction.is_some(),
        21 => p.max_execution_units_per_block.is_some(),
        22 => p.max_value_size != 0,
        23 => p.collateral_percentage != 0,
        24 => p.max_collateral_inputs != 0,
        25 => p.pool_voting_thresholds.is_some(),
        26 => p.drep_voting_thresholds.is_some(),
        27 => p.min_committee_size != 0,
        28 => p.committee_term_limit != 0,
        29 => p.governance_action_validity_period != 0,
        30 => p.governance_action_deposit.is_some(),
        31 => p.drep_deposit.is_some(),
        32 => p.drep_inactivity_period != 0,
        33 => p.min_fee_script_ref_cost_per_byte.is_some(),
        34 => p.max_ref_script_size_per_block != 0,
        35 => p.max_ref_script_size_per_tx != 0,
        36 => p.ref_script_cost_stride != 0,
        37 => p.ref_script_cost_multiplier.is_some(),
        38 => p.max_pledge_leverage.is_some(),
        39 => p.min_pool_margin.is_some(),
        40 => p.leios_announcement_period_length != 0,
        41 => p.leios_vote_period_length != 0,
        42 => p.leios_diffusion_period_length != 0,
        43 => p.leios_committee_size != 0,
        44 => p.leios_quorum_stake_threshold.is_some(),
        45 => p.max_endorser_block_references_size != 0,
        46 => p.max_endorser_block_txs_size != 0,
        47 => p.max_endorser_block_execution_units.is_some(),
        48 => p.max_ref_script_size_per_endorser_block != 0,
        _ => return None,
    })
}

fn count_eq(held: Held, n: usize) -> bool {
    held == Held::Count(n as u64)
}

/// Tells whether u5c holds what the source holds at one occurrence, or None when u5c has no counterpart.
pub fn agrees(
    location: Location,
    held: Held,
    block: &u5c::Block,
    tx: Option<&u5c::Tx>,
) -> Option<bool> {
    let header = block.header.clone().unwrap_or_default();
    let n_txs = block.body.as_ref().map_or(0, |b| b.tx.len());
    match location {
        Location::HeaderBody(0) => Some(held == Held::Uint(header.height)),
        Location::HeaderBody(1) => Some(held == Held::Uint(header.slot)),
        Location::BlockBody(0) => Some(count_eq(held, n_txs)),
        Location::HeaderBody(_) | Location::BlockBody(_) => None,
        _ => match tx {
            Some(tx) => tx_agrees(location, held, tx),
            None => Some(false),
        },
    }
}

fn tx_agrees(location: Location, held: Held, tx: &u5c::Tx) -> Option<bool> {
    use u5c::script::Script as S;
    let scripts = |pick: &dyn Fn(&S) -> bool| scripts_of(tx, pick);
    let wits = tx.witnesses.clone().unwrap_or_default();
    let validity = tx.validity.clone().unwrap_or_default();
    let collateral = tx.collateral.clone().unwrap_or_default();
    let count = |n: u64| Some(held == Held::Count(n));
    let uint = |v: u64| Some(held == Held::Uint(v));
    match location {
        Location::TxPart(0) | Location::TxPart(1) => Some(true),
        Location::TxPart(2) => Some(
            tx.auxiliary
                .as_ref()
                .is_some_and(|a| !a.metadata.is_empty() || !a.scripts.is_empty()),
        ),
        Location::TxPart(3) => Some(held == Held::Bool(tx.successful)),
        Location::Body(0) => count(tx.inputs.len() as u64),
        Location::Body(1) => count(tx.outputs.len() as u64),
        Location::Body(2) => uint(natural(tx.fee.as_ref())),
        Location::Body(3) => uint(validity.ttl),
        Location::Body(4) => count(tx.certificates.len() as u64),
        Location::Body(5) => count(tx.withdrawals.len() as u64),
        Location::Body(8) => uint(validity.start),
        Location::Body(9) => count(tx.mint.len() as u64),
        Location::Body(13) => count(collateral.collateral.len() as u64),
        Location::Body(14) => count(tx.guards.len() as u64),
        Location::Body(16) => Some(collateral.collateral_return.is_some()),
        Location::Body(17) => uint(natural(collateral.total_collateral.as_ref())),
        Location::Body(18) => count(tx.reference_inputs.len() as u64),
        Location::Body(19) => count(tx.votes.len() as u64),
        Location::Body(20) => count(tx.proposals.len() as u64),
        Location::Body(23) => count(tx.sub_transactions.len() as u64),
        Location::Body(25) => count(tx.direct_deposits.len() as u64),
        Location::Body(26) => count(tx.account_balance_intervals.len() as u64),
        Location::Body(27) => count(tx.starting_account_balance_intervals.len() as u64),
        Location::Wits(0) => count(wits.vkeywitness.len() as u64),
        Location::Wits(1) => count(scripts(&|s| matches!(s, S::Native(_)))),
        Location::Wits(2) => count(wits.bootstrap_witnesses.len() as u64),
        Location::Wits(3) => count(scripts(&|s| matches!(s, S::PlutusV1(_)))),
        Location::Wits(4) => count(wits.plutus_datums.len() as u64),
        Location::Wits(5) => count(wits.redeemers.len() as u64),
        Location::Wits(6) => count(scripts(&|s| matches!(s, S::PlutusV2(_)))),
        Location::Wits(7) => count(scripts(&|s| matches!(s, S::PlutusV3(_)))),
        Location::RedeemerTag(t @ 0..=6) => count(
            wits.redeemers
                .iter()
                .filter(|r| r.purpose == t as i32 + 1)
                .count() as u64,
        ),
        Location::NativeClause(c @ 0..=6) => {
            let mut counts = BTreeMap::new();
            for s in &wits.script {
                if let Some(S::Native(n)) = s.script.as_ref() {
                    native_counts(n, &mut counts);
                }
            }
            count(counts.get(&c).copied().unwrap_or(0))
        }
        Location::CertTag(t @ 0..=18) => count(
            tx.certificates
                .iter()
                .filter_map(|c| c.certificate.as_ref())
                .filter(|c| cert_tag(c) == t)
                .count() as u64,
        ),
        Location::PoolBls => count(
            tx.certificates
                .iter()
                .filter(|c| {
                    matches!(
                        c.certificate.as_ref(),
                        Some(u5c::certificate::Certificate::PoolRegistration(p)) if p.bls_key.is_some()
                    )
                })
                .count() as u64,
        ),
        Location::ParamUpdate(k) => {
            let mut n = 0;
            for p in &tx.proposals {
                let action = p
                    .gov_action
                    .as_ref()
                    .and_then(|a| a.governance_action.as_ref());
                if let Some(u5c::governance_action::GovernanceAction::ParameterChangeAction(c)) =
                    action
                {
                    match c.protocol_param_update.as_ref().map(|p| param_set(p, k)) {
                        Some(None) => return None,
                        Some(Some(true)) => n += 1,
                        _ => {}
                    }
                }
            }
            param_set(&u5c::PParams::default(), k)?;
            count(n)
        }
        _ => None,
    }
}

/// How often the source held a location and how often u5c failed to hold it.
#[derive(Clone, Debug, Default)]
pub struct Tally {
    pub occurrences: u64,
    pub disagreements: u64,
    pub without_counterpart: u64,
    pub first: Option<(u64, Option<[u8; 32]>)>,
}

impl Tally {
    /// Tells whether u5c failed to hold this location at least once.
    pub fn fails(&self) -> bool {
        self.disagreements > 0 || self.without_counterpart > 0
    }
}

/// The tallies of every location the scanned blocks held.
#[derive(Default, Debug)]
pub struct Coverage {
    pub blocks: u64,
    pub tallies: BTreeMap<Location, Tally>,
}

impl Coverage {
    fn record(&mut self, location: Location, verdict: Option<bool>, at: (u64, Option<[u8; 32]>)) {
        let t = self.tallies.entry(location).or_default();
        t.occurrences += 1;
        match verdict {
            Some(true) => return,
            Some(false) => t.disagreements += 1,
            None => t.without_counterpart += 1,
        }
        t.first.get_or_insert(at);
    }

    /// Adds one Dijkstra block, its CBOR without the era wrapper and its u5c mapping.
    pub fn add(&mut self, block: &[u8], number: u64, mapped: &u5c::Block) {
        self.blocks += 1;
        let scan = scan(block);
        for (location, held) in &scan.held {
            let verdict = agrees(*location, *held, mapped, None);
            self.record(*location, verdict, (number, None));
        }
        let txs = mapped.body.as_ref().map(|b| b.tx.as_slice()).unwrap_or(&[]);
        for (i, tx_scan) in scan.txs.iter().enumerate() {
            self.add_tx(tx_scan, txs.get(i), number, mapped);
        }
    }

    /// Adds one scanned transaction and its sub transactions against the u5c transactions at the same places.
    fn add_tx(&mut self, scan: &TxScan, tx: Option<&u5c::Tx>, number: u64, mapped: &u5c::Block) {
        let id = tx.and_then(|t| t.hash.as_ref().try_into().ok());
        for (location, held) in &scan.held {
            let verdict = agrees(*location, *held, mapped, tx);
            self.record(*location, verdict, (number, id));
        }
        for (j, sub) in scan.subs.iter().enumerate() {
            let mapped_sub = tx.and_then(|t| t.sub_transactions.get(j));
            self.add_tx(sub, mapped_sub, number, mapped);
        }
    }

    /// Tells whether a block was scanned and u5c held every location the scanned blocks held.
    pub fn agrees(&self) -> bool {
        self.blocks > 0 && self.failing().is_empty()
    }

    /// Lists every location u5c failed to hold that the exclusion list does not name.
    pub fn failing(&self) -> Vec<(Location, &Tally)> {
        self.tallies
            .iter()
            .filter(|(l, t)| t.fails() && !excluded(l))
            .map(|(l, t)| (*l, t))
            .collect()
    }
}
