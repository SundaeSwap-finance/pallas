use std::collections::HashMap;

use pallas_traverse::MultiEraBlock;
use pallas_utxorpc::v1beta::spec::cardano as u5c;
use u5c_chain_oracle::coverage::{Coverage, EXCLUDED, Location};
use u5c_chain_oracle::effects;
use u5c_chain_oracle::fields::{self, Case, IdVerdict};
use u5c_chain_oracle::model::AccountOp;
use u5c_chain_oracle::values::{self, Values};
use u5c_chain_oracle::{inner_block, mapper};

fn raw(number: u64) -> Vec<u8> {
    let path = format!(
        "{}/fixtures/blocks/{number}.cbor",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn id(text: &str) -> [u8; 32] {
    hex::decode(text)
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

const C2: &str = "6be37198a765e2078f1e15555bebe1a230a9594ec32821e0f5db0c76cae28386";
const C2_SUB: &str = "729149650a2469af59b1ea8be819c72010d71389683b6a1f0706879c8982d51f";
const A1: &str = "43827b78039ee71003f79eda9cbe50c44e7101195cd7a4e13fba290bbfc11faa";
const N1: &str = "2de11481d8ff00d2195c0801a440d6feb33f23e2278ce98c898769df292dccb2";
const G1: &str = "040eaed5954e8154427b5dfec71fde4d0f1148ebaed9a3fe02a1744d03b2ae45";
const R1: &str = "5095bc497783bc4b1dc7431758fffa58762e68564c3baa3f630314b214a2629f";

struct Mapped {
    number: u64,
    raw: Vec<u8>,
    u5c: u5c::Block,
}

fn mapped(number: u64) -> Mapped {
    let raw = raw(number);
    let block = MultiEraBlock::decode(&raw).expect("a block");
    let u5c = mapper().map_block(&block);
    Mapped { number, raw, u5c }
}

impl Mapped {
    fn position(&self, tx: &str) -> usize {
        self.txs()
            .iter()
            .position(|t| t.hash.as_ref() == id(tx))
            .unwrap_or_else(|| panic!("{tx} in the block"))
    }

    fn txs(&self) -> &[u5c::Tx] {
        self.u5c.body.as_ref().map_or(&[], |b| b.tx.as_slice())
    }

    fn tx_mut(&mut self, tx: &str) -> &mut u5c::Tx {
        let i = self.position(tx);
        &mut self.u5c.body.as_mut().expect("a body").tx[i]
    }

    fn coverage(&self) -> Coverage {
        let mut c = Coverage::default();
        c.add(inner_block(&self.raw), self.number, &self.u5c);
        c
    }

    fn ids(&self, names: &[&str]) -> Vec<IdVerdict> {
        let block = MultiEraBlock::decode(&self.raw).expect("a block");
        let found = fields::source_ids(block.as_dijkstra().expect("Dijkstra"), self.number)
            .into_iter()
            .collect();
        let cases: Vec<Case> = names
            .iter()
            .map(|n| Case {
                name: (*n).to_owned(),
                id: id(n),
            })
            .collect();
        let blocks = HashMap::from([(self.number, self.u5c.clone())]);
        fields::tx_ids(&cases, &found, &blocks)
            .into_iter()
            .map(|(_, v)| v)
            .collect()
    }
}

fn carried(v: &IdVerdict) -> bool {
    matches!(v, IdVerdict::Carried(_))
}

#[test]
fn u5c_carries_a_sub_transaction_id_under_its_parent_only() {
    let m = mapped(104960);
    assert!(m.txs().iter().all(|t| t.hash.as_ref() != id(C2_SUB)));
    let subs = &m.txs()[m.position(C2)].sub_transactions;
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0].hash.as_ref(), id(C2_SUB));
    let verdicts = m.ids(&[C2, C2_SUB]);
    assert!(verdicts.iter().all(carried), "{verdicts:?}");
}

#[test]
fn a_sub_transaction_id_without_its_parent_is_not_carried() {
    let mut m = mapped(104960);
    let sub = m.tx_mut(C2).sub_transactions.remove(0);
    let verdicts = m.ids(&[C2, C2_SUB]);
    assert!(
        carried(&verdicts[0]) && !carried(&verdicts[1]),
        "{verdicts:?}"
    );
    m.u5c.body.as_mut().expect("a body").tx.push(sub);
    let verdicts = m.ids(&[C2, C2_SUB]);
    assert!(
        carried(&verdicts[0]) && !carried(&verdicts[1]),
        "{verdicts:?}"
    );
}

#[test]
fn the_u5c_sub_transaction_produces_the_sub_output() {
    let mut m = mapped(104960);
    let produced = |tx: &u5c::Tx| -> Vec<([u8; 32], u32)> {
        effects::applied(tx, 104960)
            .iter()
            .flat_map(|fx| fx.produced.iter().map(|(k, _)| *k))
            .collect()
    };
    assert!(produced(&m.txs()[m.position(C2)]).contains(&(id(C2_SUB), 0)));
    m.tx_mut(C2).sub_transactions.clear();
    assert!(!produced(&m.txs()[m.position(C2)]).contains(&(id(C2_SUB), 0)));
}

#[test]
fn the_u5c_direct_deposit_credits_the_account() {
    let mut m = mapped(104949);
    let deposits = |tx: &u5c::Tx| -> Vec<AccountOp> {
        effects::applied(tx, 104949)
            .into_iter()
            .flat_map(|fx| fx.accounts)
            .filter(|op| matches!(op, AccountOp::Deposit(..)))
            .collect()
    };
    assert_eq!(deposits(&m.txs()[m.position(A1)]).len(), 1);
    m.tx_mut(A1).direct_deposits.clear();
    assert_eq!(deposits(&m.txs()[m.position(A1)]), vec![]);
}

#[test]
fn a_failed_transaction_applies_its_collateral_and_not_its_sub_transaction() {
    let m = mapped(105475);
    let tx = &m.txs()[m.position(N1)];
    assert!(!tx.successful);
    assert_eq!(tx.sub_transactions.len(), 1);
    let applied = effects::applied(tx, 105475);
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].origin.sub, None);
    assert_eq!(applied[0].produced.len(), 1);
    assert_eq!(applied[0].produced[0].0, (id(N1), tx.outputs.len() as u32));
}

#[test]
fn a_failed_transaction_lists_its_sub_transaction_id_under_it() {
    let raw = raw(105486);
    let block = MultiEraBlock::decode(&raw).expect("a block");
    let ids = fields::source_ids(block.as_dijkstra().expect("Dijkstra"), 105486);
    let n2 = id("5c2a50a1ed150518aa27171e1157a8db6367858a2288629fb00c566c69cb6e68");
    let sub = id("07f6c06348ddd70277fc220b9a7b37d19b3bde80bb4ce04c6eadff4b29348426");
    let parent = ids.iter().find(|(i, _)| *i == sub).map(|x| x.1.parent);
    assert_eq!(parent, Some(Some(n2)));
}

#[test]
fn the_bls_check_holds_a_key_only_in_the_u5c_bls_field() {
    let m = mapped(4277);
    let block = MultiEraBlock::decode(&m.raw).expect("a block");
    let mut regs = fields::registrations(block.as_dijkstra().expect("Dijkstra"), 4277, &m.u5c);
    let r = regs
        .iter_mut()
        .find(|r| r.bls.is_some())
        .expect("a registration with a BLS key");
    assert!(fields::u5c_holds_bls(r));
    let (key, _) = r.bls.clone().expect("a key");
    let mapping = r.mapped.as_mut().expect("a mapping");
    mapping
        .bls_key
        .as_mut()
        .expect("a mapped key")
        .bls_possession_proof = vec![0; 48].into();
    assert!(!fields::u5c_holds_bls(r));
    let mapping = r.mapped.as_mut().expect("a mapping");
    mapping.bls_key = None;
    mapping.pool_metadata = Some(u5c::PoolMetadata {
        url: String::new(),
        hash: key.into(),
    });
    assert!(!fields::u5c_holds_bls(r));
}

const G1_GUARD: &str = "26ef2714badd53e3477ca0aa94443e3522c4e4e895a67efb90ff427c";
const R1_GUARD: &str = "31a78786b5989dc6fd2d4ab15b297069e94106ecacceb8eb29e1b681";

const B1: &str = "f701e0201667bab62c1b9b04c3cfafaa1afba2b88284c0e36d04322a6bd0fd5b";
const B2: &str = "0e218b84ed1762aedcd483d2783a0149793fece8a14fa4eaac5e49c97d24d9cc";
const K3: &str = "20ecf94dd1d563096b73ad5527bae96bdde602d1d2b91510e4f3441d57ae8ccd";
const K3_SUB: &str = "7a8da831abf56f902a1f30b31b4fcfff4d2a5efadf88f5c58f7b2b1ff914685b";

type Fired = Vec<(&'static str, Vec<(u64, [u8; 32])>)>;

fn values(m: &Mapped) -> Values {
    let block = MultiEraBlock::decode(&m.raw).expect("a block");
    let mut v = Values::default();
    v.add(block.as_dijkstra().expect("Dijkstra"), m.number, &m.u5c);
    v
}

fn fired(v: &Values) -> Fired {
    v.reports()
        .into_iter()
        .filter(|(_, r)| !r.differences.is_empty())
        .map(|(name, r)| (name, r.differences.clone()))
        .collect()
}

fn holding(v: &Values, name: &str) -> usize {
    v.reports()
        .into_iter()
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("a report named {name}"))
        .1
        .holding
}

fn swap_tag(c: &mut u5c::StakeCredential) {
    use u5c::stake_credential::StakeCredential as C;
    c.stake_credential = match c.stake_credential.take() {
        Some(C::AddrKeyHash(h)) => Some(C::ScriptHash(h)),
        Some(C::ScriptHash(h)) => Some(C::AddrKeyHash(h)),
        None => panic!("a credential"),
    };
}

fn bump(b: &mut Option<u5c::BigInt>) {
    use u5c::big_int::BigInt as B;
    match b.as_mut().and_then(|b| b.big_int.as_mut()) {
        Some(B::Int(i)) => *i += 1,
        other => panic!("a small coin, got {other:?}"),
    }
}

fn bump_interval(x: &mut u5c::AccountBalanceInterval) {
    use u5c::account_balance_interval::Interval as I;
    match x.interval.as_mut().expect("an interval") {
        I::Exact(c) => {
            let mut c2 = Some(c.clone());
            bump(&mut c2);
            *c = c2.expect("a coin");
        }
        I::Range(r) if r.inclusive_lower_bound.is_some() => bump(&mut r.inclusive_lower_bound),
        I::Range(r) => bump(&mut r.exclusive_upper_bound),
    }
}

fn guard_clause(s: &mut u5c::NativeScript) -> Option<&mut u5c::StakeCredential> {
    use u5c::native_script::NativeScript as N;
    match s.native_script.as_mut()? {
        N::ScriptRequireGuard(c) => Some(c),
        N::ScriptAll(l) | N::ScriptAny(l) => l.items.iter_mut().find_map(guard_clause),
        N::ScriptNOfK(k) => k.scripts.iter_mut().find_map(guard_clause),
        _ => None,
    }
}

fn guarding_redeemer(tx: &mut u5c::Tx) -> &mut u5c::Redeemer {
    tx.witnesses
        .as_mut()
        .expect("witnesses")
        .redeemers
        .iter_mut()
        .find(|r| r.purpose == u5c::RedeemerPurpose::Guarding as i32)
        .expect("a guarding redeemer")
}

#[test]
fn the_chain_guards_reach_u5c_with_their_key_or_script_tag() {
    let m = mapped(106412);
    let guards = |tx: &str| values::u5c_guards(Some(&m.txs()[m.position(tx)]));
    let hash = |h: &str| hex::decode(h).expect("hex");
    assert_eq!(guards(G1), vec![Some((false, hash(G1_GUARD)))]);
    assert_eq!(guards(R1), vec![Some((true, hash(R1_GUARD)))]);
    let v = values(&m);
    assert_eq!((v.guards.holding, v.guards.values), (2, 2));
    assert_eq!(fired(&v), vec![]);
    assert!(v.guards.agrees());
}

#[test]
fn the_value_checks_hold_each_fixture_block() {
    for number in [104949, 104960, 104966, 105475, 105486, 106412, 112090, 4277] {
        let v = values(&mapped(number));
        assert!(v.guards.bodies > 0, "block {number}");
        assert_eq!(fired(&v), vec![], "block {number}");
    }
}

#[test]
fn the_value_checks_hold_the_blocks_that_carry_each_field() {
    for (number, name) in [
        (106412, "key 14 guards"),
        (104960, "key 26 intervals"),
        (104966, "key 26 intervals"),
        (104960, "key 27 starting intervals"),
        (104966, "key 27 starting intervals"),
        (106412, "guard native clauses"),
        (106412, "guarding redeemers"),
        (112090, "key 24 top level guards"),
    ] {
        let v = values(&mapped(number));
        assert!(holding(&v, name) > 0, "block {number} holds {name}");
        assert_eq!(fired(&v), vec![], "block {number}");
    }
}

#[test]
fn a_report_that_held_no_value_does_not_agree() {
    let v = values(&mapped(104960));
    assert!(v.top_level_guards.bodies > 0);
    assert_eq!(v.top_level_guards.values, 0);
    assert!(v.top_level_guards.differences.is_empty());
    assert!(!v.top_level_guards.agrees());
    assert!(!v.agrees());
}

#[test]
fn the_guard_check_fails_a_planted_tag_swap() {
    let mut m = mapped(106412);
    swap_tag(&mut m.tx_mut(R1).guards[0]);
    let v = values(&m);
    assert_eq!(v.guards.holding, 2);
    assert_eq!(fired(&v), vec![("key 14 guards", vec![(106412, id(R1))])]);
    assert!(!v.guards.agrees());
}

#[test]
fn the_guard_check_fails_a_planted_guard_on_a_body_without_one() {
    use u5c::stake_credential::StakeCredential as C;
    let mut m = mapped(104960);
    m.tx_mut(C2).guards.push(u5c::StakeCredential {
        stake_credential: Some(C::AddrKeyHash(vec![0; 28].into())),
    });
    assert_eq!(
        fired(&values(&m)),
        vec![("key 14 guards", vec![(104960, id(C2))])]
    );
}

#[test]
fn the_interval_check_fails_a_planted_bound_change() {
    let mut m = mapped(104960);
    bump_interval(&mut m.tx_mut(B1).account_balance_intervals[0]);
    let v = values(&m);
    assert_eq!(
        fired(&v),
        vec![("key 26 intervals", vec![(104960, id(B1))])]
    );
    assert!(!v.intervals.agrees());
}

#[test]
fn the_interval_check_fails_a_planted_account_change() {
    let mut m = mapped(104960);
    let account = &mut m.tx_mut(B1).account_balance_intervals[0].reward_account;
    let mut bytes = account.to_vec();
    *bytes.last_mut().expect("an account") ^= 1;
    *account = bytes.into();
    assert_eq!(
        fired(&values(&m)),
        vec![("key 26 intervals", vec![(104960, id(B1))])]
    );
}

#[test]
fn the_starting_interval_check_fails_a_planted_bound_change() {
    let mut m = mapped(104960);
    bump_interval(&mut m.tx_mut(B2).starting_account_balance_intervals[0]);
    assert_eq!(
        fired(&values(&m)),
        vec![("key 27 starting intervals", vec![(104960, id(B2))])]
    );
}

#[test]
fn the_starting_interval_check_fails_a_planted_interval_on_a_sub_transaction() {
    let mut m = mapped(104960);
    let planted = m.tx_mut(B2).starting_account_balance_intervals[0].clone();
    m.tx_mut(C2).sub_transactions[0]
        .starting_account_balance_intervals
        .push(planted);
    assert_eq!(
        fired(&values(&m)),
        vec![("key 27 starting intervals", vec![(104960, id(C2_SUB))])]
    );
}

#[test]
fn the_guard_clause_check_fails_a_planted_tag_swap() {
    use u5c::script::Script as S;
    let mut m = mapped(106412);
    let clause = m
        .tx_mut(G1)
        .witnesses
        .as_mut()
        .expect("witnesses")
        .script
        .iter_mut()
        .find_map(|s| match s.script.as_mut() {
            Some(S::Native(n)) => guard_clause(n),
            _ => None,
        })
        .expect("a guard clause");
    swap_tag(clause);
    let v = values(&m);
    assert_eq!(v.guards.holding, 2);
    assert_eq!(
        fired(&v),
        vec![("guard native clauses", vec![(106412, id(G1))])]
    );
}

#[test]
fn the_guarding_redeemer_check_fails_a_planted_index_change() {
    let mut m = mapped(106412);
    guarding_redeemer(m.tx_mut(R1)).index += 1;
    assert_eq!(
        fired(&values(&m)),
        vec![("guarding redeemers", vec![(106412, id(R1))])]
    );
}

#[test]
fn the_guarding_redeemer_check_fails_a_planted_payload_change() {
    use u5c::plutus_data::PlutusData as P;
    let mut m = mapped(106412);
    let r = guarding_redeemer(m.tx_mut(R1));
    let planted = Some(u5c::PlutusData {
        plutus_data: Some(P::BoundedBytes(vec![0xee; 3].into())),
    });
    assert_ne!(r.payload, planted);
    r.payload = planted;
    assert_eq!(
        fired(&values(&m)),
        vec![("guarding redeemers", vec![(106412, id(R1))])]
    );
}

#[test]
fn the_top_level_guard_check_fails_a_planted_datum() {
    use u5c::plutus_data::PlutusData as P;
    let mut m = mapped(112090);
    let guard = &mut m.tx_mut(K3).sub_transactions[0].required_top_level_guards[0];
    assert_eq!(guard.datum, None);
    guard.datum = Some(u5c::PlutusData {
        plutus_data: Some(P::Array(u5c::PlutusDataArray { items: vec![] })),
    });
    assert_eq!(
        fired(&values(&m)),
        vec![("key 24 top level guards", vec![(112090, id(K3_SUB))])]
    );
}

#[test]
fn the_top_level_guard_check_fails_a_planted_tag_swap() {
    let mut m = mapped(112090);
    let guard = &mut m.tx_mut(K3).sub_transactions[0].required_top_level_guards[0];
    swap_tag(guard.credential.as_mut().expect("a credential"));
    assert_eq!(
        fired(&values(&m)),
        vec![("key 24 top level guards", vec![(112090, id(K3_SUB))])]
    );
}

#[test]
fn coverage_holds_the_top_level_guards_and_fails_a_planted_drop() {
    let mut m = mapped(112090);
    let before = m.coverage();
    let t = &before.tallies[&Location::Body(24)];
    assert!(t.occurrences > 0 && !t.fails(), "{t:?}");
    m.tx_mut(K3).sub_transactions[0]
        .required_top_level_guards
        .clear();
    let after = m.coverage();
    assert_eq!(after.tallies[&Location::Body(24)].disagreements, 1);
    let f = failing(&after);
    assert!(f.contains(&Location::Body(24)), "{f:?}");
}

#[test]
fn coverage_fails_a_planted_guard_drop() {
    let mut m = mapped(106412);
    assert_eq!(m.coverage().tallies[&Location::Body(14)].occurrences, 2);
    m.tx_mut(G1).guards.clear();
    let after = m.coverage();
    assert_eq!(after.tallies[&Location::Body(14)].disagreements, 1);
    let f = failing(&after);
    assert!(f.contains(&Location::Body(14)), "{f:?}");
}

fn failing(c: &Coverage) -> Vec<Location> {
    c.failing().into_iter().map(|(l, _)| l).collect()
}

#[test]
fn coverage_holds_every_location_of_the_fixture_blocks() {
    for number in [104949, 104960, 104966, 105475, 105486, 106412, 112090, 4277] {
        let c = mapped(number).coverage();
        assert_eq!(failing(&c), vec![], "block {number}");
    }
}

#[test]
fn coverage_holds_the_dijkstra_transaction_fields() {
    let c = mapped(104966).coverage();
    for l in [
        Location::Body(0),
        Location::Body(1),
        Location::Body(2),
        Location::Body(23),
        Location::Body(25),
        Location::Body(26),
        Location::Body(27),
        Location::Wits(0),
        Location::TxPart(3),
        Location::HeaderBody(0),
        Location::HeaderBody(1),
        Location::BlockBody(0),
    ] {
        let t = c
            .tallies
            .get(&l)
            .unwrap_or_else(|| panic!("{l:?} in the block"));
        assert!(t.occurrences > 0 && !t.fails(), "{l:?} {t:?}");
    }
}

#[test]
fn coverage_holds_the_guarding_redeemer_and_the_guard_clause() {
    let c = mapped(106412).coverage();
    for l in [Location::RedeemerTag(6), Location::NativeClause(6)] {
        let t = c
            .tallies
            .get(&l)
            .unwrap_or_else(|| panic!("{l:?} in the block"));
        assert!(t.occurrences == 1 && !t.fails(), "{l:?} {t:?}");
    }
}

#[test]
fn coverage_fails_a_planted_guarding_purpose_drop() {
    let mut m = mapped(106412);
    let wits = m.tx_mut(R1).witnesses.as_mut().expect("a witness set");
    assert_eq!(wits.redeemers.len(), 1);
    wits.redeemers[0].purpose = u5c::RedeemerPurpose::Unspecified as i32;
    let after = m.coverage();
    assert_eq!(after.tallies[&Location::RedeemerTag(6)].disagreements, 1);
    let f = failing(&after);
    assert!(f.contains(&Location::RedeemerTag(6)), "{f:?}");
}

#[test]
fn coverage_fails_a_planted_guard_clause_drop() {
    let mut m = mapped(106412);
    let wits = m.tx_mut(G1).witnesses.as_mut().expect("a witness set");
    let mut dropped = 0;
    for s in &mut wits.script {
        if let Some(u5c::script::Script::Native(n)) = s.script.as_mut() {
            n.native_script = None;
            dropped += 1;
        }
    }
    assert_eq!(dropped, 1);
    let after = m.coverage();
    assert_eq!(after.tallies[&Location::NativeClause(6)].disagreements, 1);
    let f = failing(&after);
    assert!(f.contains(&Location::NativeClause(6)), "{f:?}");
}

#[test]
fn coverage_scans_the_inputs_of_every_sub_transaction() {
    let m = mapped(104966);
    let block = MultiEraBlock::decode(&m.raw).expect("a block");
    let txs = &block
        .as_dijkstra()
        .expect("Dijkstra")
        .block_body
        .transactions;
    let subs: usize = txs
        .iter()
        .map(|t| {
            t.transaction_body
                .sub_transactions
                .as_ref()
                .map_or(0, |s| s.len())
        })
        .sum();
    assert!(subs > 0);
    let c = m.coverage();
    assert_eq!(
        c.tallies[&Location::Body(0)].occurrences,
        (txs.len() + subs) as u64
    );
}

#[test]
fn coverage_fails_a_planted_sub_transaction_drop() {
    let mut m = mapped(104960);
    m.tx_mut(C2).sub_transactions.clear();
    let after = m.coverage();
    assert_eq!(after.tallies[&Location::Body(23)].disagreements, 1);
    let f = failing(&after);
    assert!(f.contains(&Location::Body(23)), "{f:?}");
    assert!(f.contains(&Location::Body(0)), "{f:?}");
}

#[test]
fn coverage_fails_a_planted_output_drop() {
    let mut m = mapped(104960);
    let before = failing(&m.coverage());
    assert!(!before.contains(&Location::Body(1)), "{before:?}");
    let tx = &mut m.u5c.body.as_mut().expect("a body").tx[0];
    assert!(!tx.outputs.is_empty());
    tx.outputs.clear();
    let after = m.coverage();
    assert_eq!(after.tallies[&Location::Body(1)].disagreements, 1);
    assert!(failing(&after).contains(&Location::Body(1)));
}

#[test]
fn the_exclusion_list_names_the_conway_positions_u5c_never_held() {
    let mut want: Vec<Location> = (2..=11).map(Location::HeaderBody).collect();
    want.extend([1, 2].map(Location::BlockBody));
    want.extend([7, 11, 15, 21, 22].map(Location::Body));
    let mut have: Vec<Location> = EXCLUDED.iter().map(|(l, _)| *l).collect();
    have.sort();
    want.sort();
    assert_eq!(have, want);
    assert!(EXCLUDED.iter().all(|(_, reason)| !reason.is_empty()));
}

#[test]
fn the_in_items_name_the_top_level_guards() {
    let items = u5c_chain_oracle::coverage::in_items();
    assert!(
        items.contains(&(
            "13 body key 24 required_top_level_guards".to_owned(),
            Location::Body(24)
        )),
        "{items:?}"
    );
}
