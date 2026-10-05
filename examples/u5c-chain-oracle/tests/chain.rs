use std::collections::HashMap;

use pallas_traverse::MultiEraBlock;
use pallas_utxorpc::v1beta::spec::cardano as u5c;
use u5c_chain_oracle::coverage::{Coverage, EXCLUDED, Location};
use u5c_chain_oracle::effects;
use u5c_chain_oracle::fields::{self, Case, GuardReport, IdVerdict};
use u5c_chain_oracle::model::AccountOp;
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

fn guard_report(m: &Mapped) -> GuardReport {
    let block = MultiEraBlock::decode(&m.raw).expect("a block");
    let mut report = GuardReport::default();
    report.add(block.as_dijkstra().expect("Dijkstra"), m.number, &m.u5c);
    report
}

#[test]
fn the_chain_guards_reach_u5c_with_their_key_or_script_tag() {
    let m = mapped(106412);
    let guards = |tx: &str| fields::u5c_guards(Some(&m.txs()[m.position(tx)]));
    let hash = |h: &str| hex::decode(h).expect("hex");
    assert_eq!(guards(G1), vec![Some((false, hash(G1_GUARD)))]);
    assert_eq!(guards(R1), vec![Some((true, hash(R1_GUARD)))]);
    let report = guard_report(&m);
    assert_eq!((report.with_guards, report.differences.len()), (2, 0));
    assert!(report.agrees());
}

#[test]
fn the_guard_check_holds_a_block_without_guards() {
    let report = guard_report(&mapped(104960));
    assert!(report.bodies > 0);
    assert_eq!((report.with_guards, report.differences.len()), (0, 0));
}

#[test]
fn the_guard_check_fails_a_planted_tag_swap() {
    use u5c::stake_credential::StakeCredential as C;
    let mut m = mapped(106412);
    let guard = &mut m.tx_mut(R1).guards[0];
    let Some(C::ScriptHash(h)) = guard.stake_credential.clone() else {
        panic!("R1 is guarded by a script, got {guard:?}");
    };
    guard.stake_credential = Some(C::AddrKeyHash(h));
    let report = guard_report(&m);
    assert_eq!(report.with_guards, 2);
    assert_eq!(report.differences, vec![(106412, id(R1))]);
    assert!(!report.agrees());
}

#[test]
fn the_guard_check_fails_a_planted_guard_on_a_body_without_one() {
    use u5c::stake_credential::StakeCredential as C;
    let mut m = mapped(104960);
    m.tx_mut(C2).guards.push(u5c::StakeCredential {
        stake_credential: Some(C::AddrKeyHash(vec![0; 28].into())),
    });
    let report = guard_report(&m);
    assert_eq!(report.differences, vec![(104960, id(C2))]);
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
    for number in [104949, 104960, 104966, 105475, 105486, 106412, 4277] {
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
    want.extend([7, 11, 15, 21, 22, 24].map(Location::Body));
    let mut have: Vec<Location> = EXCLUDED.iter().map(|(l, _)| *l).collect();
    have.sort();
    want.sort();
    assert_eq!(have, want);
    assert!(EXCLUDED.iter().all(|(_, reason)| !reason.is_empty()));
}
