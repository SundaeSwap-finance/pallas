use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use u5c_chain_oracle::compare::{self, AccountMismatch, UtxoMismatch};
use u5c_chain_oracle::coverage::{self, Location};
use u5c_chain_oracle::fields::{self, IdVerdict};
use u5c_chain_oracle::ledger::{Ledger, Violation};
use u5c_chain_oracle::model::{RefScript, TxIn};
use u5c_chain_oracle::node::{self, NodeState};
use u5c_chain_oracle::{Replay, caught, fixtures, mapper};

const SHOWN: usize = 5;

fn read_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn txin(k: &TxIn) -> String {
    format!("{}#{}", hex::encode(k.0), k.1)
}

fn utxo_cause(m: &UtxoMismatch, ledger: &Ledger) -> String {
    let k = m.key();
    match m {
        UtxoMismatch::OnlyInFold(_) => match ledger.spent_by_sub.get(&k) {
            Some(o) => format!("spent by {}", o.describe()),
            None => format!("produced by {}", hex::encode(k.0)),
        },
        UtxoMismatch::OnlyAtNode(_) => match ledger.sub_origins.get(&k.0) {
            Some(o) => format!("produced by {}", o.describe()),
            None => format!("produced by {}", hex::encode(k.0)),
        },
        UtxoMismatch::Differs(_) => format!("produced by {}", hex::encode(k.0)),
    }
}

fn script(s: &Option<RefScript>) -> String {
    match s {
        None => "none".to_owned(),
        Some(RefScript::Native) => "native".to_owned(),
        Some(RefScript::Plutus(v, b)) => format!(
            "plutus v{v} {} bytes starting {}",
            b.len(),
            hex::encode(&b[..b.len().min(8)])
        ),
    }
}

fn violation(v: &Violation) -> String {
    match v {
        Violation::UnknownInput(i, o) => format!("unknown input {} at {}", txin(i), o.describe()),
        Violation::DuplicateOutput(i, o) => {
            format!("duplicate output {} at {}", txin(i), o.describe())
        }
        Violation::UnknownAccount(c, o) => {
            format!("unknown account {} at {}", c.node_key(), o.describe())
        }
        Violation::AlreadyRegistered(c, o) => {
            format!(
                "account {} registered twice at {}",
                c.node_key(),
                o.describe()
            )
        }
        Violation::NegativeBalance(c, b, o) => {
            format!("account {} balance {b} at {}", c.node_key(), o.describe())
        }
        Violation::UnregisteredWithBalance(c, b, o) => format!(
            "account {} unregistered holding {b} at {}",
            c.node_key(),
            o.describe()
        ),
    }
}

fn account(m: &AccountMismatch, ledger: &Ledger) -> String {
    let (cred, text) = match m {
        AccountMismatch::OnlyInFold(c, b) => (c, format!("only in fold, balance {b}")),
        AccountMismatch::OnlyAtNode(c, b) => (c, format!("only at node, balance {b}")),
        AccountMismatch::Balance {
            cred,
            fold,
            node,
            earns_rewards,
        } => (
            cred,
            format!("fold {fold} node {node} earns rewards {earns_rewards}"),
        ),
    };
    let deposits: Vec<String> = ledger
        .deposits_to
        .get(cred)
        .into_iter()
        .flatten()
        .map(|o| o.describe())
        .collect();
    format!(
        "{} {text} direct deposits from [{}]",
        cred.node_key(),
        deposits.join(", ")
    )
}

fn check_state(name: &str, fold: &Ledger, node: &NodeState) -> bool {
    let report = compare::state(fold, &node.utxo, &node.accounts);
    let utxo = &report.utxo;
    let count = |f: fn(&UtxoMismatch) -> bool| utxo.iter().filter(|m| f(m)).count();
    println!(
        "check1 {name} utxo fold {} node {} mismatches {} (only in fold {}, only at node {}, differs {})",
        fold.utxo.len(),
        node.utxo.len(),
        utxo.len(),
        count(|m| matches!(m, UtxoMismatch::OnlyInFold(_))),
        count(|m| matches!(m, UtxoMismatch::OnlyAtNode(_))),
        count(|m| matches!(m, UtxoMismatch::Differs(_))),
    );
    let differing = |k: &TxIn| match (fold.utxo.get(k), node.utxo.get(k)) {
        (Some(a), Some(b)) => compare::differing_fields(a, b),
        _ => vec![],
    };
    let mut by_fields: BTreeMap<Vec<&str>, usize> = BTreeMap::new();
    for m in utxo {
        if let UtxoMismatch::Differs(k) = m {
            *by_fields.entry(differing(k)).or_default() += 1;
        }
    }
    for (fields, n) in &by_fields {
        println!("  differs in [{}] {n}", fields.join(" "));
    }
    for m in utxo.iter().take(SHOWN) {
        let kind = match m {
            UtxoMismatch::OnlyInFold(_) => "only in fold",
            UtxoMismatch::OnlyAtNode(_) => "only at node",
            UtxoMismatch::Differs(_) => "differs",
        };
        println!(
            "  {kind} {} [{}] {}",
            txin(&m.key()),
            differing(&m.key()).join(" "),
            utxo_cause(m, fold)
        );
        let k = m.key();
        if let (Some(a), Some(b)) = (fold.utxo.get(&k), node.utxo.get(&k))
            && a.script != b.script
        {
            println!(
                "    script fold {} node {}",
                script(&a.script),
                script(&b.script)
            );
        }
    }
    let accounts = &report.accounts;
    println!(
        "check1 {name} accounts exact {} rewarded {} mismatches {}",
        accounts.exact,
        accounts.rewarded,
        accounts.mismatches.len()
    );
    for m in accounts.mismatches.iter().take(SHOWN) {
        println!("  {}", account(m, fold));
    }
    println!(
        "check1 {name} node entries compared {} violations {}",
        report.compared,
        fold.violations.len()
    );
    for v in fold.violations.iter().take(SHOWN) {
        println!("  {}", violation(v));
    }
    report.agrees()
}

fn short(x: &serde_json::Value) -> String {
    match x.as_array() {
        Some(v) => format!("array of {}", v.len()),
        None => x.to_string(),
    }
}

fn location(l: &Location) -> String {
    format!("{l:?}")
}

fn run(dir: &Path, cases_path: &Path) {
    let state = node::load(&dir.join("state"));
    let genesis_path = dir.join("state").join("shelley-genesis.json");
    let genesis = read_json(&genesis_path);
    let cases = fields::cases(&read_json(cases_path));
    let wanted: HashSet<[u8; 32]> = cases.iter().map(|c| c.id).collect();
    let mut replay = Replay::new(&node::genesis(&genesis_path), wanted);
    let blocks_dir = dir.join("blocks");
    let mut last = None;
    let visited = fixtures::each_block(&blocks_dir, &state.point.hash, |entry, raw| {
        let (hash, number) = replay.block(raw);
        assert_eq!(
            hash, entry.hash,
            "block {} hash against the index",
            entry.blockno
        );
        assert_eq!(number, entry.blockno, "block number against the index");
        last = Some((entry.slot, number, hash));
    });
    let (slot, number, hash) = last.expect("at least one block");
    println!(
        "pin slot {} block {} hash {} (node {} {} {}) blocks {} txs {} replayed {:?}",
        slot,
        number,
        hex::encode(hash),
        state.point.slot,
        state.point.block,
        hex::encode(state.point.hash),
        replay.blocks,
        replay.txs,
        visited
    );
    assert!(visited.is_some(), "the capture reaches the pinned point");
    println!("mapper panics {}", replay.mapper_panics.len());
    for (b, e) in replay.mapper_panics.iter().take(SHOWN) {
        println!("  block {b}: {e}");
    }

    let u5c_green = check_state("u5c", &replay.u5c, &state) && replay.mapper_panics.is_empty();
    println!("check1 verdict {}", if u5c_green { "GREEN" } else { "RED" });

    let ids = fields::tx_ids(&cases, &replay.found, &replay.kept);
    let carried = ids
        .iter()
        .filter(|(_, v)| matches!(v, IdVerdict::Carried(_)))
        .count();
    println!(
        "check2 tx ids cases {} carried {} other {}",
        ids.len(),
        carried,
        ids.len() - carried
    );
    for (c, v) in &ids {
        println!("  {} {} {v:?}", c.name, hex::encode(c.id));
    }

    let pp = &state.protocol_parameters;
    let dijkstra = fields::dijkstra_params(pp, &genesis);
    #[allow(deprecated)]
    let mapped = caught(|| {
        mapper().map_pparams(pallas_validate::utils::MultiEraProtocolParameters::Dijkstra(dijkstra))
    });
    let params_green = match &mapped {
        Ok(p) => {
            let mismatches = fields::param_mismatches(p, pp);
            println!(
                "check2 pparams dijkstra compared {} mismatches {}",
                fields::param_pairs(p, pp).len(),
                mismatches.len(),
            );
            for (f, a, b) in &mismatches {
                println!("  {f} u5c {a} node {}", short(b));
            }
            mismatches.is_empty()
        }
        Err(e) => {
            println!("check2 pparams dijkstra mapper panicked: {e}");
            false
        }
    };
    let conway = fields::conway_params(pp, &genesis);
    #[allow(deprecated)]
    let control = mapper().map_pparams(pallas_validate::utils::MultiEraProtocolParameters::Conway(
        conway,
    ));
    let compared = fields::param_pairs(&control, pp).len();
    let control = fields::param_mismatches(&control, pp);
    println!(
        "check2 pparams conway control compared {compared} mismatches {}",
        control.len()
    );
    for (f, a, b) in &control {
        println!("  {f} u5c {} node {}", short(a), short(b));
    }
    let without = fields::node_keys_without_field(pp);
    println!(
        "check2 pparams node keys without a u5c field {}: {}",
        without.len(),
        without.join(" ")
    );

    let pools = fields::pool_report(&replay.registrations, &state.pools);
    println!(
        "check2 pools registrations {} with bls {} bls in u5c {} latest at node {} node bls agrees {} vrf agrees {} vrf differs {}",
        pools.registrations,
        pools.with_bls,
        pools.bls_in_u5c,
        pools.latest_at_node,
        pools.node_bls_agrees,
        pools.vrf_agrees,
        pools.vrf_differs.len()
    );
    let bls_blocks: Vec<u64> = replay
        .registrations
        .iter()
        .filter(|r| r.bls.is_some())
        .map(|r| r.block)
        .collect();
    println!(
        "  blocks with a bls registration {:?}",
        &bls_blocks[..bls_blocks.len().min(SHOWN)]
    );
    let guards = &replay.guards;
    println!(
        "check2 guards bodies {} with key 14 {} differences {}",
        guards.bodies,
        guards.with_guards,
        guards.differences.len()
    );
    for (b, id) in guards.differences.iter().take(SHOWN) {
        println!("  block {b} tx {}", hex::encode(id));
    }
    let check2_green = fields::ids_agree(&ids) && params_green && pools.agrees() && guards.agrees();
    println!(
        "check2 verdict {}",
        if check2_green { "GREEN" } else { "RED" }
    );

    let failing = replay.coverage.failing();
    println!(
        "check3 dijkstra blocks {} locations {} failing {}",
        replay.coverage.blocks,
        replay.coverage.tallies.len(),
        failing.len()
    );
    for (l, t) in &failing {
        println!(
            "  {} occurrences {} disagreements {} without counterpart {} first {:?}",
            location(l),
            t.occurrences,
            t.disagreements,
            t.without_counterpart,
            t.first.map(|(b, tx)| (b, tx.map(hex::encode)))
        );
    }
    let items = coverage::in_items();
    let failing_set: HashMap<Location, ()> = failing.iter().map(|(l, _)| (*l, ())).collect();
    let in_failing = items
        .iter()
        .filter(|(_, l)| failing_set.contains_key(l))
        .count();
    println!(
        "check3 in items {} failing {} absent from the chain {}",
        items.len(),
        in_failing,
        items
            .iter()
            .filter(|(_, l)| !replay.coverage.tallies.contains_key(l))
            .count()
    );
    for (name, l) in &items {
        let state = match replay.coverage.tallies.get(l) {
            Some(t) if t.fails() => "FAILS",
            Some(_) => "held",
            None => "absent",
        };
        println!("  {name} {state}");
    }
    for (l, reason) in coverage::EXCLUDED {
        let n = replay.coverage.tallies.get(&l).map_or(0, |t| t.occurrences);
        println!("check3 excluded {} occurrences {n}: {reason}", location(&l));
    }
    println!(
        "check3 verdict {}",
        if replay.coverage.agrees() {
            "GREEN"
        } else {
            "RED"
        }
    );
}

fn extract(dir: &Path, out: &Path, numbers: &[u64]) {
    std::fs::create_dir_all(out).expect("an output directory");
    let index = fixtures::index(dir);
    for n in numbers {
        let entry = index
            .iter()
            .find(|e| e.blockno == *n)
            .unwrap_or_else(|| panic!("block {n} is not in the index"));
        let records = fixtures::chunk(&dir.join("chunks").join(&entry.chunk));
        let path = out.join(format!("{n}.cbor"));
        std::fs::write(&path, &records[entry.ordinal]).expect("a written block");
        println!("{} {}", path.display(), hex::encode(entry.hash));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("run") if args.len() == 4 => run(&PathBuf::from(&args[2]), &PathBuf::from(&args[3])),
        Some("extract") if args.len() >= 4 => {
            let numbers: Vec<u64> = args[4..]
                .iter()
                .map(|a| a.parse().expect("a block number"))
                .collect();
            extract(&PathBuf::from(&args[2]), &PathBuf::from(&args[3]), &numbers)
        }
        _ => {
            eprintln!("usage: u5c-chain-oracle run <fixture dir> <chain cases json>");
            eprintln!("       u5c-chain-oracle extract <blocks dir> <out dir> <block number>...");
            std::process::exit(2);
        }
    }
}
