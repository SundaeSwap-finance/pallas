//! Checks the u5c mapping of a chain against the node that produced it, by state replay, by field comparison and by CBOR key coverage.

pub mod compare;
pub mod coverage;
pub mod effects;
pub mod fields;
pub mod fixtures;
pub mod ledger;
pub mod model;
pub mod node;

use std::collections::{HashMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};

use pallas_traverse::MultiEraBlock;
use pallas_utxorpc::v1beta::Mapper;
use pallas_utxorpc::v1beta::spec::cardano as u5c;
use pallas_utxorpc::{LedgerContext, TxoRef, UtxoMap};

use crate::coverage::Coverage;
use crate::fields::{Found, GuardReport, Registration};
use crate::ledger::Ledger;
use crate::model::Effects;

/// A ledger context that resolves nothing, so the mapper reads only the block.
#[derive(Clone, Default)]
pub struct NoLedger;

impl LedgerContext for NoLedger {
    fn get_utxos(&self, _refs: &[TxoRef]) -> Option<UtxoMap> {
        None
    }

    fn get_slot_timestamp(&self, _slot: u64) -> Option<u64> {
        None
    }
}

/// The mapper the oracle checks.
pub fn mapper() -> Mapper<NoLedger> {
    Mapper::default()
}

/// Runs `f` and returns its panic message instead of unwinding.
pub fn caught<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let out = catch_unwind(AssertUnwindSafe(f));
    std::panic::set_hook(hook);
    out.map_err(|e| {
        e.downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| e.downcast_ref::<String>().cloned())
            .unwrap_or_default()
    })
}

/// The state that replaying a chain from u5c fields alone builds.
pub struct Replay {
    pub u5c: Ledger,
    pub coverage: Coverage,
    pub registrations: Vec<Registration>,
    pub guards: GuardReport,
    pub mapper_panics: Vec<(u64, String)>,
    pub wanted: HashSet<[u8; 32]>,
    pub found: HashMap<[u8; 32], Found>,
    pub kept: HashMap<u64, u5c::Block>,
    pub blocks: u64,
    pub txs: u64,
}

impl Replay {
    /// Starts the replay from the effects of the genesis file, noting where the chain holds each wanted transaction id.
    pub fn new(genesis: &[Effects], wanted: HashSet<[u8; 32]>) -> Self {
        let mut out = Self {
            u5c: Ledger::default(),
            coverage: Coverage::default(),
            registrations: Vec::new(),
            guards: GuardReport::default(),
            mapper_panics: Vec::new(),
            wanted,
            found: HashMap::new(),
            kept: HashMap::new(),
            blocks: 0,
            txs: 0,
        };
        for fx in genesis {
            out.u5c.apply(fx);
        }
        out
    }

    /// Applies one block given as its `[era, block]` CBOR, and returns its hash and number.
    pub fn block(&mut self, raw: &[u8]) -> ([u8; 32], u64) {
        let block = MultiEraBlock::decode(raw).expect("a block the node served");
        let number = block.number();
        let hash = *block.hash();
        let mapper = mapper();
        self.blocks += 1;
        let mapped = match caught(|| mapper.map_block(&block)) {
            Ok(m) => m,
            Err(e) => {
                self.mapper_panics.push((number, e));
                return (hash, number);
            }
        };
        let txs = mapped.body.as_ref().map(|b| b.tx.as_slice()).unwrap_or(&[]);
        for tx in txs {
            self.txs += 1;
            for fx in effects::applied(tx, number) {
                self.u5c.apply(&fx);
            }
        }
        if let Some(b) = block.as_dijkstra() {
            self.coverage.add(inner_block(raw), number, &mapped);
            self.registrations
                .extend(fields::registrations(b, number, &mapped));
            self.guards.add(b, number, &mapped);
            let mut keep = false;
            for (id, at) in fields::source_ids(b, number) {
                if self.wanted.contains(&id) {
                    self.found.insert(id, at);
                    keep = true;
                }
            }
            if keep {
                self.kept.insert(number, mapped);
            }
        }
        (hash, number)
    }
}

/// Returns the block element of an `[era, block]` record.
pub fn inner_block(raw: &[u8]) -> &[u8] {
    let mut d = pallas_codec::minicbor::Decoder::new(raw);
    d.array().expect("an era wrapper");
    d.u64().expect("an era");
    &raw[d.position()..]
}
