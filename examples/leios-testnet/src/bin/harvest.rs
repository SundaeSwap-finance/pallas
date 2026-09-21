//! Cuts test fixtures from a live Leios testnet and writes what each one is.
//!
//! Six subcommands. `index` walks chain-sync and writes one row per header.
//! `scan` block-fetches a range and writes each block with a row saying what is
//! in it. `dups` walks a range without writing blocks and reports the three
//! shapes that make a strict apply reject a block. `eb` pulls one endorser
//! block body and every transaction of it. `ebcheck` and `pick` are offline:
//! `ebcheck` reports the same shapes inside one harvested payload, and `pick`
//! checks a harvested file against the hash the node reported for it and, only
//! when they agree, copies it into a fixture directory and appends that
//! fixture's entry to the directory's provenance.
//!
//! ```sh
//! RUST_LOG=info cargo run -p leios-testnet --bin harvest --features unstable -- index 172.17.0.2:3001 164 origin - out.tsv 1220000
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use pallas_codec::minicbor::{Decoder, data::Type};
use pallas_crypto::hash::{Hash, Hasher};
use pallas_network2::{
    Manager, PeerId,
    behavior::{
        AnyMessage,
        initiator::{
            Config as HandshakeConfig, HandshakeBehavior, InitiatorBehavior, InitiatorCommand,
            InitiatorEvent,
        },
    },
    interface::TcpInterface,
    protocol::{EbId, Point, handshake::n2n::VersionTable, leiosfetch},
};
use pallas_traverse::cert::BlsKeySlot;
use pallas_traverse::{MultiEraBlock, MultiEraHeader};
use tokio::{select, time::Interval};

/// One leios-fetch transaction request covers one 64 transaction window,
/// because a request spanning more than one can exceed the relay's response
/// limit.
const WINDOW: usize = 64;

/// Housekeeping is what releases a queued leios-fetch request onto the wire,
/// so the tick sets the floor on how long each endorser block window waits.
/// It also sends one keepalive per tick, and a tick short enough to queue a
/// second keepalive before the first is confirmed makes the peer answer one
/// the state no longer expects, which the initiator reads as a violation and
/// bans its own peer for.
const HOUSEKEEPING: Duration = Duration::from_millis(1000);

struct Net {
    network: Manager<TcpInterface<AnyMessage>, InitiatorBehavior, AnyMessage>,
    housekeeping: Interval,
}

impl Net {
    fn new(magic: u64) -> Self {
        let behavior = InitiatorBehavior {
            handshake: HandshakeBehavior::new(HandshakeConfig {
                supported_version: VersionTable::v11_and_above_with_query(magic, false),
            }),
            ..Default::default()
        };

        Self {
            network: Manager::new(TcpInterface::new(), behavior),
            housekeeping: tokio::time::interval(HOUSEKEEPING),
        }
    }

    fn execute(&mut self, cmd: InitiatorCommand) {
        self.network.execute(cmd);
    }

    /// Returns the next event, or `None` when `idle` passes with none.
    async fn next(&mut self, idle: Duration) -> Option<InitiatorEvent> {
        let deadline = tokio::time::Instant::now() + idle;

        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return None;
            }

            select! {
                _ = tokio::time::sleep(left) => return None,
                _ = self.housekeeping.tick() => {
                    self.network.execute(InitiatorCommand::Housekeeping);
                }
                evt = self.network.poll_next() => {
                    if let Some(evt) = evt {
                        return Some(evt);
                    }
                }
            }
        }
    }
}

fn point_of(slot: &str, hash: &str) -> Point {
    if slot == "origin" {
        Point::Origin
    } else {
        Point::Specific(
            slot.parse().expect("a slot is a number"),
            hex::decode(hash).expect("a point hash is hex"),
        )
    }
}

fn peer_of(addr: &str) -> PeerId {
    addr.parse().expect("a peer is host:port")
}

/// The protocol version a header names, for the header shapes of Babbage and
/// later. An earlier shape names it in a place this tool does not read, and
/// answers `None` rather than a version it did not find.
fn protocol_version(header: &MultiEraHeader) -> Option<(u64, u64)> {
    if let Some(h) = header.as_dijkstra() {
        return Some(h.header_body.protocol_version);
    }
    if let Some(h) = header.as_babbage() {
        return Some(h.header_body.protocol_version);
    }
    None
}

async fn run_index(args: &[String]) {
    let (addr, magic, from_slot, from_hash, out, stop_slot) = (
        &args[0],
        args[1].parse::<u64>().unwrap(),
        &args[2],
        &args[3],
        PathBuf::from(&args[4]),
        args[5].parse::<u64>().unwrap(),
    );

    let mut net = Net::new(magic);
    net.execute(InitiatorCommand::IncludePeer(peer_of(addr)));

    let mut file = fs::File::create(&out).expect("the index file is writable");
    writeln!(
        file,
        "block_no\tslot\thash\tvariant\tpv_major\tpv_minor\tann_hash\tann_size\tcert"
    )
    .unwrap();

    let mut rows = 0u64;
    let mut started = false;

    while let Some(evt) = net.next(Duration::from_secs(30)).await {
        match evt {
            InitiatorEvent::PeerInitialized(pid, (version, _)) => {
                tracing::info!(%pid, version, "peer initialized");
                if !started {
                    started = true;
                    net.execute(InitiatorCommand::StartSync(vec![point_of(
                        from_slot, from_hash,
                    )]));
                }
            }
            InitiatorEvent::IntersectionFound(pid, point, _) => {
                tracing::info!(?point, "intersection found");
                net.execute(InitiatorCommand::ContinueSync(pid));
            }
            InitiatorEvent::RollbackReceived(pid, _, _) => {
                net.execute(InitiatorCommand::ContinueSync(pid));
            }
            InitiatorEvent::BlockHeaderReceived(pid, content, _) => {
                let subtag = content.byron_prefix.map(|(s, _)| s);
                let header = MultiEraHeader::decode(content.variant, subtag, &content.cbor)
                    .expect("a served header decodes");

                let (pv_major, pv_minor) = match protocol_version(&header) {
                    Some((major, minor)) => (major.to_string(), minor.to_string()),
                    None => ("-".to_string(), "-".to_string()),
                };
                let (ann_hash, ann_size) = match header.eb_announcement() {
                    Some(a) => (hex::encode(a.eb_hash), a.eb_size),
                    None => ("-".to_string(), 0),
                };

                writeln!(
                    file,
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    header.number(),
                    header.slot(),
                    header.hash(),
                    content.variant,
                    pv_major,
                    pv_minor,
                    ann_hash,
                    ann_size,
                    match header.block_body_contains_leios_cert() {
                        Some(flag) => flag.to_string(),
                        None => "-".to_string(),
                    },
                )
                .unwrap();

                rows += 1;
                if rows % 5000 == 0 {
                    tracing::info!(rows, slot = header.slot(), "indexing");
                }

                if header.slot() >= stop_slot {
                    tracing::info!(rows, slot = header.slot(), "reached the stop slot");
                    return;
                }

                net.execute(InitiatorCommand::ContinueSync(pid));
            }
            _ => {}
        }
    }

    tracing::info!(rows, "chain-sync went idle");
}

/// Names the certificate kinds in a transaction, separating a pool
/// registration that carries a BLS key from one that does not, because the
/// two are the same kind and only the key tells them apart.
fn cert_kinds(tx: &pallas_traverse::MultiEraTx) -> Vec<String> {
    let mut out = Vec::new();

    for cert in tx.certs() {
        let name = match cert.bls_key() {
            BlsKeySlot::Key(_) => "pool_registration_bls".to_string(),
            BlsKeySlot::Null => "pool_registration_null_bls".to_string(),
            BlsKeySlot::NoSlot => "pool_registration_no_bls".to_string(),
            BlsKeySlot::NotAPoolRegistration => match cert.kind() {
                Some(kind) => format!("{kind:?}")
                    .split_whitespace()
                    .next()
                    .unwrap_or("other")
                    .trim_end_matches('(')
                    .to_string(),
                None => "none".to_string(),
            },
        };
        out.push(name);
    }

    out
}

async fn run_scan(args: &[String]) {
    let (addr, magic, from_slot, from_hash, to_slot, to_hash, out, dir) = (
        &args[0],
        args[1].parse::<u64>().unwrap(),
        &args[2],
        &args[3],
        &args[4],
        &args[5],
        PathBuf::from(&args[6]),
        PathBuf::from(&args[7]),
    );

    fs::create_dir_all(&dir).expect("the block directory is writable");

    let mut net = Net::new(magic);
    net.execute(InitiatorCommand::IncludePeer(peer_of(addr)));

    let mut file = fs::File::create(&out).expect("the scan file is writable");
    writeln!(file, "slot\thash\ttxs\tcerts\ttx_hashes").unwrap();

    let last_slot: u64 = to_slot.parse().unwrap();
    let mut started = false;
    let mut blocks = 0u64;

    while let Some(evt) = net.next(Duration::from_secs(60)).await {
        match evt {
            InitiatorEvent::PeerInitialized(pid, _) => {
                if !started {
                    started = true;
                    tracing::info!(%pid, "requesting the range");
                    net.execute(InitiatorCommand::RequestBlocks((
                        point_of(from_slot, from_hash),
                        point_of(to_slot, to_hash),
                    )));
                }
            }
            InitiatorEvent::BlockBodyReceived(_, body) => {
                let block = MultiEraBlock::decode(&body).expect("a served block decodes");
                let slot = block.slot();
                let hash = block.hash();

                let txs = block.txs();
                let mut certs: Vec<String> = Vec::new();
                for tx in &txs {
                    certs.extend(cert_kinds(tx));
                }
                let tx_hashes: Vec<String> =
                    txs.iter().map(|tx| tx.hash().to_string()).collect();

                fs::write(
                    dir.join(format!("{slot}.block")),
                    hex::encode(&body).as_bytes(),
                )
                .expect("a block file is writable");

                writeln!(
                    file,
                    "{}\t{}\t{}\t{}\t{}",
                    slot,
                    hash,
                    txs.len(),
                    if certs.is_empty() {
                        "-".to_string()
                    } else {
                        certs.join(",")
                    },
                    if tx_hashes.is_empty() {
                        "-".to_string()
                    } else {
                        tx_hashes.join(",")
                    },
                )
                .unwrap();

                blocks += 1;
                if blocks % 200 == 0 {
                    tracing::info!(blocks, slot, "scanning");
                }

                if slot >= last_slot {
                    tracing::info!(blocks, slot, "reached the end of the range");
                    return;
                }
            }
            _ => {}
        }
    }

    tracing::info!(blocks, "block-fetch went idle");
}

/// Walks a range of blocks and writes a row for each of three things a block
/// can carry that make the strict apply rule reject it, writing no blocks at
/// all, because a chain wide pass over the bodies does not fit on disk.
///
/// A range that carried none of the three writes a header row and nothing
/// else, and the closing counts say how many blocks and transactions the run
/// read, so an empty answer states what it is an answer about.
async fn run_dups(args: &[String]) {
    let (addr, magic, from_slot, from_hash, to_slot, to_hash, out) = (
        &args[0],
        args[1].parse::<u64>().unwrap(),
        &args[2],
        &args[3],
        &args[4],
        &args[5],
        PathBuf::from(&args[6]),
    );

    let mut net = Net::new(magic);
    net.execute(InitiatorCommand::IncludePeer(peer_of(addr)));

    let mut file = fs::File::create(&out).expect("the report file is writable");
    writeln!(file, "slot\tkind\tdetail").unwrap();

    let last_slot: u64 = to_slot.parse().unwrap();
    let mut started = false;
    let mut blocks = 0u64;
    let mut transactions = 0u64;
    let mut first_seen: std::collections::HashMap<Hash<32>, u64> = std::collections::HashMap::new();
    let mut found = (0u64, 0u64, 0u64);

    while let Some(evt) = net.next(Duration::from_secs(60)).await {
        match evt {
            InitiatorEvent::PeerInitialized(pid, _) => {
                if !started {
                    started = true;
                    tracing::info!(%pid, "requesting the range");
                    net.execute(InitiatorCommand::RequestBlocks((
                        point_of(from_slot, from_hash),
                        point_of(to_slot, to_hash),
                    )));
                }
            }
            InitiatorEvent::BlockBodyReceived(_, body) => {
                let block = MultiEraBlock::decode(&body).expect("a served block decodes");
                let slot = block.slot();
                let txs = block.txs();

                let hashes: Vec<Hash<32>> = txs.iter().map(|tx| tx.hash()).collect();
                let position: std::collections::HashMap<Hash<32>, usize> =
                    hashes.iter().enumerate().map(|(i, h)| (*h, i)).collect();

                for (i, tx) in txs.iter().enumerate() {
                    for input in tx.consumes() {
                        if let Some(&at) = position.get(input.hash()) {
                            if at > i {
                                writeln!(
                                    file,
                                    "{slot}\tforward_ref\tspender {i} produced_by {at} ref {}#{}",
                                    input.hash(),
                                    input.index()
                                )
                                .unwrap();
                                found.0 += 1;
                            }
                        }
                    }
                }

                let mut within: std::collections::HashMap<Hash<32>, usize> =
                    std::collections::HashMap::new();
                for (i, h) in hashes.iter().enumerate() {
                    match within.get(h) {
                        Some(&at) => {
                            writeln!(
                                file,
                                "{slot}\trepeat_within_block\tfirst {at} again {i} tx {h}"
                            )
                            .unwrap();
                            found.1 += 1;
                        }
                        None => {
                            within.insert(*h, i);
                        }
                    }
                }

                for h in &hashes {
                    transactions += 1;
                    match first_seen.get(h) {
                        Some(&earlier) if earlier != slot => {
                            writeln!(
                                file,
                                "{slot}\trepeat_across_blocks\tfirst_slot {earlier} tx {h}"
                            )
                            .unwrap();
                            found.2 += 1;
                        }
                        Some(_) => {}
                        None => {
                            first_seen.insert(*h, slot);
                        }
                    }
                }

                blocks += 1;
                if blocks % 2000 == 0 {
                    tracing::info!(
                        blocks,
                        slot,
                        transactions,
                        forward_refs = found.0,
                        within = found.1,
                        across = found.2,
                        "walking"
                    );
                }

                if slot >= last_slot {
                    break;
                }
            }
            _ => {}
        }
    }

    println!(
        "blocks {blocks}\ttransactions {transactions}\tforward_refs {}\trepeat_within_block {}\trepeat_across_blocks {}",
        found.0, found.1, found.2
    );
}

/// Counts the transactions an endorser block body commits to, which is the
/// entry count of its `{ tx_hash => size }` map.
fn eb_tx_count(body: &[u8]) -> usize {
    let mut d = Decoder::new(body);
    match d.map() {
        Ok(Some(n)) => n as usize,
        Ok(None) => {
            let mut n = 0;
            while !matches!(d.datatype(), Ok(Type::Break)) {
                if d.skip().is_err() || d.skip().is_err() {
                    break;
                }
                n += 1;
            }
            n
        }
        Err(_) => 0,
    }
}

async fn run_eb(args: &[String]) {
    let (addr, magic, slot, hash, dir, name) = (
        &args[0],
        args[1].parse::<u64>().unwrap(),
        args[2].parse::<u64>().unwrap(),
        &args[3],
        PathBuf::from(&args[4]),
        &args[5],
    );

    fs::create_dir_all(&dir).expect("the endorser block directory is writable");

    let eb: EbId = Point::Specific(slot, hex::decode(hash).expect("an endorser hash is hex"));

    let mut net = Net::new(magic);
    net.execute(InitiatorCommand::IncludePeer(peer_of(addr)));

    let mut peer: Option<PeerId> = None;
    let mut body: Option<Vec<u8>> = None;
    let mut total = 0usize;
    let mut next_window = 0usize;
    let mut txs: BTreeMap<usize, Vec<u8>> = BTreeMap::new();

    while let Some(evt) = net.next(Duration::from_secs(60)).await {
        match evt {
            InitiatorEvent::PeerInitialized(pid, _) => {
                if peer.is_none() {
                    peer = Some(pid.clone());
                    net.execute(InitiatorCommand::FetchEb(pid, eb.clone()));
                }
            }
            InitiatorEvent::EbFetched(pid, _, leiosfetch::Response::Block(raw)) => {
                let bytes = raw.raw_bytes().to_vec();
                total = eb_tx_count(&bytes);
                tracing::info!(bytes = bytes.len(), total, "endorser block body fetched");
                body = Some(bytes);

                if total == 0 {
                    break;
                }
                let end = total.min(WINDOW);
                net.execute(InitiatorCommand::FetchEbTxs(
                    pid,
                    eb.clone(),
                    leiosfetch::Bitmaps::from_indices(0..end),
                ));
                next_window = 1;
            }
            InitiatorEvent::EbFetched(pid, _, leiosfetch::Response::BlockTxs { txs: got }) => {
                let base = (next_window - 1) * WINDOW;
                for (i, tx) in got.iter().enumerate() {
                    txs.insert(base + i, tx.raw_bytes().to_vec());
                }
                tracing::info!(window = next_window - 1, got = got.len(), have = txs.len(), "transactions fetched");

                if txs.len() >= total {
                    break;
                }

                let start = next_window * WINDOW;
                if start >= total {
                    break;
                }
                let end = total.min(start + WINDOW);
                net.execute(InitiatorCommand::FetchEbTxs(
                    pid,
                    eb.clone(),
                    leiosfetch::Bitmaps::from_indices(start..end),
                ));
                next_window += 1;
            }
            _ => {}
        }
    }

    let Some(body) = body else {
        tracing::error!(slot, hash, "the peer served no body for this endorser block");
        std::process::exit(3);
    };

    fs::write(dir.join(format!("{name}.ebbody")), hex::encode(&body)).unwrap();

    let mut lines = String::new();
    for i in 0..total {
        match txs.get(&i) {
            Some(tx) => {
                lines.push_str(&hex::encode(tx));
                lines.push('\n');
            }
            None => {
                tracing::error!(index = i, "a transaction of this endorser block never arrived");
                std::process::exit(4);
            }
        }
    }
    fs::write(dir.join(format!("{name}.ebtxs")), lines).unwrap();

    println!(
        "{name}\tslot={slot}\tbody_hash={}\tbody_bytes={}\ttxs={total}",
        Hasher::<256>::hash(&body),
        body.len()
    );
}

/// Reports, for one harvested endorser payload, the two shapes inside a single
/// payload that a strict apply rejects, and how many transactions it read.
fn run_ebcheck(args: &[String]) {
    for prefix in args {
        let text = fs::read_to_string(format!("{prefix}.ebtxs"))
            .expect("the harvested endorser transactions are readable");

        // The wire carries each transaction inside a CBOR byte string, and the
        // file keeps it that way, so the envelope comes off before a decode.
        let raw: Vec<Vec<u8>> = text
            .split_whitespace()
            .map(|line| {
                let wire = hex::decode(line).expect("an endorser transaction is hex");
                Decoder::new(&wire)
                    .bytes()
                    .expect("an endorser transaction arrives in a byte string")
                    .to_vec()
            })
            .collect();

        let decoded: Vec<pallas_traverse::MultiEraTx> = raw
            .iter()
            .map(|bytes| {
                pallas_traverse::MultiEraTx::decode_for_era(pallas_traverse::Era::Dijkstra, bytes)
                    .expect("an endorser transaction decodes for Dijkstra")
            })
            .collect();

        let position: std::collections::HashMap<Hash<32>, usize> = decoded
            .iter()
            .enumerate()
            .map(|(i, tx)| (tx.hash(), i))
            .collect();

        let mut forward = 0usize;
        for (i, tx) in decoded.iter().enumerate() {
            for input in tx.consumes() {
                if let Some(&at) = position.get(input.hash()) {
                    if at > i {
                        println!(
                            "{prefix}\tforward_ref\tspender {i} produced_by {at} ref {}#{}",
                            input.hash(),
                            input.index()
                        );
                        forward += 1;
                    }
                }
            }
        }

        let repeats = decoded.len() - position.len();

        println!(
            "{prefix}\ttransactions {}\tforward_refs {forward}\trepeat_within_payload {repeats}",
            decoded.len()
        );
    }
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} names the provenance this harvest records"))
}

fn append_provenance(dir: &Path, entry: &str) {
    let path = dir.join("provenance.toml");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("the provenance file is writable");
    file.write_all(entry.as_bytes()).unwrap();
}

fn run_pick(args: &[String]) {
    let kind_of_file = args[0].as_str();

    match kind_of_file {
        "block" => {
            let (src, expected, dir, name, kind, how) = (
                PathBuf::from(&args[1]),
                &args[2],
                PathBuf::from(&args[3]),
                &args[4],
                &args[5],
                &args[6],
            );

            let hex_text = fs::read_to_string(&src).expect("the harvested block is readable");
            let raw = hex::decode(hex_text.trim()).expect("a harvested block is hex");
            let block = MultiEraBlock::decode(&raw).expect("a harvested block decodes");
            let computed = block.header().hash().to_string();

            if &computed != expected {
                eprintln!("refused {name}: the header hashes to {computed}, the node reported {expected}");
                std::process::exit(5);
            }

            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(format!("{name}.block")), hex::encode(&raw)).unwrap();

            append_provenance(
                &dir,
                &format!(
                    "\n[[fixture]]\nname = \"{name}\"\nkind = \"{kind}\"\nfiles = [\"{name}.block\"]\nchain_tag = \"{}\"\nnetwork_magic = {}\nslot = {}\nblock_hash = \"{computed}\"\ntransactions = {}\nbytes = {}\nlocated_by = \"{how}\"\nharvested_at = \"{}\"\nrelay = \"{}\"\ntool_rev = \"{}\"\nnode_image = \"{}\"\ntip_slot = {}\ntip_hash = \"{}\"\n",
                    env("HARVEST_TAG"),
                    env("HARVEST_MAGIC"),
                    block.slot(),
                    block.tx_count(),
                    raw.len(),
                    env("HARVEST_AT"),
                    env("HARVEST_RELAY"),
                    env("HARVEST_TOOL_REV"),
                    env("HARVEST_NODE_IMAGE"),
                    env("HARVEST_TIP_SLOT"),
                    env("HARVEST_TIP_HASH"),
                ),
            );

            println!("picked {name} slot {} hash {computed}", block.slot());
        }
        "eb" => {
            let (src, expected, slot, dir, name, kind, how) = (
                args[1].clone(),
                &args[2],
                &args[3],
                PathBuf::from(&args[4]),
                &args[5],
                &args[6],
                &args[7],
            );

            let body_hex = fs::read_to_string(format!("{src}.ebbody"))
                .expect("the harvested endorser body is readable");
            let body = hex::decode(body_hex.trim()).expect("an endorser body is hex");
            let computed = Hasher::<256>::hash(&body).to_string();

            if &computed != expected {
                eprintln!("refused {name}: the body hashes to {computed}, the block announced {expected}");
                std::process::exit(5);
            }

            let txs_text = fs::read_to_string(format!("{src}.ebtxs"))
                .expect("the harvested endorser transactions are readable");
            let count = txs_text.split_whitespace().count();
            let committed = eb_tx_count(&body);
            if count != committed {
                eprintln!("refused {name}: {count} transactions on file, the body commits to {committed}");
                std::process::exit(6);
            }

            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(format!("{name}.ebbody")), hex::encode(&body)).unwrap();
            fs::write(dir.join(format!("{name}.ebtxs")), &txs_text).unwrap();

            append_provenance(
                &dir,
                &format!(
                    "\n[[fixture]]\nname = \"{name}\"\nkind = \"{kind}\"\nfiles = [\"{name}.ebbody\", \"{name}.ebtxs\"]\nchain_tag = \"{}\"\nnetwork_magic = {}\nslot = {slot}\nendorser_hash = \"{computed}\"\ntransactions = {count}\nbytes = {}\nlocated_by = \"{how}\"\nharvested_at = \"{}\"\nrelay = \"{}\"\ntool_rev = \"{}\"\nnode_image = \"{}\"\ntip_slot = {}\ntip_hash = \"{}\"\n",
                    env("HARVEST_TAG"),
                    env("HARVEST_MAGIC"),
                    body.len(),
                    env("HARVEST_AT"),
                    env("HARVEST_RELAY"),
                    env("HARVEST_TOOL_REV"),
                    env("HARVEST_NODE_IMAGE"),
                    env("HARVEST_TIP_SLOT"),
                    env("HARVEST_TIP_HASH"),
                ),
            );

            println!("picked {name} slot {slot} endorser hash {computed} transactions {count}");
        }
        other => {
            eprintln!("pick takes block or eb, not {other}");
            std::process::exit(2);
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let argv: Vec<String> = std::env::args().collect();
    let Some(cmd) = argv.get(1) else {
        eprintln!("usage: harvest index|scan|dups|eb|ebcheck|pick ...");
        std::process::exit(2);
    };
    let rest: Vec<String> = argv[2..].to_vec();

    match cmd.as_str() {
        "index" => run_index(&rest).await,
        "scan" => run_scan(&rest).await,
        "dups" => run_dups(&rest).await,
        "eb" => run_eb(&rest).await,
        "ebcheck" => run_ebcheck(&rest),
        "pick" => run_pick(&rest),
        other => {
            eprintln!("unknown subcommand {other}");
            std::process::exit(2);
        }
    }
}
