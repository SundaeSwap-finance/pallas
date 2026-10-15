//! Read original Dolos flatfile frames, bypassing certificate API/index filters.
use pallas_codec::minicbor::Decoder;
use pallas_traverse::{MultiEraBlock, MultiEraHeader};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Read},
    path::Path,
};

struct Record {
    number: u64,
    slot: u64,
    hash: String,
    previous: Option<String>,
    bytes: usize,
    events: Vec<Value>,
    raw: Option<Vec<u8>>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        5,
        "archive-directory dictionary-file fixture-directory output-directory"
    );
    let fixture = Path::new(&args[3]);
    let out = Path::new(&args[4]);
    fs::create_dir_all(out)?;
    let manifest: Value = serde_json::from_slice(&fs::read(fixture.join("provenance.json"))?)?;
    let mut credentials = Vec::new();
    for case in manifest["cases"].as_array().unwrap() {
        for cert in case["certificates"].as_array().unwrap() {
            credentials.push(hex::decode(cert[1][1].as_str().unwrap())?);
        }
    }
    assert_eq!(credentials.len(), 5);
    let genesis = fs::read(fixture.join("context/shelley-genesis.json"))?;
    let genesis_text = String::from_utf8(genesis.clone())?;
    for credential in &credentials {
        assert!(
            !genesis_text
                .to_lowercase()
                .contains(&hex::encode(credential)),
            "credential occurs in genesis; inspect initial state explicitly"
        );
    }
    let dictionary = fs::read(&args[2])?;
    let mut files: Vec<_> = fs::read_dir(&args[1])?
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|s| s == "segment"))
        .collect();
    files.sort();
    let mut records: BTreeMap<String, Record> = BTreeMap::new();
    let mut frames = 0;
    let mut source_files = Vec::new();
    for path in files {
        let before = fs::metadata(&path)?;
        let mut source_hash = Sha256::new();
        let mut digest_reader = BufReader::new(fs::File::open(&path)?);
        let mut buf = vec![0; 1 << 20];
        loop {
            let n = digest_reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            source_hash.update(&buf[..n]);
        }
        source_files.push(json!({"file": path.file_name().unwrap().to_str().unwrap(), "bytes": fs::metadata(&path)?.len(), "sha256": hex::encode(source_hash.finalize())}));
        let mut reader = BufReader::new(fs::File::open(&path)?);
        while !reader.fill_buf()?.is_empty() {
            let mut raw = Vec::new();
            zstd::stream::read::Decoder::with_dictionary(&mut reader, &dictionary)?
                .single_frame()
                .read_to_end(&mut raw)?;
            frames += 1;
            let mut d = Decoder::new(&raw);
            d.array()?;
            let tag = d.u8()?;
            assert!(
                tag >= 2,
                "unexpected Byron envelope; extend header reader before claiming coverage"
            );
            d.array()?;
            let start = d.position();
            d.skip()?;
            let header = MultiEraHeader::decode(tag - 1, None, &raw[start..d.position()])?;
            if header.slot() > 1_404_987 {
                continue;
            }
            let mut events = Vec::new();
            let block = MultiEraBlock::decode(&raw)?;
            let txs = block.txs();
            for tx in &txs {
                for level in std::iter::once(tx.clone()).chain(tx.sub_transactions()) {
                    for proposal in level.gov_proposals() {
                        events.push(json!({"transaction_id": level.hash().to_string(), "proposal": format!("{proposal:?}"), "successful_archive_view": level.is_valid()}));
                    }
                }
            }
            let record = Record {
                number: header.number(),
                slot: header.slot(),
                hash: header.hash().to_string(),
                previous: header.previous_hash().map(|h| h.to_string()),
                bytes: raw.len(),
                raw: if events.is_empty() {
                    None
                } else {
                    Some(raw.clone())
                },
                events,
            };
            if records
                .get(&record.hash)
                .is_none_or(|old| old.bytes < record.bytes)
            {
                records.insert(record.hash.clone(), record);
            }
        }
        eprintln!("{}: {frames} frames read", path.display());
        let after = fs::metadata(&path)?;
        assert_eq!(
            before.len(),
            after.len(),
            "archive changed; use a frozen copy"
        );
        assert_eq!(
            before.modified()?,
            after.modified()?,
            "archive changed; use a frozen copy"
        );
    }
    // Anchor the scan to a separately fetched, successful fixture ranking block.
    let mut cursor = "1b2f5a402789360fbe155f1681f7306032817c1140bf1c7dbf9e0b431ad8d958".to_owned();
    let mut chain = Vec::new();
    loop {
        let r = records.remove(&cursor).expect("missing parent in archive");
        let previous = r.previous.clone();
        chain.push(r);
        match previous {
            Some(p) => cursor = p,
            None => break,
        }
    }
    chain.reverse();
    assert_eq!(chain[0].number, 0);
    for pair in chain.windows(2) {
        assert_eq!(pair[1].number, pair[0].number + 1);
        assert!(pair[1].slot >= pair[0].slot);
    }
    let mut chain_digest = Sha256::new();
    let mut events = Vec::new();
    for r in &chain {
        chain_digest.update(format!("{}\t{}\t{}\n", r.number, r.slot, r.hash));
        for event in &r.events {
            let mut event = event.clone();
            event["slot"] = json!(r.slot);
            event["block_number"] = json!(r.number);
            event["block_hash"] = json!(r.hash);
            event["archive_block"] = json!(format!("{}.archive.block", r.slot));
            events.push(event);
        }
        if let Some(raw) = &r.raw {
            fs::write(
                out.join(format!("{}.archive.block", r.slot)),
                hex::encode(raw),
            )?;
        }
    }
    let result = json!({"tool": "musashi-parameter-history", "archive": args[1], "source_segments": source_files, "dictionary_sha256": hex::encode(Sha256::digest(dictionary)), "shelley_genesis_sha256": hex::encode(Sha256::digest(genesis)), "initial_credentials_absent": credentials.iter().map(hex::encode).collect::<Vec<_>>(), "frames_read": frames, "canonical_blocks": chain.len(), "first_slot": chain[0].slot, "last_slot": chain.last().unwrap().slot, "last_hash": chain.last().unwrap().hash, "continuity": "all parent hashes present; block numbers consecutive from zero", "ordered_header_inventory_sha256": hex::encode(chain_digest.finalize()), "events": events, "limits": "Dolos expanded archive trust; this verifies header continuity, not full consensus or all endorser commitments. Certificate CBOR is re-encoded for reporting; original archive blocks retained."});
    fs::write(out.join("scan.json"), serde_json::to_vec_pretty(&result)?)?;
    println!(
        "{} canonical blocks; {} governance proposals",
        chain.len(),
        result["events"].as_array().unwrap().len()
    );
    Ok(())
}
