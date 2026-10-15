use pallas_traverse::MultiEraBlock;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader, Read},
    path::Path,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let archive = Path::new(&args[1]);
    let out = Path::new(&args[3]);
    fs::create_dir_all(out)?;
    let targets: Vec<String> = serde_json::from_slice(&fs::read(&args[4])?)?;
    let targets: BTreeSet<_> = targets.into_iter().collect();
    let dict = fs::read(&args[2])?;
    let mut files: Vec<_> = fs::read_dir(archive)?
        .map(|x| x.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "segment"))
        .collect();
    files.sort();
    let mut found = BTreeMap::new();
    let mut frames = 0;
    let credentials = vec![
        "550fafb22a38e9df21ca1735f9eb7ec4ca75fb6efcd2a6d0d2c7d69b",
        "aabeb9796cfbf5847e567e16adb0d021632bd16685458d67a8f9a09f",
    ];
    let needles: Vec<_> = credentials
        .iter()
        .map(|h| hex::decode(h).unwrap())
        .collect();
    let mut history: BTreeMap<String, (Option<String>, u64, usize, Vec<serde_json::Value>)> =
        BTreeMap::new();
    for path in files {
        let mut reader = BufReader::new(fs::File::open(&path)?);
        while !reader.fill_buf()?.is_empty() {
            let mut raw = vec![];
            zstd::stream::read::Decoder::with_dictionary(&mut reader, &dict)?
                .single_frame()
                .read_to_end(&mut raw)?;
            frames += 1;
            if frames % 10000 == 0 {
                eprintln!("frames {frames}");
            }
            let block = MultiEraBlock::decode(&raw)?;
            let mut events = vec![];
            let transactions = block.txs();
            for tx in &transactions {
                for level in std::iter::once(tx.clone()).chain(tx.sub_transactions()) {
                    if level.is_valid() {
                        for cert in level.certs() {
                            let raw = if let Some(c) = cert.as_dijkstra() {
                                pallas_codec::minicbor::to_vec(c)?
                            } else if let Some(c) = cert.as_conway() {
                                pallas_codec::minicbor::to_vec(c)?
                            } else if let Some(c) = cert.as_alonzo() {
                                pallas_codec::minicbor::to_vec(c)?
                            } else {
                                return Err("unknown certificate era".into());
                            };
                            if needles.iter().any(|n| raw.windows(28).any(|w| w == n)) {
                                events.push(json!({"transaction":tx.hash().to_string(),"kind":"certificate","cbor":hex::encode(raw),"decoded":format!("{cert:?}")}));
                            }
                        }
                        for (address, amount) in level.withdrawals_sorted_set() {
                            if needles.iter().any(|n| address.ends_with(n)) {
                                events.push(json!({"transaction":tx.hash().to_string(),"kind":"withdrawal","address":hex::encode(address),"amount":amount}));
                            }
                        }
                        if let Some(native) = level.as_dijkstra() {
                            for (address, amount) in native
                                .transaction_body
                                .direct_deposits
                                .iter()
                                .flat_map(|x| x.iter())
                            {
                                if needles.iter().any(|n| address.ends_with(n)) {
                                    events.push(json!({"transaction":tx.hash().to_string(),"kind":"direct_deposit","address":hex::encode(address.as_slice()),"amount":amount}));
                                }
                            }
                        }
                        if let Some(native) = level.as_dijkstra_sub() {
                            for (address, amount) in native
                                .sub_transaction_body
                                .direct_deposits
                                .iter()
                                .flat_map(|x| x.iter())
                            {
                                if needles.iter().any(|n| address.ends_with(n)) {
                                    events.push(json!({"transaction":level.hash().to_string(),"kind":"direct_deposit","address":hex::encode(address.as_slice()),"amount":amount}));
                                }
                            }
                        }
                    }
                }
                let hash = tx.hash().to_string();
                if !targets.contains(&hash) {
                    continue;
                }
                if found.contains_key(&hash) {
                    continue;
                }
                let native = tx.as_dijkstra().ok_or("target not native")?;
                let body = native.transaction_body.raw_cbor();
                fs::write(
                    out.join(format!("{hash}.body.hex")),
                    hex::encode(body) + "\n",
                )?;
                for (i, o) in tx.outputs().iter().enumerate() {
                    fs::write(
                        out.join(format!("{hash}.{i}.output.hex")),
                        hex::encode(o.encode()) + "\n",
                    )?;
                }
                fs::write(
                    out.join(format!("{hash}.tx.hex")),
                    hex::encode(pallas_codec::minicbor::to_vec(
                        native.to_mempool_transaction(),
                    )?) + "\n",
                )?;
                found.insert(hash,json!({"slot":block.slot(),"block":block.hash().to_string(),"success":tx.is_valid(),"source_segment":path.file_name().unwrap().to_str().unwrap()}));
            }
            let hash = block.hash().to_string();
            if history.get(&hash).is_none_or(|old| old.2 < raw.len()) {
                history.insert(
                    hash,
                    (
                        block.header().previous_hash().map(|h| h.to_string()),
                        block.slot(),
                        raw.len(),
                        events,
                    ),
                );
            }
        }
    }
    if std::env::var_os("CAPTURE_ONLY").is_some() {
        fs::write(
            out.join("scan.json"),
            serde_json::to_vec_pretty(&json!({"frames":frames,"found":found}))?,
        )?;
        return Ok(());
    }
    let mut cursor = "1b2f5a402789360fbe155f1681f7306032817c1140bf1c7dbf9e0b431ad8d958".to_owned();
    let mut account_history = vec![];
    let mut headers = 0;
    loop {
        let (parent, slot, _, events) = history.get(&cursor).ok_or("missing canonical parent")?;
        headers += 1;
        if !events.is_empty() {
            account_history.push(json!({"slot":slot,"block":cursor,"events":events}));
        }
        if let Some(parent) = parent {
            cursor = parent.clone();
        } else {
            break;
        }
    }
    account_history.reverse();
    fs::write(
        out.join("account-history.json"),
        serde_json::to_vec_pretty(
            &json!({"credentials":credentials,"canonical_headers":headers,"events":account_history,"limit":"successful transactions in the frozen Dolos expanded archive; not consensus validation or a node account-state dump"}),
        )?,
    )?;
    fs::write(
        out.join("scan.json"),
        serde_json::to_vec_pretty(
            &json!({"frames":frames,"found":found,"missing":targets.difference(&found.keys().cloned().collect()).collect::<Vec<_>>()}),
        )?,
    )?;
    println!(
        "scanned {frames} frames, found {} / {} targets",
        found.len(),
        targets.len()
    );
    Ok(())
}
