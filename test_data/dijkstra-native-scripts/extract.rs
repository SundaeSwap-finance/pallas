//! Read-only extraction from Dolos expanded archive segment frames.
//! Dependencies: local pallas-traverse (unstable), pallas-codec, hex, serde_json, zstd.
use pallas_traverse::MultiEraBlock;
use serde_json::json;
use std::{
    fs,
    io::{BufRead, BufReader, Read},
    path::Path,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let segment = Path::new(&args[1]);
    let dict = fs::read(&args[2])?;
    let out = Path::new(&args[3]);
    fs::create_dir_all(out)?;
    let mut r = BufReader::new(fs::File::open(segment)?);
    let mut found = std::collections::BTreeMap::new();
    let mut frames = 0;
    while !r.fill_buf()?.is_empty() {
        let mut raw = Vec::new();
        zstd::stream::read::Decoder::with_dictionary(&mut r, &dict)?
            .single_frame()
            .read_to_end(&mut raw)?;
        frames += 1;
        let block = MultiEraBlock::decode(&raw)?;
        for tx in block.txs() {
            let hash = tx.hash().to_string();
            let label = match hash.as_str() {
                "ca60ffd71d5dc8fa94ad7d0103183511004e0d42efd7b3a07e1aa6bfc19e5f69" => "mint",
                "f615fb416d70838b965ff08ae99a60d59e0f723a17918ff7dd1c921f376da52d" => "producer",
                _ => continue,
            };
            if found.contains_key(label) {
                continue;
            }
            let native = tx.as_dijkstra().ok_or("target is not Dijkstra")?;
            if label == "mint" {
                // Reconstruct only the mempool envelope. KeepRaw preserves signed fields.
                fs::write(
                    out.join("mint.tx.hex"),
                    hex::encode(pallas_codec::minicbor::to_vec(
                        native.to_mempool_transaction(),
                    )?) + "\n",
                )?;
            } else {
                fs::write(
                    out.join("producer.body.hex"),
                    hex::encode(native.transaction_body.raw_cbor()) + "\n",
                )?;
                fs::write(
                    out.join("mint.input.hex"),
                    hex::encode(tx.outputs()[0].encode()) + "\n",
                )?;
            }
            found.insert(label, json!({"transaction_id":hash,"slot":block.slot(),"block_hash":block.hash().to_string(),"archive_success":tx.is_valid(),"segment":segment.file_name().unwrap().to_str(),"frame":frames}));
        }
        if found.len() == 2 {
            break;
        }
    }
    if found.len() != 2 {
        return Err("missing target".into());
    }
    fs::write(
        out.join("extraction.json"),
        serde_json::to_vec_pretty(&found)?,
    )?;
    Ok(())
}
