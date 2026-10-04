use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;

/// One block as `capture_blocks.py` indexed it.
#[derive(Clone, Debug)]
pub struct Indexed {
    pub era: u64,
    pub slot: u64,
    pub blockno: u64,
    pub hash: [u8; 32],
    pub chunk: String,
    pub ordinal: usize,
}

/// Reads `index.jsonl` in chain order.
pub fn index(dir: &Path) -> Vec<Indexed> {
    let file = File::open(dir.join("index.jsonl")).expect("an index.jsonl");
    BufReader::new(file)
        .lines()
        .map(|line| {
            let v: serde_json::Value = serde_json::from_str(&line.expect("a line")).expect("json");
            Indexed {
                era: v["era"].as_u64().expect("an era"),
                slot: v["slot"].as_u64().expect("a slot"),
                blockno: v["blockno"].as_u64().expect("a block number"),
                hash: hex::decode(v["hash"].as_str().expect("a hash"))
                    .expect("hex")
                    .try_into()
                    .expect("32 bytes"),
                chunk: v["chunk"].as_str().expect("a chunk").to_owned(),
                ordinal: v["ordinal"].as_u64().expect("an ordinal") as usize,
            }
        })
        .collect()
}

/// Reads the length prefixed `[era, block]` records of one chunk file.
pub fn chunk(path: &PathBuf) -> Vec<Vec<u8>> {
    let mut reader = GzDecoder::new(File::open(path).expect("a chunk file"));
    let mut out = Vec::new();
    loop {
        let mut len = [0u8; 4];
        match reader.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return out,
            Err(e) => panic!("{}: {e}", path.display()),
        }
        let mut record = vec![0; u32::from_be_bytes(len) as usize];
        reader.read_exact(&mut record).expect("a whole record");
        out.push(record);
    }
}

/// Calls `visit` on each indexed block in chain order up to and including the block named by `last`, and returns how many it visited.
pub fn each_block(
    dir: &Path,
    last: &[u8; 32],
    mut visit: impl FnMut(&Indexed, &[u8]),
) -> Option<usize> {
    let index = index(dir);
    let mut loaded: Option<(String, Vec<Vec<u8>>)> = None;
    for (n, entry) in index.iter().enumerate() {
        if loaded.as_ref().is_none_or(|(name, _)| *name != entry.chunk) {
            let records = chunk(&dir.join("chunks").join(&entry.chunk));
            loaded = Some((entry.chunk.clone(), records));
        }
        let records = &loaded.as_ref().expect("a loaded chunk").1;
        visit(entry, &records[entry.ordinal]);
        if &entry.hash == last {
            return Some(n + 1);
        }
    }
    None
}
