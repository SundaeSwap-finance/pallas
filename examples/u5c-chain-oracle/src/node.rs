use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use pallas_addresses::Address;
use pallas_crypto::hash::Hasher;
use serde_json::Value;

use crate::model::{AccountOp, Credential, Effects, Origin, Output, RefScript, TxIn};

fn read(path: &Path) -> Value {
    let text = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn bytes(hex_text: &str) -> Vec<u8> {
    hex::decode(hex_text).unwrap_or_else(|e| panic!("{hex_text}: {e}"))
}

fn hash<const N: usize>(hex_text: &str) -> [u8; N] {
    bytes(hex_text)
        .try_into()
        .expect("a hash of the expected size")
}

/// The chain point the node state was read at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point {
    pub slot: u64,
    pub block: u64,
    pub hash: [u8; 32],
}

/// The node's view of one stake pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pool {
    pub vrf: Vec<u8>,
    pub bls: Option<(Vec<u8>, Vec<u8>)>,
}

/// Everything the node reported at one chain point.
pub struct NodeState {
    pub point: Point,
    pub utxo: HashMap<TxIn, Output>,
    pub accounts: HashMap<Credential, i128>,
    pub pools: HashMap<[u8; 28], Pool>,
    pub protocol_parameters: Value,
}

fn script(x: &Value) -> Option<RefScript> {
    let script = x.get("script")?;
    let kind = script.get("type")?.as_str()?;
    let version = match kind {
        "PlutusScriptV1" => 1,
        "PlutusScriptV2" => 2,
        "PlutusScriptV3" => 3,
        "PlutusScriptV4" => 4,
        _ => return Some(RefScript::Native),
    };
    Some(RefScript::Plutus(
        version,
        bytes(script.get("cborHex")?.as_str()?),
    ))
}

/// Reads one entry of `query utxo --output-json`.
pub fn output(x: &Value) -> Output {
    let address = x["address"].as_str().expect("an address");
    let address = Address::from_bech32(address)
        .unwrap_or_else(|e| panic!("{address}: {e}"))
        .to_vec();
    let mut coin = 0;
    let mut assets = BTreeMap::new();
    for (policy, v) in x["value"].as_object().expect("a value") {
        if policy == "lovelace" {
            coin = v.as_u64().expect("a coin");
            continue;
        }
        for (name, qty) in v.as_object().expect("an asset map") {
            assets.insert(
                (bytes(policy), bytes(name)),
                qty.as_u64().expect("a quantity"),
            );
        }
    }
    let datum_hash = x
        .get("datumhash")
        .and_then(Value::as_str)
        .or_else(|| x.get("inlineDatumhash").and_then(Value::as_str))
        .map(hash::<32>);
    Output {
        address,
        coin,
        assets,
        datum_hash,
        script: x.get("referenceScript").and_then(script),
    }
}

fn txin(key: &str) -> TxIn {
    let (id, index) = key.split_once('#').expect("a txid#index key");
    (hash::<32>(id), index.parse().expect("an output index"))
}

/// Reads the account name the ledger state uses into a credential.
pub fn credential(key: &str) -> Credential {
    let (kind, h) = key.split_once('-').expect("a kind-hash account key");
    Credential {
        script: kind == "scriptHash",
        hash: hash::<28>(h),
    }
}

/// Reads the state files that `pin_state.sh` writes.
pub fn load(dir: &Path) -> NodeState {
    let point = read(&dir.join("point.json"));
    let point = Point {
        slot: point["slot"].as_u64().expect("a slot"),
        block: point["block"].as_u64().expect("a block number"),
        hash: hash::<32>(point["hash"].as_str().expect("a hash")),
    };
    let utxo = read(&dir.join("utxo.json"))
        .as_object()
        .expect("a utxo map")
        .iter()
        .map(|(k, v)| (txin(k), output(v)))
        .collect();
    let ledger = read(&dir.join("ledger-state.json"));
    let delegation = &ledger["stateBefore"]["esLState"]["delegationState"];
    let accounts = delegation["dstate"]["accounts"]
        .as_object()
        .expect("an account map")
        .iter()
        .map(|(k, v)| {
            (
                credential(k),
                i128::from(v["balance"].as_u64().expect("a balance")),
            )
        })
        .collect();
    let mut pools = HashMap::new();
    for section in ["stakePools", "futureStakePoolParams"] {
        for (id, v) in delegation["pstate"][section]
            .as_object()
            .expect("a pool map")
        {
            let bls = v["spsBlsKey"]["bksKey"].as_object().map(|k| {
                (
                    bytes(k["blsPubKey"].as_str().expect("a key")),
                    bytes(k["blsPossessionProof"].as_str().expect("a proof")),
                )
            });
            let vrf = bytes(v["spsVrf"].as_str().expect("a vrf key hash"));
            pools.insert(hash::<28>(id), Pool { vrf, bls });
        }
    }
    NodeState {
        point,
        utxo,
        accounts,
        pools,
        protocol_parameters: read(&dir.join("protocol-parameters.json")),
    }
}

/// Lists the effects of the genesis file's initial funds, stake credentials and pools.
pub fn genesis(path: &Path) -> Vec<Effects> {
    let genesis = read(path);
    let extra = &genesis["extraConfig"];
    let mut produced = Vec::new();
    let funds = genesis["initialFunds"].as_object().into_iter().flatten();
    let extra_funds = extra["initialFunds"]["data"]
        .as_object()
        .into_iter()
        .flatten();
    for (address, coin) in funds.chain(extra_funds) {
        let address = bytes(address);
        let id: [u8; 32] = *Hasher::<256>::hash(&address);
        produced.push((
            (id, 0),
            Output {
                address,
                coin: coin.as_u64().expect("a coin"),
                assets: BTreeMap::new(),
                datum_hash: None,
                script: None,
            },
        ));
    }
    let mut accounts = Vec::new();
    for (cred, _pool) in extra["stakeCredentials"]["data"]
        .as_object()
        .into_iter()
        .flatten()
    {
        let cred = Credential {
            script: false,
            hash: hash::<28>(cred),
        };
        accounts.push(AccountOp::Register(cred));
        accounts.push(AccountOp::Delegate(cred));
    }
    for pool in extra["stakePools"]["data"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|x| x.1)
    {
        let cred = &pool["accountAddress"]["credential"];
        let (script, h) = match cred.get("keyHash") {
            Some(h) => (false, h),
            None => (true, &cred["scriptHash"]),
        };
        accounts.push(AccountOp::RewardTarget(Credential {
            script,
            hash: hash::<28>(h.as_str().expect("a credential hash")),
        }));
    }
    vec![Effects {
        origin: Origin {
            block: 0,
            top: [0; 32],
            sub: None,
        },
        spent: vec![],
        produced,
        accounts,
    }]
}
