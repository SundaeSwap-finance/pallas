//! Decodes each Dijkstra value of `test_data/dijkstra-ledger` and compares every leaf with the ledger's reading of it.
#![cfg(feature = "unstable")]

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

use pallas_codec::minicbor;
use pallas_codec::utils::{KeepRaw, Nullable};
use pallas_crypto::hash::Hasher;
use pallas_primitives::dijkstra as d;
use pallas_primitives::{BigInt, PlutusData, StakeCredential};
use serde_json::{Map, Value, json};

/// A disagreement the test accepts, by kind, class and field path, with the reason it stands.
struct Listed {
    kind: &'static str,
    class: &'static str,
    path: &'static str,
    reason: &'static str,
}

const LISTED: &[Listed] = &[Listed {
    kind: "eb",
    class: REFUSES,
    path: "",
    reason: "the pinned ledger writes eb_references as an array of pairs, and EndorserBlock reads the map the node sends over leios-fetch",
}];

/// The rules of `defs.cddl` no committed value credits, with the reason none does.
const UNCREDITED: &[(&str, &str)] = &[
    ("language", "no rule refers to it"),
    ("potential_languages", "no rule refers to it"),
    ("signkey_kes", "no rule refers to it"),
    ("eb_references", "pallas reads no value of it, see LISTED"),
    ("eb_reference", "pallas reads no value of it, see LISTED"),
];

const REFUSES: &str = "pallas refuses the value";
const LACKS: &str = "pallas lacks a leaf";
const EXTRA: &str = "pallas has an extra leaf";
const DIFFERS: &str = "a leaf differs";
const DUPLICATE: &str = "pallas holds a duplicate";
const REENCODING_REFUSED: &str = "pallas refuses its own encoding";
const REENCODING_DIFFERS: &str = "pallas encodes another value";

const KINDS: [&str; 6] = ["tx", "body", "wits", "ppu", "block", "eb"];

fn enc<T: minicbor::Encode<()>>(x: &T) -> Vec<u8> {
    minicbor::to_vec(x).expect("encode to a vec")
}

fn cb<T: minicbor::Encode<()>>(x: &T) -> Value {
    raw(&enc(x))
}

fn raw(bytes: &[u8]) -> Value {
    json!({ "cbor": hex::encode(bytes) })
}

fn opt<T>(x: Option<&T>, f: impl FnOnce(&T) -> Value) -> Value {
    x.map(f).unwrap_or(Value::Null)
}

fn nullable<T: Clone>(x: &Nullable<T>, f: impl FnOnce(&T) -> Value) -> Value {
    match x {
        Nullable::Some(v) => f(v),
        Nullable::Null | Nullable::Undefined => Value::Null,
    }
}

fn set(items: impl IntoIterator<Item = Value>) -> Value {
    json!({ "set": items.into_iter().collect::<Vec<_>>() })
}

fn oset(items: impl IntoIterator<Item = Value>) -> Value {
    json!({ "oset": items.into_iter().collect::<Vec<_>>() })
}

fn map(pairs: impl IntoIterator<Item = (Value, Value)>) -> Value {
    json!({ "map": pairs.into_iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>() })
}

fn omap(pairs: impl IntoIterator<Item = (Value, Value)>) -> Value {
    json!({ "omap": pairs.into_iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>() })
}

fn tagged(tag: &str, fields: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    m.insert("tag".into(), json!(tag));
    for (k, v) in fields {
        m.insert(k.into(), v);
    }
    Value::Object(m)
}

fn obj(fields: Vec<(&str, Value)>) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

fn set_cb<T: minicbor::Encode<()>>(x: Option<&[T]>) -> Value {
    set(x.unwrap_or(&[]).iter().map(cb))
}

fn map_cb<'a, K: minicbor::Encode<()> + 'a, V: minicbor::Encode<()> + 'a>(
    x: Option<impl IntoIterator<Item = (&'a K, &'a V)>>,
) -> Value {
    match x {
        None => map([]),
        Some(it) => map(it.into_iter().map(|(k, v)| (cb(k), cb(v)))),
    }
}

/// The decimal digits of a big endian unsigned magnitude.
fn decimal(be: &[u8]) -> String {
    let mut n: Vec<u8> = be.iter().copied().skip_while(|b| *b == 0).collect();
    if n.is_empty() {
        return "0".into();
    }
    let mut out = Vec::new();
    while !n.is_empty() {
        let mut rem: u32 = 0;
        let mut q = Vec::with_capacity(n.len());
        for &b in &n {
            let cur = rem * 256 + b as u32;
            let digit = cur / 10;
            rem = cur % 10;
            if !(q.is_empty() && digit == 0) {
                q.push(digit as u8);
            }
        }
        out.push(b'0' + rem as u8);
        n = q;
    }
    out.reverse();
    String::from_utf8(out).expect("ascii digits")
}

/// The decimal digits of the negative integer `-1 - n` for a big endian magnitude `n`.
fn negative_decimal(be: &[u8]) -> String {
    let mut v = be.to_vec();
    let mut i = v.len();
    loop {
        if i == 0 {
            v.insert(0, 1);
            break;
        }
        i -= 1;
        if v[i] == 255 {
            v[i] = 0;
        } else {
            v[i] += 1;
            break;
        }
    }
    format!("-{}", decimal(&v))
}

fn data(x: &PlutusData) -> Value {
    match x {
        PlutusData::Constr(c) => {
            let ix = match c.tag {
                121..=127 => (c.tag - 121).to_string(),
                1280..=1400 => (c.tag - 1280 + 7).to_string(),
                102 => c.any_constructor.map(|i| i.to_string()).unwrap_or_default(),
                t => format!("tag {t}"),
            };
            tagged(
                "constr",
                vec![
                    ("ix", json!(ix)),
                    ("fields", Value::Array(c.fields.iter().map(data).collect())),
                ],
            )
        }
        PlutusData::Map(kvs) => tagged(
            "map",
            vec![(
                "entries",
                Value::Array(kvs.iter().map(|(k, v)| json!([data(k), data(v)])).collect()),
            )],
        ),
        PlutusData::Array(xs) => tagged(
            "list",
            vec![("items", Value::Array(xs.iter().map(data).collect()))],
        ),
        PlutusData::BigInt(BigInt::Int(i)) => {
            tagged("int", vec![("v", json!(i128::from(i.0).to_string()))])
        }
        PlutusData::BigInt(BigInt::BigUInt(b)) => tagged("int", vec![("v", json!(decimal(b)))]),
        PlutusData::BigInt(BigInt::BigNInt(b)) => {
            tagged("int", vec![("v", json!(negative_decimal(b)))])
        }
        PlutusData::BoundedBytes(b) => {
            tagged("bytes", vec![("v", json!(hex::encode(b.as_slice())))])
        }
    }
}

fn native(x: &d::NativeScript) -> Value {
    use d::NativeScript as S;
    let all = |xs: &[S]| Value::Array(xs.iter().map(native).collect());
    match x {
        S::ScriptPubkey(h) => tagged("sig", vec![("hash", cb(h))]),
        S::ScriptAll(xs) => tagged("all", vec![("scripts", all(xs))]),
        S::ScriptAny(xs) => tagged("any", vec![("scripts", all(xs))]),
        S::ScriptNOfK(m, xs) => tagged(
            "m_of",
            vec![("m", json!(m.to_string())), ("scripts", all(xs))],
        ),
        S::InvalidBefore(s) => tagged("start", vec![("slot", cb(s))]),
        S::InvalidHereafter(s) => tagged("expire", vec![("slot", cb(s))]),
        S::ScriptRequireGuard(c) => tagged("guard", vec![("cred", cb(c))]),
    }
}

fn native_script(x: &d::NativeScript) -> Value {
    tagged("native", vec![("script", native(x))])
}

fn plutus<const V: usize>(x: &d::PlutusScript<V>) -> Value {
    tagged(
        &format!("plutus_v{V}"),
        vec![("bytes", json!(hex::encode(x.0.as_slice())))],
    )
}

fn plutus_hash<const V: usize>(x: &d::PlutusScript<V>) -> Value {
    cb(&Hasher::<224>::hash_tagged(x.0.as_slice(), V as u8))
}

fn script_ref(x: &d::ScriptRef) -> Value {
    match x {
        d::ScriptRef::NativeScript(s) => native_script(s),
        d::ScriptRef::PlutusV1Script(s) => plutus(s),
        d::ScriptRef::PlutusV2Script(s) => plutus(s),
        d::ScriptRef::PlutusV3Script(s) => plutus(s),
        d::ScriptRef::PlutusV4Script(s) => plutus(s),
    }
}

fn assets<A: minicbor::Encode<()>>(m: &d::Multiasset<A>) -> Value {
    map(m
        .iter()
        .map(|(p, names)| (cb(p), map_cb(Some(names.iter())))))
}

fn output(x: &d::TransactionOutput) -> Value {
    use pallas_primitives::{alonzo, conway};
    match x {
        d::TransactionOutput::Legacy(o) => {
            let (coin, multi) = match &o.amount {
                alonzo::Value::Coin(c) => (cb(c), map([])),
                alonzo::Value::Multiasset(c, m) => (cb(c), assets(m)),
            };
            obj(vec![
                ("address", cb(&o.address)),
                ("coin", coin),
                ("assets", multi),
                (
                    "datum",
                    opt(o.datum_hash.as_ref(), |h| {
                        tagged("hash", vec![("hash", cb(h))])
                    }),
                ),
                ("script", Value::Null),
            ])
        }
        d::TransactionOutput::PostAlonzo(o) => {
            let (coin, multi) = match &*o.value {
                conway::Value::Coin(c) => (cb(c), map([])),
                conway::Value::Multiasset(c, m) => (cb(c), assets(m)),
            };
            let datum = opt(o.datum_option.as_ref(), |x| match &**x {
                d::DatumOption::Hash(h) => tagged("hash", vec![("hash", cb(h))]),
                d::DatumOption::Data(w) => tagged("inline", vec![("data", data(&w.0))]),
            });
            obj(vec![
                ("address", cb(&o.address)),
                ("coin", coin),
                ("assets", multi),
                ("datum", datum),
                ("script", opt(o.script_ref.as_ref(), |s| script_ref(&s.0))),
            ])
        }
    }
}

fn cert(x: &d::Certificate) -> Value {
    match x {
        d::Certificate::PoolRegistration {
            operator,
            vrf_keyhash,
            bls_key,
            pledge,
            cost,
            margin,
            reward_account,
            pool_owners,
            relays,
            pool_metadata,
        } => tagged(
            "pool_reg",
            vec![
                ("operator", cb(operator)),
                ("vrf", cb(vrf_keyhash)),
                ("bls", opt(bls_key.as_ref(), |k| nullable(k, cb))),
                ("pledge", cb(pledge)),
                ("cost", cb(cost)),
                ("margin", cb(margin)),
                ("account", cb(reward_account)),
                ("owners", set(pool_owners.iter().map(cb))),
                ("relays", Value::Array(relays.iter().map(cb).collect())),
                ("metadata", opt(pool_metadata.as_ref(), cb)),
            ],
        ),
        other => cb(other),
    }
}

fn action(x: &d::GovAction) -> Value {
    match x {
        d::GovAction::TreasuryWithdrawals(ws, policy) => tagged(
            "treasury_withdrawals",
            vec![
                ("withdrawals", map_cb(Some(ws.iter()))),
                ("policy", opt(policy.as_ref(), cb)),
            ],
        ),
        d::GovAction::UpdateCommittee(prev, remove, add, threshold) => tagged(
            "update_committee",
            vec![
                ("prev", opt(prev.as_ref(), cb)),
                ("remove", set(remove.iter().map(cb))),
                ("add", map_cb(Some(add.iter()))),
                ("threshold", cb(threshold)),
            ],
        ),
        other => cb(other),
    }
}

fn proposal(x: &d::ProposalProcedure) -> Value {
    obj(vec![
        ("deposit", cb(&x.deposit)),
        ("account", cb(&x.reward_account)),
        ("action", action(&x.gov_action)),
        ("anchor", cb(&x.anchor)),
    ])
}

fn votes(x: Option<&d::VotingProcedures>) -> Value {
    match x {
        None => map([]),
        Some(m) => map(m
            .iter()
            .map(|(voter, vs)| (cb(voter), map_cb(Some(vs.iter()))))),
    }
}

fn guards(x: Option<&d::Guards>) -> Value {
    match x {
        None => oset([]),
        Some(d::Guards::AddrKeyhashes(hs)) => {
            oset(hs.iter().map(|h| cb(&StakeCredential::AddrKeyhash(*h))))
        }
        Some(d::Guards::Credentials(cs)) => oset(cs.iter().map(cb)),
    }
}

fn top_guards(x: Option<&d::RequiredTopLevelGuards>) -> Value {
    match x {
        None => map([]),
        Some(m) => map(m.iter().map(|(c, v)| (cb(c), nullable(v, data)))),
    }
}

fn donation(x: Option<&d::PositiveCoin>) -> Value {
    cb(&x.map(|coin| u64::from(**coin)).unwrap_or(0))
}

/// The fields a top level body and a sub transaction body both hold, by the ledger reading's names.
fn shared<'a>(
    inputs: &[d::TransactionInput],
    reference_inputs: Option<&d::NonEmptySet<d::TransactionInput>>,
    outputs: &[d::TransactionOutput<'a>],
    certs: Option<&d::NonEmptySet<d::Certificate>>,
    withdrawals: Option<&d::Withdrawals>,
    ttl: Option<u64>,
    start: Option<u64>,
) -> Vec<(&'static str, Value)> {
    vec![
        ("inputs", set(inputs.iter().map(cb))),
        ("reference_inputs", set_cb(reference_inputs.map(|x| &x[..]))),
        (
            "outputs",
            Value::Array(outputs.iter().map(output).collect()),
        ),
        (
            "certs",
            oset(certs.map(|x| &x[..]).unwrap_or(&[]).iter().map(cert)),
        ),
        ("withdrawals", map_cb(withdrawals.map(|w| w.iter()))),
        ("ttl", opt(ttl.as_ref(), cb)),
        ("start", opt(start.as_ref(), cb)),
    ]
}

fn proposals(x: Option<&d::NonEmptySet<d::ProposalProcedure>>) -> Value {
    oset(x.map(|x| &x[..]).unwrap_or(&[]).iter().map(proposal))
}

fn mint(x: Option<&d::Mint>) -> Value {
    x.map(assets).unwrap_or_else(|| map([]))
}

fn body(b: &d::TransactionBody) -> Value {
    let mut f = shared(
        &b.inputs,
        b.reference_inputs.as_ref(),
        &b.outputs,
        b.certificates.as_ref(),
        b.withdrawals.as_ref(),
        b.ttl,
        b.validity_interval_start,
    );
    let subs = b.sub_transactions.as_ref().map(|x| &x[..]).unwrap_or(&[]);
    f.extend(vec![
        ("fee", cb(&b.fee)),
        ("collateral", set_cb(b.collateral.as_ref().map(|x| &x[..]))),
        (
            "collateral_return",
            opt(b.collateral_return.as_ref(), output),
        ),
        ("total_collateral", opt(b.total_collateral.as_ref(), cb)),
        ("guards", guards(b.guards.as_ref())),
        ("mint", mint(b.mint.as_ref())),
        ("script_data_hash", opt(b.script_data_hash.as_ref(), cb)),
        ("aux_hash", opt(b.auxiliary_data_hash.as_ref(), cb)),
        ("network", opt(b.network_id.as_ref(), cb)),
        ("votes", votes(b.voting_procedures.as_ref())),
        ("proposals", proposals(b.proposal_procedures.as_ref())),
        ("treasury", opt(b.treasury_value.as_ref(), cb)),
        ("donation", donation(b.donation.as_ref())),
        (
            "sub_txs",
            omap(subs.iter().map(|s| {
                (
                    cb(&Hasher::<256>::hash(s.sub_transaction_body.raw_cbor())),
                    sub_tx(s),
                )
            })),
        ),
        (
            "top_guards",
            top_guards(b.required_top_level_guards.as_ref()),
        ),
        (
            "deposits",
            map_cb(b.direct_deposits.as_ref().map(|x| x.iter())),
        ),
        (
            "balance_intervals",
            map_cb(b.account_balance_intervals.as_ref().map(|x| x.iter())),
        ),
        (
            "starting_balance_intervals",
            map_cb(
                b.starting_account_balance_intervals
                    .as_ref()
                    .map(|x| x.iter()),
            ),
        ),
    ]);
    obj(f)
}

fn sub_body(b: &d::SubTransactionBody) -> Value {
    let mut f = shared(
        &b.inputs,
        b.reference_inputs.as_ref(),
        &b.outputs,
        b.certificates.as_ref(),
        b.withdrawals.as_ref(),
        b.ttl,
        b.validity_interval_start,
    );
    f.extend(vec![
        ("guards", guards(b.guards.as_ref())),
        ("mint", mint(b.mint.as_ref())),
        ("script_data_hash", opt(b.script_data_hash.as_ref(), cb)),
        ("aux_hash", opt(b.auxiliary_data_hash.as_ref(), cb)),
        ("network", opt(b.network_id.as_ref(), cb)),
        ("votes", votes(b.voting_procedures.as_ref())),
        ("proposals", proposals(b.proposal_procedures.as_ref())),
        ("treasury", opt(b.treasury_value.as_ref(), cb)),
        ("donation", donation(b.donation.as_ref())),
        (
            "top_guards",
            top_guards(b.required_top_level_guards.as_ref()),
        ),
        (
            "deposits",
            map_cb(b.direct_deposits.as_ref().map(|x| x.iter())),
        ),
        (
            "balance_intervals",
            map_cb(b.account_balance_intervals.as_ref().map(|x| x.iter())),
        ),
    ]);
    obj(f)
}

fn wits(w: &d::WitnessSet) -> Value {
    let mut scripts = Vec::new();
    for s in w.native_script.as_ref().map(|x| &x[..]).unwrap_or(&[]) {
        scripts.push((
            cb(&Hasher::<224>::hash_tagged(s.raw_cbor(), 0)),
            native_script(s),
        ));
    }
    macro_rules! push_plutus {
        ($field:ident) => {
            for s in w.$field.as_ref().map(|x| &x[..]).unwrap_or(&[]) {
                scripts.push((plutus_hash(s), plutus(s)));
            }
        };
    }
    push_plutus!(plutus_v1_script);
    push_plutus!(plutus_v2_script);
    push_plutus!(plutus_v3_script);
    push_plutus!(plutus_v4_script);
    let datums: &[KeepRaw<PlutusData>] = w.plutus_data.as_ref().map(|x| &x[..]).unwrap_or(&[]);
    let redeemers = match &w.redeemer {
        None => map([]),
        Some(r) => map(r.0.iter().map(|(k, v)| {
            (
                cb(k),
                obj(vec![("data", data(&v.data)), ("units", cb(&v.ex_units))]),
            )
        })),
    };
    obj(vec![
        ("vkeys", set_cb(w.vkeywitness.as_ref().map(|x| &x[..]))),
        (
            "boots",
            set_cb(w.bootstrap_witness.as_ref().map(|x| &x[..])),
        ),
        ("scripts", map(scripts)),
        (
            "datums",
            map(datums
                .iter()
                .map(|x| (cb(&Hasher::<256>::hash(x.raw_cbor())), data(x)))),
        ),
        ("redeemers", redeemers),
    ])
}

fn metadata(m: Option<&d::Metadata>) -> Value {
    map_cb(m.map(|x| x.iter()))
}

fn aux(a: &d::AuxiliaryData) -> Value {
    let natives = |xs: Option<&Vec<KeepRaw<d::NativeScript>>>| {
        Value::Array(
            xs.map(|x| &x[..])
                .unwrap_or(&[])
                .iter()
                .map(|x| native(x))
                .collect(),
        )
    };
    let (md, ns, ps) = match a {
        d::AuxiliaryData::Shelley(md) => (metadata(Some(md)), natives(None), map([])),
        d::AuxiliaryData::ShelleyMa(x) => (
            metadata(Some(&x.transaction_metadata)),
            natives(x.auxiliary_scripts.as_ref()),
            map([]),
        ),
        d::AuxiliaryData::PostAlonzo(x) => {
            fn lang<const V: usize>(
                xs: Option<&Vec<d::PlutusScript<V>>>,
            ) -> Option<(Value, Value)> {
                xs.filter(|xs| !xs.is_empty()).map(|xs| {
                    (
                        json!(format!("plutus_v{V}")),
                        Value::Array(
                            xs.iter()
                                .map(|s| json!(hex::encode(s.0.as_slice())))
                                .collect(),
                        ),
                    )
                })
            }
            let ps = [
                lang(x.plutus_v1_scripts.as_ref()),
                lang(x.plutus_v2_scripts.as_ref()),
                lang(x.plutus_v3_scripts.as_ref()),
                lang(x.plutus_v4_scripts.as_ref()),
            ];
            (
                metadata(x.metadata.as_ref()),
                natives(x.native_scripts.as_ref()),
                map(ps.into_iter().flatten()),
            )
        }
    };
    obj(vec![("metadata", md), ("native", ns), ("plutus", ps)])
}

fn sub_tx(s: &d::SubTransaction) -> Value {
    obj(vec![
        ("body", sub_body(&s.sub_transaction_body)),
        ("wits", wits(&s.transaction_witness_set)),
        ("aux", nullable(&s.auxiliary_data, |a| aux(a))),
    ])
}

fn tx(
    b: &KeepRaw<d::TransactionBody>,
    w: &d::WitnessSet,
    valid: bool,
    a: &Nullable<KeepRaw<d::AuxiliaryData>>,
) -> Value {
    obj(vec![
        ("id", cb(&Hasher::<256>::hash(b.raw_cbor()))),
        ("body", body(b)),
        ("wits", wits(w)),
        ("valid", json!(valid)),
        ("aux", nullable(a, |a| aux(a))),
    ])
}

fn block(b: &d::Block) -> Value {
    let h = &b.header.header_body;
    let header = obj(vec![
        ("block_no", cb(&h.block_number)),
        ("slot", cb(&h.slot)),
        ("prev", cb(&h.prev_hash)),
        ("issuer_vk", cb(&h.issuer_vkey)),
        ("vrf_vk", cb(&h.vrf_vkey)),
        ("vrf", cb(&h.vrf_result)),
        ("body_size", cb(&h.block_body_size)),
        ("body_hash", cb(&h.block_body_hash)),
        ("ocert", cb(&h.operational_cert)),
        ("version", cb(&h.header_version_info)),
        ("leios_cert", json!(h.block_body_contains_leios_cert)),
        ("eb", nullable(&h.eb_announcement, cb)),
        ("sig", cb(&b.header.body_signature)),
        ("hash", cb(&Hasher::<256>::hash(b.header.raw_cbor()))),
    ]);
    let txs = b
        .block_body
        .transactions
        .iter()
        .map(|t| {
            tx(
                &t.transaction_body,
                &t.transaction_witness_set,
                t.success,
                &t.auxiliary_data,
            )
        })
        .collect();
    obj(vec![
        ("header", header),
        ("txs", Value::Array(txs)),
        ("leios_cert", nullable(&b.block_body.leios_certificate, cb)),
        ("peras_cert", nullable(&b.block_body.peras_certificate, cb)),
    ])
}

/// A value as pallas reads it, and the bytes pallas encodes it to.
type Reading = Result<(Value, Vec<u8>), String>;

fn read_tx(bytes: &[u8]) -> Reading {
    let t: d::MempoolTransaction = minicbor::decode(bytes).map_err(|e| e.to_string())?;
    // A mempool transaction that decodes is phase two valid, since the decoder refuses `false`.
    let dump = tx(
        &t.transaction_body,
        &t.transaction_witness_set,
        true,
        &t.auxiliary_data,
    );
    Ok((dump, enc(&t)))
}

fn read_body(bytes: &[u8]) -> Reading {
    let b: d::TransactionBody = minicbor::decode(bytes).map_err(|e| e.to_string())?;
    let mut dump = body(&b);
    dump["id"] = cb(&Hasher::<256>::hash(bytes));
    Ok((dump, enc(&b)))
}

fn read_wits(bytes: &[u8]) -> Reading {
    let w: d::WitnessSet = minicbor::decode(bytes).map_err(|e| e.to_string())?;
    Ok((wits(&w), enc(&w)))
}

fn read_ppu(bytes: &[u8]) -> Reading {
    let u: d::ProtocolParamUpdate = minicbor::decode(bytes).map_err(|e| e.to_string())?;
    let again = enc(&u);
    Ok((raw(&again), again))
}

fn read_block(bytes: &[u8]) -> Reading {
    let b: d::Block = minicbor::decode(bytes).map_err(|e| e.to_string())?;
    Ok((block(&b), enc(&b)))
}

fn read_eb(bytes: &[u8]) -> Reading {
    let e: d::EndorserBlock = minicbor::decode(bytes).map_err(|e| e.to_string())?;
    Ok((omap(e.iter().map(|(h, n)| (cb(h), cb(n)))), enc(&e)))
}

fn reader(kind: &str) -> fn(&[u8]) -> Reading {
    match kind {
        "tx" => read_tx,
        "body" => read_body,
        "wits" => read_wits,
        "ppu" => read_ppu,
        "block" => read_block,
        "eb" => read_eb,
        k => panic!("unknown kind {k}"),
    }
}

/// Runs a reading, turning a panic into an error.
fn guarded(read: fn(&[u8]) -> Reading, bytes: &[u8]) -> Reading {
    match catch_unwind(AssertUnwindSafe(|| read(bytes))) {
        Ok(r) => r,
        Err(e) => Err(
            match (e.downcast_ref::<&str>(), e.downcast_ref::<String>()) {
                (Some(s), _) => format!("panic: {s}"),
                (_, Some(s)) => format!("panic: {s}"),
                _ => "panic".to_string(),
            },
        ),
    }
}

/// A value in the form two readings share exactly when they read the same value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Normal {
    Null,
    Undefined,
    Bool(bool),
    Str(String),
    Int(String),
    Ratio(i128, i128),
    Bytes(Vec<u8>),
    Text(String),
    Float(Vec<u8>),
    Simple(u8),
    Tag(u64, Box<Normal>),
    List(Vec<Normal>),
    Map(BTreeMap<Normal, Normal>),
    Set(BTreeSet<Normal>),
    OSet(Vec<Normal>),
    OMap(Vec<(Normal, Normal)>),
    Record(BTreeMap<String, Normal>),
    Unreadable(String),
}

/// A CBOR reader that ignores the encoding choices that leave the value unchanged.
struct Cbor<'a> {
    b: &'a [u8],
    p: usize,
}

impl Cbor<'_> {
    fn byte(&mut self) -> Result<u8, String> {
        let x = *self.b.get(self.p).ok_or("end of input")?;
        self.p += 1;
        Ok(x)
    }

    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        let end = self.p.checked_add(n).filter(|e| *e <= self.b.len());
        let end = end.ok_or("end of input")?;
        let out = &self.b[self.p..end];
        self.p = end;
        Ok(out)
    }

    fn arg(&mut self, info: u8) -> Result<u64, String> {
        let n = match info {
            0..=23 => return Ok(info as u64),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(format!("additional info {info}")),
        };
        Ok(self
            .take(n)?
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | *b as u64))
    }

    fn at_break(&self) -> bool {
        self.b.get(self.p) == Some(&0xff)
    }

    fn count(&mut self, info: u8) -> Result<Option<u64>, String> {
        if info == 31 {
            Ok(None)
        } else {
            self.arg(info).map(Some)
        }
    }

    fn items<T>(
        &mut self,
        len: Option<u64>,
        mut one: impl FnMut(&mut Self) -> Result<T, String>,
    ) -> Result<Vec<T>, String> {
        let mut out = Vec::new();
        match len {
            Some(n) => {
                for _ in 0..n {
                    out.push(one(self)?);
                }
            }
            None => {
                while !self.at_break() {
                    out.push(one(self)?);
                }
                self.p += 1;
            }
        }
        Ok(out)
    }

    fn chunks(&mut self, major: u8, info: u8) -> Result<Vec<u8>, String> {
        if info != 31 {
            let n = self.arg(info)? as usize;
            return Ok(self.take(n)?.to_vec());
        }
        let mut out = Vec::new();
        while !self.at_break() {
            let ib = self.byte()?;
            if ib >> 5 != major || ib & 31 == 31 {
                return Err("bad string chunk".into());
            }
            let n = self.arg(ib & 31)? as usize;
            out.extend_from_slice(self.take(n)?);
        }
        self.p += 1;
        Ok(out)
    }

    fn item(&mut self) -> Result<Normal, String> {
        let ib = self.byte()?;
        let (major, info) = (ib >> 5, ib & 31);
        Ok(match major {
            0 => Normal::Int(self.arg(info)?.to_string()),
            1 => Normal::Int((-1 - self.arg(info)? as i128).to_string()),
            2 => Normal::Bytes(self.chunks(2, info)?),
            3 => Normal::Text(String::from_utf8_lossy(&self.chunks(3, info)?).into_owned()),
            4 => {
                let len = self.count(info)?;
                Normal::List(self.items(len, |r| r.item())?)
            }
            5 => {
                let len = self.count(info)?;
                Normal::Map(
                    self.items(len, |r| Ok((r.item()?, r.item()?)))?
                        .into_iter()
                        .collect(),
                )
            }
            6 => {
                let tag = self.arg(info)?;
                tagged_value(tag, self.item()?)
            }
            _ => match info {
                20 => Normal::Bool(false),
                21 => Normal::Bool(true),
                22 => Normal::Null,
                23 => Normal::Undefined,
                25 => Normal::Float(self.take(2)?.to_vec()),
                26 => Normal::Float(self.take(4)?.to_vec()),
                27 => Normal::Float(self.take(8)?.to_vec()),
                _ => Normal::Simple(self.arg(info)? as u8),
            },
        })
    }
}

fn gcd(a: u128, b: u128) -> u128 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// The value of a tagged item, with set tags dropped, bignums as integers and rationals reduced.
fn tagged_value(tag: u64, inner: Normal) -> Normal {
    match (tag, inner) {
        (258, inner) => inner,
        (2, Normal::Bytes(b)) => Normal::Int(decimal(&b)),
        (3, Normal::Bytes(b)) => Normal::Int(negative_decimal(&b)),
        (30, Normal::List(xs)) if xs.len() == 2 => {
            let parsed: Vec<Option<i128>> = xs
                .iter()
                .map(|x| match x {
                    Normal::Int(s) => s.parse().ok(),
                    _ => None,
                })
                .collect();
            match parsed[..] {
                [Some(n), Some(d)] if d != 0 => {
                    let g = gcd(n.unsigned_abs(), d.unsigned_abs()).max(1) as i128;
                    let sign = if d < 0 { -1 } else { 1 };
                    Normal::Ratio(sign * n / g, sign * d / g)
                }
                _ => Normal::Tag(30, Box::new(Normal::List(xs))),
            }
        }
        (tag, inner) => Normal::Tag(tag, Box::new(inner)),
    }
}

fn cbor_hex(hexstr: &str) -> Normal {
    let Ok(bytes) = hex::decode(hexstr) else {
        return Normal::Unreadable(hexstr.to_string());
    };
    let mut r = Cbor { b: &bytes, p: 0 };
    match r.item() {
        Ok(v) if r.p == bytes.len() => v,
        _ => Normal::Unreadable(hexstr.to_string()),
    }
}

/// The normal form of a reading, recording the path of each duplicate a set or map removes.
fn normal(v: &Value, path: &str, dups: &mut Vec<String>) -> Normal {
    match v {
        Value::Object(m) if m.len() == 1 && m.contains_key("cbor") => {
            cbor_hex(m["cbor"].as_str().unwrap_or_default())
        }
        Value::Object(m) if m.len() == 1 && m.contains_key("set") => {
            let items = elements(&m["set"], path, dups);
            let n = items.len();
            let out: BTreeSet<Normal> = items.into_iter().collect();
            if out.len() != n {
                dups.push(path.to_string());
            }
            Normal::Set(out)
        }
        Value::Object(m) if m.len() == 1 && m.contains_key("oset") => {
            let mut out: Vec<Normal> = Vec::new();
            for x in elements(&m["oset"], path, dups) {
                if out.contains(&x) {
                    dups.push(path.to_string());
                } else {
                    out.push(x);
                }
            }
            Normal::OSet(out)
        }
        Value::Object(m) if m.len() == 1 && (m.contains_key("map") || m.contains_key("omap")) => {
            let ordered = m.contains_key("omap");
            let pairs = m.values().next().and_then(Value::as_array);
            let mut out: Vec<(Normal, Normal)> = Vec::new();
            for pair in pairs.into_iter().flatten() {
                let k = normal(&pair[0], path, dups);
                let v = normal(&pair[1], path, dups);
                match out.iter().position(|(x, _)| *x == k) {
                    Some(at) => {
                        dups.push(path.to_string());
                        if !ordered {
                            out[at].1 = v;
                        }
                    }
                    None => out.push((k, v)),
                }
            }
            if ordered {
                Normal::OMap(out)
            } else {
                Normal::Map(out.into_iter().collect())
            }
        }
        Value::Object(m) => Normal::Record(
            m.iter()
                .map(|(k, x)| (k.clone(), normal(x, &format!("{path}.{k}"), dups)))
                .collect(),
        ),
        Value::Array(xs) => Normal::List(
            xs.iter()
                .map(|x| normal(x, &format!("{path}[]"), dups))
                .collect(),
        ),
        Value::String(s) => Normal::Str(s.clone()),
        Value::Bool(b) => Normal::Bool(*b),
        Value::Null => Normal::Null,
        Value::Number(n) => Normal::Str(n.to_string()),
    }
}

fn elements(v: &Value, path: &str, dups: &mut Vec<String>) -> Vec<Normal> {
    v.as_array()
        .into_iter()
        .flatten()
        .map(|x| normal(x, &format!("{path}[]"), dups))
        .collect()
}

/// The value without its transaction ids, which name the bytes rather than the value.
fn without_ids(v: &Normal) -> Normal {
    match v {
        Normal::Record(m) => Normal::Record(
            m.iter()
                .filter(|(k, _)| k.as_str() != "id")
                .map(|(k, x)| (k.clone(), without_ids(x)))
                .collect(),
        ),
        Normal::List(xs) => Normal::List(xs.iter().map(without_ids).collect()),
        Normal::OMap(xs) => Normal::OMap(
            xs.iter()
                .map(|(k, x)| (k.clone(), without_ids(x)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// The leaves of two normal forms that agree, and the paths and values of those that differ.
#[derive(Default)]
struct Diff {
    agree: usize,
    differ: Vec<(&'static str, String, String)>,
}

fn leaves(v: &Normal) -> usize {
    let sum = match v {
        Normal::List(xs) | Normal::OSet(xs) => xs.iter().map(leaves).sum(),
        Normal::Set(xs) => xs.iter().map(leaves).sum(),
        Normal::Map(m) => m.iter().map(|(k, x)| leaves(k) + leaves(x)).sum(),
        Normal::OMap(m) => m.iter().map(|(k, x)| leaves(k) + leaves(x)).sum(),
        Normal::Record(m) => m.values().map(leaves).sum(),
        Normal::Tag(_, x) => leaves(x),
        _ => 1,
    };
    sum.max(1)
}

fn short(v: &Normal) -> String {
    let s = format!("{v:?}");
    if s.len() > 160 {
        format!("{}...", &s[..s.floor_char_boundary(160)])
    } else {
        s
    }
}

/// The path segment naming a map key or set element: a small integer by its value, anything else by a short hash.
fn segment(k: &Normal) -> String {
    match k {
        Normal::Int(s) if s.len() < 4 => format!("<{s}>"),
        _ => {
            use std::hash::{DefaultHasher, Hash, Hasher as _};
            let mut h = DefaultHasher::new();
            format!("{k:?}").hash(&mut h);
            format!("{{{:012x}}}", h.finish() & 0xffff_ffff_ffff)
        }
    }
}

/// The path with collection positions and keys replaced, so it names a field rather than one value.
fn generic(path: &str) -> String {
    let mut out = String::new();
    let mut chars = path.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '[' => {
                chars.by_ref().find(|c| *c == ']');
                out.push_str("[]");
            }
            '{' => {
                chars.by_ref().find(|c| *c == '}');
                out.push_str("{}");
            }
            c => out.push(c),
        }
    }
    out
}

fn compare(ledger: Option<&Normal>, pallas: Option<&Normal>, path: &str, out: &mut Diff) {
    match (ledger, pallas) {
        (Some(a), Some(b)) if a == b => out.agree += leaves(a),
        (Some(Normal::Record(a)), Some(Normal::Record(b))) => {
            let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
            for k in keys {
                compare(a.get(k), b.get(k), &format!("{path}.{k}"), out);
            }
        }
        (Some(Normal::List(a)), Some(Normal::List(b)))
        | (Some(Normal::OSet(a)), Some(Normal::OSet(b))) => {
            for i in 0..a.len().max(b.len()) {
                compare(a.get(i), b.get(i), &format!("{path}[{i}]"), out);
            }
        }
        (Some(Normal::Set(a)), Some(Normal::Set(b))) => {
            for x in a.union(b) {
                let p = format!("{path}{}", segment(x));
                compare(a.get(x), b.get(x), &p, out);
            }
        }
        (Some(Normal::Map(a)), Some(Normal::Map(b))) => {
            let keys: BTreeSet<&Normal> = a.keys().chain(b.keys()).collect();
            for k in keys {
                compare(a.get(k), b.get(k), &format!("{path}{}", segment(k)), out);
            }
        }
        (Some(Normal::OMap(a)), Some(Normal::OMap(b))) => {
            let order =
                |m: &[(Normal, Normal)]| m.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>();
            if order(a) != order(b) {
                out.differ
                    .push((DIFFERS, format!("{path}.order"), String::new()));
            }
            let a: BTreeMap<Normal, Normal> = a.iter().cloned().collect();
            let b: BTreeMap<Normal, Normal> = b.iter().cloned().collect();
            compare(Some(&Normal::Map(a)), Some(&Normal::Map(b)), path, out);
        }
        (Some(Normal::Tag(t, a)), Some(Normal::Tag(u, b))) if t == u => {
            compare(Some(a), Some(b), &format!("{path}#{t}"), out)
        }
        (Some(a), None) => out.differ.push((LACKS, path.to_string(), short(a))),
        (None, Some(b)) => out.differ.push((EXTRA, path.to_string(), short(b))),
        (Some(a), Some(b)) => out.differ.push((
            DIFFERS,
            path.to_string(),
            format!("ledger {} pallas {}", short(a), short(b)),
        )),
        (None, None) => {}
    }
}

struct Disagreement {
    kind: &'static str,
    source: String,
    i: u64,
    class: &'static str,
    path: String,
    detail: String,
}

#[derive(Default)]
struct Tally {
    values: usize,
    read: usize,
    reencoded: usize,
    agree: usize,
    disagreements: Vec<Disagreement>,
    credit: BTreeMap<String, usize>,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// The rule names of `defs.cddl`, generic rules by the name before their parameters.
fn rule_names() -> Vec<String> {
    let cddl = std::fs::read_to_string(root().join("pallas-primitives/src/dijkstra/defs.cddl"))
        .expect("defs.cddl");
    cddl.lines()
        .filter_map(|line| {
            let name: String = line
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
                .collect();
            let rest = line[name.len()..].trim_start();
            let rest = match rest.strip_prefix('<') {
                Some(r) => r.split_once('>')?.1.trim_start(),
                None => rest,
            };
            (!name.is_empty() && rest.starts_with('=')).then_some(name)
        })
        .collect()
}

/// Compares one vector with pallas, crediting its rules when pallas reads it as the ledger does.
fn check(kind: &'static str, line: &str, tally: &mut Tally) {
    let v: Value = serde_json::from_str(line).expect("vector line");
    let bytes = hex::decode(v["hex"].as_str().expect("hex")).expect("hex digits");
    let source = v["source"].as_str().unwrap_or_default().to_string();
    let i = v["i"].as_u64().unwrap_or_default();
    let mut found = Vec::new();
    let mut dis = |class, path: String, detail: String| {
        found.push(Disagreement {
            kind,
            source: source.clone(),
            i,
            class,
            path,
            detail,
        })
    };
    let read = reader(kind);
    let (dump, again) = match guarded(read, &bytes) {
        Ok(x) => x,
        Err(e) => {
            dis(REFUSES, String::new(), e);
            tally.disagreements.extend(found);
            return;
        }
    };
    let mut ignored = Vec::new();
    let ledger = normal(&v["ledger"], "", &mut ignored);
    let mut dups = Vec::new();
    let ours = normal(&dump, "", &mut dups);
    for path in dups {
        dis(DUPLICATE, generic(&path), path);
    }
    let mut diff = Diff::default();
    compare(Some(&ledger), Some(&ours), "", &mut diff);
    for (class, path, detail) in diff.differ {
        dis(class, generic(&path), format!("{path}: {detail}"));
    }
    if again != bytes {
        tally.reencoded += 1;
        match guarded(read, &again) {
            Err(e) => dis(REENCODING_REFUSED, String::new(), e),
            Ok((dump, _)) => {
                let mut redump = Diff::default();
                let again = normal(&dump, "", &mut Vec::new());
                compare(
                    Some(&without_ids(&ours)),
                    Some(&without_ids(&again)),
                    "",
                    &mut redump,
                );
                if let Some((_, path, detail)) = redump.differ.first() {
                    dis(
                        REENCODING_DIFFERS,
                        generic(path),
                        format!("{path}: {detail}"),
                    );
                }
            }
        }
    }
    tally.read += 1;
    tally.agree += diff.agree;
    if found.is_empty() {
        for rule in v["rules"].as_array().into_iter().flatten() {
            *tally
                .credit
                .entry(rule.as_str().unwrap_or_default().to_string())
                .or_default() += 1;
        }
    }
    tally.disagreements.extend(found);
}

fn run() {
    let rules = rule_names();
    let mut tally = Tally::default();
    let dir = root().join("test_data/dijkstra-ledger");
    for kind in KINDS {
        let text = std::fs::read_to_string(dir.join(format!("{kind}.jsonl"))).expect("vector file");
        let before = (
            tally.values,
            tally.read,
            tally.reencoded,
            tally.agree,
            tally.disagreements.len(),
        );
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            tally.values += 1;
            check(kind, line, &mut tally);
        }
        println!(
            "{kind}: values {}, read by pallas {}, encoded to other bytes {}, leaves agree {}, disagreements {}",
            tally.values - before.0,
            tally.read - before.1,
            tally.reencoded - before.2,
            tally.agree - before.3,
            tally.disagreements.len() - before.4,
        );
    }

    let mut failures = Vec::new();
    let mut matched = vec![0usize; LISTED.len()];
    for d in &tally.disagreements {
        let at = LISTED
            .iter()
            .position(|l| l.kind == d.kind && l.class == d.class && l.path == d.path);
        match at {
            Some(at) => matched[at] += 1,
            None => failures.push(format!(
                "{} {} {}: {} at {}: {}",
                d.kind, d.source, d.i, d.class, d.path, d.detail
            )),
        }
    }
    for (l, n) in LISTED.iter().zip(&matched) {
        println!(
            "listed {n}: {} {} {}: {}",
            l.kind, l.class, l.path, l.reason
        );
        if *n == 0 {
            failures.push(format!(
                "listed disagreement matches no value: {} {}",
                l.kind, l.class
            ));
        }
    }

    let names: BTreeSet<&str> = rules.iter().map(String::as_str).collect();
    for name in tally.credit.keys() {
        if !names.contains(name.as_str()) {
            failures.push(format!(
                "a vector credits {name}, which defs.cddl does not define"
            ));
        }
    }
    let counts: Vec<String> = rules
        .iter()
        .map(|r| format!("{r}={}", tally.credit.get(r).copied().unwrap_or(0)))
        .collect();
    println!("rules {}: {}", rules.len(), counts.join(" "));
    for r in &rules {
        let credited = tally.credit.get(r).copied().unwrap_or(0) > 0;
        let listed = UNCREDITED.iter().any(|(name, _)| name == r);
        match (credited, listed) {
            (false, false) => failures.push(format!("no value credits {r}")),
            (true, true) => failures.push(format!("{r} is credited, so it leaves UNCREDITED")),
            _ => {}
        }
    }
    for (name, _) in UNCREDITED {
        if !names.contains(name) {
            failures.push(format!(
                "UNCREDITED names {name}, which defs.cddl does not define"
            ));
        }
    }
    let credited = rules
        .iter()
        .filter(|r| tally.credit.contains_key(*r))
        .count();
    println!(
        "values {}, read by pallas {}, leaves agree {}, rules credited {credited} of {}, listed disagreements {}, failures {}",
        tally.values,
        tally.read,
        tally.agree,
        rules.len(),
        matched.iter().sum::<usize>(),
        failures.len(),
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn ledger_vectors_read_as_the_ledger_reads_them() {
    let outcome = std::thread::Builder::new()
        .stack_size(1 << 28)
        .spawn(run)
        .expect("spawn")
        .join();
    if let Err(e) = outcome {
        std::panic::resume_unwind(e);
    }
}

#[test]
fn equal_values_in_other_encodings_agree() {
    let pairs = [
        ("d9010282 0102", "820102"),
        ("a2 0102 0304", "a2 0304 0102"),
        ("d81e82 0204", "d81e82 0102"),
        ("c241 05", "05"),
        ("c341 05", "25"),
        ("5f 4101 4102 ff", "42 0102"),
    ];
    for (a, b) in pairs {
        let (a, b) = (a.replace(' ', ""), b.replace(' ', ""));
        let mut diff = Diff::default();
        compare(Some(&cbor_hex(&a)), Some(&cbor_hex(&b)), "", &mut diff);
        assert!(diff.differ.is_empty(), "{a} and {b}: {:?}", diff.differ);
    }
    let set_a = json!({ "set": [{ "cbor": "01" }, { "cbor": "02" }] });
    let set_b = json!({ "set": [{ "cbor": "02" }, { "cbor": "01" }] });
    let mut diff = Diff::default();
    let (a, b) = (
        normal(&set_a, "", &mut vec![]),
        normal(&set_b, "", &mut vec![]),
    );
    compare(Some(&a), Some(&b), "", &mut diff);
    assert!(diff.differ.is_empty());
}

#[test]
fn different_values_differ() {
    let pairs = [
        ("820102", "820201", DIFFERS),
        ("a10102", "a10103", DIFFERS),
        ("a2 0102 0304", "a1 0102", LACKS),
        ("82 01 02", "83 01 02 03", EXTRA),
        ("d81e82 0102", "d81e82 0103", DIFFERS),
        ("c241 05", "06", DIFFERS),
        ("41 00", "40", DIFFERS),
    ];
    for (a, b, class) in pairs {
        let (a, b) = (a.replace(' ', ""), b.replace(' ', ""));
        let mut diff = Diff::default();
        compare(Some(&cbor_hex(&a)), Some(&cbor_hex(&b)), "", &mut diff);
        assert!(
            diff.differ.iter().any(|(c, _, _)| *c == class),
            "{a} and {b}: {:?}",
            diff.differ
        );
    }
    let ordered_a = json!({ "omap": [[{ "cbor": "01" }, { "cbor": "02" }], [{ "cbor": "03" }, { "cbor": "04" }]] });
    let ordered_b = json!({ "omap": [[{ "cbor": "03" }, { "cbor": "04" }], [{ "cbor": "01" }, { "cbor": "02" }]] });
    let mut diff = Diff::default();
    let (a, b) = (
        normal(&ordered_a, "", &mut vec![]),
        normal(&ordered_b, "", &mut vec![]),
    );
    compare(Some(&a), Some(&b), "", &mut diff);
    assert_eq!(diff.differ.len(), 1);
    let mut dups = Vec::new();
    normal(
        &json!({ "set": [{ "cbor": "01" }, { "cbor": "01" }] }),
        "",
        &mut dups,
    );
    assert_eq!(dups.len(), 1);
}
