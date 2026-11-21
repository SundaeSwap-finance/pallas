use super::{
    AccountBalanceInterval, AccountBalanceIntervals, AuxiliaryData, Block, BlockTransaction,
    Certificate, CostModels, DRep, DatumOption, EndorserBlock, GovAction, Guards, Header,
    MempoolTransaction, NativeScript, NonEmptySet, PlutusData, ProposalProcedure,
    ProtocolParamUpdate, ProtocolVersion, RationalNumber, Relay, ScriptRef, Set, SetArm,
    StakeCredential, SubTransactionBody, TransactionBody, TransactionOutput, Voter, WitnessSet,
};
use crate::flat_enum::{assert_reads_either_length_form, decode_all};
use pallas_codec::minicbor;
use pallas_codec::utils::{CborWrap, KeepRaw, Nullable};
use pallas_crypto::hash::Hasher;

type BlockWrapper<'b> = (u16, Block<'b>);

/// Provenance for these fixtures is in `test_data/dijkstra-fixtures.md`.
const TEST_BLOCKS: &[(&str, &str)] = &[
    (
        "dijkstra1",
        include_str!("../../../test_data/dijkstra1.block"),
    ),
    (
        "dijkstra2",
        include_str!("../../../test_data/dijkstra2.block"),
    ),
    (
        "dijkstra3",
        include_str!("../../../test_data/dijkstra3.block"),
    ),
    (
        "dijkstra4",
        include_str!("../../../test_data/dijkstra4.block"),
    ),
    (
        "dijkstra5",
        include_str!("../../../test_data/dijkstra5.block"),
    ),
    (
        "dijkstra6",
        include_str!("../../../test_data/dijkstra6.block"),
    ),
    (
        "dijkstra7",
        include_str!("../../../test_data/dijkstra7.block"),
    ),
    (
        "dijkstra8",
        include_str!("../../../test_data/dijkstra8.block"),
    ),
    (
        "dijkstra9",
        include_str!("../../../test_data/dijkstra9.block"),
    ),
    (
        "dijkstra10",
        include_str!("../../../test_data/dijkstra10.block"),
    ),
    (
        "dijkstra11",
        include_str!("../../../test_data/dijkstra11.block"),
    ),
    (
        "dijkstra12",
        include_str!("../../../test_data/dijkstra12.block"),
    ),
    (
        "dijkstra13",
        include_str!("../../../test_data/dijkstra13.block"),
    ),
    (
        "dijkstra14",
        include_str!("../../../test_data/dijkstra14.block"),
    ),
    (
        "dijkstra15",
        include_str!("../../../test_data/dijkstra15.block"),
    ),
    (
        "dijkstra-rc-2026w42-7",
        include_str!("../../../test_data/dijkstra-rc-2026w42-7.block"),
    ),
    (
        "dijkstra-rc-2026w42-11",
        include_str!("../../../test_data/dijkstra-rc-2026w42-11.block"),
    ),
];

/// Blocks from before the fork. Their bodies are the Conway five element
/// shape and their header bodies are already the twelve field Dijkstra one,
/// so the Dijkstra block type must refuse them on the body.
const PRE_FORK_BLOCKS: &[(&str, &str)] =
    &[("conway5", include_str!("../../../test_data/conway5.block"))];

/// Endorser block bodies and the number of transactions each names.
const ENDORSER_BLOCKS: &[(&str, &str, usize)] = &[
    (
        "dijkstra-eb1",
        include_str!("../../../test_data/dijkstra-eb1.ebbody"),
        1,
    ),
    (
        "dijkstra-eb2",
        include_str!("../../../test_data/dijkstra-eb2.ebbody"),
        30,
    ),
    (
        "dijkstra-17402",
        include_str!("../../../test_data/dijkstra-17402.ebbody"),
        244,
    ),
];

const WITH_TRANSACTIONS: usize = 1;

fn block_named(name: &str) -> &'static str {
    TEST_BLOCKS
        .iter()
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("no fixture named {name}"))
        .1
}

fn block_of(name: &str) -> Block<'static> {
    let bytes: &'static [u8] =
        Box::leak(hex::decode(block_named(name)).unwrap().into_boxed_slice());
    let (_, block): BlockWrapper<'static> = minicbor::decode(bytes)
        .unwrap_or_else(|e| panic!("{name} should decode as a Dijkstra block: {e:?}"));
    block
}

fn header_of(name: &str) -> Header {
    let block = block_of(name);
    minicbor::decode(block.header.raw_cbor()).unwrap()
}

#[test]
fn block_isomorphic_decoding_encoding() {
    for (name, block_str) in TEST_BLOCKS.iter() {
        let bytes = hex::decode(block_str).unwrap_or_else(|_| panic!("bad block file {name}"));

        let block: BlockWrapper = minicbor::decode(&bytes)
            .unwrap_or_else(|e| panic!("error decoding cbor for file {name}: {e:?}"));

        let bytes2 = minicbor::to_vec(block)
            .unwrap_or_else(|e| panic!("error encoding block cbor for file {name}: {e:?}"));

        let first_diff = bytes
            .iter()
            .zip(bytes2.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(bytes.len().min(bytes2.len()));

        assert!(
            bytes.eq(&bytes2),
            "{name}: re-encoded bytes didn't match original, in {} out {}, first difference at byte {first_diff}\n  orig {}\n  ours {}",
            bytes.len(),
            bytes2.len(),
            hex::encode(&bytes[first_diff.saturating_sub(8)..(first_diff + 24).min(bytes.len())]),
            hex::encode(&bytes2[first_diff.saturating_sub(8)..(first_diff + 24).min(bytes2.len())]),
        );
    }
}

#[test]
fn endorser_block_isomorphic_decoding_encoding() {
    for (name, body_str, transactions) in ENDORSER_BLOCKS.iter() {
        let bytes = hex::decode(body_str).unwrap_or_else(|_| panic!("bad body file {name}"));

        let block: EndorserBlock = minicbor::decode(&bytes)
            .unwrap_or_else(|e| panic!("error decoding cbor for file {name}: {e:?}"));
        assert_eq!(block.len(), *transactions, "{name}: transaction count");

        assert_eq!(
            hex::encode(minicbor::to_vec(&block).unwrap()),
            hex::encode(&bytes),
            "{name}: re-encoded bytes didn't match original"
        );
    }
}

/// `Block::header` is a `KeepRaw` and re-emits the bytes it was decoded from,
/// so the block round trip cannot catch a wrong header. This re-encodes the
/// header through its own type, which is what exercises the field count.
#[test]
fn header_isomorphic_decoding_encoding() {
    for (name, block_str) in TEST_BLOCKS.iter() {
        let bytes = hex::decode(block_str).unwrap();
        let (_, block): BlockWrapper = minicbor::decode(&bytes).unwrap();

        let raw = block.header.raw_cbor();
        let reencoded = minicbor::to_vec(block.header.clone().unwrap()).unwrap();

        assert_eq!(
            hex::encode(raw),
            hex::encode(&reencoded),
            "{name}: header re-encoded through its own type did not match the wire bytes"
        );
    }
}

/// The transaction level twin of the header test. A `KeepRaw` replays the
/// bytes it read, so a map key the model has no field for is skipped in and
/// replayed out, and only re-encoding through each type catches that.
#[test]
fn transaction_payloads_reencode_to_their_wire_bytes() {
    let mut bodies = 0usize;
    let mut witness_sets = 0usize;
    let mut auxiliary_data = 0usize;

    for (name, block_str) in TEST_BLOCKS.iter() {
        let bytes = hex::decode(block_str).unwrap();
        let (_, block): BlockWrapper = minicbor::decode(&bytes).unwrap();

        for (i, tx) in block.block_body.transactions.iter().enumerate() {
            assert_eq!(
                hex::encode(minicbor::to_vec(tx.transaction_body.clone().unwrap()).unwrap()),
                hex::encode(tx.transaction_body.raw_cbor()),
                "{name} transaction {i}: the body re-encoded through its own type did not match the wire bytes"
            );
            bodies += 1;

            assert_eq!(
                hex::encode(minicbor::to_vec(tx.transaction_witness_set.clone().unwrap()).unwrap()),
                hex::encode(tx.transaction_witness_set.raw_cbor()),
                "{name} transaction {i}: the witness set re-encoded through its own type did not match the wire bytes"
            );
            witness_sets += 1;

            if let crate::Nullable::Some(aux) = &tx.auxiliary_data {
                assert_eq!(
                    hex::encode(minicbor::to_vec(aux.clone().unwrap()).unwrap()),
                    hex::encode(aux.raw_cbor()),
                    "{name} transaction {i}: the auxiliary data re-encoded through its own type did not match the wire bytes"
                );
                auxiliary_data += 1;
            }
        }
    }

    assert_eq!(
        (bodies, witness_sets, auxiliary_data),
        (46, 46, 5),
        "the fixtures should carry forty six transactions, each with a body and a witness set, five of them with auxiliary data"
    );
}

const INDEFINITE_BYTES_TXS: &[(&str, &str, &str, usize, &str, &str)] = &[
    (
        "dijkstra-indef-bytes1",
        include_str!("../../../test_data/dijkstra-indef-bytes1.tx"),
        "943a88c97f86522b2cda39d1d6bd076ea51a696e5ad41c41e4c6d38ce8f7dd50",
        11,
        "e040142528145d15aeea4834e948b87030a94ed33cdf3f7fff0364cf84a2408a",
        "00b44447f25f59bf23280d29fdea97f4e341e0bcd1d407ce80a8f11ede1ec80930158084eb5c735fd9bfb1ec53b8b5001c4b39d32c116b4921",
    ),
    (
        "dijkstra-indef-bytes2",
        include_str!("../../../test_data/dijkstra-indef-bytes2.tx"),
        "b026c42a9cf28aff7ce8624487f4d2b8f45df93454ac0ea2842408c1673cce5c",
        7,
        "943a88c97f86522b2cda39d1d6bd076ea51a696e5ad41c41e4c6d38ce8f7dd50",
        "00b44447f25f59bf23280d29fdea97f4e341e0bcd1d407ce80a8f11ede1ec80930158084eb5c735fd9bfb1ec53b8b5001c4b39d32c116b4921",
    ),
];

#[test]
fn transactions_with_indefinite_length_byte_strings_decode_and_keep_their_ids() {
    for (name, tx_hex, id, indefinite, input_id, address) in INDEFINITE_BYTES_TXS {
        let bytes = hex::decode(tx_hex).unwrap();

        let tx: MempoolTransaction = minicbor::decode(&bytes)
            .unwrap_or_else(|e| panic!("{name} should decode as a mempool transaction: {e:?}"));

        let input = tx.transaction_body.inputs.first().unwrap();
        assert_eq!(
            hex::encode(input.transaction_id),
            *input_id,
            "{name}: the first input id should be its chunks joined in order"
        );

        let Some(TransactionOutput::Legacy(output)) = tx.transaction_body.outputs.first() else {
            panic!("{name}: the first output should be in the array form");
        };
        assert_eq!(
            hex::encode(&*output.address),
            *address,
            "{name}: the first output address should be its chunks joined in order"
        );

        let body = tx.transaction_body.raw_cbor();
        let begins = minicbor::decode::Tokenizer::new(body)
            .filter(|token| matches!(token, Ok(minicbor::data::Token::BeginBytes)))
            .count();
        assert_eq!(
            begins, *indefinite,
            "{name}: the body should hold {indefinite} indefinite length byte strings"
        );

        assert_eq!(
            hex::encode(pallas_crypto::hash::Hasher::<256>::hash(body)),
            *id,
            "{name}: the id is the hash of the body bytes as read"
        );

        assert_eq!(
            hex::encode(minicbor::to_vec(&tx).unwrap()),
            *tx_hex,
            "{name}: the transaction should re-encode to the bytes it was read from"
        );
    }
}

/// Transactions holding a PlutusV4 witness script, in their own witness set or a sub transaction's.
const V4_WITNESS_TXS: &[(&str, &str)] = &[
    (
        "dijkstra-v4-witness",
        include_str!("../../../test_data/dijkstra-v4-witness.tx"),
    ),
    (
        "dijkstra-v4-sub-witness",
        include_str!("../../../test_data/dijkstra-v4-sub-witness.tx"),
    ),
];

/// The keys of a CBOR map, in ascending order.
fn map_keys(cbor: &[u8]) -> Vec<u64> {
    let mut d = minicbor::Decoder::new(cbor);
    let n = d.map().unwrap().unwrap();
    let mut keys: Vec<u64> = (0..n)
        .map(|_| {
            let key = d.u64().unwrap();
            d.skip().unwrap();
            key
        })
        .collect();
    keys.sort();
    keys
}

/// The node writes key 8 ahead of key 5, so the test compares keys.
#[test]
fn a_witness_set_holding_a_plutus_v4_script_keeps_every_key_on_reencode() {
    let mut witness_sets = 0usize;
    let mut mismatched = Vec::new();

    for (name, tx_str) in V4_WITNESS_TXS {
        let bytes = hex::decode(tx_str).unwrap();
        let tx: BlockTransaction = minicbor::decode(&bytes).unwrap();
        let subs = tx
            .transaction_body
            .sub_transactions
            .iter()
            .flat_map(|x| x.iter())
            .map(|x| &x.transaction_witness_set);

        for (i, wits) in std::iter::once(&tx.transaction_witness_set)
            .chain(subs)
            .enumerate()
        {
            let wire = map_keys(wits.raw_cbor());
            let encoded = map_keys(&minicbor::to_vec(wits.clone().unwrap()).unwrap());
            if encoded != wire {
                mismatched.push((*name, i, wire, encoded));
            }
            witness_sets += 1;
        }
    }

    assert_eq!(witness_sets, 4, "two transactions and two sub transactions");
    assert_eq!(
        mismatched,
        vec![],
        "these witness sets lost or gained a key on re-encode"
    );
}

/// Run over an empty tail and a populated one, because an empty tail is two
/// bytes and a length check could match that by accident.
#[test]
fn dijkstra_header_is_not_a_babbage_header() {
    for name in ["dijkstra1", "dijkstra8"] {
        let bytes = hex::decode(block_named(name)).unwrap();
        let (_, block): BlockWrapper = minicbor::decode(&bytes).unwrap();
        let raw = block.header.raw_cbor();

        let as_babbage: crate::babbage::Header =
            minicbor::decode(raw).expect("babbage decoder accepts a dijkstra header");
        let babbage_bytes = minicbor::to_vec(&as_babbage).unwrap();
        assert!(
            babbage_bytes.len() < raw.len(),
            "{name}: expected the babbage header type to silently drop the leios fields"
        );

        let as_dijkstra: Header = minicbor::decode(raw).unwrap();

        let leios_tail = minicbor::to_vec(as_dijkstra.header_body.block_body_contains_leios_cert)
            .unwrap()
            .len()
            + minicbor::to_vec(&as_dijkstra.header_body.eb_announcement)
                .unwrap()
                .len();
        assert_eq!(
            raw.len() - babbage_bytes.len(),
            leios_tail,
            "{name}: the dropped tail should be exactly block_body_contains_leios_cert plus eb_announcement"
        );

        assert_eq!(minicbor::to_vec(&as_dijkstra).unwrap(), raw);
    }

    let empty: Header = header_of("dijkstra1");
    assert!(!empty.header_body.block_body_contains_leios_cert);
    assert!(matches!(
        empty.header_body.eb_announcement,
        crate::Nullable::Null
    ));

    let populated: Header = header_of("dijkstra8");
    assert!(populated.header_body.block_body_contains_leios_cert);
    assert!(matches!(
        populated.header_body.eb_announcement,
        crate::Nullable::Some(_)
    ));

    let width = |h: &Header| {
        minicbor::to_vec(&h.header_body.eb_announcement)
            .unwrap()
            .len()
    };
    assert_eq!(width(&empty), 1, "a nil announcement is one byte");
    assert!(
        width(&populated) > 32,
        "an announcement carrying a 32 byte hash cannot fit in {} bytes",
        width(&populated)
    );
}

/// The refusal is the block body's, not the header's, so both halves are
/// asserted: a refusal that fired at the header would be a different fact.
#[test]
fn pre_fork_blocks_are_refused_as_dijkstra_blocks() {
    for (name, block_str) in PRE_FORK_BLOCKS.iter() {
        let bytes = hex::decode(block_str).unwrap();

        let decoded: Result<BlockWrapper, _> = minicbor::decode(&bytes);
        assert!(
            decoded.is_err(),
            "{name} is a pre fork block and must not decode as a Dijkstra one"
        );

        // Conway's type reads it, so the refusal above is about the era and not a damaged fixture.
        let (_, conway): (u16, crate::conway::Block) = minicbor::decode(&bytes)
            .unwrap_or_else(|e| panic!("{name} should decode as a Conway block: {e:?}"));
        let raw_header = conway.header.raw_cbor();

        let through_conway = minicbor::to_vec(conway.header.clone().unwrap()).unwrap();
        assert!(
            through_conway.len() < raw_header.len(),
            "{name}: Conway's ten field header body should drop the Leios tail, raw {} re-encoded {}",
            raw_header.len(),
            through_conway.len()
        );

        let as_dijkstra: Header = minicbor::decode(raw_header).unwrap_or_else(|e| {
            panic!("{name}: a pre fork header on this chain is already twelve fields: {e:?}")
        });
        assert_eq!(
            minicbor::to_vec(&as_dijkstra).unwrap(),
            raw_header,
            "{name}: the Dijkstra header type should give every byte back"
        );
    }
}

/// Neither form may decode as the other, or a closure would carry a verdict nobody issued.
#[test]
fn a_block_transaction_is_not_a_mempool_transaction() {
    let bytes = hex::decode(TEST_BLOCKS[WITH_TRANSACTIONS].1).unwrap();
    let (_, block): BlockWrapper = minicbor::decode(&bytes).unwrap();

    let tx = block
        .block_body
        .transactions
        .first()
        .expect("this fixture must carry at least one transaction");

    let four = minicbor::to_vec(tx).unwrap();
    let back: BlockTransaction = minicbor::decode(&four).unwrap();
    assert_eq!(&back, tx);

    let as_mempool: Result<MempoolTransaction, _> = minicbor::decode(&four);
    assert!(
        as_mempool.is_err(),
        "a block transaction must not decode as a mempool transaction"
    );

    let three = minicbor::to_vec(tx.to_mempool_transaction()).unwrap();
    let round: MempoolTransaction = minicbor::decode(&three).unwrap();
    assert!(!round.is_valid_supplied);
    assert_eq!(
        four.len() - three.len(),
        minicbor::to_vec(tx.success).unwrap().len(),
        "the two forms should differ by the flag and nothing else"
    );

    let as_block: Result<BlockTransaction, _> = minicbor::decode(&three);
    assert!(
        as_block.is_err(),
        "a mempool transaction must not decode as a block transaction"
    );
}

/// A valid block transaction comes back byte for byte from a round trip through
/// the mempool form.
#[test]
fn a_mempool_transaction_becomes_a_valid_block_transaction() {
    let bytes = hex::decode(TEST_BLOCKS[WITH_TRANSACTIONS].1).unwrap();
    let (_, block): BlockWrapper = minicbor::decode(&bytes).unwrap();

    let tx = block
        .block_body
        .transactions
        .first()
        .expect("this fixture must carry at least one transaction");

    let three = minicbor::to_vec(tx.to_mempool_transaction()).unwrap();
    let mempool: MempoolTransaction = minicbor::decode(&three).unwrap();

    let rebuilt = BlockTransaction::from(mempool.clone());
    assert!(rebuilt.success, "the mempool form admits no other verdict");

    let spelled_out = MempoolTransaction {
        is_valid_supplied: true,
        ..mempool
    };
    assert_eq!(
        BlockTransaction::from(spelled_out),
        rebuilt,
        "a `true` written out means what the three element form means"
    );
    assert_eq!(&rebuilt, tx, "nothing but the flag was restored");
    assert_eq!(
        minicbor::to_vec(&rebuilt).unwrap(),
        minicbor::to_vec(tx).unwrap(),
        "the round trip is byte for byte"
    );

    let four = minicbor::to_vec(&rebuilt).unwrap();
    let round: Result<MempoolTransaction, _> = minicbor::decode(&four);
    assert!(
        round.is_err(),
        "the rebuilt transaction must no longer read as a mempool one"
    );
}

/// Heap addresses of an input, a vkey witness and a metadata label, which a
/// move leaves unchanged.
fn heap_addresses(
    body: &TransactionBody,
    witnesses: &WitnessSet,
    auxiliary_data: &Nullable<KeepRaw<AuxiliaryData>>,
) -> [usize; 3] {
    let input = body.inputs.first().expect("a transaction spends an input");
    let vkey = witnesses
        .vkeywitness
        .as_ref()
        .and_then(|w| w.first())
        .expect("the fixture transaction is signed");
    let label = match auxiliary_data {
        Nullable::Some(aux) => match &**aux {
            AuxiliaryData::PostAlonzo(aux) => aux.metadata.as_ref().and_then(|m| m.keys().next()),
            _ => None,
        },
        _ => None,
    }
    .expect("the fixture transaction carries metadata");

    [
        input as *const _ as usize,
        vkey as *const _ as usize,
        label as *const _ as usize,
    ]
}

#[test]
fn a_mempool_transaction_is_moved_into_its_block_form() {
    let bytes = hex::decode(block_named("dijkstra4")).unwrap();
    let (_, block): BlockWrapper = minicbor::decode(&bytes).unwrap();

    let tx = block
        .block_body
        .transactions
        .first()
        .expect("dijkstra4 carries a transaction");

    let three = minicbor::to_vec(tx.to_mempool_transaction()).unwrap();
    let mempool: MempoolTransaction = minicbor::decode(&three).unwrap();

    let before = heap_addresses(
        &mempool.transaction_body,
        &mempool.transaction_witness_set,
        &mempool.auxiliary_data,
    );
    let rebuilt = BlockTransaction::from(mempool);
    let after = heap_addresses(
        &rebuilt.transaction_body,
        &rebuilt.transaction_witness_set,
        &rebuilt.auxiliary_data,
    );

    assert_eq!(
        after, before,
        "the body, witness set and auxiliary data must keep their allocations"
    );
}

const DEFS_CDDL: &str = include_str!("defs.cddl");
const MODEL_RS: &str = include_str!("model.rs");
const TESTS_RS: &str = include_str!("tests.rs");

/// The leios-fetch messages of the vendored cardano-blueprint, the second source this module cites.
#[cfg(feature = "blueprint")]
const LEIOS_FETCH_CDDL: &str =
    include_str!("../../../cardano-blueprint/src/network/node-to-node/leios-fetch/messages.cddl");

/// Rules this module cites that the leios-fetch messages define.
const LEIOS_FETCH_RULES: &[&str] = &["endorser_block"];

/// Rules the vendored revision does not define, because the ledger deleted or
/// renamed each one. A resync that brings one back fails the test below.
const ABSENT_RULES: &[&str] = &[
    // Deleted outright along with the block body's index set.
    "invalid_transactions",
    "transaction_index",
    // Renamed to `block_transaction`.
    "transaction",
    // Renamed to `mempool_transaction`.
    "transaction_mempool",
    // Renamed to `eb_announcement`, then to `eb_references_announcement`.
    "leios_announcement",
    "eb_announcement",
    // Renamed to `bls_key`.
    "leios_key",
    // Deleted with `redeemers`' array arm.
    "redeemer",
    // Widened into `guards` at the same key.
    "required_signers",
    // Dropped certificate variants 0 and 1.
    "account_registration_cert",
    "account_unregistration_cert",
    // Renamed to `guardrails_script_hash`.
    "policy_hash",
];

/// Backticked names in this module's doc comments that are not CDDL rules:
/// field names inside a quoted rule, prelude types, and CBOR literals.
const NOT_RULES: &[&str] = &[
    // Prelude types and control operators.
    "bool",
    "bytes",
    "cbor",
    "nil",
    "size",
    "uint",
    // The generic parameter of the three set rules, not a rule itself.
    "a0",
    // Field names inside a quoted rule body.
    "block_body_contains_leios_cert",
    "bls_possession_proof",
    "bls_pubkey",
    "body_signature",
    "deposit",
    "eb_hash",
    "eb_size",
    "highest_supported_major_version",
    "is_valid",
    "pledge",
    "self_reported_software_tag",
    "signers",
    "success",
    "ttl",
    // Values rather than rules.
    "false",
    "guarding",
    "true",
    // Parameters of the scan below, named in their own doc comments.
    "name",
    "text",
];

/// True when the CDDL `text` defines `name` as a rule, not merely mentions it.
fn defines_rule(text: &str, name: &str) -> bool {
    text.lines().any(|line| {
        line.strip_prefix(name).is_some_and(|rest| {
            let rest = rest.trim_start();
            // A plain rule is `name =`, a generic one is `name<a0> =`.
            rest.starts_with('=') || rest.starts_with('<')
        })
    })
}

/// Every snake case word in `text`. A word with an upper case letter is a
/// Rust name and never a CDDL rule.
fn snake_words(text: &str) -> Vec<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| {
            word.starts_with(|c: char| c.is_ascii_lowercase())
                && word
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
        .map(str::to_string)
        .collect()
}

/// The rule a backticked span cites: a bare rule name, or a quoted
/// definition `name = ...`. Anything else in backticks is prose.
fn rule_citation(span: &str) -> Option<(String, &str)> {
    let name: String = span
        .chars()
        .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
        .collect();
    if !name.starts_with(|c: char| c.is_ascii_lowercase()) {
        return None;
    }

    let mut rest = span[name.len()..].trim_start();
    if let Some(after) = rest.strip_prefix('<') {
        rest = after.split_once('>')?.1.trim_start();
    }

    match rest.strip_prefix('=') {
        Some(body) => Some((name, body)),
        None if rest.is_empty() => Some((name, "")),
        None => None,
    }
}

/// Every rule citation in this module's doc comments, as the rule name and
/// the quoted text after its `=`. Both files are scanned, because a doc
/// comment in either one can cite a rule.
fn citations() -> Vec<(String, String)> {
    let mut found = Vec::new();

    for line in MODEL_RS.lines().chain(TESTS_RS.lines()) {
        let line = line.trim_start();
        if !(line.starts_with("///") || line.starts_with("//!")) {
            continue;
        }
        assert!(
            line.matches('`').count() % 2 == 0,
            "a doc comment opens a backtick it does not close, so the scan below cannot tell quoted text from prose: {line}"
        );

        for (i, span) in line.split('`').enumerate() {
            // Even indices are the prose between the quoted spans.
            if i % 2 == 0 {
                continue;
            }
            if let Some((name, body)) = rule_citation(span) {
                found.push((name, body.to_string()));
            }
        }
    }

    found
}

/// Every CDDL rule this module's doc comments cite.
fn cited_rules() -> std::collections::BTreeSet<String> {
    let mut cited = std::collections::BTreeSet::new();

    for (name, body) in citations() {
        // A leios-fetch rule's body names leios-fetch rules, so only the rule's name is added.
        if !LEIOS_FETCH_RULES.contains(&name.as_str()) {
            cited.extend(snake_words(&body));
        }
        cited.insert(name);
    }

    cited
}

/// Every citation has to land in exactly one of four places: a rule the
/// vendored file defines, a rule on the leios-fetch list, a rule the ledger
/// removed, or a name that is not one.
#[test]
fn every_cited_rule_matches_the_vendored_cddl() {
    let cited = cited_rules();

    // Every assertion below is satisfied by a scan that returns nothing.
    for expected in [
        "block",
        "block_body",
        "block_transaction",
        "certificate",
        "endorser_block",
        "guards",
        "header_body",
        "protocol_param_update",
        "transaction_body",
        "transaction_witness_set",
    ] {
        assert!(
            cited.contains(expected),
            "the citation scan did not find `{expected}`, which this module models and cites"
        );
    }
    assert!(
        cited.len() >= 60,
        "the citation scan found only {} names, far fewer than the module cites",
        cited.len()
    );

    let unaccounted: Vec<&str> = cited
        .iter()
        .map(String::as_str)
        .filter(|name| {
            !defines_rule(DEFS_CDDL, name)
                && !LEIOS_FETCH_RULES.contains(name)
                && !ABSENT_RULES.contains(name)
                && !NOT_RULES.contains(name)
        })
        .collect();
    assert!(
        unaccounted.is_empty(),
        "a doc comment cites {unaccounted:?}, which defs.cddl does not define and no list accounts for"
    );

    let doubled: Vec<&str> = LEIOS_FETCH_RULES
        .iter()
        .copied()
        .filter(|name| defines_rule(DEFS_CDDL, name))
        .collect();
    assert!(
        doubled.is_empty(),
        "defs.cddl defines {doubled:?}, so they belong to it rather than to the leios-fetch list"
    );

    let resurrected: Vec<&str> = ABSENT_RULES
        .iter()
        .copied()
        .filter(|name| defines_rule(DEFS_CDDL, name))
        .collect();
    assert!(
        resurrected.is_empty(),
        "defs.cddl defines {resurrected:?}, which this module models as removed or renamed"
    );

    let parked: Vec<&str> = NOT_RULES
        .iter()
        .copied()
        .filter(|name| defines_rule(DEFS_CDDL, name))
        .collect();
    assert!(
        parked.is_empty(),
        "defs.cddl defines {parked:?}, so they are rules and do not belong on the not-a-rule list"
    );

    let stale: Vec<&str> = NOT_RULES
        .iter()
        .chain(LEIOS_FETCH_RULES)
        .copied()
        .filter(|name| !cited.contains(*name))
        .collect();
    assert!(
        stale.is_empty(),
        "no doc comment names {stale:?} any more, so a list has entries nothing needs"
    );

    // No list above can pass by the predicate always agreeing.
    assert!(defines_rule(DEFS_CDDL, "block_body"));
    assert!(!defines_rule(DEFS_CDDL, "block_bod"));
    assert!(!defines_rule(DEFS_CDDL, "no_such_rule_exists"));
}

#[cfg(feature = "blueprint")]
#[test]
fn every_leios_fetch_citation_matches_the_leios_fetch_messages() {
    let unsourced: Vec<&str> = LEIOS_FETCH_RULES
        .iter()
        .copied()
        .filter(|name| !defines_rule(LEIOS_FETCH_CDDL, name))
        .collect();
    assert!(
        unsourced.is_empty(),
        "the leios-fetch messages do not define {unsourced:?}, so they do not belong on its list"
    );

    let words = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let quoted: Vec<String> = citations()
        .into_iter()
        .filter(|(name, body)| LEIOS_FETCH_RULES.contains(&name.as_str()) && !body.is_empty())
        .map(|(name, body)| words(&format!("{name} ={body}")))
        .collect();
    for rule in LEIOS_FETCH_RULES {
        assert!(
            quoted
                .iter()
                .any(|quote| quote.starts_with(&format!("{rule} ="))),
            "no doc comment quotes `{rule}`, so nothing checks its text against the leios-fetch messages"
        );
    }
    for quote in &quoted {
        assert!(
            LEIOS_FETCH_CDDL.lines().any(|line| words(line) == *quote),
            "a doc comment quotes `{quote}`, which is no line of the leios-fetch messages"
        );
    }

    // The list cannot pass by the predicate always agreeing.
    assert!(defines_rule(LEIOS_FETCH_CDDL, "endorser_block"));
    assert!(!defines_rule(LEIOS_FETCH_CDDL, "block_body"));
}

#[test]
fn conway_header_is_refused_as_dijkstra() {
    let conway = hex::decode(include_str!("../../../test_data/conway1.block")).unwrap();
    let (_, block): (u16, crate::conway::Block) = minicbor::decode(&conway).unwrap();
    let raw = block.header.raw_cbor();

    let decoded: Result<KeepRaw<'_, Header>, _> = minicbor::decode(raw);
    assert!(
        decoded.is_err(),
        "a ten field Conway header must not decode as a Dijkstra header"
    );
}

/// A `proposal_procedure` whose `gov_action` is a `parameter_change_action`
/// setting one key. Hand built, because no fixture carries a proposal.
fn proposal_setting(key: u64) -> Vec<u8> {
    let hex_str = match key {
        0 => include_str!("../../../test_data/proposal-param-change-key0.hex"),
        48 => include_str!("../../../test_data/proposal-param-change-key48.hex"),
        other => panic!("no proposal fixture sets key {other}"),
    };

    hex::decode(hex_str).expect("invalid hex")
}

/// A short type would turn a key 48 change into an update that changes nothing.
#[test]
fn a_proposal_keeps_the_dijkstra_parameter_keys() {
    // Key 0 exists in every era, so a failure here is about the proposal shape.
    let shared_key = proposal_setting(0);
    let decoded: ProposalProcedure =
        minicbor::decode(&shared_key).expect("a proposal setting key 0 must decode");
    assert_eq!(
        hex::encode(minicbor::to_vec(&decoded).unwrap()),
        hex::encode(&shared_key),
        "a proposal setting key 0 lost bytes on re-encode"
    );

    let dijkstra_key = proposal_setting(48);
    let decoded: ProposalProcedure =
        minicbor::decode(&dijkstra_key).expect("a proposal setting key 48 must decode");
    assert_eq!(
        hex::encode(minicbor::to_vec(&decoded).unwrap()),
        hex::encode(&dijkstra_key),
        "a proposal setting key 48 lost it on re-encode, so the update type this era's gov_action carries stops short of 48"
    );

    match decoded.gov_action {
        GovAction::ParameterChange(_, update, _) => assert_eq!(
            update.max_ref_script_size_per_endorser_block,
            Some(20_000),
            "key 48 decoded into no field"
        ),
        other => panic!("expected a parameter change action, found {other:?}"),
    }
}

#[test]
fn a_parameter_update_re_encodes_every_key_and_each_nil() {
    let cases = [
        // Key 38 set to a value, the shape every earlier key has.
        ("38 set", "a11826d81e820301"),
        // Keys 49 to 56, with 50 and 54 as tag 30 rationals.
        (
            "49 to 56",
            "a8183118711832d81e8207031833187218341873183518741836d81e8201091837187518381876",
        ),
        // Keys 38 and 53 set to nil, which the CDDL admits for those two keys alone.
        ("38 and 53 nil", "a21826f61835f6"),
    ];

    let mut lost = Vec::new();
    for (label, hex_str) in cases {
        let bytes = hex::decode(hex_str).unwrap();
        let update: ProtocolParamUpdate = minicbor::decode(&bytes)
            .unwrap_or_else(|e| panic!("{label}: the update did not decode: {e:?}"));
        let encoded = hex::encode(minicbor::to_vec(&update).unwrap());
        if encoded != hex_str {
            lost.push((label, encoded));
        }
    }

    assert_eq!(lost, vec![], "these updates lost a key on re-encode");
}

/// `pool_params` carries `? bls_key : bls_key/ nil` (`defs.cddl`) between
/// `vrf_keyhash` and `pledge`. Every fixture certificate reaches the wire
/// inside a `KeepRaw` body, so without this the length choice runs nowhere.
#[test]
fn a_pool_registration_re_encodes_each_bls_key_state() {
    // A real registration off the chain, so the fields around the slot are the node's.
    let mut populated = None;
    for (_, block_str) in TEST_BLOCKS.iter() {
        let bytes = hex::decode(block_str).unwrap();
        let (_, block): BlockWrapper = minicbor::decode(&bytes).unwrap();
        for tx in block.block_body.transactions.iter() {
            let body = tx.transaction_body.clone().unwrap();
            let Some(certificates) = body.certificates else {
                continue;
            };
            for certificate in certificates.iter() {
                if matches!(certificate, Certificate::PoolRegistration { .. }) {
                    populated = Some(certificate.clone());
                }
            }
        }
    }
    let populated = populated.expect("the fixtures must carry a pool registration");

    let Certificate::PoolRegistration { ref bls_key, .. } = populated else {
        unreachable!()
    };
    assert!(
        matches!(bls_key, Some(crate::Nullable::Some(_))),
        "the chain carries this slot populated, which is the state the other two are built from"
    );

    let in_state = |slot| {
        let mut certificate = populated.clone();
        if let Certificate::PoolRegistration { bls_key, .. } = &mut certificate {
            *bls_key = slot;
        }
        certificate
    };

    let states = [
        ("populated", populated.clone(), 0x8b),
        ("nil", in_state(Some(crate::Nullable::Null)), 0x8b),
        ("absent", in_state(None), 0x8a),
    ];

    let mut encodings = Vec::new();
    for (label, certificate, array_header) in states.iter() {
        let bytes = minicbor::to_vec(certificate).unwrap();
        assert_eq!(
            bytes[0], *array_header,
            "{label}: the slot decides the array length"
        );

        let back: Certificate = minicbor::decode(&bytes)
            .unwrap_or_else(|e| panic!("{label}: a pool registration did not decode: {e:?}"));
        assert_eq!(&back, certificate, "{label}");

        encodings.push((label, bytes));
    }

    assert_ne!(
        encodings[0].1, encodings[1].1,
        "a populated slot and a nil slot must not encode alike"
    );
    assert_ne!(
        encodings[1].1, encodings[2].1,
        "a nil slot and an absent slot must not encode alike"
    );
}

/// No fixture carries either shape, so without this the encoder's four
/// element branch and the decoder's refusal of `false` run nowhere.
#[test]
fn a_mempool_transaction_re_encodes_both_accepted_shapes() {
    let bytes = hex::decode(TEST_BLOCKS[WITH_TRANSACTIONS].1).unwrap();
    let (_, block): BlockWrapper = minicbor::decode(&bytes).unwrap();
    let tx = block
        .block_body
        .transactions
        .first()
        .expect("this fixture must carry at least one transaction");

    let three = tx.to_mempool_transaction();
    let three_bytes = minicbor::to_vec(&three).unwrap();
    assert_eq!(
        three_bytes[0], 0x83,
        "a mempool transaction is three elements"
    );
    let back: MempoolTransaction = minicbor::decode(&three_bytes).unwrap();
    assert_eq!(back, three);

    let mut four = three.clone();
    four.is_valid_supplied = true;
    let four_bytes = minicbor::to_vec(&four).unwrap();
    assert_eq!(four_bytes[0], 0x84, "the tolerated form is four elements");
    let back: MempoolTransaction = minicbor::decode(&four_bytes).unwrap();
    assert_eq!(back, four);
    assert!(back.is_valid_supplied);

    // The body and the witness set replay their own bytes, so the flag's position
    // is computable. Checking the byte stops the refusal below firing elsewhere.
    let flag_at =
        1 + tx.transaction_body.raw_cbor().len() + tx.transaction_witness_set.raw_cbor().len();
    assert_eq!(four_bytes[flag_at], 0xf5, "the flag should be `true` here");

    let mut with_false = four_bytes.clone();
    with_false[flag_at] = 0xf4;
    let refused: Result<MempoolTransaction, _> = minicbor::decode(&with_false);
    assert!(
        refused.is_err(),
        "`false` is not an allowed value for the flag"
    );
}

/// An empty array has no first element to decide the arm on, so it is refused.
#[test]
fn an_empty_guards_array_is_refused() {
    let keyhash = [0x11u8; 28];

    let mut empty = vec![0x80];
    empty.push(0x58);
    empty.push(0x1c);
    empty.extend_from_slice(&keyhash);

    // The byte string after the empty array is not part of it.
    let decoded: Result<Guards, _> = minicbor::decode(&empty);
    assert!(
        decoded.is_err(),
        "an empty guards array must be refused, decoded as {:?}",
        decoded.ok()
    );

    // The same shape with one element decodes, so the refusal is about emptiness.
    let mut one_keyhash = vec![0x81, 0x58, 0x1c];
    one_keyhash.extend_from_slice(&keyhash);
    let decoded: Guards =
        minicbor::decode(&one_keyhash).expect("a one element addr_keyhash guards must decode");
    assert!(matches!(decoded, Guards::AddrKeyhashes(_)));

    let mut one_credential = vec![0x81, 0x82, 0x00, 0x58, 0x1c];
    one_credential.extend_from_slice(&keyhash);
    let decoded: Guards =
        minicbor::decode(&one_credential).expect("a one element credential guards must decode");
    assert!(matches!(decoded, Guards::Credentials(_)));
}

/// The bytes of a body with one input and no outputs, ending with the given hex keys.
fn body_ending(top: bool, rest: &str) -> &'static [u8] {
    let (header, fee) = if top { ("a4", "0200") } else { ("a3", "") };
    let input = format!("d9010281825820{}00", "03".repeat(32));
    generated(&format!("{header}00{input}0180{fee}{rest}"))
}

#[test]
fn an_empty_guards_set_in_either_body_reads_as_no_guards() {
    for empty in ["d9010280", "80", "9fff"] {
        let top: TransactionBody = decode_all(body_ending(true, &format!("0e{empty}")));
        assert_eq!(top.guards, None, "{empty}");
        let sub: SubTransactionBody = decode_all(body_ending(false, &format!("0e{empty}")));
        assert_eq!(sub.guards, None, "{empty}");
    }
}

#[test]
fn a_guards_set_with_a_key_in_either_body_reads_as_that_key() {
    let one = format!("0ed9010281581c{}", "06".repeat(28));
    let top: TransactionBody = decode_all(body_ending(true, &one));
    assert!(matches!(top.guards, Some(Guards::AddrKeyhashes(_))));
    let sub: SubTransactionBody = decode_all(body_ending(false, &one));
    assert!(matches!(sub.guards, Some(Guards::AddrKeyhashes(_))));
}

#[test]
fn a_guards_value_that_is_not_a_set_is_refused_in_either_body() {
    let top: Result<TransactionBody, _> = minicbor::decode(body_ending(true, "0e01"));
    assert!(top.is_err());
    let sub: Result<SubTransactionBody, _> = minicbor::decode(body_ending(false, "0e01"));
    assert!(sub.is_err());
}

/// A type reaching Alonzo's native script from here would refuse a whole
/// block over a guard clause in a transaction that used the array form.
#[test]
fn the_array_form_of_auxiliary_data_carries_this_eras_native_scripts() {
    let keyhash = [0x7a; 28];

    // `[{}, [[6, [0, h'..']]]]`, one guard clause in the array form.
    let mut aux = vec![0x82, 0xa0, 0x81, 0x82, 0x06, 0x82, 0x00, 0x58, 0x1c];
    aux.extend_from_slice(&keyhash);

    let decoded: AuxiliaryData =
        minicbor::decode(&aux).expect("the array form carrying a guard clause must decode");

    let AuxiliaryData::ShelleyMa(inner) = &decoded else {
        panic!("an array must decode as the ShelleyMa arm, found {decoded:?}");
    };
    let scripts = inner
        .auxiliary_scripts
        .as_ref()
        .expect("a guard clause must not make the whole auxiliary scripts field read as absent");
    assert_eq!(scripts.len(), 1);
    assert!(
        matches!(*scripts[0], NativeScript::ScriptRequireGuard(_)),
        "the guard clause must survive, found {:?}",
        scripts[0]
    );

    assert_eq!(
        hex::encode(minicbor::to_vec(&decoded).unwrap()),
        hex::encode(&aux),
        "the array form must re-encode to the bytes it was read from"
    );
}

/// `script_n_of_k`'s threshold is `int64` here just as in alonzo (`defs.cddl`
/// carries the note in both); the extremes are where an unsigned regression
/// would fail first.
#[test]
fn n_of_k_threshold_is_signed_at_the_extremes() {
    for n in [i64::MIN, -1, 0, i64::MAX] {
        let script = NativeScript::ScriptNOfK(n, vec![]);
        let bytes = minicbor::to_vec(&script).unwrap();
        let decoded: NativeScript = minicbor::decode(&bytes).unwrap();
        assert_eq!(decoded, script, "round trip for n={n}");

        let alonzo_bytes =
            minicbor::to_vec(crate::alonzo::NativeScript::ScriptNOfK(n, vec![])).unwrap();
        assert_eq!(
            bytes, alonzo_bytes,
            "wire bytes must match alonzo's for n={n}"
        );
    }
}

/// The header hash each fixture was cut against, from `test_data/dijkstra-fixtures.md`.
const HEADER_HASHES: &[(&str, &str)] = &[
    (
        "dijkstra1",
        "d0c2a26a0192baf397b75cd38137987d82036c269089362842888279f3e19daf",
    ),
    (
        "dijkstra2",
        "adb23531ebb61891912e6a4bdabcbaaa053223d2de342eedbaa9b6af4fb526f3",
    ),
    (
        "dijkstra3",
        "294b3df1e6758e6f17f2b5a09ed469c6ec37c2db4d274264c8ee5edabe31229a",
    ),
    (
        "dijkstra4",
        "f8926da4333a3ce5fdb7b60a00d80eb23da0823c6962f06abfdee149b59dae41",
    ),
    (
        "dijkstra5",
        "7b7c9f48ac331106e9f9ef03856090bc6275f09fca5bb4c789068d04c54b079a",
    ),
    (
        "dijkstra6",
        "dec1d7087ff0191191fd3bac1559ae1b9c40b93ad33ec9cfba1f2e4722019a23",
    ),
    (
        "dijkstra7",
        "920a4883bf663cd3640af8ee87292edd391ff9b99debef2ba556f2f8e9d5761d",
    ),
    (
        "dijkstra8",
        "33a48eee693522320891dd4d1da8ee33c288c854eb25337802dbc4c912571d07",
    ),
    (
        "dijkstra9",
        "112495349409ccaa7a57e810aa59b014337612438a3e07cd5ce1bb3126dfbbea",
    ),
    (
        "dijkstra10",
        "917c72dcd2d2222df5cc82fcebea55c4f9135e5f1491afd66d79d48d52e42f60",
    ),
    (
        "dijkstra11",
        "e45c1dc810ddfb36ffb9647eaf08861b4611fb4e872a227c00337dddf2680b8c",
    ),
    (
        "dijkstra12",
        "3e0e56a9af0cb26e0641747ca835874135d02d35a29820a5e4de6beb37c17914",
    ),
    (
        "dijkstra13",
        "cf522686b27e452b3e261904058c7e323f3723e2f5c629e5a7542579b59474b4",
    ),
    (
        "dijkstra14",
        "9b481f4b4fa46de9a1bde085570b5fc9d90f161f99bde7f63bfe4ed20dbc37bf",
    ),
    (
        "dijkstra15",
        "0db84efa0259153a240cecacd0f9e52f942d40f96b132ebd0d5b3526e19b3a7b",
    ),
    (
        "dijkstra-rc-2026w42-7",
        "0d88c2182f7b6f1c2796677109d918c430538bf6b4df11c1ebf29a94243a3cd6",
    ),
    (
        "dijkstra-rc-2026w42-11",
        "f2fccd6e970425d1403101bc6553a4fb6a548a27d465fd29ae4c2ab11992b204",
    ),
];

/// The hash is over the header CBOR span, so it also pins where the body begins.
#[test]
fn every_fixture_hashes_to_its_recorded_header_hash() {
    assert_eq!(
        HEADER_HASHES.len(),
        TEST_BLOCKS.len(),
        "every fixture needs a recorded hash, and no row may name a fixture that is gone"
    );

    for (name, expected) in HEADER_HASHES.iter() {
        let block = block_of(name);
        let hashed = pallas_crypto::hash::Hasher::<256>::hash(block.header.raw_cbor());
        assert_eq!(
            hex::encode(hashed),
            *expected,
            "{name}: the header does not hash to the value it was cut against"
        );
    }

    let first = block_of("dijkstra1");
    let mut damaged = first.header.raw_cbor().to_vec();
    let last = damaged.len() - 1;
    damaged[last] ^= 0x01;
    assert_ne!(
        hex::encode(pallas_crypto::hash::Hasher::<256>::hash(&damaged)),
        HEADER_HASHES[0].1,
        "one flipped bit must change the header hash"
    );
}

/// Every value is read out of the block, because asking only whether the slot
/// is non nil would pass on a certificate decoded into the wrong two fields.
#[test]
fn a_block_carrying_both_leios_fields_reads_both() {
    let block = block_of("dijkstra8");
    let header = header_of("dijkstra8");

    // The header's flag and the body's slot are independent, and they agree.
    assert!(
        header.header_body.block_body_contains_leios_cert,
        "dijkstra8 is a block whose header says it carries a certificate"
    );

    let crate::Nullable::Some(certificate) = &block.block_body.leios_certificate else {
        panic!("dijkstra8 must carry a leios certificate in its block body");
    };

    assert_eq!(
        hex::encode(certificate.signers.as_slice()),
        "f218a17300000e08200200"
    );
    assert_eq!(certificate.signers.len(), 11);
    assert_eq!(
        hex::encode(certificate.signature.as_slice()),
        "b033236ab20c0f6aeec3a32c78500aa532c23c442f914e4688e831a7972524955e2ceaa29a898ec813f7993d08bd6d18"
    );
    assert_eq!(
        certificate.signature.len(),
        48,
        "a BLS12-381 signature is 48 bytes"
    );

    let crate::Nullable::Some(announcement) = &header.header_body.eb_announcement else {
        panic!("dijkstra8 must carry an endorser block announcement");
    };
    assert_eq!(
        hex::encode(announcement.eb_hash),
        "de5f4b812d0e6dc3129510c6663de4ea99bbd6bf019ec2d541853242926fd446"
    );
    assert_eq!(announcement.eb_hash.as_ref().len(), 32);
    assert_eq!(announcement.eb_size, 39495);

    // Peras is reserved and unused, so this slot is the empty answer.
    assert!(matches!(
        block.block_body.peras_certificate,
        crate::Nullable::Null
    ));
}

/// A model that read the certificate out of the announcement, or set the flag
/// from either, would pass on every other block in the set.
#[test]
fn a_certificate_travels_without_an_announcement() {
    let block = block_of("dijkstra9");
    let header = header_of("dijkstra9");

    assert!(header.header_body.block_body_contains_leios_cert);
    assert!(
        matches!(header.header_body.eb_announcement, crate::Nullable::Null),
        "dijkstra9 is the block that certifies without announcing"
    );

    let crate::Nullable::Some(certificate) = &block.block_body.leios_certificate else {
        panic!("dijkstra9 must carry a leios certificate");
    };
    assert_eq!(
        hex::encode(certificate.signers.as_slice()),
        "fb38a17604001208208000"
    );
    assert_eq!(
        hex::encode(certificate.signature.as_slice()),
        "aaffc43163076f2f58434d4b4d68c34afe09b45bc6da439cdef3d09ecba6b395a55335ba4a2f1feb6eba3096b0abe250"
    );
    assert_eq!(certificate.signature.len(), 48);

    // The two certificates differ, so neither test reads a decoder constant.
    let other = block_of("dijkstra8");
    let crate::Nullable::Some(first) = &other.block_body.leios_certificate else {
        unreachable!()
    };
    assert_ne!(first.signers, certificate.signers);
    assert_ne!(first.signature, certificate.signature);

    // And the other direction of the pair: a block with neither field.
    let plain = block_of("dijkstra11");
    assert!(matches!(
        plain.block_body.leios_certificate,
        crate::Nullable::Null
    ));
    assert!(matches!(
        header_of("dijkstra11").header_body.eb_announcement,
        crate::Nullable::Null
    ));
    assert!(
        !header_of("dijkstra11")
            .header_body
            .block_body_contains_leios_cert
    );
}

/// `eb_references_announcement = [eb_hash : hash32, eb_size : uint .size 4]` (`defs.cddl`).
/// dijkstra15 announces 71103 bytes, past what two bytes hold, so the size is
/// written as a five byte uint where dijkstra8's 39495 is a three byte one.
#[test]
fn an_announced_size_reaches_the_five_byte_uint() {
    assert!(
        71103 > u32::from(u16::MAX),
        "the wide case has to be past what a two byte uint holds"
    );

    for (name, size, head, payload) in [
        ("dijkstra8", 39495u32, 0x19u8, 2usize),
        ("dijkstra15", 71103, 0x1a, 4),
    ] {
        let block = block_of(name);
        let header = header_of(name);

        let crate::Nullable::Some(announcement) = &header.header_body.eb_announcement else {
            panic!("{name} must carry an endorser block announcement");
        };
        assert_eq!(announcement.eb_size, size, "{name}: the announced size");
        assert_eq!(
            announcement.eb_hash.as_ref().len(),
            32,
            "{name}: the announced hash"
        );

        let encoded = minicbor::to_vec(announcement).unwrap();
        assert_eq!(
            encoded[35], head,
            "{name}: the CBOR head byte the size re-encodes to"
        );
        assert_eq!(
            encoded.len(),
            36 + payload,
            "{name}: the size head byte is followed by {payload} payload bytes"
        );

        let raw = block.header.raw_cbor();
        assert!(
            raw.windows(encoded.len()).any(|w| w == encoded),
            "{name}: the announcement did not re-encode to a span of the header it was read from"
        );
    }
}

/// Transaction body key 3 is `ttl`, and dijkstra10 carries both output forms
/// at once, so one block reads the map form and the legacy array form.
#[test]
fn a_ttl_and_both_output_forms_are_read_from_one_block() {
    let block = block_of("dijkstra10");

    let mut ttls = Vec::new();
    let mut map_outputs = 0usize;
    let mut array_outputs = 0usize;

    for tx in block.block_body.transactions.iter() {
        let body = tx.transaction_body.clone().unwrap();
        if let Some(ttl) = body.ttl {
            ttls.push(ttl);
        }
        for output in body.outputs.iter() {
            match output {
                TransactionOutput::PostAlonzo(_) => map_outputs += 1,
                TransactionOutput::Legacy(_) => array_outputs += 1,
            }
        }
    }

    // A model with no field for key 3 would skip it in and replay it out, so
    // the round trip cannot see it and this is what does.
    assert_eq!(
        ttls,
        vec![468_996],
        "dijkstra10 sets ttl on exactly one of its seven transactions"
    );

    assert_eq!(
        (map_outputs, array_outputs),
        (5, 2),
        "dijkstra10 carries five map form outputs and two legacy array ones"
    );

    let first = block.block_body.transactions.first().unwrap();
    let body = first.transaction_body.clone().unwrap();
    let TransactionOutput::PostAlonzo(output) = body.outputs.first().unwrap() else {
        panic!("dijkstra10's first transaction pays to a map form output");
    };
    assert!(
        !output.address.is_empty(),
        "a map form output carries an address at key 0"
    );
    assert!(
        matches!(*output.value, crate::conway::Value::Coin(_)),
        "this output pays plain ada"
    );
    assert!(
        output.datum_option.is_none(),
        "no datum option exists anywhere on this chain"
    );
    assert!(
        output.script_ref.is_none(),
        "no script reference exists anywhere on this chain"
    );
}

/// `delegation_to_drep_cert = (9, stake_credential, drep)` (`defs.cddl`).
/// dijkstra13 is the only fixture that reaches the tag 9 arm.
#[test]
fn a_vote_delegation_certificate_is_read_from_the_chain() {
    let block = block_of("dijkstra13");

    let mut certificates = Vec::new();
    for tx in block.block_body.transactions.iter() {
        let body = tx.transaction_body.clone().unwrap();
        if let Some(found) = body.certificates {
            certificates.extend(found.iter().cloned());
        }
    }

    assert_eq!(
        certificates.len(),
        2,
        "dijkstra13 carries a registration and a vote delegation"
    );

    let delegation = certificates
        .iter()
        .find(|c| matches!(c, Certificate::VoteDeleg(..)))
        .expect("dijkstra13 must carry a vote delegation certificate");
    let Certificate::VoteDeleg(credential, drep) = delegation else {
        unreachable!()
    };
    assert!(
        matches!(credential, StakeCredential::AddrKeyhash(_)),
        "this delegation is by key hash, found {credential:?}"
    );
    assert!(
        matches!(drep, DRep::Abstain),
        "this delegation is to the predefined abstain drep, found {drep:?}"
    );

    // A different arm, so the find above chose rather than took the only one.
    assert!(
        certificates
            .iter()
            .any(|c| matches!(c, Certificate::Reg(..))),
        "the block's other certificate is a registration"
    );

    let round: Certificate = minicbor::decode(&minicbor::to_vec(delegation).unwrap()).unwrap();
    assert_eq!(&round, delegation);
}

/// The fixture set holds both arms. If the bare arm ever left it, the round
/// trip would go on passing with the arm exercised by nothing.
#[test]
fn a_set_re_encodes_the_arm_it_was_read_from() {
    let mut tagged = 0usize;
    let mut bare = 0usize;

    for (name, block_str) in TEST_BLOCKS.iter() {
        let bytes = hex::decode(block_str).unwrap();
        let (_, block): BlockWrapper = minicbor::decode(&bytes).unwrap();

        for (i, tx) in block.block_body.transactions.iter().enumerate() {
            let body = tx.transaction_body.clone().unwrap();
            match body.inputs.arm() {
                SetArm::Tagged => tagged += 1,
                SetArm::Bare => bare += 1,
            }

            // Key 0 is the body map's first key, so the inputs span starts two
            // bytes in. Both of those bytes are checked rather than assumed.
            let raw = tx.transaction_body.raw_cbor();
            assert!(
                (0xa0..=0xb7).contains(&raw[0]),
                "{name} transaction {i}: a body is a map of at most 23 keys"
            );
            assert_eq!(
                raw[1], 0x00,
                "{name} transaction {i}: inputs are the body's first key"
            );
            assert!(
                raw[2..].starts_with(&minicbor::to_vec(&body.inputs).unwrap()),
                "{name} transaction {i}: the inputs did not re-encode to the span they were read from"
            );
        }
    }

    assert_eq!(
        (tagged, bare),
        (39, 7),
        "the fixtures carry thirty nine tagged input sets and seven bare ones"
    );

    // A type that normalised the arms would satisfy everything above and fail here.
    let built: Set<u8> = vec![1u8, 2].into();
    assert_eq!(
        built.arm(),
        SetArm::Tagged,
        "a set that was built rather than decoded writes the tagged arm"
    );
    assert_ne!(
        hex::encode(minicbor::to_vec(&built).unwrap()),
        hex::encode(minicbor::to_vec(built.clone().with_arm(SetArm::Bare)).unwrap()),
        "the two arms must not encode alike"
    );
}

/// `certificates : nonempty_set<certificate>` (`defs.cddl`). Every other
/// fixture writes that set under tag 258, and dijkstra14 writes it bare, so
/// both arms of the body's key 4 are read from real bytes rather than one.
#[test]
fn a_certificate_set_is_read_on_both_arms_from_the_chain() {
    let mut tagged = Vec::new();
    let mut bare = Vec::new();

    for (name, _) in TEST_BLOCKS.iter() {
        let block = block_of(name);

        for tx in block.block_body.transactions.iter() {
            let body = tx.transaction_body.clone().unwrap();
            let Some(certificates) = body.certificates else {
                continue;
            };

            let encoded = minicbor::to_vec(&certificates).unwrap();
            match certificates.arm() {
                SetArm::Tagged => {
                    assert_eq!(
                        encoded[0], 0xd9,
                        "{name}: a tagged certificate set re-encodes under a two byte tag"
                    );
                    tagged.push(*name);
                }
                SetArm::Bare => {
                    assert_eq!(
                        encoded[0] >> 5,
                        4,
                        "{name}: a bare certificate set re-encodes as a plain array"
                    );
                    bare.push(*name);
                }
            }
        }
    }

    assert_eq!(
        bare,
        vec!["dijkstra14"],
        "dijkstra14 is the fixture whose transaction body writes its certificates bare"
    );
    assert_eq!(
        tagged.len(),
        10,
        "every other certificate set in the fixtures is tagged, and found {tagged:?}"
    );

    let block = block_of("dijkstra14");
    let tx = block
        .block_body
        .transactions
        .iter()
        .next()
        .expect("dijkstra14 carries a transaction");
    let body = tx.transaction_body.clone().unwrap();
    let certificates = body
        .certificates
        .expect("dijkstra14 carries the certificates key");

    assert_eq!(certificates.len(), 1);
    assert!(
        matches!(certificates[0], Certificate::PoolRegistration { .. }),
        "dijkstra14 registers a pool, found {:?}",
        certificates[0]
    );
    assert_eq!(
        body.inputs.arm(),
        SetArm::Bare,
        "dijkstra14 writes its input set bare as well"
    );
}

/// So the test above is about the guard clause and not about the array form.
#[test]
fn the_array_form_still_carries_a_clause_every_era_has() {
    let keyhash = [0x5c; 28];

    let mut aux = vec![0x82, 0xa0, 0x81, 0x82, 0x00, 0x58, 0x1c];
    aux.extend_from_slice(&keyhash);

    let decoded: AuxiliaryData = minicbor::decode(&aux).expect("must decode");

    let AuxiliaryData::ShelleyMa(inner) = &decoded else {
        panic!("an array must decode as the ShelleyMa arm")
    };
    let scripts = inner.auxiliary_scripts.as_ref().expect("readable");
    assert_eq!(scripts.len(), 1);
    assert!(matches!(*scripts[0], NativeScript::ScriptPubkey(_)));

    assert_eq!(
        hex::encode(minicbor::to_vec(&decoded).unwrap()),
        hex::encode(&aux)
    );
}

#[test]
fn a_set_of_one_element_reads_on_both_arms() {
    let tagged = [0xd9, 0x01, 0x02, 0x81, 0x01];
    let bare = [0x81, 0x01];

    let decoded: NonEmptySet<u64> =
        minicbor::decode(&tagged).expect("a tagged one element nonempty set must decode");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded.arm(), SetArm::Tagged);

    let decoded: NonEmptySet<u64> =
        minicbor::decode(&bare).expect("a bare one element nonempty set must decode");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded.arm(), SetArm::Bare);

    let empty: Set<u64> = minicbor::decode(&[0x80]).expect("an empty set must decode");
    assert!(empty.is_empty());
    let empty: Set<u64> =
        minicbor::decode(&[0xd9, 0x01, 0x02, 0x80]).expect("an empty tagged set must decode");
    assert!(empty.is_empty());
}

#[test]
fn an_empty_array_is_not_a_nonempty_set() {
    let cases: &[(&str, &[u8])] = &[
        ("tagged", &[0xd9, 0x01, 0x02, 0x80]),
        ("bare", &[0x80]),
        ("tagged indefinite", &[0xd9, 0x01, 0x02, 0x9f, 0xff]),
        ("bare indefinite", &[0x9f, 0xff]),
    ];

    for (arm, bytes) in cases {
        let err = minicbor::decode::<NonEmptySet<u64>>(bytes)
            .expect_err("an empty nonempty_set must not decode");
        assert!(
            err.to_string().contains("a nonempty set"),
            "the {arm} empty array was refused for some other reason: {err}"
        );
    }
}

#[test]
fn a_body_field_typed_nonempty_refuses_an_empty_array() {
    let top: &[u8] = &[0xa3, 0x00, 0x80, 0x01, 0x80, 0x02, 0x00];
    let sub: &[u8] = &[0xa2, 0x00, 0x80, 0x01, 0x80];
    minicbor::decode::<TransactionBody>(top).expect("a body without the field must decode");
    minicbor::decode::<SubTransactionBody>(sub).expect("a sub body without the field must decode");

    let with_empty = |body: &[u8], key: u8| {
        let mut bytes = vec![body[0] + 1];
        bytes.extend_from_slice(&body[1..]);
        bytes.extend_from_slice(&[key, 0x80]);
        bytes
    };
    for key in [4, 13, 18, 20, 23] {
        let err = minicbor::decode::<TransactionBody>(&with_empty(top, key))
            .expect_err("an empty nonempty field must not decode");
        assert!(
            err.to_string().contains("a nonempty set"),
            "body key {key} was refused for some other reason: {err}"
        );
    }
    for key in [4, 18, 20] {
        let err = minicbor::decode::<SubTransactionBody>(&with_empty(sub, key))
            .expect_err("an empty nonempty field must not decode");
        assert!(
            err.to_string().contains("a nonempty set"),
            "sub body key {key} was refused for some other reason: {err}"
        );
    }
}

#[test]
fn cost_models_keeps_a_key_the_named_fields_do_not_cover() {
    // a2                      map of two keys
    //   00  82 01 02          key 0, the PlutusV1 model [1, 2]
    //   04  81 03             key 4, inside the CDDL's 4 .. 255 wildcard
    let with_wildcard_key = [0xa2, 0x00, 0x82, 0x01, 0x02, 0x04, 0x81, 0x03];

    let decoded: CostModels =
        minicbor::decode(&with_wildcard_key).expect("a cost models map with key 4 must decode");
    assert_eq!(decoded.plutus_v1, Some(vec![1, 2]));
    assert_eq!(decoded.unknown.get(&4), Some(&vec![3]));
    assert_eq!(
        hex::encode(minicbor::to_vec(&decoded).unwrap()),
        hex::encode(with_wildcard_key),
        "the cost model under key 4 was dropped on re-encode"
    );

    let named_only = [0xa1, 0x00, 0x82, 0x01, 0x02];
    let decoded: CostModels = minicbor::decode(&named_only).expect("a named key must decode");
    assert!(decoded.unknown.is_empty());
    assert_eq!(
        hex::encode(minicbor::to_vec(&decoded).unwrap()),
        hex::encode(named_only)
    );
}

#[test]
fn the_legal_account_balance_interval_forms_still_read() {
    let cases: &[(&str, &[u8], AccountBalanceInterval)] = &[
        (
            "bounded",
            &[0x82, 0x01, 0x02],
            AccountBalanceInterval::Bounded(1, 2),
        ),
        (
            "lower",
            &[0x82, 0x01, 0xf6],
            AccountBalanceInterval::LowerBound(1),
        ),
        (
            "upper",
            &[0x82, 0xf6, 0x02],
            AccountBalanceInterval::UpperBound(2),
        ),
        ("bare coin", &[0x0a], AccountBalanceInterval::Exact(10)),
        (
            "indefinite",
            &[0x9f, 0x01, 0x02, 0xff],
            AccountBalanceInterval::Bounded(1, 2),
        ),
    ];

    for (name, bytes, want) in cases {
        let decoded: AccountBalanceInterval =
            minicbor::decode(bytes).unwrap_or_else(|e| panic!("the {name} form must decode: {e}"));
        assert_eq!(&decoded, want, "the {name} form read as something else");
    }

    let definite_in_a_map = [
        0xa2, // map of two reward accounts
        0x41, 0x01, 0x82, 0x01, 0x02, // the first carries a bounded interval
        0x41, 0x02, 0x0a, // the second carries a bare coin
    ];
    let decoded: AccountBalanceIntervals =
        minicbor::decode(&definite_in_a_map).expect("a map of definite intervals must decode");
    assert_eq!(decoded.len(), 2);

    let indefinite_in_a_map = [
        0xa2, 0x41, 0x01, 0x9f, 0x01, 0x02, 0xff, // an indefinite interval
        0x41, 0x02, 0x0a,
    ];
    let decoded: AccountBalanceIntervals =
        minicbor::decode(&indefinite_in_a_map).expect("a map of indefinite intervals must decode");
    assert_eq!(decoded.len(), 2);
}

/// The bytes of a map form output with an address and a coin, ending with the given hex field.
fn output_ending_in(field: &str) -> Vec<u8> {
    hex::decode(format!("a300581d61{}0100{field}", "11".repeat(28))).unwrap()
}

#[test]
fn a_script_reference_in_tag_24_bytes_in_chunks_reads_as_the_joined_chunks() {
    let bytes = output_ending_in("03d8185f42820043820180ff");
    let TransactionOutput::PostAlonzo(output) = decode_all(&bytes) else {
        panic!("the output is a map");
    };
    let Some(CborWrap(ScriptRef::NativeScript(script))) = &output.script_ref else {
        panic!("the output holds a native script reference");
    };
    assert_eq!(**script, NativeScript::ScriptAll(vec![]));
    assert_eq!(script.raw_cbor(), [0x82, 0x01, 0x80]);
}

#[test]
fn an_inline_datum_in_tag_24_bytes_in_chunks_reads_as_the_joined_chunks() {
    let bytes = output_ending_in("028201d8185f41184118ff");
    let TransactionOutput::PostAlonzo(output) = decode_all(&bytes) else {
        panic!("the output is a map");
    };
    let Some(DatumOption::Data(CborWrap(data))) = output.datum_option.as_deref() else {
        panic!("the output holds an inline datum");
    };
    assert_eq!(data.raw_cbor(), [0x18, 0x18]);
}

#[test]
fn values_ending_in_an_absent_value_reencode_as_the_ledger_wrote_them() {
    use super::TransactionBody;

    for hex in [
        include_str!("../../../test_data/dijkstra-generated/body-certificates-ending-in-null.hex"),
        include_str!("../../../test_data/dijkstra-generated/body-governance-ending-in-null.hex"),
    ] {
        let bytes = hex::decode(hex).unwrap();
        let body: TransactionBody = minicbor::decode(&bytes).unwrap();
        assert_eq!(hex::encode(minicbor::to_vec(&body).unwrap()), hex);
    }
}

#[test]
fn an_account_balance_interval_is_two_elements_or_none() {
    let cases: &[(&str, &[u8])] = &[
        ("three element", &[0x83, 0x01, 0x02, 0x03]),
        ("one element", &[0x81, 0x01]),
        ("empty", &[0x80]),
        ("three element indefinite", &[0x9f, 0x01, 0x02, 0x03, 0xff]),
    ];

    for (name, bytes) in cases {
        let err = minicbor::decode::<AccountBalanceInterval>(bytes)
            .expect_err("an array that is not two elements must not decode");
        assert!(
            err.to_string().contains("account_balance_interval"),
            "the {name} array was refused for some other reason: {err}"
        );
    }
}

/// The bytes of one vector from `test_data/dijkstra-generated`.
fn generated(hex: &str) -> &'static [u8] {
    Box::leak(hex::decode(hex).unwrap().into_boxed_slice())
}

/// Whether a rational number equals `numerator / denominator` as a ratio.
fn same_ratio(found: &RationalNumber, numerator: u64, denominator: u64) -> bool {
    found.numerator as u128 * denominator as u128 == found.denominator as u128 * numerator as u128
}

#[test]
fn a_generated_parameter_update_keeps_the_keys_after_an_indefinite_rational() {
    let bytes = generated(include_str!(
        "../../../test_data/dijkstra-generated/ppu-rational-indefinite.hex"
    ));
    let update: ProtocolParamUpdate = decode_all(bytes);

    assert_eq!(update.minfee_a, Some(0x30417a8beab11095));
    assert_eq!(update.minfee_b, Some(0x93d15ea0c1acc926));
    assert_eq!(update.max_block_body_size, Some(0x327f8f25));
    assert_eq!(update.max_transaction_size, Some(0x7f16cbc8));
    assert_eq!(update.max_block_header_size, Some(0x4a9f));
    assert_eq!(update.key_deposit, Some(0xd78ece0e55ae6876));
    assert_eq!(update.pool_deposit, Some(0xf20ce478efceddf0));
    assert_eq!(update.maximum_epoch, Some(0x13adde3c));
    assert_eq!(update.desired_number_of_stake_pools, Some(0x890a));
    assert!(same_ratio(
        update.pool_pledge_influence.as_ref().unwrap(),
        0x6e24f5aeed36f7f5,
        0xd81f3b4fc11e15ae
    ));
    assert!(same_ratio(
        update.expansion_rate.as_ref().unwrap(),
        251,
        832
    ));
    assert!(same_ratio(
        update.treasury_growth_rate.as_ref().unwrap(),
        0x555555555555540a,
        0x555555555555543d
    ));
    assert_eq!(update.ada_per_utxo_byte, Some(0xe242b5b210626137));
}

#[test]
fn a_generated_relay_in_an_indefinite_array_reads_to_its_break() {
    let bytes = generated(include_str!(
        "../../../test_data/dijkstra-generated/relay-indefinite.hex"
    ));
    let relay: Relay = decode_all(bytes);

    assert_eq!(
        relay,
        Relay::MultiHostName("\u{241a}\u{3bdc1}\u{d0}".to_string())
    );
}

#[test]
fn a_generated_certificate_in_an_indefinite_array_reads_to_its_break() {
    let bytes = generated(include_str!(
        "../../../test_data/dijkstra-generated/body-certificate-indefinite.hex"
    ));
    let body: TransactionBody = decode_all(bytes);

    let certificates: Vec<_> = body.certificates.unwrap().to_vec();
    assert_eq!(
        certificates,
        vec![Certificate::UpdateDRepCert(
            StakeCredential::ScriptHash(
                "931c0e475a84cfe718b21f9ae8224c5077671633d9f8cacff61e009b"
                    .parse()
                    .unwrap()
            ),
            None
        )]
    );
}

#[test]
fn a_generated_value_in_an_indefinite_array_reads_to_its_break() {
    let bytes = generated(include_str!(
        "../../../test_data/dijkstra-generated/body-value-indefinite.hex"
    ));
    let body: TransactionBody = decode_all(bytes);

    let [TransactionOutput::Legacy(output)] = &body.outputs[..] else {
        panic!("the body holds one array form output");
    };
    let crate::alonzo::Value::Multiasset(coin, assets) = &output.amount else {
        panic!("the output value is a coin and assets");
    };
    assert_eq!(*coin, 18052182784416840275);
    let policy: crate::PolicyId = "a05a12f1f644247a57a10eec17c3f9752b30f44fbe49736dbc92c083"
        .parse()
        .unwrap();
    let names: Vec<_> = assets[&policy].iter().collect();
    assert_eq!(names.len(), 1);
    assert!(names[0].0.is_empty());
    assert_eq!(*names[0].1, 5424943601111550909);
}

#[test]
fn a_generated_transaction_in_an_indefinite_array_reads_to_its_break() {
    let bytes = generated(include_str!(
        "../../../test_data/dijkstra-generated/tx-indefinite.hex"
    ));
    let tx: MempoolTransaction = decode_all(bytes);

    assert!(tx.is_valid_supplied);
    assert_eq!(tx.transaction_body.fee, 10309690930332875869);
    let [TransactionOutput::Legacy(output)] = &tx.transaction_body.outputs[..] else {
        panic!("the body holds one array form output");
    };
    let coin = match &output.amount {
        crate::alonzo::Value::Coin(coin) | crate::alonzo::Value::Multiasset(coin, _) => *coin,
    };
    assert_eq!(coin, 13818883891935063992);
    assert_eq!(
        tx.transaction_witness_set
            .vkeywitness
            .as_ref()
            .map(|w| w.len()),
        Some(2)
    );
    assert_eq!(
        tx.transaction_witness_set
            .plutus_v1_script
            .as_ref()
            .map(|s| s.len()),
        Some(1)
    );
    assert!(matches!(tx.auxiliary_data, crate::Nullable::Null));
}

#[test]
fn a_generated_constructor_102_in_an_indefinite_array_hashes_as_the_ledger_does() {
    let bytes = generated(include_str!(
        "../../../test_data/dijkstra-generated/wits-constr-102-indefinite.hex"
    ));
    let witnesses: WitnessSet = decode_all(bytes);

    let datums = witnesses.plutus_data.unwrap();
    let hashes: Vec<String> = datums
        .iter()
        .map(|datum| Hasher::<256>::hash(datum.raw_cbor()).to_string())
        .collect();
    assert_eq!(
        hashes,
        [
            "f929da3fb67b303d9fd90a2fce58316023844d6b1f5d49fb399480f0f8e2f73e",
            "ee155ace9c40292074cb6aff8c9ccdd273c81648ff1149ef36bcea6ebb8a3e25",
        ]
    );
    let PlutusData::Constr(constr) = &*datums[0] else {
        panic!("the first datum is a constructor");
    };
    assert_eq!(constr.constr_index(), 1000);
    assert!(constr.fields.is_empty());
}

#[test]
fn a_generated_hard_fork_version_in_an_indefinite_array_decodes() {
    let bytes = generated(include_str!(
        "../../../test_data/dijkstra-generated/proposal-hard-fork-indefinite-version.hex"
    ));
    let body: TransactionBody = decode_all(bytes);

    let proposals: Vec<_> = body.proposal_procedures.unwrap().to_vec();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].deposit, 15225768051747963167);
    assert_eq!(
        proposals[0].gov_action,
        GovAction::HardForkInitiation(None, ProtocolVersion::try_from((3, 2317795968)).unwrap())
    );
}

/// Provenance for this fixture is in `test_data/dijkstra-generated.md`.
const VERSION_INFO_BLOCK: &str =
    include_str!("../../../test_data/dijkstra-generated/block-header-version-info.hex");

/// The version info of the generated block's header, as hex.
const VERSION_INFO: &str = "821a3be658c11aeb03cba5";

fn generated_header_hex() -> String {
    let block = hex::decode(VERSION_INFO_BLOCK.trim()).unwrap();
    let mut d = minicbor::Decoder::new(&block);
    d.array().unwrap();
    let start = d.position();
    d.skip().unwrap();
    hex::encode(&block[start..d.position()])
}

#[test]
fn a_version_info_in_an_indefinite_array_reads_to_its_break() {
    let header = generated_header_hex();
    let bytes = hex::decode(header.replace(VERSION_INFO, "9f1a3be658c11aeb03cba5ff")).unwrap();
    let mut d = minicbor::Decoder::new(&bytes);
    let header: Header = d.decode().expect("an indefinite version info must decode");
    assert_eq!(d.position(), bytes.len());
    let info = &header.header_body.header_version_info;
    assert_eq!(info.highest_supported_major_version, 1004951745);
    assert_eq!(info.self_reported_software_tag, 3942894501);
}

#[test]
fn a_version_info_field_past_four_bytes_is_refused() {
    let header = generated_header_hex();
    assert_eq!(header.matches(VERSION_INFO).count(), 1);
    let at = header.find(VERSION_INFO).unwrap() / 2;

    let widest = hex::decode(header.replace(VERSION_INFO, "821affffffff1affffffff")).unwrap();
    minicbor::decode::<Header>(&widest).expect("both fields at u32::MAX must decode");

    for (field, info, position) in [
        (
            "highest_supported_major_version",
            "821b00000001000000001aeb03cba5",
            at + 1,
        ),
        (
            "self_reported_software_tag",
            "821a3be658c11b0000000100000000",
            at + 6,
        ),
    ] {
        let mutated = hex::decode(header.replace(VERSION_INFO, info)).unwrap();
        let err =
            minicbor::decode::<Header>(&mutated).expect_err("a field of 2^32 must not decode");
        assert_eq!(
            err.position(),
            Some(position),
            "{field} was refused somewhere else: {err}"
        );
    }
}

const HASH: &str = "581c11111111111111111111111111111111111111111111111111111111";
const HASH32: &str = "58201111111111111111111111111111111111111111111111111111111111111111";
const REWARD: &str = "581de111111111111111111111111111111111111111111111111111111111";

#[test]
fn a_gov_action_reads_either_length_form() {
    let id = format!("82{HASH32}00");
    let credential = format!("8200{HASH}");
    assert_reads_either_length_form::<GovAction>(&[
        format!("8400{id}a10001{HASH}"),
        format!("8301{id}820a00"),
        format!("8302a1{REWARD}01{HASH}"),
        format!("8203{id}"),
        format!("8504{id}81{credential}a1{credential}01d81e820102"),
        format!("8305{id}828260{HASH32}{HASH}"),
        "8106".to_string(),
    ]);
}

#[test]
fn a_script_reference_reads_either_length_form() {
    assert_reads_either_length_form::<ScriptRef>(&[
        format!("82008200{HASH}"),
        "82014100".to_string(),
        "82024100".to_string(),
        "82034100".to_string(),
        "82044100".to_string(),
    ]);
}

#[test]
fn a_native_script_reads_either_length_form() {
    let script = format!("8200{HASH}");
    assert_reads_either_length_form::<NativeScript>(&[
        script.clone(),
        format!("820181{script}"),
        "820280".to_string(),
        "83030180".to_string(),
        "820401".to_string(),
        "820501".to_string(),
        format!("82068201{HASH}"),
    ]);
}

#[test]
fn a_generated_credential_in_an_indefinite_array_decodes() {
    let bytes = generated(include_str!(
        "../../../test_data/dijkstra-generated/body-credential-indefinite.hex"
    ));
    let body: TransactionBody = decode_all(bytes);

    assert_eq!(
        body.certificates.unwrap().to_vec(),
        vec![Certificate::StakeDelegation(
            StakeCredential::ScriptHash(
                "17ab434af5e4d2fcc4815897879f52d2068af2dc2630974ac0333a2b"
                    .parse()
                    .unwrap()
            ),
            "bc7069ba4ab9909c4b1517f3bd9ccbb45b075569c163820971dbe63e"
                .parse()
                .unwrap(),
        )]
    );
}

#[test]
fn generated_dreps_in_indefinite_arrays_decode() {
    let bytes = generated(include_str!(
        "../../../test_data/dijkstra-generated/body-drep-indefinite.hex"
    ));
    let body: TransactionBody = decode_all(bytes);

    assert_eq!(
        body.certificates.unwrap().to_vec(),
        vec![
            Certificate::VoteRegDeleg(
                StakeCredential::AddrKeyhash(
                    "098118293e4e9f9862dd7a9e876d00ca97e3b98ead92b6a2e7c30dc9"
                        .parse()
                        .unwrap()
                ),
                DRep::NoConfidence,
                0x97a8a827c45150b1
            ),
            Certificate::VoteRegDeleg(
                StakeCredential::AddrKeyhash(
                    "b8f80a08bf5b6bad733522cd91768136b5aad289bff7a51d7d620508"
                        .parse()
                        .unwrap()
                ),
                DRep::Abstain,
                0x41a4ecaab467a454
            ),
        ]
    );
}

#[test]
fn generated_datum_options_in_indefinite_arrays_decode() {
    let bytes = generated(include_str!(
        "../../../test_data/dijkstra-generated/body-datum-option-indefinite.hex"
    ));
    let body: TransactionBody = decode_all(bytes);

    let [
        TransactionOutput::PostAlonzo(hashed),
        TransactionOutput::PostAlonzo(inline),
    ] = &body.outputs[..]
    else {
        panic!("the body holds two map form outputs");
    };
    assert!(matches!(
        hashed.datum_option.as_deref(),
        Some(DatumOption::Hash(hash))
            if hash.to_string() == "f76479ff10b1f158e4b6c98049836b3bd0abe3fcceab1a5d646fdaa8f0d312fb"
    ));
    assert!(matches!(
        inline.datum_option.as_deref(),
        Some(DatumOption::Data(CborWrap(data))) if data.raw_cbor() == [0x80]
    ));
}

#[test]
fn a_generated_gov_action_in_an_indefinite_array_decodes() {
    let bytes = generated(include_str!(
        "../../../test_data/dijkstra-generated/body-gov-action-indefinite.hex"
    ));
    let body: TransactionBody = decode_all(bytes);

    let proposals: Vec<_> = body.proposal_procedures.unwrap().to_vec();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].deposit, 0x3092f0c34ad35adb);
    let account =
        hex::decode("f100020200000101010201000101010000010100000001010201000101").unwrap();
    assert_eq!(
        proposals[0].gov_action,
        GovAction::TreasuryWithdrawals([(account.into(), 0xa1d446b07e0bbe31)].into(), None)
    );
}

#[test]
fn a_generated_voter_in_an_indefinite_array_decodes() {
    let bytes = generated(include_str!(
        "../../../test_data/dijkstra-generated/body-voter-indefinite.hex"
    ));
    let body: TransactionBody = decode_all(bytes);

    let voters: Vec<_> = body.voting_procedures.unwrap().keys().cloned().collect();
    assert_eq!(
        voters,
        vec![Voter::ConstitutionalCommitteeKey(
            "7ff244d677b8920e733c5117a58478eb164d06298ca4bde583ac1e76"
                .parse()
                .unwrap()
        )]
    );
}

#[test]
fn a_generated_guard_credential_in_an_indefinite_array_decodes() {
    let bytes = generated(include_str!(
        "../../../test_data/dijkstra-generated/body-guard-credential-indefinite.hex"
    ));
    let body: TransactionBody = decode_all(bytes);

    let Some(Guards::Credentials(credentials)) = body.guards else {
        panic!("the body holds credential guards");
    };
    assert_eq!(
        credentials.to_vec(),
        vec![StakeCredential::AddrKeyhash(
            "b7fa435c83b33b9504b0aa55247460636800452cd4ed29cedd431dfe"
                .parse()
                .unwrap()
        )]
    );
}

#[test]
fn a_generated_script_reference_in_an_indefinite_array_decodes() {
    let bytes = generated(include_str!(
        "../../../test_data/dijkstra-generated/body-script-ref-indefinite.hex"
    ));
    let body: TransactionBody = decode_all(bytes);

    let [TransactionOutput::PostAlonzo(output)] = &body.outputs[..] else {
        panic!("the body holds one map form output");
    };
    let Some(CborWrap(ScriptRef::NativeScript(script))) = &output.script_ref else {
        panic!("the output holds a native script reference");
    };
    assert_eq!(**script, NativeScript::InvalidHereafter(0x73e96a1328c7873b));
}

#[test]
fn generated_native_scripts_in_indefinite_arrays_decode() {
    let bytes = generated(include_str!(
        "../../../test_data/dijkstra-generated/wits-native-scripts-indefinite.hex"
    ));
    let witnesses: WitnessSet = decode_all(bytes);

    let scripts: Vec<NativeScript> = witnesses
        .native_script
        .unwrap()
        .to_vec()
        .into_iter()
        .map(KeepRaw::unwrap)
        .collect();
    assert_eq!(
        scripts,
        vec![
            NativeScript::InvalidHereafter(0x73e96a1328c7873b),
            NativeScript::ScriptAny(vec![
                NativeScript::InvalidHereafter(0x7b16eeee03a344c6),
                NativeScript::InvalidBefore(0xdc760102a6a9e550),
            ]),
            NativeScript::ScriptRequireGuard(StakeCredential::ScriptHash(
                "35315820fb38df0f2034fa91fed7a4199d1d4b2d1b0d2a165345e349"
                    .parse()
                    .unwrap()
            )),
        ]
    );
}

/// The interval `defs.cddl` gives a fraction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum FractionKind {
    Unit,
    NonNegative,
    Positive,
}

/// The type a fraction position is read through.
#[derive(Clone, Copy)]
enum FractionHolder {
    Update,
    Certificate,
    GovAction,
}

/// A place that holds a fraction, with `R` in its hex standing for the fraction.
struct FractionPosition {
    name: String,
    kind: FractionKind,
    holder: FractionHolder,
    template: String,
}

const HALF: &str = "d81e820102";

/// Every fraction position of this era, with the interval `defs.cddl` gives it.
fn fraction_positions() -> Vec<FractionPosition> {
    use FractionKind::*;

    let update = |key: u64, kind: FractionKind, value: String| FractionPosition {
        name: format!("parameter update key {key}"),
        kind,
        holder: FractionHolder::Update,
        template: match key {
            0..=23 => format!("a1{key:02x}{value}"),
            _ => format!("a118{key:02x}{value}"),
        },
    };

    let mut positions = vec![
        FractionPosition {
            name: "pool registration margin".to_string(),
            kind: Unit,
            holder: FractionHolder::Certificate,
            template: format!("8a03{HASH}{HASH32}0101R{REWARD}8080f6"),
        },
        FractionPosition {
            name: "committee update threshold".to_string(),
            kind: Unit,
            holder: FractionHolder::GovAction,
            template: "8504f680a0R".to_string(),
        },
    ];

    for (key, kind) in [
        (9, NonNegative),
        (10, Unit),
        (11, Unit),
        (33, NonNegative),
        (37, Positive),
        (38, NonNegative),
        (39, Unit),
        (44, Unit),
        (50, Positive),
        (54, Unit),
    ] {
        positions.push(update(key, kind, "R".to_string()));
    }

    // Keys 19, 25 and 26 hold arrays of fractions, so each element is a position.
    for (key, kind, len) in [(19, NonNegative, 2), (25, Unit, 5), (26, Unit, 10)] {
        for index in 0..len {
            let elements: String = (0..len)
                .map(|i| if i == index { "R" } else { HALF })
                .collect();
            let mut position = update(key, kind, format!("{:02x}{elements}", 0x80 + len));
            position.name = format!("{} element {index}", position.name);
            positions.push(position);
        }
    }

    positions
}

/// Whether the holder reads the bytes to their last byte.
fn reads_whole(holder: FractionHolder, bytes: &[u8]) -> bool {
    fn whole<'b, T: minicbor::Decode<'b, ()>>(bytes: &'b [u8]) -> bool {
        let mut d = minicbor::Decoder::new(bytes);
        d.decode::<T>().is_ok() && d.position() == bytes.len()
    }

    match holder {
        FractionHolder::Update => whole::<ProtocolParamUpdate>(bytes),
        FractionHolder::Certificate => whole::<Certificate>(bytes),
        FractionHolder::GovAction => whole::<GovAction>(bytes),
    }
}

/// Asserts that every fraction position reads each fraction exactly when the ledger's interval of its kind holds it.
fn assert_each_position_reads(fractions: &[&str], unit: bool, nonnegative: bool, positive: bool) {
    let mut counts = std::collections::BTreeMap::new();
    let mut wrong = Vec::new();

    for position in fraction_positions() {
        let control = hex::decode(position.template.replace('R', HALF)).unwrap();
        assert!(
            reads_whole(position.holder, &control),
            "{} must read one half, so a refusal below is about the fraction",
            position.name
        );

        let expected = match position.kind {
            FractionKind::Unit => unit,
            FractionKind::NonNegative => nonnegative,
            FractionKind::Positive => positive,
        };
        for fraction in fractions {
            let bytes = hex::decode(position.template.replace('R', fraction)).unwrap();
            if reads_whole(position.holder, &bytes) != expected {
                wrong.push(format!(
                    "{} ({:?}) {}: {fraction}",
                    position.name,
                    position.kind,
                    if expected { "refused" } else { "read" },
                ));
            }
        }
        *counts.entry(position.kind).or_insert(0) += 1;
    }

    assert_eq!(
        counts,
        std::collections::BTreeMap::from([
            (FractionKind::Unit, 22),
            (FractionKind::NonNegative, 5),
            (FractionKind::Positive, 2),
        ])
    );
    assert_eq!(wrong, Vec::<String>::new());
}

#[test]
fn a_fraction_inside_every_interval_reads_at_each_position() {
    assert_each_position_reads(
        &[
            HALF,
            "d81e820101",
            "d81e821bffffffffffffffff1bffffffffffffffff",
            "d81e82011b8ac7230489e80000",
        ],
        true,
        true,
        true,
    );
}

#[test]
fn an_indefinite_fraction_of_two_numbers_reads_at_each_position() {
    assert_each_position_reads(&["d81e9f0102ff"], true, true, true);
}

#[test]
fn a_fraction_tagged_other_than_30_is_refused() {
    assert_each_position_reads(&["d81f820102", "d81d820102"], false, false, false);
}

#[test]
fn an_untagged_fraction_is_refused() {
    assert_each_position_reads(&["820102"], false, false, false);
}

#[test]
fn a_fraction_of_three_numbers_is_refused() {
    assert_each_position_reads(&["d81e83010203"], false, false, false);
}

#[test]
fn a_fraction_of_one_number_is_refused() {
    assert_each_position_reads(&["d81e8101"], false, false, false);
}

#[test]
fn an_empty_fraction_is_refused() {
    assert_each_position_reads(&["d81e80"], false, false, false);
}

#[test]
fn an_indefinite_fraction_of_other_than_two_numbers_is_refused() {
    assert_each_position_reads(
        &["d81e9f010203ff", "d81e9f01ff", "d81e9fff"],
        false,
        false,
        false,
    );
}

#[test]
fn a_zero_denominator_is_refused() {
    assert_each_position_reads(&["d81e820100", "d81e820000"], false, false, false);
}

#[test]
fn a_negative_number_is_refused() {
    assert_each_position_reads(&["d81e822002", "d81e820121"], false, false, false);
}

#[test]
fn a_fraction_above_one_is_refused_only_as_a_unit_interval() {
    assert_each_position_reads(
        &[
            "d81e820302",
            "d81e821bffffffffffffffff01",
            "d81e821bffffffffffffffff1bfffffffffffffffe",
        ],
        false,
        true,
        true,
    );
}

#[test]
fn a_zero_fraction_is_refused_only_as_a_positive_interval() {
    assert_each_position_reads(
        &["d81e820001", "d81e82001bffffffffffffffff"],
        true,
        true,
        false,
    );
}

#[test]
fn a_fraction_below_the_positive_minimum_is_refused_only_as_a_positive_interval() {
    assert_each_position_reads(
        &["d81e82011b8ac7230489e80001", "d81e82011bffffffffffffffff"],
        true,
        true,
        false,
    );
}

/// Decodes the bytes as one value that ends exactly where they do.
fn read<T: minicbor::Decode<'static, ()>>(
    bytes: &'static [u8],
) -> Result<(), minicbor::decode::Error> {
    let mut d = minicbor::Decoder::new(bytes);
    d.decode::<T>()?;
    match d.position() == bytes.len() {
        true => Ok(()),
        false => Err(minicbor::decode::Error::message(
            "bytes left after the value",
        )),
    }
}

/// A record the ledger refuses, beside the same record with one choice or key changed to one it reads.
struct Refusal {
    class: &'static str,
    read: fn(&'static [u8]) -> Result<(), minicbor::decode::Error>,
    refused: String,
    known: String,
}

/// The hex of a body with one input, no outputs and, at the top, a zero fee, followed by the given entries.
fn body_with(top: bool, entries: &[&str]) -> String {
    let input = format!("d9010281825820{}00", "03".repeat(32));
    let (fee, count) = if top { ("0200", 3) } else { ("", 2) };
    format!(
        "{:02x}00{input}0180{fee}{}",
        0xa0 + count + entries.len(),
        entries.concat()
    )
}

/// The hex of a map form output with an address and a zero coin, followed by the given entries.
fn output_with(entries: &[&str]) -> String {
    format!(
        "{:02x}00581d61{}0100{}",
        0xa2 + entries.len(),
        "11".repeat(28),
        entries.concat()
    )
}

/// Every optional field whose value holds a choice, with the ledger refusing an unknown arm.
fn unknown_arms() -> Vec<Refusal> {
    let arms = |entry: String, refused: &str, known: &str| {
        (entry.replace("ARM", refused), entry.replace("ARM", known))
    };
    let body_fields = [
        (
            "certificates",
            arms(format!("048183098200{HASH}82ARM00"), "05", "02"),
        ),
        ("guards", arms(format!("0e8182ARM{HASH}"), "02", "00")),
        ("network_id", arms("0fARM".to_string(), "05", "01")),
        (
            "voting_procedures",
            arms(format!("13a18200{HASH}a182{HASH32}0082ARMf6"), "05", "01"),
        ),
        (
            "proposal_procedures",
            arms(format!("14818400{REWARD}81ARM8260{HASH32}"), "09", "06"),
        ),
        (
            "required_top_level_guards",
            arms("1818a1ARMf6".to_string(), "8102", &format!("8200{HASH}")),
        ),
    ];
    let mut cases = Vec::new();

    for (top, record, read) in [
        (
            true,
            "transaction_body",
            read::<TransactionBody> as fn(_) -> _,
        ),
        (false, "sub_transaction_body", read::<SubTransactionBody>),
    ] {
        for (field, (refused, known)) in &body_fields {
            cases.push(Refusal {
                class: Box::leak(format!("{record}.{field}").into_boxed_str()),
                read,
                refused: body_with(top, &[refused]),
                known: body_with(top, &[known]),
            });
        }
    }

    let (refused_return, known_return) = arms(
        format!("10{}", output_with(&[&format!("0282ARM{HASH32}")])),
        "05",
        "00",
    );
    let sub_transactions = |arm: &str| {
        let sub_body = body_with(false, &[&format!("0e8182{arm}{HASH}")]);
        format!("178183{sub_body}a0f6")
    };
    cases.extend([
        Refusal {
            class: "transaction_body.collateral_return",
            read: read::<TransactionBody>,
            refused: body_with(true, &[&refused_return]),
            known: body_with(true, &[&known_return]),
        },
        Refusal {
            class: "transaction_body.sub_transactions",
            read: read::<TransactionBody>,
            refused: body_with(true, &[&sub_transactions("02")]),
            known: body_with(true, &[&sub_transactions("00")]),
        },
        Refusal {
            class: "transaction_witness_set.native_script",
            read: read::<WitnessSet>,
            refused: "a10181820900".to_string(),
            known: "a10181820400".to_string(),
        },
        Refusal {
            class: "transaction_witness_set.redeemers",
            read: read::<WitnessSet>,
            refused: "a105a181098200820000".to_string(),
            known: "a105a18200008200820000".to_string(),
        },
        Refusal {
            class: "auxiliary_data_map.native_scripts",
            read: read::<AuxiliaryData>,
            refused: "d90103a10181820900".to_string(),
            known: "d90103a10181820400".to_string(),
        },
        Refusal {
            class: "auxiliary_data_array.auxiliary_scripts",
            read: read::<AuxiliaryData>,
            refused: "82a081820900".to_string(),
            known: "82a081820400".to_string(),
        },
        Refusal {
            class: "transaction_output.datum_option",
            read: read::<TransactionOutput>,
            refused: output_with(&[&format!("028205{HASH32}")]),
            known: output_with(&[&format!("028200{HASH32}")]),
        },
        Refusal {
            class: "transaction_output.script_ref",
            read: read::<TransactionOutput>,
            refused: output_with(&["03d81843820900"]),
            known: output_with(&["03d818458200820400"]),
        },
    ]);

    cases
}

/// Every map record, with a key its rule lacks: inside the range of its keys, past the last, below zero, and for a sub transaction body each key only the top body holds.
fn unknown_keys() -> Vec<Refusal> {
    let mut cases = Vec::new();
    let mut add = |class: &'static str,
                   read: fn(&'static [u8]) -> Result<(), minicbor::decode::Error>,
                   record: &dyn Fn(&str) -> String,
                   refused: &[&str],
                   known: &str| {
        for key in refused {
            cases.push(Refusal {
                class,
                read,
                refused: record(key),
                known: record(known),
            });
        }
    };

    let top = |entry: &str| body_with(true, &[entry]);
    add(
        "transaction_body inside",
        read::<TransactionBody>,
        &top,
        &["0600", "0a00", "0c00"],
        "0300",
    );
    add(
        "transaction_body past",
        read::<TransactionBody>,
        &top,
        &["181c00"],
        "0300",
    );
    add(
        "transaction_body below",
        read::<TransactionBody>,
        &top,
        &["2000"],
        "0300",
    );

    let sub = |entry: &str| body_with(false, &[entry]);
    add(
        "sub_transaction_body inside",
        read::<SubTransactionBody>,
        &sub,
        &["0600", "0a00", "0c00"],
        "0300",
    );
    add(
        "sub_transaction_body past",
        read::<SubTransactionBody>,
        &sub,
        &["181c00"],
        "0300",
    );
    add(
        "sub_transaction_body below",
        read::<SubTransactionBody>,
        &sub,
        &["2000"],
        "0300",
    );
    add(
        "sub_transaction_body top only",
        read::<SubTransactionBody>,
        &sub,
        &["0200", "0d00", "1000", "1100", "1700", "181b00"],
        "0300",
    );

    let witnesses = |key: &str| format!("a1{key}814100");
    add(
        "transaction_witness_set past",
        read::<WitnessSet>,
        &witnesses,
        &["09"],
        "03",
    );
    add(
        "transaction_witness_set below",
        read::<WitnessSet>,
        &witnesses,
        &["20"],
        "03",
    );

    let auxiliary = |key: &str| format!("d90103a1{key}80");
    add(
        "auxiliary_data_map past",
        read::<AuxiliaryData>,
        &auxiliary,
        &["06"],
        "02",
    );
    add(
        "auxiliary_data_map below",
        read::<AuxiliaryData>,
        &auxiliary,
        &["20"],
        "02",
    );

    let output = |key: &str| output_with(&[&format!("{key}8200{HASH32}")]);
    add(
        "transaction_output past",
        read::<TransactionOutput>,
        &output,
        &["04"],
        "02",
    );
    add(
        "transaction_output below",
        read::<TransactionOutput>,
        &output,
        &["20"],
        "02",
    );

    let update = |entry: &str| format!("a1{entry}");
    add(
        "protocol_param_update inside",
        read::<ProtocolParamUpdate>,
        &update,
        &["0c00", "0f00"],
        "0000",
    );
    add(
        "protocol_param_update past",
        read::<ProtocolParamUpdate>,
        &update,
        &["183900"],
        "0000",
    );
    add(
        "protocol_param_update below",
        read::<ProtocolParamUpdate>,
        &update,
        &["2000"],
        "0000",
    );

    cases
}

/// Asserts that the cases hold at least one case of each expected class and of no other class.
fn assert_classes(cases: &[Refusal], expected: &[&str]) {
    let mut counts = std::collections::BTreeMap::new();
    for case in cases {
        *counts.entry(case.class).or_insert(0) += 1;
    }
    let found: Vec<_> = counts.keys().copied().collect();
    let mut expected = expected.to_vec();
    expected.sort();
    assert_eq!(found, expected, "case counts per class: {counts:?}");
}

const UNKNOWN_ARM_CLASSES: &[&str] = &[
    "transaction_body.certificates",
    "transaction_body.guards",
    "transaction_body.network_id",
    "transaction_body.collateral_return",
    "transaction_body.voting_procedures",
    "transaction_body.proposal_procedures",
    "transaction_body.sub_transactions",
    "transaction_body.required_top_level_guards",
    "sub_transaction_body.certificates",
    "sub_transaction_body.guards",
    "sub_transaction_body.network_id",
    "sub_transaction_body.voting_procedures",
    "sub_transaction_body.proposal_procedures",
    "sub_transaction_body.required_top_level_guards",
    "transaction_witness_set.native_script",
    "transaction_witness_set.redeemers",
    "auxiliary_data_map.native_scripts",
    "auxiliary_data_array.auxiliary_scripts",
    "transaction_output.datum_option",
    "transaction_output.script_ref",
];

const UNKNOWN_KEY_CLASSES: &[&str] = &[
    "transaction_body inside",
    "transaction_body past",
    "transaction_body below",
    "sub_transaction_body inside",
    "sub_transaction_body past",
    "sub_transaction_body below",
    "sub_transaction_body top only",
    "transaction_witness_set past",
    "transaction_witness_set below",
    "auxiliary_data_map past",
    "auxiliary_data_map below",
    "transaction_output past",
    "transaction_output below",
    "protocol_param_update inside",
    "protocol_param_update past",
    "protocol_param_update below",
];

#[test]
fn each_record_reads_with_a_known_arm_or_key_in_place_of_the_refused_one() {
    let cases: Vec<_> = unknown_arms().into_iter().chain(unknown_keys()).collect();
    assert_classes(&unknown_arms(), UNKNOWN_ARM_CLASSES);
    assert_classes(&unknown_keys(), UNKNOWN_KEY_CLASSES);

    let failed: Vec<_> = cases
        .iter()
        .filter_map(|case| {
            (case.read)(generated(&case.known))
                .err()
                .map(|err| format!("{} {}: {err}", case.class, case.known))
        })
        .collect();
    assert!(
        failed.is_empty(),
        "{} of {} refused:\n{}",
        failed.len(),
        cases.len(),
        failed.join("\n")
    );
}

#[test]
fn an_unknown_arm_in_an_optional_field_is_refused() {
    let cases = unknown_arms();
    assert_classes(&cases, UNKNOWN_ARM_CLASSES);

    let failed: Vec<_> = cases
        .iter()
        .filter_map(|case| match (case.read)(generated(&case.refused)) {
            Err(err) if err.is_unknown_variant() => None,
            Err(err) => Some(format!("{} refused for another reason: {err}", case.class)),
            Ok(()) => Some(format!("{} read", case.class)),
        })
        .collect();
    assert!(
        failed.is_empty(),
        "{} of {} not refused as an unknown arm:\n{}",
        failed.len(),
        cases.len(),
        failed.join("\n")
    );
}

#[test]
fn an_unknown_map_key_is_refused() {
    let cases = unknown_keys();
    assert_classes(&cases, UNKNOWN_KEY_CLASSES);

    let failed: Vec<_> = cases
        .iter()
        .filter_map(|case| match (case.read)(generated(&case.refused)) {
            Err(err) if err.to_string().contains("unknown key") => None,
            Err(err) => Some(format!(
                "{} {} refused for another reason: {err}",
                case.class, case.refused
            )),
            Ok(()) => Some(format!("{} {} read", case.class, case.refused)),
        })
        .collect();
    assert!(
        failed.is_empty(),
        "{} of {} not refused as an unknown key:\n{}",
        failed.len(),
        cases.len(),
        failed.join("\n")
    );
}

impl super::SetElement for u64 {
    fn same_element(&self, other: &Self) -> bool {
        self == other
    }
}

type Read = fn(&[u8]) -> Result<(), minicbor::decode::Error>;

/// A map of small keys, each written in one byte or behind `0x18`.
fn map_of(entries: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut bytes = vec![0xa0 | u8::try_from(entries.len()).unwrap()];
    for (key, value) in entries {
        if *key >= 24 {
            bytes.push(0x18);
        }
        bytes.push(*key);
        bytes.extend_from_slice(value);
    }
    bytes
}

/// A top or sub transaction body holding the given bytes at the given key beside its required keys.
fn body_holding(top: bool, key: u8, value: &[u8]) -> Vec<u8> {
    let mut entries = vec![(0u8, vec![0x80]), (1, vec![0x80])];
    if top {
        entries.push((2, vec![0x00]));
    }
    match entries.iter_mut().find(|(k, _)| *k == key) {
        Some(entry) => entry.1 = value.to_vec(),
        None => entries.push((key, value.to_vec())),
    }
    map_of(&entries)
}

fn read_body(bytes: &[u8]) -> Result<(), minicbor::decode::Error> {
    minicbor::decode::<TransactionBody>(bytes).map(drop)
}

fn read_sub_body(bytes: &[u8]) -> Result<(), minicbor::decode::Error> {
    minicbor::decode::<SubTransactionBody>(bytes).map(drop)
}

fn read_witnesses(bytes: &[u8]) -> Result<(), minicbor::decode::Error> {
    minicbor::decode::<WitnessSet>(bytes).map(drop)
}

fn read_certificate(bytes: &[u8]) -> Result<(), minicbor::decode::Error> {
    minicbor::decode::<Certificate>(bytes).map(drop)
}

fn read_gov_action(bytes: &[u8]) -> Result<(), minicbor::decode::Error> {
    minicbor::decode::<GovAction>(bytes).map(drop)
}

fn read_update(bytes: &[u8]) -> Result<(), minicbor::decode::Error> {
    minicbor::decode::<ProtocolParamUpdate>(bytes).map(drop)
}

fn bytes_of(length: u8, fill: u8) -> Vec<u8> {
    let mut bytes = if length < 24 {
        vec![0x40 | length]
    } else {
        vec![0x58, length]
    };
    bytes.extend(std::iter::repeat_n(fill, usize::from(length)));
    bytes
}

fn input_element(n: u8) -> Vec<u8> {
    [vec![0x82], bytes_of(32, 0x11), vec![n]].concat()
}

fn keyhash_element(n: u8) -> Vec<u8> {
    bytes_of(28, n)
}

fn credential_element(n: u8) -> Vec<u8> {
    [vec![0x82, 0x00], bytes_of(28, n)].concat()
}

fn certificate_element(n: u8) -> Vec<u8> {
    [vec![0x83, 0x02], credential_element(n), bytes_of(28, 0x22)].concat()
}

fn proposal_element(n: u8) -> Vec<u8> {
    let mut reward_account = vec![0x58, 29, 0xe0];
    reward_account.extend(std::iter::repeat_n(n, 28));
    [
        vec![0x84, 0x00],
        reward_account,
        vec![0x81, 0x06, 0x82, 0x60],
        bytes_of(32, 0x00),
    ]
    .concat()
}

fn vkey_witness_element(n: u8) -> Vec<u8> {
    [vec![0x82], bytes_of(32, n), bytes_of(64, 0x00)].concat()
}

fn bootstrap_witness_element(n: u8) -> Vec<u8> {
    [
        vec![0x84],
        bytes_of(32, n),
        bytes_of(64, 0x00),
        bytes_of(32, 0x00),
        vec![0x41, 0xa0],
    ]
    .concat()
}

fn native_script_element(n: u8) -> Vec<u8> {
    [vec![0x82, 0x00], bytes_of(28, n)].concat()
}

fn plutus_script_element(n: u8) -> Vec<u8> {
    vec![0x41, n]
}

fn plutus_data_element(n: u8) -> Vec<u8> {
    vec![n]
}

/// A sub transaction with no witnesses whose body holds the given ttl.
fn sub_transaction_element(n: u8) -> Vec<u8> {
    [
        vec![0x83],
        map_of(&[(0, vec![0x80]), (1, vec![0x80]), (3, vec![n])]),
        vec![0xa0, 0xf6],
    ]
    .concat()
}

/// A sub transaction with one key witness whose body holds the given ttl.
fn witnessed_sub_transaction_element(n: u8) -> Vec<u8> {
    [
        vec![0x83],
        map_of(&[(0, vec![0x80]), (1, vec![0x80]), (3, vec![n])]),
        map_of(&[(0, [vec![0x81], vkey_witness_element(1)].concat())]),
        vec![0xf6],
    ]
    .concat()
}

/// The element with its first head rewritten to carry its argument in eight bytes.
fn widened(element: &[u8]) -> Vec<u8> {
    let major = element[0] >> 5;
    let info = element[0] & 0x1f;
    let (argument, head) = match info {
        0..=23 => (u64::from(info), 1),
        24 => (u64::from(element[1]), 2),
        _ => panic!("every element here has a head of at most two bytes"),
    };
    let mut wide = vec![(major << 5) | 27];
    wide.extend_from_slice(&argument.to_be_bytes());
    wide.extend_from_slice(&element[head..]);
    wide
}

fn set_of(tagged: bool, elements: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = if tagged {
        vec![0xd9, 0x01, 0x02]
    } else {
        Vec::new()
    };
    bytes.push(0x80 | u8::try_from(elements.len()).unwrap());
    for element in elements {
        bytes.extend_from_slice(element);
    }
    bytes
}

fn pool_registration_holding(owners: &[u8], relays: &[u8]) -> Vec<u8> {
    let mut reward_account = vec![0x58, 29, 0xe0];
    reward_account.extend(std::iter::repeat_n(0x33, 28));
    [
        vec![0x8a, 0x03],
        bytes_of(28, 0x44),
        bytes_of(32, 0x55),
        vec![0x00, 0x00, 0xd8, 0x1e, 0x82, 0x00, 0x01],
        reward_account,
        owners.to_vec(),
        relays.to_vec(),
        vec![0xf6],
    ]
    .concat()
}

/// One position that decodes a set: where it is, how its enclosing value is
/// read, and whether the ledger keys its elements by the bytes they were read from.
struct SetPosition {
    name: &'static str,
    enclose: fn(&[u8]) -> Vec<u8>,
    read: Read,
    element: fn(u8) -> Vec<u8>,
    keyed_by_bytes: bool,
}

fn set_positions() -> Vec<SetPosition> {
    macro_rules! at {
        ($name:literal, $enclose:expr, $read:expr, $element:expr, $by_bytes:literal) => {
            SetPosition {
                name: $name,
                enclose: $enclose,
                read: $read,
                element: $element,
                keyed_by_bytes: $by_bytes,
            }
        };
    }

    vec![
        at!(
            "body 0",
            |s| body_holding(true, 0, s),
            read_body,
            input_element,
            false
        ),
        at!(
            "body 4",
            |s| body_holding(true, 4, s),
            read_body,
            certificate_element,
            false
        ),
        at!(
            "body 13",
            |s| body_holding(true, 13, s),
            read_body,
            input_element,
            false
        ),
        at!(
            "body 14 key hashes",
            |s| body_holding(true, 14, s),
            read_body,
            keyhash_element,
            false
        ),
        at!(
            "body 14 credentials",
            |s| body_holding(true, 14, s),
            read_body,
            credential_element,
            false
        ),
        at!(
            "body 18",
            |s| body_holding(true, 18, s),
            read_body,
            input_element,
            false
        ),
        at!(
            "body 20",
            |s| body_holding(true, 20, s),
            read_body,
            proposal_element,
            false
        ),
        at!(
            "body 23",
            |s| body_holding(true, 23, s),
            read_body,
            sub_transaction_element,
            false
        ),
        at!(
            "sub body 0",
            |s| body_holding(false, 0, s),
            read_sub_body,
            input_element,
            false
        ),
        at!(
            "sub body 4",
            |s| body_holding(false, 4, s),
            read_sub_body,
            certificate_element,
            false
        ),
        at!(
            "sub body 14 key hashes",
            |s| body_holding(false, 14, s),
            read_sub_body,
            keyhash_element,
            false
        ),
        at!(
            "sub body 14 credentials",
            |s| body_holding(false, 14, s),
            read_sub_body,
            credential_element,
            false
        ),
        at!(
            "sub body 18",
            |s| body_holding(false, 18, s),
            read_sub_body,
            input_element,
            false
        ),
        at!(
            "sub body 20",
            |s| body_holding(false, 20, s),
            read_sub_body,
            proposal_element,
            false
        ),
        at!(
            "witness 0",
            |s| map_of(&[(0, s.to_vec())]),
            read_witnesses,
            vkey_witness_element,
            false
        ),
        at!(
            "witness 1",
            |s| map_of(&[(1, s.to_vec())]),
            read_witnesses,
            native_script_element,
            true
        ),
        at!(
            "witness 2",
            |s| map_of(&[(2, s.to_vec())]),
            read_witnesses,
            bootstrap_witness_element,
            false
        ),
        at!(
            "witness 3",
            |s| map_of(&[(3, s.to_vec())]),
            read_witnesses,
            plutus_script_element,
            false
        ),
        at!(
            "witness 4",
            |s| map_of(&[(4, s.to_vec())]),
            read_witnesses,
            plutus_data_element,
            true
        ),
        at!(
            "witness 6",
            |s| map_of(&[(6, s.to_vec())]),
            read_witnesses,
            plutus_script_element,
            false
        ),
        at!(
            "witness 7",
            |s| map_of(&[(7, s.to_vec())]),
            read_witnesses,
            plutus_script_element,
            false
        ),
        at!(
            "witness 8",
            |s| map_of(&[(8, s.to_vec())]),
            read_witnesses,
            plutus_script_element,
            false
        ),
        at!(
            "pool owners",
            |s| pool_registration_holding(s, &[0x80]),
            read_certificate,
            keyhash_element,
            false
        ),
        at!(
            "committee removed",
            |s| [
                vec![0x85, 0x04, 0xf6],
                s.to_vec(),
                vec![0xa0, 0xd8, 0x1e, 0x82, 0x00, 0x01]
            ]
            .concat(),
            read_gov_action,
            credential_element,
            false
        ),
    ]
}

/// Every set position against the cardano-ledger `9df9f98c` set decoders
/// (`Decoder.hs` `decodeSetLikeEnforceNoDuplicates`, `TxBody.hs` 467 to 469
/// for sub transactions by id, `AlonzoTxWits.hs` 339 for witnesses keyed by
/// their bytes), which refuse a repeated element on either arm, refuse one
/// value written two ways unless the set keys its elements by their bytes,
/// and accept two different elements.
#[test]
fn every_set_position_refuses_an_element_the_ledger_counts_twice() {
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();

    for position in set_positions() {
        let first = (position.element)(1);
        let second = (position.element)(2);
        let read = |elements: &[Vec<u8>], tagged: bool| {
            (position.read)(&(position.enclose)(&set_of(tagged, elements)))
        };

        for tagged in [true, false] {
            read(&[first.clone(), second.clone()], tagged).unwrap_or_else(|err| {
                panic!(
                    "{}: two different elements must decode, found {err}",
                    position.name
                )
            });
            *counts.entry("different elements accepted").or_default() += 1;

            let err = read(&[first.clone(), first.clone()], tagged).expect_err(position.name);
            assert!(
                err.to_string().contains("a repeated element"),
                "{}: the repeated element was refused for some other reason: {err}",
                position.name
            );
            *counts.entry("repeated element refused").or_default() += 1;
        }

        let two_ways = read(&[first.clone(), widened(&first)], true);
        if position.keyed_by_bytes {
            two_ways.unwrap_or_else(|err| {
                panic!(
                    "{}: one value written two ways is two elements here, found {err}",
                    position.name
                )
            });
            *counts
                .entry("two ways accepted where keyed by bytes")
                .or_default() += 1;
        } else {
            let err = two_ways.expect_err(position.name);
            assert!(
                err.to_string().contains("a repeated element"),
                "{}: the value written two ways was refused for some other reason: {err}",
                position.name
            );
            *counts
                .entry("two ways refused where keyed by value")
                .or_default() += 1;
        }
    }

    // The ledger keys a sub transaction by its body, so different witnesses do not make it a second one.
    let same_body = body_holding(
        true,
        23,
        &set_of(
            true,
            &[
                sub_transaction_element(1),
                witnessed_sub_transaction_element(1),
            ],
        ),
    );
    let err = read_body(&same_body).expect_err("one sub transaction body twice must not decode");
    assert!(
        err.to_string().contains("a repeated element"),
        "the repeated sub transaction body was refused for some other reason: {err}"
    );
    *counts
        .entry("one sub body with two witness sets refused")
        .or_default() += 1;

    assert_eq!(
        counts,
        std::collections::BTreeMap::from([
            ("different elements accepted", 48),
            ("one sub body with two witness sets refused", 1),
            ("repeated element refused", 48),
            ("two ways accepted where keyed by bytes", 2),
            ("two ways refused where keyed by value", 22),
        ]),
        "a class ran on a different number of positions than the table lists"
    );
}

/// One bounded position: the value written there, the class it stands for,
/// and the reason a refusal must give, or none where the value must decode.
struct BoundedCase {
    class: &'static str,
    position: String,
    bytes: Vec<u8>,
    read: Read,
    refused_for: Option<&'static str>,
}

const WORD16_AT_BOUND: &[u8] = &[0x19, 0xff, 0xff];
const WORD16_PAST_BOUND: &[u8] = &[0x1a, 0x00, 0x01, 0x00, 0x00];
const WORD32_AT_BOUND: &[u8] = &[0x1a, 0xff, 0xff, 0xff, 0xff];
const WORD32_PAST_BOUND: &[u8] = &[0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
const INT64_AT_BOUND: &[u8] = &[0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
const INT64_PAST_BOUND: &[u8] = &[0x1b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

fn input_with_index(index: &[u8]) -> Vec<u8> {
    [vec![0x82], bytes_of(32, 0x11), index.to_vec()].concat()
}

fn gov_action_id_with_index(index: &[u8]) -> Vec<u8> {
    [vec![0x82], bytes_of(32, 0x66), index.to_vec()].concat()
}

/// A legacy or map form output holding one asset of the given quantity.
fn output_with_quantity(legacy: bool, quantity: u8) -> Vec<u8> {
    let value = [
        vec![0x82, 0x01, 0xa1],
        bytes_of(28, 0x77),
        vec![0xa1, 0x40, quantity],
    ]
    .concat();
    if legacy {
        [vec![0x82, 0x41, 0x00], value].concat()
    } else {
        map_of(&[(0, vec![0x41, 0x00]), (1, value)])
    }
}

fn bounded_cases() -> Vec<BoundedCase> {
    let mut cases = Vec::new();
    let mut case = |class, position: String, bytes: Vec<u8>, read: Read, refused_for| {
        cases.push(BoundedCase {
            class,
            position,
            bytes,
            read,
            refused_for,
        })
    };

    // `transaction_input`, TxIn.hs 131 to 135 reads the index with "expected word16".
    for (top, key) in [(true, 0), (true, 13), (true, 18), (false, 0), (false, 18)] {
        let read: Read = if top { read_body } else { read_sub_body };
        let kind = if top { "body" } else { "sub body" };
        for (class, index, refused_for) in [
            ("word at its bound", WORD16_AT_BOUND, None),
            (
                "word past its bound",
                WORD16_PAST_BOUND,
                Some("as TransactionInput"),
            ),
        ] {
            let set = set_of(true, &[input_with_index(index)]);
            case(
                class,
                format!("{kind} {key} input index"),
                body_holding(top, key, &set),
                read,
                refused_for,
            );
        }
    }

    // `gov_action_id`, Procedures.hs 160 holds the index as a Word16.
    for (class, index, refused_for) in [
        ("word at its bound", WORD16_AT_BOUND, None),
        (
            "word past its bound",
            WORD16_PAST_BOUND,
            Some("as GovActionId"),
        ),
    ] {
        let id = gov_action_id_with_index(index);
        let actions = [
            (
                "parameter change",
                [vec![0x84, 0x00], id.clone(), vec![0xa0, 0xf6]].concat(),
            ),
            (
                "hard fork",
                [vec![0x83, 0x01], id.clone(), vec![0x82, 0x0a, 0x00]].concat(),
            ),
            ("no confidence", [vec![0x82, 0x03], id.clone()].concat()),
            (
                "update committee",
                [
                    vec![0x85, 0x04],
                    id.clone(),
                    vec![0x80, 0xa0, 0xd8, 0x1e, 0x82, 0x00, 0x01],
                ]
                .concat(),
            ),
            (
                "new constitution",
                [
                    vec![0x83, 0x05],
                    id.clone(),
                    vec![0x82, 0x82, 0x60],
                    bytes_of(32, 0x00),
                    vec![0xf6],
                ]
                .concat(),
            ),
        ];
        for (action, bytes) in actions {
            case(
                class,
                format!("{action} previous action"),
                bytes,
                read_gov_action,
                refused_for,
            );
        }

        let procedures = [
            vec![0xa1, 0x82, 0x00],
            bytes_of(28, 0x88),
            vec![0xa1],
            id.clone(),
            vec![0x82, 0x00, 0xf6],
        ]
        .concat();
        let refused_for = refused_for.map(|_| "as VotingProcedures");
        case(
            class,
            "body 19 voted action".into(),
            body_holding(true, 19, &procedures),
            read_body,
            refused_for,
        );
        case(
            class,
            "sub body 19 voted action".into(),
            body_holding(false, 19, &procedures),
            read_sub_body,
            refused_for,
        );
    }

    // `port`, BaseTypes.hs 700 holds it as a Word16.
    for (class, port, refused_for) in [
        ("word at its bound", WORD16_AT_BOUND, None),
        ("word past its bound", WORD16_PAST_BOUND, Some("as Relays")),
    ] {
        let by_address = [vec![0x81, 0x84, 0x00], port.to_vec(), vec![0xf6, 0xf6]].concat();
        let by_name = [vec![0x81, 0x83, 0x01], port.to_vec(), vec![0x60]].concat();
        case(
            class,
            "address relay port".into(),
            pool_registration_holding(&[0x80], &by_address),
            read_certificate,
            refused_for,
        );
        case(
            class,
            "name relay port".into(),
            pool_registration_holding(&[0x80], &by_name),
            read_certificate,
            refused_for,
        );
    }

    // `protocol_version`, Version.hs 59 to 63 and 113 to 132 bound the major
    // version to 0 through 13, and BaseTypes.hs 212 holds the minor as a Word32.
    for (class, version, refused_for) in [
        (
            "word at its bound",
            [vec![0x82, 0x0d], WORD32_AT_BOUND.to_vec()].concat(),
            None,
        ),
        (
            "word past its bound",
            vec![0x82, 0x0e, 0x00],
            Some("as ProtocolVersion"),
        ),
        (
            "word past its bound",
            [vec![0x82, 0x0d], WORD32_PAST_BOUND.to_vec()].concat(),
            Some("as ProtocolVersion"),
        ),
    ] {
        case(
            class,
            "hard fork version".into(),
            [vec![0x83, 0x01, 0xf6], version].concat(),
            read_gov_action,
            refused_for,
        );
    }

    // `ex_units`, ExUnits.hs 208 to 225 refuses either count past maxBound :: Int64.
    for (class, units, refused_for) in [
        (
            "word at its bound",
            [vec![0x82], INT64_AT_BOUND.to_vec(), INT64_AT_BOUND.to_vec()].concat(),
            None,
        ),
        (
            "word past its bound",
            [vec![0x82], INT64_PAST_BOUND.to_vec(), vec![0x00]].concat(),
            Some("as ExUnits"),
        ),
        (
            "word past its bound",
            [vec![0x82, 0x00], INT64_PAST_BOUND.to_vec()].concat(),
            Some("as ExUnits"),
        ),
    ] {
        let redeemers = [vec![0xa1, 0x82, 0x00, 0x00, 0x82, 0x00], units.clone()].concat();
        case(
            class,
            "witness 5 redeemer budget".into(),
            map_of(&[(5, redeemers)]),
            read_witnesses,
            refused_for,
        );
        for key in [20, 21, 47] {
            case(
                class,
                format!("update {key}"),
                map_of(&[(key, units.clone())]),
                read_update,
                refused_for,
            );
        }
    }

    // `cost_models`, CostModels.hs 380 keys the models by Word8.
    for (class, key, refused_for) in [
        ("word at its bound", vec![0x18, 0xff], None),
        ("word past its bound", vec![0x19, 0x01, 0x00], Some("u8")),
    ] {
        let models = [vec![0xa1], key, vec![0x80]].concat();
        case(
            class,
            "update 18 cost model key".into(),
            map_of(&[(18, models)]),
            read_update,
            refused_for,
        );
    }

    // `protocol_param_update`, the Word16 and Word32 fields of the Dijkstra
    // record in PParams.hs, with key 36 a NonZero Word32.
    for key in [4, 8, 23, 24, 27, 43, 51, 52] {
        case(
            "word at its bound",
            format!("update {key}"),
            map_of(&[(key, WORD16_AT_BOUND.to_vec())]),
            read_update,
            None,
        );
        case(
            "word past its bound",
            format!("update {key}"),
            map_of(&[(key, WORD16_PAST_BOUND.to_vec())]),
            read_update,
            Some("u16"),
        );
    }
    for key in [
        2, 3, 7, 22, 28, 29, 32, 34, 35, 36, 40, 41, 42, 45, 46, 48, 49, 53,
    ] {
        case(
            "word at its bound",
            format!("update {key}"),
            map_of(&[(key, WORD32_AT_BOUND.to_vec())]),
            read_update,
            None,
        );
        case(
            "word past its bound",
            format!("update {key}"),
            map_of(&[(key, WORD32_PAST_BOUND.to_vec())]),
            read_update,
            Some("u32"),
        );
    }
    case(
        "one where zero is refused",
        "update 36".into(),
        map_of(&[(36, vec![0x01])]),
        read_update,
        None,
    );
    case(
        "zero where one is the least",
        "update 36".into(),
        map_of(&[(36, vec![0x00])]),
        read_update,
        Some("unexpected 0"),
    );

    // `positive_coin`, TxBody.hs 437 reads the donation with decodePositiveCoin.
    for top in [true, false] {
        let (kind, read): (&str, Read) = if top {
            ("body", read_body)
        } else {
            ("sub body", read_sub_body)
        };
        case(
            "one where zero is refused",
            format!("{kind} 22 donation"),
            body_holding(top, 22, &[0x01]),
            read,
            None,
        );
        case(
            "zero where one is the least",
            format!("{kind} 22 donation"),
            body_holding(top, 22, &[0x00]),
            read,
            Some("as PositiveCoin"),
        );
    }

    // `value`, MaryValue.hs 344 to 349 refuses an asset quantity of zero.
    for (form, legacy, refused_for) in [
        ("legacy", true, "as LegacyTransactionOutput"),
        ("map", false, "as Value"),
    ] {
        for (kind, top, key) in [
            ("body", true, 1),
            ("body", true, 16),
            ("sub body", false, 1),
        ] {
            let read: Read = if top { read_body } else { read_sub_body };
            let enclose = |output: Vec<u8>| {
                if key == 1 {
                    body_holding(top, key, &[vec![0x81], output].concat())
                } else {
                    body_holding(top, key, &output)
                }
            };
            case(
                "one where zero is refused",
                format!("{kind} {key} {form} output asset"),
                enclose(output_with_quantity(legacy, 1)),
                read,
                None,
            );
            case(
                "zero where one is the least",
                format!("{kind} {key} {form} output asset"),
                enclose(output_with_quantity(legacy, 0)),
                read,
                Some(refused_for),
            );
        }
    }

    cases
}

/// Every bounded position against the cardano-ledger `9df9f98c` decoder
/// cited beside it: a value at its bound decodes, and a value past it, or a
/// zero where the least value is one, is refused for that bound.
#[test]
fn every_bounded_position_refuses_a_value_the_ledger_refuses() {
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();

    for case in bounded_cases() {
        let decoded = (case.read)(&case.bytes);
        match (case.refused_for, decoded) {
            (None, Ok(())) => {}
            (None, Err(err)) => panic!(
                "{} ({}): must decode, found {err}",
                case.position, case.class
            ),
            (Some(reason), Ok(())) => panic!(
                "{} ({}): must be refused for {reason}",
                case.position, case.class
            ),
            (Some(reason), Err(err)) => assert!(
                err.to_string().contains(reason),
                "{} ({}): refused for some other reason than {reason}: {err}",
                case.position,
                case.class
            ),
        }
        *counts.entry(case.class).or_default() += 1;
    }

    assert_eq!(
        counts,
        std::collections::BTreeMap::from([
            ("one where zero is refused", 9),
            ("word at its bound", 46),
            ("word past its bound", 51),
            ("zero where one is the least", 9),
        ]),
        "a class ran on a different number of positions than the table lists"
    );
}
