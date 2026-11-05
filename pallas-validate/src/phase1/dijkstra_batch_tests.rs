//! Synthetic script-free batches; the retained real Plutus batch remains unsupported.
use super::{
    dijkstra_tests::{env, error, sign, synthetic},
    *,
};
use crate::utils::dijkstra_state::DijkstraAccount;
use pallas_addresses::{Network, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart};
use pallas_codec::{
    minicbor,
    utils::{CborWrap, KeepRaw, MaybeIndefArray, Nullable},
};
use pallas_crypto::{
    hash::{Hash, Hasher},
    key::ed25519::SecretKey,
};
use pallas_primitives::dijkstra as n;
use pallas_traverse::{MultiEraInput, MultiEraOutput, OriginalHash};
use std::borrow::Cow;

fn owned(input: n::TransactionInput) -> MultiEraInput<'static> {
    MultiEraInput::AlonzoCompatible(Box::new(Cow::Owned(input)))
}
fn batch(test: impl FnOnce(n::BlockTransaction<'_>, n::TransactionOutput<'_>)) {
    synthetic(|mut tx, input| {
        let mut sub: n::SubTransaction =
            minicbor::decode(&[0x83, 0xa2, 0x00, 0x80, 0x01, 0x80, 0xa0, 0xf6]).unwrap();
        let mut source = tx.transaction_body.inputs[0].clone();
        source.index = 99;
        sub.sub_transaction_body.inputs = vec![source].into();
        // The sub consumes a full input but creates zero outputs. The top creates
        // the aggregate output. Per-level value conservation would reject this.
        sub.sub_transaction_body.outputs = MaybeIndefArray::Def(vec![]);
        sub.sub_transaction_body.validity_interval_start = Some(1400000);
        sub.sub_transaction_body.ttl = Some(1400010);
        let key = Hasher::<224>::hash(SecretKey::from([71; 32]).public_key().as_ref());
        sub.sub_transaction_body.guards = Some(n::Guards::AddrKeyhashes(
            n::NonEmptySet::from_vec(vec![key]).unwrap(),
        ));
        sub.sub_transaction_body.required_top_level_guards = Some(
            [(n::StakeCredential::AddrKeyhash(key), Nullable::Null)]
                .into_iter()
                .collect(),
        );
        tx.transaction_body.guards = sub.sub_transaction_body.guards.clone();
        sign_sub(&mut sub);
        let mut outputs = tx.transaction_body.outputs.clone().to_vec();
        let n::TransactionOutput::PostAlonzo(ref mut output) = outputs[0] else {
            unreachable!()
        };
        let n::Value::Coin(ref mut coin) = output.value else {
            unreachable!()
        };
        *coin += MultiEraOutput::from_dijkstra(&input).value().coin();
        tx.transaction_body.outputs = MaybeIndefArray::Def(outputs);
        tx.transaction_body.sub_transactions = n::NonEmptySet::from_vec(vec![sub]);
        sign(&mut tx);
        test(tx, input);
    });
}
fn sign_sub(sub: &mut n::SubTransaction<'_>) {
    let key = SecretKey::from([71; 32]);
    let hash = Hasher::<256>::hash(&minicbor::to_vec(&sub.sub_transaction_body).unwrap());
    sub.transaction_witness_set.vkeywitness = n::NonEmptySet::from_vec(vec![n::VKeyWitness {
        vkey: key.public_key().as_ref().to_vec().into(),
        signature: key.sign(hash).as_ref().to_vec().into(),
    }]);
}
fn run(
    tx: &n::BlockTransaction<'_>,
    input: &n::TransactionOutput<'_>,
    e: &Environment,
) -> crate::utils::ValidationResult {
    let original = tx.transaction_body.inputs[0].clone();
    let mut second = original.clone();
    second.index = 99;
    let utxos = [
        (owned(original), MultiEraOutput::from_dijkstra(input)),
        (owned(second), MultiEraOutput::from_dijkstra(input)),
    ]
    .into_iter()
    .collect();
    validate_txs(
        &[MultiEraTx::from_dijkstra(tx)],
        e,
        &utxos,
        &mut CertState::default(),
    )
}
#[test]
fn dijkstra_batch_aggregate_balance_and_native_size() {
    batch(|tx, input| {
        let result = run(&tx, &input, &env());
        assert!(result.is_ok(), "{result:?}");
        let size = minicbor::to_vec(tx.to_mempool_transaction()).unwrap().len() as u32;
        let mut e = env();
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.max_transaction_size = size;
        pp.minfee_a = 1;
        pp.minfee_b = 200000 - size;
        assert!(run(&tx, &input, &e).is_ok());
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.minfee_b += 1;
        error(run(&tx, &input, &e), "PostAlonzo(FeeBelowMin)");
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.minfee_b -= 1;
        pp.max_transaction_size -= 1;
        error(run(&tx, &input, &e), "PostAlonzo(MaxTxSizeExceeded)");
    });
}
#[test]
fn dijkstra_batch_sub_signatures_and_required_top_guards() {
    batch(|tx, input| {
        let mut changed = tx.clone();
        change_sub(&mut changed, |sub| {
            sub.transaction_witness_set.vkeywitness = None
        });
        sign(&mut changed);
        error(
            run(&changed, &input, &env()),
            "PostAlonzo(VKWitnessMissing)",
        );
        changed = tx.clone();
        change_sub(&mut changed, |sub| {
            sub.transaction_witness_set.vkeywitness = tx.transaction_witness_set.vkeywitness.clone()
        });
        sign(&mut changed);
        error(
            run(&changed, &input, &env()),
            "PostAlonzo(VKWrongSignature)",
        );
        changed = tx.clone();
        changed.transaction_body.guards = None;
        sign(&mut changed);
        error(
            run(&changed, &input, &env()),
            "PostAlonzo(ReqSignerMissing)",
        );
        changed = tx.clone();
        change_sub(&mut changed, |sub| {
            sub.sub_transaction_body.guards = Some(n::Guards::AddrKeyhashes(
                n::NonEmptySet::from_vec(vec![[9; 28].into()]).unwrap(),
            ));
            sign_sub(sub);
        });
        sign(&mut changed);
        error(
            run(&changed, &input, &env()),
            "PostAlonzo(VKWitnessMissing)",
        );
    });
}
#[test]
fn dijkstra_batch_original_inputs_and_no_double_spending() {
    batch(|tx, input| {
        let mut changed = tx.clone();
        let mut sub = changed.transaction_body.sub_transactions.as_ref().unwrap()[0].clone();
        sub.sub_transaction_body.inputs = changed.transaction_body.inputs.clone();
        sign_sub(&mut sub);
        changed.transaction_body.sub_transactions = n::NonEmptySet::from_vec(vec![sub]);
        sign(&mut changed);
        error(run(&changed, &input, &env()), "DijkstraInputAlreadySpent");
        changed = tx.clone();
        let sub = changed.transaction_body.sub_transactions.as_ref().unwrap()[0].clone();
        changed.transaction_body.sub_transactions =
            n::NonEmptySet::from_vec(vec![sub.clone(), sub]);
        sign(&mut changed);
        error(run(&changed, &input, &env()), "DijkstraInputAlreadySpent");
        changed = tx.clone();
        change_sub(&mut changed, |sub| {
            sub.sub_transaction_body.inputs = vec![n::TransactionInput {
                transaction_id: [9; 32].into(),
                index: 0,
            }]
            .into();
            sign_sub(sub);
        });
        sign(&mut changed);
        error(run(&changed, &input, &env()), "PostAlonzo(InputNotInUTxO)");
    });
}
#[test]
fn dijkstra_batch_validity_boundaries_and_real_scripted_batch_inputs() {
    batch(|tx, input| {
        for slot in [1400000, 1400009] {
            let mut e = env();
            e.block_slot = slot;
            assert!(run(&tx, &input, &e).is_ok());
        }
        let mut e = env();
        e.block_slot = 1399999;
        error(run(&tx, &input, &e), "PostAlonzo(BlockPrecedesValInt)");
        e.block_slot = 1400010;
        error(run(&tx, &input, &e), "PostAlonzo(BlockExceedsValInt)");
    });
    let raw = hex::decode(include_str!("../../../test_data/dijkstra-subtx.tx").trim()).unwrap();
    let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &raw).unwrap();
    error(
        validate_txs(&[tx], &env(), &UTxOs::new(), &mut CertState::default()),
        "PostAlonzo(InputNotInUTxO)",
    );
}

fn change_sub(tx: &mut n::BlockTransaction<'_>, f: impl FnOnce(&mut n::SubTransaction<'_>)) {
    let mut sub = tx.transaction_body.sub_transactions.as_ref().unwrap()[0].clone();
    f(&mut sub);
    tx.transaction_body.sub_transactions = n::NonEmptySet::from_vec(vec![sub]);
}

#[test]
fn dijkstra_batch_cannot_spend_output_created_in_same_batch() {
    batch(|mut tx, input| {
        let mut first = tx.transaction_body.sub_transactions.as_ref().unwrap()[0].clone();
        first.sub_transaction_body.outputs =
            MaybeIndefArray::Def(vec![tx.transaction_body.outputs[0].clone()]);
        sign_sub(&mut first);
        let created = Hasher::<256>::hash(&minicbor::to_vec(&first.sub_transaction_body).unwrap());
        let mut second = first.clone();
        second.sub_transaction_body.inputs = vec![n::TransactionInput {
            transaction_id: created,
            index: 0,
        }]
        .into();
        sign_sub(&mut second);
        tx.transaction_body.sub_transactions = n::NonEmptySet::from_vec(vec![first, second]);
        sign(&mut tx);
        error(run(&tx, &input, &env()), "PostAlonzo(InputNotInUTxO)");
    });
}

/// `run`, with the sub-transaction's input resolving to `sub_input`.
fn run_sub(
    tx: &n::BlockTransaction<'_>,
    input: &n::TransactionOutput<'_>,
    sub_input: &n::TransactionOutput<'_>,
) -> crate::utils::ValidationResult {
    run_with(tx, input, sub_input, &[], &env())
}
/// `run_sub`, with `extra` UTxOs available for reference.
fn run_with(
    tx: &n::BlockTransaction<'_>,
    input: &n::TransactionOutput<'_>,
    sub_input: &n::TransactionOutput<'_>,
    extra: &[(n::TransactionInput, n::TransactionOutput<'_>)],
    e: &Environment,
) -> crate::utils::ValidationResult {
    run_full(tx, input, sub_input, extra, e, &mut CertState::default())
}
/// `run_with`, against the given account state.
fn run_full(
    tx: &n::BlockTransaction<'_>,
    input: &n::TransactionOutput<'_>,
    sub_input: &n::TransactionOutput<'_>,
    extra: &[(n::TransactionInput, n::TransactionOutput<'_>)],
    e: &Environment,
    state: &mut CertState,
) -> crate::utils::ValidationResult {
    let utxos = utxo_set(tx, input, sub_input, extra);
    validate_txs(&[MultiEraTx::from_dijkstra(tx)], e, &utxos, state)
}
/// The outputs `run_with` resolves the batch's inputs and the extra inputs to.
fn utxo_set<'b>(
    tx: &n::BlockTransaction<'_>,
    input: &'b n::TransactionOutput<'_>,
    sub_input: &'b n::TransactionOutput<'_>,
    extra: &'b [(n::TransactionInput, n::TransactionOutput<'_>)],
) -> crate::utils::UTxOs<'b> {
    let original = tx.transaction_body.inputs[0].clone();
    let mut second = original.clone();
    second.index = 99;
    [
        (owned(original), MultiEraOutput::from_dijkstra(input)),
        (owned(second), MultiEraOutput::from_dijkstra(sub_input)),
    ]
    .into_iter()
    .chain(
        extra
            .iter()
            .map(|(i, o)| (owned(i.clone()), MultiEraOutput::from_dijkstra(o))),
    )
    .collect()
}

fn post_alonzo<'a, 'b>(
    output: &'a mut n::TransactionOutput<'b>,
) -> &'a mut n::PostAlonzoTransactionOutput<'b> {
    let n::TransactionOutput::PostAlonzo(out) = output else {
        unreachable!()
    };
    out
}

fn tokens(coin: u64, quantity: u64) -> pallas_primitives::conway::Value {
    pallas_primitives::conway::Value::Multiasset(
        coin,
        [(
            [8; 28].into(),
            [(b"token".to_vec().into(), quantity.try_into().unwrap())]
                .into_iter()
                .collect(),
        )]
        .into_iter()
        .collect(),
    )
}

fn script_address() -> pallas_codec::utils::Bytes {
    ShelleyAddress::new(
        Network::Testnet,
        ShelleyPaymentPart::Script([9; 28].into()),
        ShelleyDelegationPart::Null,
    )
    .to_vec()
    .into()
}

/// The shape of a babel-fee offer that places a DEX order: the sub spends a key
/// input holding tokens and pays them, with some coin, to a script under an
/// inline datum. The top level supplies that coin.
fn token_order_batch(
    test: impl FnOnce(n::BlockTransaction<'_>, n::TransactionOutput<'_>, n::TransactionOutput<'_>),
) {
    batch(|mut tx, input| {
        let coin = MultiEraOutput::from_dijkstra(&input).value().coin();
        let order_coin = 2_000_000;
        let mut sub_input = input.clone();
        post_alonzo(&mut sub_input).value = tokens(coin, 7);
        let mut order = tx.transaction_body.outputs[0].clone();
        let out = post_alonzo(&mut order);
        out.address = script_address();
        out.value = tokens(order_coin, 7);
        out.datum_option = Some(
            pallas_primitives::conway::DatumOption::Data(pallas_codec::utils::CborWrap(
                n::PlutusData::BigInt(n::BigInt::Int(42.into())).into(),
            ))
            .into(),
        );
        let mut sub = tx.transaction_body.sub_transactions.as_ref().unwrap()[0].clone();
        sub.sub_transaction_body.outputs = MaybeIndefArray::Def(vec![order]);
        sign_sub(&mut sub);
        tx.transaction_body.sub_transactions = n::NonEmptySet::from_vec(vec![sub]);
        let mut outputs = tx.transaction_body.outputs.clone().to_vec();
        let n::Value::Coin(ref mut top) = post_alonzo(&mut outputs[0]).value else {
            unreachable!()
        };
        *top -= order_coin;
        tx.transaction_body.outputs = MaybeIndefArray::Def(outputs);
        sign(&mut tx);
        test(tx, input, sub_input);
    });
}

#[test]
fn dijkstra_batch_sub_pays_tokens_to_a_script_under_a_datum() {
    token_order_batch(|tx, input, sub_input| {
        let result = run_sub(&tx, &input, &sub_input);
        assert!(result.is_ok(), "{result:?}");
    });
}

#[test]
fn dijkstra_batch_sub_key_inputs_may_carry_datums_and_reference_scripts() {
    token_order_batch(|tx, input, sub_input| {
        let mut with_datum = sub_input.clone();
        post_alonzo(&mut with_datum).datum_option =
            Some(pallas_primitives::conway::DatumOption::Hash([0; 32].into()).into());
        let result = run_sub(&tx, &input, &with_datum);
        assert!(result.is_ok(), "{result:?}");
        let mut with_script = sub_input;
        post_alonzo(&mut with_script).script_ref = Some(CborWrap(n::ScriptRef::NativeScript(
            native(n::NativeScript::ScriptAll(vec![])),
        )));
        let result = run_sub(&tx, &input, &with_script);
        assert!(result.is_ok(), "{result:?}");
    });
}

fn native(script: n::NativeScript) -> KeepRaw<'static, n::NativeScript> {
    let bytes = minicbor::to_vec(script).unwrap();
    minicbor::decode::<KeepRaw<'_, n::NativeScript>>(&bytes)
        .unwrap()
        .to_owned()
}
fn guard_key() -> Hash<28> {
    Hasher::<224>::hash(SecretKey::from([71; 32]).public_key().as_ref())
}
fn locked(hash: Hash<28>) -> pallas_codec::utils::Bytes {
    ShelleyAddress::new(
        Network::Testnet,
        ShelleyPaymentPart::Script(hash),
        ShelleyDelegationPart::Null,
    )
    .to_vec()
    .into()
}
/// Puts `f`'s changes into the batch's sub-transaction and signs both levels.
fn resign(tx: &mut n::BlockTransaction<'_>, f: impl FnOnce(&mut n::SubTransaction<'_>)) {
    change_sub(tx, |sub| {
        f(sub);
        sign_sub(sub);
    });
    sign(tx);
}

#[test]
fn dijkstra_batch_sub_spends_a_native_script_input() {
    token_order_batch(|tx, input, sub_input| {
        let script = native(n::NativeScript::ScriptPubkey(guard_key()));
        let mut spent = sub_input.clone();
        post_alonzo(&mut spent).address = locked(script.original_hash());
        error(
            run_sub(&tx, &input, &spent),
            "PostAlonzo(ScriptWitnessMissing)",
        );
        let witnessed = |script: &KeepRaw<'static, n::NativeScript>| {
            let mut changed = tx.clone();
            resign(&mut changed, |sub| {
                sub.transaction_witness_set.native_script =
                    n::NonEmptySet::from_vec(vec![script.clone()]);
            });
            changed
        };
        let result = run_sub(&witnessed(&script), &input, &spent);
        assert!(result.is_ok(), "{result:?}");
        // A key-locked input needs no script, so the witness is extraneous.
        error(
            run_sub(&witnessed(&script), &input, &sub_input),
            "PostAlonzo(UnneededNativeScript)",
        );
        // The sub's own validity interval [1400000, 1400010) bounds its timelocks.
        for (slot, expected) in [(1400010, None), (1400009, Some("NativeScriptDenial"))] {
            let timelock = native(n::NativeScript::InvalidHereafter(slot));
            let mut spent = sub_input.clone();
            post_alonzo(&mut spent).address = locked(timelock.original_hash());
            let result = run_sub(&witnessed(&timelock), &input, &spent);
            match expected {
                None => assert!(result.is_ok(), "{result:?}"),
                Some(e) => error(result, &format!("PostAlonzo({e})")),
            }
        }
        let other = native(n::NativeScript::ScriptPubkey([9; 28].into()));
        let mut spent = sub_input.clone();
        post_alonzo(&mut spent).address = locked(other.original_hash());
        error(
            run_sub(&witnessed(&other), &input, &spent),
            "PostAlonzo(NativeScriptDenial)",
        );
    });
}

#[test]
fn dijkstra_batch_sub_reference_inputs_provide_scripts_within_the_size_cap() {
    token_order_batch(|tx, input, sub_input| {
        let script = native(n::NativeScript::ScriptPubkey(guard_key()));
        let mut spent = sub_input.clone();
        post_alonzo(&mut spent).address = locked(script.original_hash());
        let reference = n::TransactionInput {
            transaction_id: [7; 32].into(),
            index: 0,
        };
        let mut holder = input.clone();
        post_alonzo(&mut holder).script_ref =
            Some(CborWrap(n::ScriptRef::NativeScript(script.clone())));
        let mut changed = tx.clone();
        resign(&mut changed, |sub| {
            sub.sub_transaction_body.reference_inputs =
                n::NonEmptySet::from_vec(vec![reference.clone()]);
        });
        error(
            run_sub(&changed, &input, &spent),
            "PostAlonzo(ReferenceInputNotInUTxO)",
        );
        let extra = [(reference, holder)];
        let result = run_with(&changed, &input, &spent, &extra, &env());
        assert!(result.is_ok(), "{result:?}");
        let mut e = env();
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.max_ref_script_size_per_tx = minicbor::to_vec(&*script).unwrap().len() as u32 - 1;
        error(
            run_with(&changed, &input, &spent, &extra, &e),
            "DijkstraReferenceScriptsTooLarge",
        );
    });
}

#[test]
fn dijkstra_batch_sub_metadata_must_match_its_hash() {
    token_order_batch(|tx, input, sub_input| {
        // {674: "hi"}, CIP-20 message metadata.
        let raw = [0xa1, 0x19, 0x02, 0xa2, 0x62, 0x68, 0x69];
        let metadata = || -> KeepRaw<'static, n::AuxiliaryData> {
            minicbor::decode::<KeepRaw<'_, n::AuxiliaryData>>(&raw)
                .unwrap()
                .to_owned()
        };
        for (hash, expected) in [
            (Some(Hasher::<256>::hash(&raw)), None),
            (Some([0; 32].into()), Some("PostAlonzo(MetadataHash)")),
            (None, Some("PostAlonzo(MetadataHash)")),
        ] {
            let mut changed = tx.clone();
            resign(&mut changed, |sub| {
                sub.sub_transaction_body.auxiliary_data_hash = hash;
                sub.auxiliary_data = Nullable::Some(metadata());
            });
            let result = run_sub(&changed, &input, &sub_input);
            match expected {
                None => assert!(result.is_ok(), "{result:?}"),
                Some(e) => error(result, e),
            }
        }
    });
}

/// An address locked by the Byron key that `bootstrap` signs with.
pub(super) fn byron_address() -> pallas_codec::utils::Bytes {
    use pallas_addresses::byron::{AddrType, AddressPayload, ByronAddress, SpendingData};
    let xpub = [SecretKey::from([7; 32]).public_key().as_ref(), &[9; 32][..]].concat();
    ByronAddress::from(AddressPayload::new(
        AddrType::PubKey,
        SpendingData::PubKey(xpub.into()),
        vec![].into(),
    ))
    .to_vec()
    .into()
}
pub(super) fn bootstrap(signed: &[u8]) -> n::BootstrapWitness {
    let key = SecretKey::from([7; 32]);
    n::BootstrapWitness {
        public_key: key.public_key().as_ref().to_vec().into(),
        signature: key.sign(signed).as_ref().to_vec().into(),
        chain_code: vec![9; 32].into(),
        attributes: vec![0xa0].into(),
    }
}
pub(super) fn body_hash<T: minicbor::Encode<()>>(body: &T) -> Hash<32> {
    Hasher::<256>::hash(&minicbor::to_vec(body).unwrap())
}

#[test]
fn dijkstra_batch_sub_spends_a_bootstrap_input() {
    token_order_batch(|tx, input, sub_input| {
        let mut spent = sub_input.clone();
        post_alonzo(&mut spent).address = byron_address();
        let body = body_hash(
            &tx.transaction_body.sub_transactions.as_ref().unwrap()[0].sub_transaction_body,
        );
        for (witnesses, expected) in [
            (vec![bootstrap(body.as_ref())], None),
            (vec![], Some("PostAlonzo(VKWitnessMissing)")),
            (
                vec![bootstrap(&[0; 32])],
                Some("PostAlonzo(VKWrongSignature)"),
            ),
        ] {
            let mut changed = tx.clone();
            change_sub(&mut changed, |sub| {
                sub.transaction_witness_set.bootstrap_witness = n::NonEmptySet::from_vec(witnesses);
            });
            sign(&mut changed);
            let result = run_sub(&changed, &input, &spent);
            match expected {
                None => assert!(result.is_ok(), "{result:?}"),
                Some(e) => error(result, e),
            }
        }
    });
}

/// The key hash the ledger takes for the key `bootstrap` signs with, under `chain_code` and the `attributes` bytes as sent.
fn bootstrap_root(chain_code: &[u8], attributes: &[u8]) -> Hash<28> {
    let key = SecretKey::from([7; 32]);
    pallas_addresses::byron::AddressPayload::hash_address_id_preimage(
        &[
            &super::conway::BOOTSTRAP_ROOT_HEADER[..],
            key.public_key().as_ref(),
            chain_code,
            attributes,
        ]
        .concat(),
    )
}
/// A Byron address whose root is `root`.
fn byron_address_at(root: Hash<28>) -> pallas_codec::utils::Bytes {
    use pallas_addresses::byron::{AddrType, AddressPayload, ByronAddress};
    ByronAddress::from(AddressPayload {
        root,
        attributes: vec![].into(),
        addrtype: AddrType::PubKey,
    })
    .to_vec()
    .into()
}
/// `bootstrap`, with the given chain code and attribute bytes.
fn bootstrap_with(signed: &[u8], chain_code: &[u8], attributes: &[u8]) -> n::BootstrapWitness {
    n::BootstrapWitness {
        chain_code: chain_code.to_vec().into(),
        attributes: attributes.to_vec().into(),
        ..bootstrap(signed)
    }
}
/// Adds `witness` to the bootstrap witnesses of `witnesses`.
pub(super) fn add_bootstrap(witnesses: &mut n::WitnessSet<'_>, witness: n::BootstrapWitness) {
    let mut all: Vec<_> = witnesses
        .bootstrap_witness
        .iter()
        .flat_map(|x| x.iter().cloned())
        .collect();
    all.push(witness);
    witnesses.bootstrap_witness = n::NonEmptySet::from_vec(all);
}

#[test]
fn dijkstra_bootstrap_roots_hash_the_attribute_bytes_as_sent() {
    token_order_batch(|tx, input, sub_input| {
        let body = body_hash(
            &tx.transaction_body.sub_transactions.as_ref().unwrap()[0].sub_transaction_body,
        );
        for (address, expected) in [
            (&[0xa0][..], Some("PostAlonzo(VKWitnessMissing)")),
            (&[0xbf, 0xff][..], None),
        ] {
            let mut spent = sub_input.clone();
            post_alonzo(&mut spent).address = byron_address_at(bootstrap_root(&[9; 32], address));
            let mut changed = tx.clone();
            change_sub(&mut changed, |sub| {
                add_bootstrap(
                    &mut sub.transaction_witness_set,
                    bootstrap_with(body.as_ref(), &[9; 32], &[0xbf, 0xff]),
                );
            });
            sign(&mut changed);
            let result = run_sub(&changed, &input, &spent);
            match expected {
                None => assert!(result.is_ok(), "{result:?}"),
                Some(e) => error(result, e),
            }
        }
    });
}

/// The CRC-32 a Byron address checks its payload with.
fn crc32(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(!0u32, |crc, byte| {
        (0..8).fold(crc ^ u32::from(*byte), |c, _| {
            (c >> 1) ^ (0xedb8_8320 & (c & 1).wrapping_neg())
        })
    })
}
/// A Byron address whose attributes are `entries`, each key with its value bytes.
fn byron_address_attributed(entries: &[(u8, Vec<u8>)]) -> pallas_codec::utils::Bytes {
    let mut e = minicbor::Encoder::new(vec![]);
    e.array(3).unwrap().bytes(&[0; 28]).unwrap();
    e.map(entries.len() as u64).unwrap();
    for (key, value) in entries {
        e.u8(*key).unwrap().bytes(value).unwrap();
    }
    e.u8(0).unwrap();
    let payload = e.into_writer();
    pallas_addresses::byron::ByronAddress::new(&payload, crc32(&payload))
        .to_vec()
        .into()
}

#[test]
fn dijkstra_byron_test_addresses_carry_their_checksum() {
    let address = pallas_addresses::byron::ByronAddress::from_bytes(&byron_address()).unwrap();
    assert_eq!(crc32(&address.payload.0), address.crc);
}

#[test]
fn dijkstra_outputs_may_pay_byron_addresses() {
    let magic = minicbor::to_vec(42u32).unwrap();
    let path = |n: usize| minicbor::to_vec(minicbor::bytes::ByteVec::from(vec![0; n])).unwrap();
    let too_large = Some("DijkstraBootstrapAttributesTooLarge");
    let cases = [
        (vec![(2, magic.clone())], None),
        (vec![], Some("PostAlonzo(OutputWrongNetworkID)")),
        (vec![(1, path(64)), (2, magic.clone())], None),
        (vec![(1, path(65)), (2, magic.clone())], too_large),
        (vec![(2, magic.clone()), (7, vec![0; 64])], None),
        (vec![(2, magic.clone()), (7, vec![0; 65])], too_large),
    ];
    token_order_batch(|tx, input, sub_input| {
        for (entries, expected) in cases {
            let address = byron_address_attributed(&entries);
            let mut top = tx.clone();
            let mut outputs = top.transaction_body.outputs.clone().to_vec();
            post_alonzo(&mut outputs[0]).address = address.clone();
            top.transaction_body.outputs = MaybeIndefArray::Def(outputs);
            sign(&mut top);
            let mut sub = tx.clone();
            resign(&mut sub, |sub| {
                let mut outputs = sub.sub_transaction_body.outputs.clone().to_vec();
                let order = post_alonzo(&mut outputs[0]);
                order.address = address.clone();
                order.datum_option = None;
                sub.sub_transaction_body.outputs = MaybeIndefArray::Def(outputs);
            });
            for (level, changed) in [("top", top), ("sub", sub)] {
                let result = run_sub(&changed, &input, &sub_input);
                match expected {
                    None => assert!(result.is_ok(), "{level} {entries:?} {result:?}"),
                    Some(e) => error(result, e),
                }
            }
        }
    });
}

#[test]
fn dijkstra_key_guards_are_met_by_bootstrap_keys() {
    batch(|tx, input| {
        let root = bootstrap_root(&[9; 32], &[0xa0]);
        let guards = Some(n::Guards::AddrKeyhashes(
            n::NonEmptySet::from_vec(vec![guard_key(), root]).unwrap(),
        ));
        for witnessed in [false, true] {
            let mut changed = tx.clone();
            change_sub(&mut changed, |sub| {
                sub.sub_transaction_body.guards = guards.clone();
                sign_sub(sub);
                if witnessed {
                    let body = body_hash(&sub.sub_transaction_body);
                    add_bootstrap(&mut sub.transaction_witness_set, bootstrap(body.as_ref()));
                }
            });
            sign(&mut changed);
            let result = run(&changed, &input, &env());
            match witnessed {
                true => assert!(result.is_ok(), "sub {result:?}"),
                false => error(result, "PostAlonzo(VKWitnessMissing)"),
            }
            let mut changed = tx.clone();
            changed.transaction_body.guards = guards.clone();
            sign(&mut changed);
            if witnessed {
                let body = body_hash(&changed.transaction_body);
                add_bootstrap(
                    &mut changed.transaction_witness_set,
                    bootstrap(body.as_ref()),
                );
            }
            let result = run(&changed, &input, &env());
            match witnessed {
                true => assert!(result.is_ok(), "top {result:?}"),
                false => error(result, "PostAlonzo(VKWitnessMissing)"),
            }
        }
    });
}

#[test]
fn dijkstra_native_signatures_are_not_met_by_bootstrap_keys() {
    batch(|mut tx, input| {
        let policy = native(n::NativeScript::ScriptPubkey(bootstrap_root(
            &[9; 32],
            &[0xa0],
        )));
        let mut outputs = tx.transaction_body.outputs.clone().to_vec();
        let coin = MultiEraOutput::from_dijkstra(&outputs[0]).value().coin();
        let minted: n::Multiasset<n::NonZeroInt> = [(
            policy.original_hash(),
            [(b"token".to_vec().into(), 5.try_into().unwrap())]
                .into_iter()
                .collect(),
        )]
        .into_iter()
        .collect();
        post_alonzo(&mut outputs[0]).value = pallas_primitives::conway::Value::Multiasset(
            coin,
            [(
                policy.original_hash(),
                [(b"token".to_vec().into(), 5.try_into().unwrap())]
                    .into_iter()
                    .collect(),
            )]
            .into_iter()
            .collect(),
        );
        tx.transaction_body.outputs = MaybeIndefArray::Def(outputs);
        tx.transaction_body.mint = Some(minted);
        tx.transaction_witness_set.native_script = n::NonEmptySet::from_vec(vec![policy]);
        sign(&mut tx);
        let body = body_hash(&tx.transaction_body);
        add_bootstrap(&mut tx.transaction_witness_set, bootstrap(body.as_ref()));
        error(run(&tx, &input, &env()), "PostAlonzo(NativeScriptDenial)");
    });
}

#[test]
fn dijkstra_bootstrap_chain_codes_are_32_bytes() {
    batch(|tx, input| {
        for (length, expected) in [
            (31, Some("DijkstraMalformed(\"bootstrap witness\")")),
            (33, Some("DijkstraMalformed(\"bootstrap witness\")")),
            (32, None),
        ] {
            let mut changed = tx.clone();
            let body = body_hash(&changed.transaction_body);
            add_bootstrap(
                &mut changed.transaction_witness_set,
                bootstrap_with(body.as_ref(), &vec![9; length], &[0xa0]),
            );
            let result = run(&changed, &input, &env());
            match expected {
                None => assert!(result.is_ok(), "top {length} {result:?}"),
                Some(e) => error(result, e),
            }
            let mut changed = tx.clone();
            change_sub(&mut changed, |sub| {
                let body = body_hash(&sub.sub_transaction_body);
                add_bootstrap(
                    &mut sub.transaction_witness_set,
                    bootstrap_with(body.as_ref(), &vec![9; length], &[0xa0]),
                );
            });
            sign(&mut changed);
            let result = run(&changed, &input, &env());
            match expected {
                None => assert!(result.is_ok(), "sub {length} {result:?}"),
                Some(e) => error(result, e),
            }
        }
    });
}

/// A key witness over `hash` by the key with seed byte `seed`.
fn key_witness(seed: u8, hash: &[u8]) -> n::VKeyWitness {
    let key = SecretKey::from([seed; 32]);
    n::VKeyWitness {
        vkey: key.public_key().as_ref().to_vec().into(),
        signature: key.sign(hash).as_ref().to_vec().into(),
    }
}
/// Key and bootstrap witness sets over `body`, each with the verdict it should get.
fn witness_cases(body: &[u8]) -> Vec<(Vec<n::VKeyWitness>, Vec<n::BootstrapWitness>, &str)> {
    let signed = key_witness(71, body);
    let key = |vkey: usize, signature: usize| n::VKeyWitness {
        vkey: signed.vkey[..vkey].to_vec().into(),
        signature: signed.signature[..signature].to_vec().into(),
    };
    let byron = |public_key: usize, signature: usize| {
        let whole = bootstrap(body);
        n::BootstrapWitness {
            public_key: whole.public_key[..public_key].to_vec().into(),
            signature: whole.signature[..signature].to_vec().into(),
            ..whole
        }
    };
    vec![
        (
            vec![signed.clone(), key_witness(72, body)],
            vec![],
            "Ok(())",
        ),
        (
            vec![signed.clone(), key_witness(71, b"elsewhere")],
            vec![],
            "Err(PostAlonzo(VKWrongSignature))",
        ),
        (
            vec![signed.clone(), signed.clone()],
            vec![],
            "Err(DijkstraMalformed(\"duplicate key witnesses\"))",
        ),
        (
            vec![key(31, 64)],
            vec![],
            "Err(DijkstraMalformed(\"key witness\"))",
        ),
        (
            vec![key(32, 63)],
            vec![],
            "Err(DijkstraMalformed(\"key witness\"))",
        ),
        (
            vec![signed.clone()],
            vec![bootstrap(body), bootstrap_with(body, &[8; 32], &[0xa0])],
            "Ok(())",
        ),
        (
            vec![signed.clone()],
            vec![bootstrap(body), bootstrap(b"elsewhere")],
            "Err(DijkstraMalformed(\"duplicate bootstrap witnesses\"))",
        ),
        (
            vec![signed.clone()],
            vec![byron(31, 64)],
            "Err(DijkstraMalformed(\"bootstrap witness\"))",
        ),
        (
            vec![signed.clone()],
            vec![byron(32, 63)],
            "Err(DijkstraMalformed(\"bootstrap witness\"))",
        ),
    ]
}

#[test]
fn dijkstra_an_empty_guards_set_in_a_sub_is_no_guards() {
    batch(|tx, input| {
        let cases = [
            (
                &[0xf6][..],
                "Err(DijkstraUnsupported(\"subtransaction body fields\"))",
            ),
            (&[0x80], "Ok(())"),
            (&[0x9f, 0xff], "Ok(())"),
            (&[0xd9, 0x01, 0x02, 0x80], "Ok(())"),
        ];
        for (set, expected) in cases {
            let mut sub = tx.transaction_body.sub_transactions.as_ref().unwrap()[0].clone();
            sub.sub_transaction_body.guards = None;
            let mut raw = minicbor::to_vec(&sub.sub_transaction_body).unwrap();
            raw[0] += 1;
            raw.push(14);
            raw.extend_from_slice(set);
            sub.sub_transaction_body = minicbor::decode(&raw).unwrap();
            sign_sub(&mut sub);
            let mut changed = tx.clone();
            changed.transaction_body.sub_transactions = n::NonEmptySet::from_vec(vec![sub]);
            sign(&mut changed);
            assert_eq!(
                format!("{:?}", run(&changed, &input, &env())),
                expected,
                "{set:02x?}"
            );
        }
    });
}

#[test]
fn dijkstra_witnesses_the_node_does_not_decode_are_malformed() {
    batch(|tx, input| {
        let top = body_hash(&tx.transaction_body);
        for (i, (keys, bootstraps, expected)) in witness_cases(top.as_ref()).into_iter().enumerate()
        {
            let mut changed = tx.clone();
            changed.transaction_witness_set.vkeywitness = n::NonEmptySet::from_vec(keys);
            changed.transaction_witness_set.bootstrap_witness =
                n::NonEmptySet::from_vec(bootstraps);
            let result = run(&changed, &input, &env());
            assert_eq!(format!("{result:?}"), expected, "top case {i}");
        }
        let sub = tx.transaction_body.sub_transactions.as_ref().unwrap()[0].clone();
        let sub = body_hash(&sub.sub_transaction_body);
        for (i, (keys, bootstraps, expected)) in witness_cases(sub.as_ref()).into_iter().enumerate()
        {
            let mut changed = tx.clone();
            change_sub(&mut changed, |sub| {
                sub.transaction_witness_set.vkeywitness = n::NonEmptySet::from_vec(keys);
                sub.transaction_witness_set.bootstrap_witness =
                    n::NonEmptySet::from_vec(bootstraps);
            });
            sign(&mut changed);
            let result = run(&changed, &input, &env());
            assert_eq!(format!("{result:?}"), expected, "sub case {i}");
        }
    });
}

#[test]
fn dijkstra_fields_the_node_does_not_decode_are_malformed() {
    batch(|tx, input| {
        let outcome =
            |changed: &n::BlockTransaction<'_>| format!("{:?}", run(changed, &input, &env()));
        let malformed = |label: &str| format!("Err(DijkstraMalformed({label:?}))");
        let key = guard_key();
        let other = Hasher::<224>::hash(SecretKey::from([72; 32]).public_key().as_ref());
        let guards = |keys: Vec<Hash<28>>| {
            Some(n::Guards::AddrKeyhashes(
                n::NonEmptySet::from_vec(keys).unwrap(),
            ))
        };
        let mut changed = tx.clone();
        changed.transaction_body.guards = guards(vec![key, other]);
        let body = body_hash(&changed.transaction_body);
        changed.transaction_witness_set.vkeywitness = n::NonEmptySet::from_vec(vec![
            key_witness(71, body.as_ref()),
            key_witness(72, body.as_ref()),
        ]);
        assert_eq!(outcome(&changed), "Ok(())");
        changed.transaction_body.guards = guards(vec![key, key]);
        sign(&mut changed);
        assert_eq!(outcome(&changed), malformed("duplicate guards"));
        let mut changed = tx.clone();
        change_sub(&mut changed, |sub| {
            sub.sub_transaction_body.guards = guards(vec![key, key]);
            sign_sub(sub);
        });
        sign(&mut changed);
        assert_eq!(outcome(&changed), malformed("duplicate guards"));

        let mut changed = tx.clone();
        changed.transaction_body.required_top_level_guards = Some(Default::default());
        sign(&mut changed);
        assert_eq!(
            outcome(&changed),
            malformed("empty required top-level guards")
        );
        let mut changed = tx.clone();
        change_sub(&mut changed, |sub| {
            sub.sub_transaction_body.required_top_level_guards = Some(Default::default());
            sign_sub(sub);
        });
        sign(&mut changed);
        assert_eq!(
            outcome(&changed),
            malformed("empty required top-level guards")
        );

        let mut changed = tx.clone();
        changed.transaction_body.withdrawals = Some(Default::default());
        sign(&mut changed);
        assert_eq!(outcome(&changed), malformed("empty withdrawals"));

        let policy = |names: Vec<(Vec<u8>, i64)>| -> n::Multiasset<n::NonZeroInt> {
            [(
                key,
                names
                    .into_iter()
                    .map(|(name, quantity)| (name.into(), quantity.try_into().unwrap()))
                    .collect(),
            )]
            .into_iter()
            .collect()
        };
        for mint in [
            Default::default(),
            policy(vec![]),
            policy(vec![(vec![1; 33], 1)]),
        ] {
            let mut changed = tx.clone();
            changed.transaction_body.mint = Some(mint);
            sign(&mut changed);
            assert_eq!(outcome(&changed), malformed("multi-asset value"));
        }

        let redeemed = |redeemer: KeepRaw<'static, n::Redeemers>| {
            let mut changed = tx.clone();
            changed.transaction_witness_set.redeemer = Some(redeemer);
            outcome(&changed)
        };
        assert_eq!(
            redeemed(KeepRaw::from(n::Redeemers(Default::default()))),
            malformed("empty redeemers")
        );
        let limit = i64::MAX as u64;
        assert_eq!(
            redeemed(spend_redeemer(limit, limit)),
            redeemed(spend_redeemer(1, 1))
        );
        for (mem, steps) in [(limit + 1, 0), (0, limit + 1)] {
            assert_eq!(
                redeemed(spend_redeemer(mem, steps)),
                malformed("execution units")
            );
        }

        let datums = |raw: &'static [u8]| {
            let mut changed = tx.clone();
            changed.transaction_witness_set.plutus_data = Some(minicbor::decode(raw).unwrap());
            outcome(&changed)
        };
        // Zero written in one byte and in two bytes are different datums.
        assert_eq!(datums(&[0x82, 0x00, 0x18, 0x00]), datums(&[0x81, 0x00]));
        assert_eq!(datums(&[0x82, 0x00, 0x00]), malformed("duplicate datums"));
    });
}

#[test]
fn dijkstra_batch_top_level_mints_under_a_native_policy() {
    batch(|mut tx, input| {
        let policy = native(n::NativeScript::ScriptPubkey(guard_key()));
        let minted = |quantity: i64| -> n::Multiasset<n::NonZeroInt> {
            [(
                policy.original_hash(),
                [(b"token".to_vec().into(), quantity.try_into().unwrap())]
                    .into_iter()
                    .collect(),
            )]
            .into_iter()
            .collect()
        };
        let mut outputs = tx.transaction_body.outputs.clone().to_vec();
        let coin = MultiEraOutput::from_dijkstra(&outputs[0]).value().coin();
        post_alonzo(&mut outputs[0]).value = pallas_primitives::conway::Value::Multiasset(
            coin,
            [(
                policy.original_hash(),
                [(b"token".to_vec().into(), 5.try_into().unwrap())]
                    .into_iter()
                    .collect(),
            )]
            .into_iter()
            .collect(),
        );
        tx.transaction_body.outputs = MaybeIndefArray::Def(outputs);
        tx.transaction_body.mint = Some(minted(5));
        tx.transaction_witness_set.native_script = n::NonEmptySet::from_vec(vec![policy.clone()]);
        sign(&mut tx);
        let result = run(&tx, &input, &env());
        assert!(result.is_ok(), "{result:?}");
        tx.transaction_body.mint = Some(minted(6));
        sign(&mut tx);
        error(run(&tx, &input, &env()), "PostAlonzo(PreservationOfValue)");
    });
}

#[test]
fn dijkstra_batch_sub_mints_under_a_native_policy() {
    batch(|tx, input| {
        let minting =
            |policy: &KeepRaw<'static, n::NativeScript>, quantity: i64, witnessed: bool| {
                let hash = policy.original_hash();
                let assets = |quantity: i64| -> n::Multiasset<n::NonZeroInt> {
                    [(
                        hash,
                        [(b"token".to_vec().into(), quantity.try_into().unwrap())]
                            .into_iter()
                            .collect(),
                    )]
                    .into_iter()
                    .collect()
                };
                let mut changed = tx.clone();
                let mut outputs = changed.transaction_body.outputs.clone().to_vec();
                let coin = MultiEraOutput::from_dijkstra(&outputs[0]).value().coin();
                post_alonzo(&mut outputs[0]).value = pallas_primitives::conway::Value::Multiasset(
                    coin,
                    [(
                        hash,
                        [(b"token".to_vec().into(), 5.try_into().unwrap())]
                            .into_iter()
                            .collect(),
                    )]
                    .into_iter()
                    .collect(),
                );
                changed.transaction_body.outputs = MaybeIndefArray::Def(outputs);
                resign(&mut changed, |sub| {
                    sub.sub_transaction_body.mint = Some(assets(quantity));
                    if witnessed {
                        sub.transaction_witness_set.native_script =
                            n::NonEmptySet::from_vec(vec![policy.clone()]);
                    }
                });
                run(&changed, &input, &env())
            };
        let policy = native(n::NativeScript::ScriptPubkey(guard_key()));
        let result = minting(&policy, 5, true);
        assert!(result.is_ok(), "{result:?}");
        error(
            minting(&policy, 5, false),
            "PostAlonzo(ScriptWitnessMissing)",
        );
        error(minting(&policy, 6, true), "PostAlonzo(PreservationOfValue)");
        let other = native(n::NativeScript::ScriptPubkey([9; 28].into()));
        error(minting(&other, 5, true), "PostAlonzo(NativeScriptDenial)");
    });
}

#[test]
fn dijkstra_batch_sub_tokens_balance_across_the_batch() {
    token_order_batch(|tx, input, sub_input| {
        // The sub spends 8 tokens but the batch pays out only 7.
        let mut more = sub_input;
        let coin = MultiEraOutput::from_dijkstra(&more).value().coin();
        post_alonzo(&mut more).value = tokens(coin, 8);
        error(
            run_sub(&tx, &input, &more),
            "PostAlonzo(PreservationOfValue)",
        );
    });
}

fn key(seed: u8) -> Hash<28> {
    Hasher::<224>::hash(SecretKey::from([seed; 32]).public_key().as_ref())
}
/// Adds a signature by the key with `seed` over `body` to `witnesses`.
fn cosign(witnesses: &mut n::WitnessSet<'_>, seed: u8, body: Hash<32>) {
    let key = SecretKey::from([seed; 32]);
    let mut all: Vec<_> = witnesses
        .vkeywitness
        .iter()
        .flat_map(|x| x.iter().cloned())
        .collect();
    all.push(n::VKeyWitness {
        vkey: key.public_key().as_ref().to_vec().into(),
        signature: key.sign(body).as_ref().to_vec().into(),
    });
    witnesses.vkeywitness = n::NonEmptySet::from_vec(all);
}
/// A UTxO at `[7; 32]#0` holding `script` as a reference script.
fn reference_holder<'a>(
    input: &n::TransactionOutput<'a>,
    script: KeepRaw<'static, n::NativeScript>,
) -> (n::TransactionInput, n::TransactionOutput<'a>) {
    let mut holder = input.clone();
    post_alonzo(&mut holder).script_ref = Some(CborWrap(n::ScriptRef::NativeScript(script)));
    let reference = n::TransactionInput {
        transaction_id: [7; 32].into(),
        index: 0,
    };
    (reference, holder)
}

#[test]
fn dijkstra_batch_sub_native_scripts_see_only_the_sub_signatures() {
    token_order_batch(|tx, input, sub_input| {
        let script = native(n::NativeScript::ScriptPubkey(key(72)));
        let mut spent = sub_input;
        post_alonzo(&mut spent).address = locked(script.original_hash());
        let mut changed = tx.clone();
        resign(&mut changed, |sub| {
            sub.transaction_witness_set.native_script =
                n::NonEmptySet::from_vec(vec![script.clone()]);
        });
        let top = body_hash(&changed.transaction_body);
        cosign(&mut changed.transaction_witness_set, 72, top);
        // Key 72 signs the top level only.
        error(
            run_sub(&changed, &input, &spent),
            "PostAlonzo(NativeScriptDenial)",
        );
        change_sub(&mut changed, |sub| {
            let body = body_hash(&sub.sub_transaction_body);
            cosign(&mut sub.transaction_witness_set, 72, body);
        });
        sign(&mut changed);
        let result = run_sub(&changed, &input, &spent);
        assert!(result.is_ok(), "{result:?}");
    });
}

#[test]
fn dijkstra_batch_scripts_may_be_provided_at_the_other_level() {
    token_order_batch(|tx, input, sub_input| {
        let script = native(n::NativeScript::ScriptPubkey(guard_key()));
        // The sub needs the script; the top level provides it.
        let mut spent = sub_input.clone();
        post_alonzo(&mut spent).address = locked(script.original_hash());
        let mut changed = tx.clone();
        changed.transaction_witness_set.native_script =
            n::NonEmptySet::from_vec(vec![script.clone()]);
        sign(&mut changed);
        let result = run_sub(&changed, &input, &spent);
        assert!(result.is_ok(), "{result:?}");
        // The top level needs the script; the sub provides it.
        let mut top_input = input.clone();
        post_alonzo(&mut top_input).address = locked(script.original_hash());
        let mut changed = tx.clone();
        resign(&mut changed, |sub| {
            sub.transaction_witness_set.native_script =
                n::NonEmptySet::from_vec(vec![script.clone()]);
        });
        let result = run_sub(&changed, &top_input, &sub_input);
        assert!(result.is_ok(), "{result:?}");
    });
}

#[test]
fn dijkstra_batch_top_level_withdraws_under_a_native_script() {
    batch(|mut tx, input| {
        let script = native(n::NativeScript::ScriptPubkey(guard_key()));
        let hash = script.original_hash();
        let mut reward = vec![0xf0];
        reward.extend(hash.as_ref());
        tx.transaction_body.withdrawals = Some(std::collections::BTreeMap::from([(
            reward.into(),
            1_000_000,
        )]));
        let mut outputs = tx.transaction_body.outputs.clone().to_vec();
        let n::Value::Coin(ref mut coin) = post_alonzo(&mut outputs[0]).value else {
            unreachable!()
        };
        *coin += 1_000_000;
        tx.transaction_body.outputs = MaybeIndefArray::Def(outputs);
        tx.transaction_witness_set.native_script = n::NonEmptySet::from_vec(vec![script]);
        sign(&mut tx);
        for (balance, expected) in [
            (2_000_000, None),
            (
                500_000,
                Some("DijkstraInvalidWithdrawal(\"amount exceeds the original balance\")"),
            ),
        ] {
            let mut state = CertState::default();
            state.dijkstra.accounts.insert(
                n::StakeCredential::ScriptHash(hash),
                Some(DijkstraAccount {
                    balance,
                    deposit: 2_000_000,
                }),
            );
            let result = run_full(&tx, &input, &input, &[], &env(), &mut state);
            match expected {
                None => assert!(result.is_ok(), "{result:?}"),
                Some(e) => error(result, e),
            }
        }
    });
}

#[test]
fn dijkstra_batch_inputs_may_have_pointer_and_bootstrap_addresses() {
    token_order_batch(|tx, input, sub_input| {
        let mut pointer = sub_input.clone();
        post_alonzo(&mut pointer).address = ShelleyAddress::new(
            Network::Testnet,
            ShelleyPaymentPart::Key(guard_key()),
            ShelleyDelegationPart::Pointer(pallas_addresses::Pointer::new(1, 2, 3)),
        )
        .to_vec()
        .into();
        let result = run_sub(&tx, &input, &pointer);
        assert!(result.is_ok(), "{result:?}");
        let mut byron = input.clone();
        post_alonzo(&mut byron).address = byron_address();
        error(
            run_sub(&tx, &byron, &sub_input),
            "PostAlonzo(VKWitnessMissing)",
        );
        let mut changed = tx.clone();
        changed.transaction_witness_set.bootstrap_witness =
            n::NonEmptySet::from_vec(vec![bootstrap(
                body_hash(&changed.transaction_body).as_ref(),
            )]);
        let result = run_sub(&changed, &byron, &sub_input);
        assert!(result.is_ok(), "{result:?}");
    });
}

#[test]
fn dijkstra_batch_sub_reference_scripts_leave_the_fee_unchanged() {
    token_order_batch(|tx, input, sub_input| {
        let (reference, holder) =
            reference_holder(&input, native(n::NativeScript::ScriptAll(vec![])));
        // A minimum fee equal to the fee the transaction pays, before reference scripts.
        let exact = |tx: &n::BlockTransaction<'_>| {
            let size = minicbor::to_vec(tx.to_mempool_transaction()).unwrap().len() as u64;
            let mut e = env();
            let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
                unreachable!()
            };
            pp.minfee_a = 1;
            pp.minfee_b = (tx.transaction_body.fee - size) as u32;
            e
        };
        let extra = [(reference.clone(), holder)];
        let mut referenced = tx.clone();
        resign(&mut referenced, |sub| {
            sub.sub_transaction_body.reference_inputs =
                n::NonEmptySet::from_vec(vec![reference.clone()]);
        });
        let e = exact(&referenced);
        let result = run_with(&referenced, &input, &sub_input, &extra, &e);
        assert!(result.is_ok(), "{result:?}");
        let mut top = tx.clone();
        top.transaction_body.reference_inputs = n::NonEmptySet::from_vec(vec![reference]);
        sign(&mut top);
        let e = exact(&top);
        error(
            run_with(&top, &input, &sub_input, &extra, &e),
            "PostAlonzo(FeeBelowMin)",
        );
    });
}

#[test]
fn dijkstra_min_fee_is_the_fee_validation_refuses_one_below() {
    token_order_batch(|tx, input, sub_input| {
        let (reference, holder) =
            reference_holder(&input, native(n::NativeScript::ScriptAll(vec![])));
        let extra = [(reference.clone(), holder)];
        let with_minfee_b = |b: u32| {
            let mut e = env();
            let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
                unreachable!()
            };
            pp.minfee_a = 1;
            pp.minfee_b = b;
            e
        };
        let min_fee = |tx: &n::BlockTransaction<'_>, e: &Environment| {
            let MultiEraProtocolParameters::Dijkstra(ref pp) = e.prot_params else {
                unreachable!()
            };
            let utxos = utxo_set(tx, &input, &sub_input, &extra);
            dijkstra::dijkstra_min_fee(tx, &utxos, pp).unwrap()
        };
        let size = |tx: &n::BlockTransaction<'_>| {
            minicbor::to_vec(tx.to_mempool_transaction()).unwrap().len() as u64
        };
        let mut referenced = tx.clone();
        resign(&mut referenced, |sub| {
            sub.sub_transaction_body.reference_inputs =
                n::NonEmptySet::from_vec(vec![reference.clone()]);
        });
        assert_eq!(min_fee(&referenced, &with_minfee_b(0)), size(&referenced));
        let mut top = tx.clone();
        top.transaction_body.reference_inputs = n::NonEmptySet::from_vec(vec![reference]);
        sign(&mut top);
        let unpaid = min_fee(&top, &with_minfee_b(0));
        assert!(unpaid > size(&top), "{unpaid} {}", size(&top));
        let e = with_minfee_b((top.transaction_body.fee - unpaid) as u32);
        assert_eq!(min_fee(&top, &e), top.transaction_body.fee);
        let result = run_with(&top, &input, &sub_input, &extra, &e);
        assert!(result.is_ok(), "{result:?}");
        let e = with_minfee_b((top.transaction_body.fee - unpaid + 1) as u32);
        error(
            run_with(&top, &input, &sub_input, &extra, &e),
            "PostAlonzo(FeeBelowMin)",
        );
    });
}

/// Redeemers declaring one spend of `mem` memory and no steps.
fn redeemers(mem: u64) -> KeepRaw<'static, n::Redeemers> {
    spend_redeemer(mem, 0)
}
/// Redeemers declaring one spend of `mem` memory and `steps` steps.
fn spend_redeemer(mem: u64, steps: u64) -> KeepRaw<'static, n::Redeemers> {
    let map = [(
        n::RedeemersKey {
            tag: n::RedeemerTag::Spend,
            index: 0,
        },
        n::RedeemersValue {
            data: n::PlutusData::BigInt(n::BigInt::Int(0.into())),
            ex_units: pallas_primitives::ExUnits { mem, steps },
        },
    )]
    .into_iter()
    .collect::<std::collections::BTreeMap<_, _>>();
    KeepRaw::from(n::Redeemers(map))
}

#[test]
fn dijkstra_min_fee_prices_the_redeemers_of_every_level_once() {
    batch(|tx, input| {
        let mut e = env();
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.minfee_a = 0;
        pp.minfee_b = 0;
        pp.execution_costs.mem_price = pallas_primitives::RationalNumber {
            numerator: 1,
            denominator: 2,
        };
        // At half a lovelace per memory unit, two redeemers of one unit cost 1 priced together
        // and 2 priced one level at a time.
        for (top, sub, expected) in [(None, Some(3), 2), (Some(1), Some(1), 1)] {
            let mut changed = tx.clone();
            changed.transaction_witness_set.redeemer = top.map(redeemers);
            change_sub(&mut changed, |sub_tx| {
                sub_tx.transaction_witness_set.redeemer = sub.map(redeemers);
            });
            let original = changed.transaction_body.inputs[0].clone();
            let utxos = [(owned(original), MultiEraOutput::from_dijkstra(&input))]
                .into_iter()
                .collect();
            assert_eq!(
                dijkstra::dijkstra_min_fee(&changed, &utxos, pp).unwrap(),
                expected,
                "{top:?} {sub:?}"
            );
        }
    });
}

#[test]
fn dijkstra_batch_sub_reference_inputs_are_distinct_and_counted_once() {
    token_order_batch(|tx, input, sub_input| {
        let (reference, holder) =
            reference_holder(&input, native(n::NativeScript::ScriptAll(vec![])));
        let mut changed = tx.clone();
        resign(&mut changed, |sub| {
            sub.sub_transaction_body.reference_inputs =
                n::NonEmptySet::from_vec(vec![reference.clone(), reference.clone()]);
        });
        error(
            run_with(&changed, &input, &sub_input, &[(reference, holder)], &env()),
            "DijkstraUnsupported(\"duplicate reference inputs\")",
        );
        // The sub spends and references the same UTxO; its script counts once.
        let script = native(n::NativeScript::ScriptAll(vec![]));
        let mut spent = sub_input;
        post_alonzo(&mut spent).script_ref =
            Some(CborWrap(n::ScriptRef::NativeScript(script.clone())));
        let mut changed = tx.clone();
        resign(&mut changed, |sub| {
            sub.sub_transaction_body.reference_inputs =
                n::NonEmptySet::from_vec(vec![sub.sub_transaction_body.inputs[0].clone()]);
        });
        let mut e = env();
        let MultiEraProtocolParameters::Dijkstra(ref mut pp) = e.prot_params else {
            unreachable!()
        };
        pp.max_ref_script_size_per_tx = minicbor::to_vec(&*script).unwrap().len() as u32;
        let result = run_with(&changed, &input, &spent, &[], &e);
        assert!(result.is_ok(), "{result:?}");
    });
}

#[test]
fn dijkstra_batch_sub_guard_scripts_are_needed() {
    token_order_batch(|tx, input, sub_input| {
        let signed = native(n::NativeScript::ScriptPubkey(guard_key()));
        let denied = native(n::NativeScript::ScriptPubkey([9; 28].into()));
        let guarded = |script: Option<&KeepRaw<'static, n::NativeScript>>,
                       witness: Option<&KeepRaw<'static, n::NativeScript>>| {
            let mut changed = tx.clone();
            resign(&mut changed, |sub| {
                let mut guards = vec![n::StakeCredential::AddrKeyhash(guard_key())];
                guards.extend(script.map(|x| n::StakeCredential::ScriptHash(x.original_hash())));
                sub.sub_transaction_body.guards = Some(n::Guards::Credentials(
                    n::NonEmptySet::from_vec(guards).unwrap(),
                ));
                sub.transaction_witness_set.native_script =
                    witness.and_then(|x| n::NonEmptySet::from_vec(vec![x.clone()]));
            });
            changed
        };
        let result = run_sub(&guarded(Some(&signed), Some(&signed)), &input, &sub_input);
        assert!(result.is_ok(), "{result:?}");
        error(
            run_sub(&guarded(None, Some(&signed)), &input, &sub_input),
            "PostAlonzo(UnneededNativeScript)",
        );
        error(
            run_sub(&guarded(Some(&signed), None), &input, &sub_input),
            "PostAlonzo(ScriptWitnessMissing)",
        );
        error(
            run_sub(&guarded(Some(&denied), Some(&denied)), &input, &sub_input),
            "PostAlonzo(NativeScriptDenial)",
        );
    });
}

#[test]
fn dijkstra_batch_sub_native_guards_read_the_sub_guards() {
    token_order_batch(|tx, input, sub_input| {
        let key = n::StakeCredential::AddrKeyhash(guard_key());
        let first = native(n::NativeScript::ScriptRequireGuard(key.clone()));
        let named = n::StakeCredential::ScriptHash(first.original_hash());
        let second = native(n::NativeScript::ScriptRequireGuard(named.clone()));
        let mut spent = sub_input.clone();
        post_alonzo(&mut spent).address = locked(second.original_hash());
        let guarded = |guards: Vec<n::StakeCredential>,
                       witnesses: Vec<KeepRaw<'static, n::NativeScript>>| {
            let mut changed = tx.clone();
            resign(&mut changed, |sub| {
                sub.sub_transaction_body.guards = Some(n::Guards::Credentials(
                    n::NonEmptySet::from_vec(guards).unwrap(),
                ));
                sub.transaction_witness_set.native_script = n::NonEmptySet::from_vec(witnesses);
            });
            changed
        };
        let result = run_sub(
            &guarded(
                vec![named.clone(), key.clone()],
                vec![first.clone(), second.clone()],
            ),
            &input,
            &spent,
        );
        assert!(result.is_ok(), "{result:?}");
        error(
            run_sub(
                &guarded(vec![key.clone()], vec![second.clone()]),
                &input,
                &spent,
            ),
            "PostAlonzo(NativeScriptDenial)",
        );
    });
}

#[test]
fn dijkstra_batch_unused_guard_scripts_are_not_checked() {
    token_order_batch(|tx, input, sub_input| {
        let guarded = native(n::NativeScript::ScriptRequireGuard(
            n::StakeCredential::AddrKeyhash([1; 28].into()),
        ));
        let (reference, holder) = reference_holder(&input, guarded);
        let mut changed = tx.clone();
        resign(&mut changed, |sub| {
            sub.sub_transaction_body.reference_inputs =
                n::NonEmptySet::from_vec(vec![reference.clone()]);
        });
        let result = run_with(&changed, &input, &sub_input, &[(reference, holder)], &env());
        assert!(result.is_ok(), "{result:?}");
    });
}

#[test]
fn dijkstra_batch_rejects_duplicate_required_top_level_guards() {
    batch(|tx, input| {
        // The sub's required top-level guards hold one key with no datum. The
        // duplicate is either the same bytes or the same credential with its
        // constructor written as a two-byte integer.
        let entry = |constructor: &[u8]| {
            let mut entry = [&[0x82][..], constructor, &[0x58, 0x1c]].concat();
            entry.extend(guard_key().as_ref());
            entry.push(0xf6);
            entry
        };
        let single = [&[0x18, 0x18, 0xa1][..], &entry(&[0x00])].concat();
        for duplicate in [entry(&[0x00]), entry(&[0x18, 0x00])] {
            let double = [&[0x18, 0x18, 0xa2][..], &entry(&[0x00]), &duplicate].concat();
            let mut raw = minicbor::to_vec(&tx).unwrap();
            let at = raw.windows(single.len()).position(|w| w == single).unwrap();
            raw.splice(at..at + single.len(), double);
            let patched: n::BlockTransaction = minicbor::decode(&raw).unwrap();
            error(
                run(&patched, &input, &env()),
                "DijkstraMalformed(\"duplicate required top-level guards\")",
            );
        }
    });
}

#[test]
fn dijkstra_batch_required_script_guard_needs_a_datum() {
    batch(|mut tx, input| {
        let script = native(n::NativeScript::ScriptAll(vec![]));
        let guard = n::StakeCredential::ScriptHash(script.original_hash());
        tx.transaction_body.guards = Some(n::Guards::Credentials(
            n::NonEmptySet::from_vec(vec![
                n::StakeCredential::AddrKeyhash(guard_key()),
                guard.clone(),
            ])
            .unwrap(),
        ));
        tx.transaction_witness_set.native_script = n::NonEmptySet::from_vec(vec![script]);
        sign(&mut tx);
        let result = run(&tx, &input, &env());
        assert!(result.is_ok(), "{result:?}");
        let mut changed = tx.clone();
        resign(&mut changed, |sub| {
            sub.sub_transaction_body
                .required_top_level_guards
                .as_mut()
                .unwrap()
                .insert(guard.clone(), Nullable::Null);
        });
        error(run(&changed, &input, &env()), "DijkstraGuardWithoutDatum");
        let mut changed = tx.clone();
        changed.transaction_body.required_top_level_guards =
            Some([(guard.clone(), Nullable::Null)].into_iter().collect());
        sign(&mut changed);
        error(run(&changed, &input, &env()), "DijkstraGuardWithoutDatum");
    });
}
