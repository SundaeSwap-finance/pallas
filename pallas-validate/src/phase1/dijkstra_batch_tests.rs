//! Synthetic script-free batches; the retained real Plutus batch remains unsupported.
use super::{
    dijkstra_tests::{env, error, sign, synthetic},
    *,
};
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
fn dijkstra_batch_validity_boundaries_and_unsupported_real_scripted_batch() {
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
    // This original capture also has top-level references/collateral for its
    // scripted sub. It is not evidence for positive key-only batch acceptance.
    error(
        validate_txs(&[tx], &env(), &UTxOs::new(), &mut CertState::default()),
        "DijkstraUnsupported(\"stateful or scripted subtransaction\")",
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
fn byron_address() -> pallas_codec::utils::Bytes {
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
fn bootstrap(signed: &[u8]) -> n::BootstrapWitness {
    let key = SecretKey::from([7; 32]);
    n::BootstrapWitness {
        public_key: key.public_key().as_ref().to_vec().into(),
        signature: key.sign(signed).as_ref().to_vec().into(),
        chain_code: vec![9; 32].into(),
        attributes: vec![0xa0].into(),
    }
}
fn body_hash<T: minicbor::Encode<()>>(body: &T) -> Hash<32> {
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
                Some(
                    "DijkstraInvalidWithdrawal(\"amount does not match available account balance\")",
                ),
            ),
        ] {
            let mut state = CertState::default();
            state
                .dijkstra_account_balances
                .insert(n::StakeCredential::ScriptHash(hash), Some(balance));
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
                "DijkstraUnsupported(\"duplicate required top-level guards\")",
            );
        }
    });
}
