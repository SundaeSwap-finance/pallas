//! Synthetic key-only batches; the retained real scripted batch remains unsupported.
use super::{
    dijkstra_tests::{env, error, sign, synthetic},
    *,
};
use pallas_addresses::{Network, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart};
use pallas_codec::{
    minicbor,
    utils::{MaybeIndefArray, Nullable},
};
use pallas_crypto::{hash::Hasher, key::ed25519::SecretKey};
use pallas_primitives::dijkstra as n;
use pallas_traverse::{MultiEraInput, MultiEraOutput};
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
    let original = tx.transaction_body.inputs[0].clone();
    let mut second = original.clone();
    second.index = 99;
    let utxos = [
        (owned(original), MultiEraOutput::from_dijkstra(input)),
        (owned(second), MultiEraOutput::from_dijkstra(sub_input)),
    ]
    .into_iter()
    .collect();
    validate_txs(
        &[MultiEraTx::from_dijkstra(tx)],
        &env(),
        &utxos,
        &mut CertState::default(),
    )
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
fn dijkstra_batch_sub_inputs_still_need_a_key_and_no_datum() {
    token_order_batch(|tx, input, sub_input| {
        let mut scripted = sub_input.clone();
        post_alonzo(&mut scripted).address = script_address();
        error(
            run_sub(&tx, &input, &scripted),
            "DijkstraUnsupported(\"script payment credential\")",
        );
        let mut with_datum = sub_input;
        post_alonzo(&mut with_datum).datum_option =
            Some(pallas_primitives::conway::DatumOption::Hash([0; 32].into()).into());
        error(
            run_sub(&tx, &input, &with_datum),
            "DijkstraUnsupported(\"output datum or reference script\")",
        );
    });
}
