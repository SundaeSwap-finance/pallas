//! Synthetic key-only batches; the retained real scripted batch remains unsupported.
use super::{
    dijkstra_tests::{env, error, sign, synthetic},
    *,
};
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
        "DijkstraUnsupported(\"script fields without script registration\")",
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
