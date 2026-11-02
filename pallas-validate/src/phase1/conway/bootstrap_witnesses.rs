//! Bootstrap witnesses as the keys they provide to Conway witness checks.
use super::*;
use pallas_addresses::byron::{AddrType, SpendingData};
use pallas_codec::minicbor;
use pallas_crypto::key::ed25519::SecretKey;
use pallas_traverse::Era;

fn input() -> TransactionInput {
    TransactionInput {
        transaction_id: Hash::new([0; 32]),
        index: 0,
    }
}

fn spending_input(prepare: impl FnOnce(&mut Tx<'_>)) -> Vec<u8> {
    let mut raw = vec![0x84, 0xa3, 0x00, 0x81, 0x82, 0x58, 0x20]; // transaction, body, one input
    raw.extend([0; 32]);
    raw.extend([0x00, 0x01, 0x80, 0x02, 0x00]); // no outputs, no fee
    raw.extend([0xa0, 0xf5, 0xf6]); // no witnesses, valid, no auxiliary data
    let mut tx: Tx = minicbor::decode(&raw).unwrap();
    prepare(&mut tx);
    minicbor::to_vec(tx).unwrap()
}

fn witness(attributes: &[u8], signed: &[u8]) -> BootstrapWitness {
    let key = SecretKey::from([7; 32]);
    BootstrapWitness {
        public_key: key.public_key().as_ref().to_vec().into(),
        signature: key.sign(signed).as_ref().to_vec().into(),
        chain_code: vec![9; 32].into(),
        attributes: attributes.to_vec().into(),
    }
}

fn root(attributes: &[u8]) -> AddressId {
    let key = SecretKey::from([7; 32]);
    AddressPayload::hash_address_id_preimage(
        &[
            &BOOTSTRAP_ROOT_HEADER[..],
            key.public_key().as_ref(),
            &[9; 32],
            attributes,
        ]
        .concat(),
    )
}

fn byron_utxo(root: AddressId) -> Vec<u8> {
    let address = ByronAddress::from(AddressPayload {
        root,
        attributes: vec![].into(),
        addrtype: AddrType::PubKey,
    });
    minicbor::to_vec(pallas_primitives::alonzo::TransactionOutput {
        address: address.to_vec().into(),
        amount: babbage::Value::Coin(5_000_000),
        datum_hash: None,
    })
    .unwrap()
}

fn utxos(output: &[u8]) -> UTxOs<'_> {
    UTxOs::from([(
        MultiEraInput::AlonzoCompatible(Box::new(std::borrow::Cow::Owned(input()))),
        MultiEraOutput::decode(Era::Alonzo, output).unwrap(),
    )])
}

fn with_bootstrap(tx: &mut Tx<'_>, witnesses: Vec<BootstrapWitness>) {
    tx.transaction_witness_set.bootstrap_witness = witnesses.try_into().ok();
}

#[test]
fn the_canonical_root_header_is_the_encoded_key_spending_data() {
    let key = SecretKey::from([7; 32]);
    let xpub = [key.public_key().as_ref(), &[9; 32][..]].concat();
    let payload = AddressPayload::new(
        AddrType::PubKey,
        SpendingData::PubKey(xpub.into()),
        vec![].into(),
    );
    assert_eq!(payload.root, root(&[0xa0]));
}

#[test]
fn a_byron_input_is_witnessed_by_the_attribute_bytes_as_sent() {
    for (sent, address, expected) in [
        (
            &[0xbf, 0xff][..],
            &[0xa0][..],
            "Err(PostAlonzo(VKWitnessMissing))",
        ),
        (&[0xa0][..], &[0xa0][..], "Ok(())"),
        (&[0xbf, 0xff][..], &[0xbf, 0xff][..], "Ok(())"),
        (&[0x01][..], &[0x01][..], "Ok(())"),
    ] {
        let raw = spending_input(|_| {});
        let mut tx: Tx = minicbor::decode(&raw).unwrap();
        let hash = tx.transaction_body.original_hash();
        with_bootstrap(&mut tx, vec![witness(sent, hash.as_ref())]);
        let output = byron_utxo(root(address));
        assert_eq!(
            format!("{:?}", check_witness_set(&tx, &utxos(&output))),
            expected,
            "{sent:02x?}"
        );
    }
}

#[test]
fn a_required_signer_is_met_by_a_bootstrap_key() {
    let output = byron_utxo(root(&[0xa0]));
    let utxos = utxos(&output);
    for (signer, signs, expected) in [
        ([1; 28].into(), true, "Err(PostAlonzo(ReqSignerMissing))"),
        (root(&[0xa0]), false, "Err(PostAlonzo(ReqSignerWrongSig))"),
        (root(&[0xa0]), true, "Ok(())"),
    ] {
        let raw = spending_input(|tx| {
            tx.transaction_body.required_signers = vec![signer].try_into().ok()
        });
        let mut tx: Tx = minicbor::decode(&raw).unwrap();
        let hash = tx.transaction_body.original_hash();
        let signed = if signs { hash } else { Hash::new([0; 32]) };
        with_bootstrap(&mut tx, vec![witness(&[0xa0], signed.as_ref())]);
        assert_eq!(
            format!("{:?}", check_witness_set(&tx, &utxos)),
            expected,
            "{signer}"
        );
    }
}
