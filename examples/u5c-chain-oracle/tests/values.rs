use pallas_codec::minicbor;
use pallas_primitives::PlutusData;
use pallas_utxorpc::v1beta::spec::cardano as u5c;
use u5c_chain_oracle::mapper;
use u5c_chain_oracle::values::{Token, source_datum, u5c_datum};

fn decode(text: &str) -> PlutusData {
    minicbor::decode(&hex::decode(text).expect("hex")).expect("a datum")
}

fn source(text: &str) -> Vec<Token> {
    source_datum(&decode(text))
}

fn integer(x: u5c::big_int::BigInt) -> Vec<Token> {
    u5c_datum(&u5c::PlutusData {
        plutus_data: Some(u5c::plutus_data::PlutusData::BigInt(u5c::BigInt {
            big_int: Some(x),
        })),
    })
}

const TWO_TO_63: &str = "1b8000000000000000";

#[test]
fn an_integer_above_i64_matches_its_u5c_big_unsigned_form() {
    use u5c::big_int::BigInt as B;
    let n = vec![0x80, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(source(TWO_TO_63), integer(B::BigUInt(n.clone().into())));
    let mut padded = vec![0];
    padded.extend(n);
    assert_eq!(source(TWO_TO_63), integer(B::BigUInt(padded.into())));
}

#[test]
fn an_integer_above_i64_differs_from_a_u5c_int_cut_to_64_bits() {
    use u5c::big_int::BigInt as B;
    assert_ne!(source(TWO_TO_63), integer(B::Int(i64::MIN)));
}

#[test]
fn a_negative_integer_matches_its_u5c_int_and_big_negative_forms() {
    use u5c::big_int::BigInt as B;
    assert_eq!(source("20"), integer(B::Int(-1)));
    assert_eq!(source("20"), integer(B::BigNInt(vec![0].into())));
}

#[test]
fn integers_that_differ_only_in_sign_differ() {
    use u5c::big_int::BigInt as B;
    assert_ne!(source("20"), integer(B::Int(0)));
    assert_ne!(source("00"), integer(B::BigNInt(vec![].into())));
}

#[test]
fn a_nested_datum_matches_its_mapping_token_for_token() {
    let d = decode("d87982a10141ab80");
    assert_eq!(
        source_datum(&d),
        vec![
            Token::Constr {
                tag: 121,
                any_constructor: 0,
                fields: 2
            },
            Token::Map(1),
            Token::Integer {
                negative: false,
                n: vec![1]
            },
            Token::Bytes(vec![0xab]),
            Token::Array(0),
        ]
    );
    assert_eq!(source_datum(&d), u5c_datum(&mapper().map_plutus_datum(&d)));
}

#[test]
fn a_map_pair_with_key_and_value_swapped_differs() {
    use u5c::plutus_data::PlutusData as P;
    let d = decode("a10141ab");
    let mut mapped = mapper().map_plutus_datum(&d);
    let Some(P::Map(m)) = mapped.plutus_data.as_mut() else {
        panic!("a map, got {mapped:?}");
    };
    let pair = &mut m.pairs[0];
    std::mem::swap(&mut pair.key, &mut pair.value);
    assert_ne!(source_datum(&d), u5c_datum(&mapped));
}
