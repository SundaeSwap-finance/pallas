//! Synthetic evaluator semantics, separate from the unchanged network capture.
use super::{error::Error, evaluator::eval_native_v3};
use amaru_uplc_native::{arena::Arena, flat, syn::parse_program};
use pallas_codec::minicbor;
use pallas_primitives::{PlutusData, conway::ExUnits};

fn evaluate(body: &str) -> Result<super::evaluator::ScriptEvalResult, Error> {
    let arena = Arena::new();
    let source = format!("(program 1.1.0 (lam ctx {body}))");
    let program = parse_program(&arena, &source, amaru_kernel::ProtocolVersion::new(12, 0))
        .into_result()
        .expect(&source);
    let bytes = minicbor::to_vec(minicbor::bytes::ByteVec::from(
        flat::encode(program).unwrap(),
    ))
    .unwrap();
    let params: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test_data/musashi-phase1/registration-epoch64-parameters.json"
    ))
    .unwrap();
    let costs: Vec<i64> =
        serde_json::from_value(params["cost_models_raw"]["PlutusV3"].clone()).unwrap();
    eval_native_v3(
        &bytes,
        &PlutusData::Array(pallas_codec::utils::MaybeIndefArray::Def(vec![])),
        &costs,
        ExUnits {
            mem: 16_500_000,
            steps: 10_000_000_000,
        },
    )
}
fn ignore(body: &str) -> String {
    format!("[(lam ignored (con unit ())) {body}]")
}
fn grow_bytes(body: &str, rounds: usize) -> String {
    let mut body = body.to_owned();
    for _ in 0..rounds {
        body = format!("[(lam bytes {body}) [[(builtin appendByteString) bytes] bytes]]");
    }
    format!("[(lam bytes {body}) (con bytestring #00)]")
}

#[test]
fn registration_bytestring_bound_is_on_selected_operands_not_results() {
    for builtin in ["blake2b_256", "blake2b_224"] {
        for (rounds, success) in [(16, true), (17, false)] {
            let body = ignore(&grow_bytes(&format!("[(builtin {builtin}) bytes]"), rounds));
            let result = evaluate(&body).unwrap();
            assert_eq!(result.success, success, "{builtin}, {rounds}: {result:?}");
            if !success {
                assert!(
                    result
                        .failure
                        .unwrap()
                        .message
                        .contains("operand exceeds 65536")
                );
            }
        }
    }
    // An append can RETURN 131072 bytes; these consumers do not unlift
    // CByteString.
    for body in [
        "bytes",
        "[(builtin bData) bytes]",
        "[(builtin lengthOfByteString) bytes]",
    ] {
        assert!(evaluate(&ignore(&grow_bytes(body, 17))).unwrap().success);
    }
    // Exactly 65537, not just a power-of-two overshoot.
    let body = "[(builtin blake2b_256) [[(builtin consByteString) (con integer 0)] bytes]]";
    assert!(!evaluate(&ignore(&grow_bytes(body, 16))).unwrap().success);
}

#[test]
fn registration_checks_each_bounded_bytestring_argument() {
    for body in [
        "[[(builtin appendByteString) bytes] (con bytestring #)]",
        "[[(builtin appendByteString) (con bytestring #)] bytes]",
        "[[(builtin equalsByteString) bytes] (con bytestring #)]",
        "[[(builtin equalsByteString) (con bytestring #)] bytes]",
        "[[(builtin lessThanEqualsByteString) bytes] (con bytestring #)]",
        "[[(builtin lessThanEqualsByteString) (con bytestring #)] bytes]",
        "[[(builtin consByteString) (con integer 0)] bytes]",
        "[[[(builtin verifyEd25519Signature) (con bytestring #)] bytes] (con bytestring #)]",
    ] {
        let result = evaluate(&ignore(&grow_bytes(body, 17))).unwrap();
        assert!(!result.success, "{body}: {result:?}");
        assert!(
            result
                .failure
                .unwrap()
                .message
                .contains("operand exceeds 65536")
        );
    }
}

#[test]
fn registration_casing_selects_and_applies_builtin_fields() {
    for body in [
        "(case (con unit ()) (con unit ()))",
        "(case (con bool False) (con unit ()))",
        "(case (con bool True) (error) (con unit ()))",
        "(case (con integer 1) (error) (con unit ()))",
        "(case (con (list integer) []) (error) (con unit ()))",
        "(case (con (list integer) [1]) (lam head (lam tail (case head (error) (case tail (error) (con unit ()))))))",
        "(case (con (pair integer bool) (1, True)) (lam first (lam second (case first (error) (case second (error) (con unit ()))))))",
        "(case (constr 0 (con integer 1)) (lam field (case field (error) (con unit ()))))",
    ] {
        let result = evaluate(body).unwrap();
        assert!(result.success, "{body}: {result:?}");
    }
}

#[test]
fn registration_casing_rejects_wrong_arity_indices_and_types() {
    for body in [
        "(case (con unit ()))",
        "(case (con unit ()) (con unit ()) (con unit ()))",
        "(case (con bool True) (con unit ()))",
        "(case (con bool False) (con unit ()) (con unit ()) (con unit ()))",
        "(case (con integer -1) (con unit ()))",
        "(case (con integer 1) (con unit ()))",
        "(case (con (list integer) []) (lam a (lam b (con unit ()))))",
        "(case (con (list integer) [1]) (lam a (lam b (con unit ()))) (con unit ()) (con unit ()))",
        "(case (con (pair integer integer) (1, 2)) (lam a (lam b (con unit ()))) (con unit ()))",
        "(case (con bytestring #00) (con unit ()))",
    ] {
        assert!(!evaluate(body).unwrap().success, "{body}");
    }
}

#[test]
fn registration_constructor_tags_fail_without_panicking() {
    for (tag, success) in [
        ("0", true),
        ("18446744073709551615", true),
        ("-1", false),
        ("18446744073709551616", false),
    ] {
        let body = ignore(&format!(
            "[[(builtin constrData) (con integer {tag})] (con (list data) [])]"
        ));
        let result = evaluate(&body).unwrap();
        assert_eq!(result.success, success, "{tag}: {result:?}");
        if !success {
            assert!(result.failure.unwrap().message.contains("Word64"));
        }
    }
}

#[test]
fn registration_cons_byte_string_keeps_v3_byte_range() {
    for (value, success) in [(-1, false), (0, true), (255, true), (256, false)] {
        let result = evaluate(&ignore(&format!(
            "[[(builtin consByteString) (con integer {value})] (con bytestring #)]"
        )))
        .unwrap();
        assert_eq!(result.success, success, "{value}: {result:?}");
    }
}

#[test]
fn registration_integer_bounds_are_explicit_subset_errors() {
    use amaru_uplc_native::constant::Integer;
    let bound = Integer::from(1) << 262_143usize;
    for (value, supported) in [
        (&bound - 1, true),
        (-&bound, true),
        (bound.clone(), false),
        (-&bound - 1, false),
    ] {
        let body = ignore(&format!(
            "[[(builtin addInteger) (con integer {value})] (con integer 0)]"
        ));
        match evaluate(&body) {
            Ok(result) => assert!(supported && result.success, "unexpected acceptance"),
            Err(Error::DijkstraUnsupported(
                "integer operand outside audited registration range",
            )) => assert!(!supported),
            other => panic!("unexpected range result: {other:?}"),
        }
    }
    assert!(
        evaluate(&ignore(&format!("[(builtin iData) (con integer {bound})]")))
            .unwrap()
            .success
    );
}

#[test]
fn registration_builtin_case_matches_independent_cli_budget() {
    let result = evaluate("(case (con bool True) (error) (con unit ()))").unwrap();
    assert!(result.success);
    // cardano-cli 11.2.2.0, afa091b4..., offline native protocol-12 comparison.
    assert_eq!(
        result.units,
        ExUnits {
            mem: 700,
            steps: 96_100
        }
    );
}
