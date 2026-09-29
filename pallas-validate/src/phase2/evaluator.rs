use amaru_kernel::{PlutusVersion, ProtocolVersion};
use amaru_uplc::{
    arena::Arena,
    binder::DeBruijn,
    bumpalo::Bump,
    constant::Constant,
    data::PlutusData as PragmaPlutusData,
    flat,
    machine::{CostModel, ExBudget},
    program::Program,
    term::Term,
};
use pallas_codec::minicbor;
use pallas_primitives::conway::{ExUnits, Language, PlutusData};

use super::error::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MachineFailure {
    pub message: String,
    pub budget: ExUnits,
    pub logs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScriptEvalResult {
    pub success: bool,
    pub units: ExUnits,
    pub logs: Vec<String>,
    pub failure: Option<MachineFailure>,
}

pub(crate) fn eval_script(
    language: Language,
    script_bytes: &[u8],
    datum: Option<&PlutusData>,
    redeemer: &PlutusData,
    script_context: &PlutusData,
    protocol_version_major: u32,
) -> Result<ScriptEvalResult, Error> {
    let arena = Arena::from_bump(Bump::with_capacity(1_024_000));
    let plutus_version = map_language(&language);

    let flat_bytes: minicbor::bytes::ByteVec = minicbor::decode(script_bytes)?;

    let (program, remainder): (&Program<DeBruijn>, _) = flat::decode(
        &arena,
        &flat_bytes,
        ProtocolVersion::new(protocol_version_major.into(), 0),
    )?;
    if matches!(language, Language::PlutusV3) && remainder > 0 {
        return Err(amaru_uplc::flat::FlatDecodeError::TrailingBytes(remainder).into());
    }

    let datum_term = datum.map(|d| plutus_data_to_term(&arena, d));
    let redeemer_term = plutus_data_to_term(&arena, redeemer);
    let script_context_term = plutus_data_to_term(&arena, script_context);

    let program = match &language {
        Language::PlutusV1 | Language::PlutusV2 => {
            let program = if let Some(datum_term) = datum_term {
                program.apply(&arena, datum_term)
            } else {
                program
            };
            program
                .apply(&arena, redeemer_term)
                .apply(&arena, script_context_term)
        }
        Language::PlutusV3 => program.apply(&arena, script_context_term),
    };

    let costs = match plutus_version {
        PlutusVersion::V1 => CostModel::DEFAULT_V1.as_slice(),
        PlutusVersion::V2 => CostModel::DEFAULT_V2.as_slice(),
        PlutusVersion::V3 => CostModel::DEFAULT_V3.as_slice(),
    };
    let result = program.eval(
        &arena,
        CostModel::new(
            plutus_version,
            ProtocolVersion::new(protocol_version_major.into(), 0),
            costs,
        ),
        ExBudget::default(),
    );

    let units = budget_to_ex_units(result.info.consumed_budget);
    let logs = result.info.logs;

    let failure = result.term.as_ref().err().map(|err| MachineFailure {
        message: err.to_string(),
        budget: units,
        logs: logs.clone(),
    });

    let success = match (&result.term, &language) {
        (Ok(_), Language::PlutusV1 | Language::PlutusV2) => true,
        (Ok(term), Language::PlutusV3) => matches!(
            term,
            Term::Constant(constant) if matches!(**constant, Constant::Unit)
        ),
        (Err(_), _) => false,
    };

    Ok(ScriptEvalResult {
        success,
        units,
        logs,
        failure,
    })
}

fn plutus_data_to_term<'a>(arena: &'a Arena, data: &PlutusData) -> &'a Term<'a, DeBruijn> {
    // Bridge pallas PlutusData -> amaru-uplc PlutusData through CBOR. Both
    // sides implement the same Plutus data encoding; the upstream amaru node
    // uses this exact pattern. Vec writer is Infallible and the bytes are
    // fresh, so neither side can fail in practice.
    let bytes = minicbor::to_vec(data).expect("PlutusData encode");
    let pragma_data = PragmaPlutusData::from_cbor(arena, &bytes).expect("PlutusData decode");
    Term::data(arena, pragma_data)
}

fn budget_to_ex_units(budget: ExBudget) -> ExUnits {
    ExUnits {
        mem: budget.mem.max(0) as u64,
        steps: budget.cpu.max(0) as u64,
    }
}

fn map_language(language: &Language) -> PlutusVersion {
    match language {
        Language::PlutusV1 => PlutusVersion::V1,
        Language::PlutusV2 => PlutusVersion::V2,
        Language::PlutusV3 => PlutusVersion::V3,
    }
}

/// Evaluate only the documented protocol-12 native registration subset.
/// Pass all 350 coefficients unchanged to the local Amaru evaluator.
/// All builtins outside the registration subset reject statically.
#[cfg(feature = "unstable")]
pub(crate) fn eval_native_v3(
    script_bytes: &[u8],
    context: &PlutusData,
    costs: &[i64],
    budget: ExUnits,
) -> Result<ScriptEvalResult, Error> {
    use amaru_uplc::builtin::DefaultFunction as F;
    let arena = Arena::from_bump(Bump::with_capacity(1_024_000));
    let flat_bytes: minicbor::bytes::ByteVec = minicbor::decode(script_bytes)?;
    let (program, remainder): (&Program<DeBruijn>, _) =
        flat::decode(&arena, &flat_bytes, ProtocolVersion::new(12, 0))?;
    if remainder > 0 {
        return Err(amaru_uplc::flat::FlatDecodeError::TrailingBytes(remainder).into());
    }
    let mut pending = vec![program.term];
    while let Some(term) = pending.pop() {
        match term {
            Term::Builtin(f) => match f {
                F::AddInteger
                | F::AppendByteString
                | F::BData
                | F::Blake2b_224
                | F::Blake2b_256
                | F::ChooseData
                | F::ChooseList
                | F::ConsByteString
                | F::ConstrData
                | F::DivideInteger
                | F::EqualsByteString
                | F::EqualsData
                | F::EqualsInteger
                | F::FstPair
                | F::HeadList
                | F::IData
                | F::IfThenElse
                | F::LengthOfByteString
                | F::LessThanEqualsByteString
                | F::LessThanEqualsInteger
                | F::LessThanInteger
                | F::ListData
                | F::MapData
                | F::MkCons
                | F::MkPairData
                | F::ModInteger
                | F::SerialiseData
                | F::SndPair
                | F::TailList
                | F::UnBData
                | F::UnConstrData
                | F::UnIData
                | F::UnListData
                | F::UnMapData
                | F::VerifyEd25519Signature => (),
                _ => {
                    return Err(Error::DijkstraUnsupported(
                        "V3 builtin outside audited registration subset",
                    ));
                }
            },
            Term::Lambda { body, .. } | Term::Delay(body) | Term::Force(body) => pending.push(body),
            Term::Apply { function, argument } => {
                pending.push(function);
                pending.push(argument);
            }
            Term::Constr { fields, .. } => pending.extend(*fields),
            Term::Case { constr, branches } => {
                pending.push(constr);
                pending.extend(*branches);
            }
            Term::Var(_) | Term::Constant(_) | Term::Error => (),
        }
    }
    let initial = ExBudget {
        mem: i64::try_from(budget.mem)
            .map_err(|_| Error::DijkstraInvalid("memory budget overflow"))?,
        cpu: i64::try_from(budget.steps)
            .map_err(|_| Error::DijkstraInvalid("CPU budget overflow"))?,
    };
    let program = program.apply(&arena, plutus_data_to_term(&arena, context));
    let result = program.eval(
        &arena,
        CostModel::new(PlutusVersion::V3, ProtocolVersion::new(12, 0), costs),
        initial,
    );
    let units = budget_to_ex_units(result.info.consumed_budget);
    let logs = result.info.logs;
    let failure = result.term.as_ref().err().map(|err| MachineFailure {
        message: err.to_string(),
        budget: units,
        logs: logs.clone(),
    });
    let success = matches!(result.term, Ok(Term::Constant(c)) if matches!(**c, Constant::Unit))
        && units.mem <= budget.mem
        && units.steps <= budget.steps;
    Ok(ScriptEvalResult {
        success,
        units,
        logs,
        failure,
    })
}

#[cfg(test)]
mod tests {
    use amaru_uplc::{arena::Arena, flat, syn::parse_program};
    use pallas_codec::{minicbor, utils::Int};
    use pallas_primitives::{BigInt, PlutusScript};

    use crate::phase2::data::Data as LedgerData;

    use super::*;

    const PROTOCOL_VERSION_MAJOR: u32 = 9;

    fn zero_data() -> PlutusData {
        LedgerData::integer(BigInt::Int(Int::from(0i64)))
    }

    fn integer_data(value: i64) -> PlutusData {
        LedgerData::integer(BigInt::Int(Int::from(value)))
    }

    fn list_data(values: impl IntoIterator<Item = i64>) -> PlutusData {
        LedgerData::list(values.into_iter().map(integer_data).collect())
    }

    fn bytes_data(bytes: &[u8]) -> PlutusData {
        LedgerData::bytestring(bytes.to_vec())
    }

    fn script_cbor(source: &str) -> Vec<u8> {
        let arena = Arena::new();
        let program = parse_program(
            &arena,
            source,
            ProtocolVersion::new(PROTOCOL_VERSION_MAJOR.into(), 0),
        )
        .into_result()
        .expect("parse program");
        let flat_bytes = flat::encode(program).expect("flat encode");
        minicbor::to_vec(PlutusScript::<3>(flat_bytes.into())).expect("cbor encode script")
    }

    #[test]
    fn script_cbor_decode_failure_is_typed() {
        let err = eval_script(
            Language::PlutusV3,
            &[0x01],
            None,
            &zero_data(),
            &zero_data(),
            PROTOCOL_VERSION_MAJOR,
        )
        .unwrap_err();

        assert!(matches!(err, Error::DecodeError(_)), "got {err:?}");
    }

    #[test]
    fn flat_decode_failure_is_typed() {
        let script = minicbor::to_vec(PlutusScript::<3>(vec![0xff].into())).unwrap();

        let err = eval_script(
            Language::PlutusV3,
            &script,
            None,
            &zero_data(),
            &zero_data(),
            PROTOCOL_VERSION_MAJOR,
        )
        .unwrap_err();

        assert!(matches!(err, Error::FlatDecode(_)), "got {err:?}");
    }

    #[test]
    fn machine_failure_keeps_logs() {
        // Body: addInteger 1 (trace "phase2-log" ()).
        // Argument is evaluated first: trace fires, returns (). Then
        // addInteger 1 () fails with a type mismatch.
        let script = script_cbor(
            r#"(program 1.1.0
                (lam ctx
                  [[(builtin addInteger) (con integer 1)]
                   [[(force (builtin trace)) (con string "phase2-log")] (con unit ())]]))"#,
        );

        let result = eval_script(
            Language::PlutusV3,
            &script,
            None,
            &zero_data(),
            &zero_data(),
            PROTOCOL_VERSION_MAJOR,
        )
        .unwrap();

        assert!(!result.success, "{result:#?}");
        let failure = result.failure.expect("machine failure should be captured");
        assert!(
            failure.logs.iter().any(|x| x == "phase2-log"),
            "logs were {:?}",
            failure.logs
        );
        assert!(!failure.message.is_empty());
    }

    #[test]
    fn serialise_data_v3_script_evaluates_without_panic() {
        // Regression test: previous evaluator (txpipe uplc-turbo fork) panicked
        // on serialiseData for V3 scripts. This must complete without panicking
        // and yield a successful unit result.
        let script = script_cbor(
            r#"(program 1.1.0
                (lam ctx
                  [(lam discard (con unit ()))
                   [(builtin serialiseData) (con data (I 0))]]))"#,
        );

        let result = eval_script(
            Language::PlutusV3,
            &script,
            None,
            &zero_data(),
            &zero_data(),
            PROTOCOL_VERSION_MAJOR,
        )
        .unwrap();

        assert!(result.success, "{result:#?}");
        assert!(result.failure.is_none(), "{result:#?}");
    }

    #[test]
    fn plutus_v2_applies_datum_then_redeemer_then_context() {
        // 3-arg lambda: succeeds only when called with all three args, in
        // order datum -> redeemer -> context. The body unwraps each via
        // type-specific builtins so a wrong type for any slot fails.
        let script = script_cbor(
            r#"(program 1.0.0
                (lam d (lam r (lam c
                  [(lam di [(lam lr [(lam bc (con unit ())) [(builtin unBData) c]]) [(builtin unListData) r]]) [(builtin unIData) d]]))))"#,
        );

        let result = eval_script(
            Language::PlutusV2,
            &script,
            Some(&integer_data(1)),
            &list_data([2]),
            &bytes_data(&[3]),
            PROTOCOL_VERSION_MAJOR,
        )
        .unwrap();

        assert!(result.success, "{result:#?}");
        assert!(result.failure.is_none(), "{result:#?}");
    }

    #[test]
    fn plutus_v2_skips_missing_datum_and_applies_redeemer_then_context() {
        // 2-arg lambda: when datum is None, only redeemer + context are
        // applied.
        let script = script_cbor(
            r#"(program 1.0.0
                (lam r (lam c
                  [(lam lr [(lam bc (con unit ())) [(builtin unBData) c]]) [(builtin unListData) r]])))"#,
        );

        let result = eval_script(
            Language::PlutusV2,
            &script,
            None,
            &list_data([2]),
            &bytes_data(&[3]),
            PROTOCOL_VERSION_MAJOR,
        )
        .unwrap();

        assert!(result.success, "{result:#?}");
        assert!(result.failure.is_none(), "{result:#?}");
    }
}
