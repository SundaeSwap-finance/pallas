//! Native Dijkstra evaluation with the protocol-aware backend.
use super::{
    error::Error,
    evaluator::{MachineFailure, ScriptEvalResult},
};
use amaru_kernel::{PlutusVersion, ProtocolVersion};
use amaru_uplc_native::{
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
use pallas_primitives::conway::{ExUnits, PlutusData};

/// Evaluate only the documented protocol-12 native registration subset.
/// Pass all 350 coefficients unchanged to the local Amaru evaluator.
/// All builtins outside the registration subset reject statically.
pub(crate) fn eval_native_v3(
    script_bytes: &[u8],
    context: &PlutusData,
    costs: &[i64],
    budget: ExUnits,
) -> Result<ScriptEvalResult, Error> {
    use amaru_uplc_native::builtin::DefaultFunction as F;
    let arena = Arena::from_bump(Bump::with_capacity(1_024_000));
    let flat_bytes: minicbor::bytes::ByteVec = minicbor::decode(script_bytes)?;
    let (program, remainder): (&Program<DeBruijn>, _) =
        flat::decode(&arena, &flat_bytes, ProtocolVersion::new(12, 0))?;
    if remainder > 0 {
        return Err(amaru_uplc_native::flat::FlatDecodeError::TrailingBytes(remainder).into());
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
    if matches!(
        result.term,
        Err(amaru_uplc_native::machine::MachineError::Runtime(
            amaru_uplc_native::machine::RuntimeError::IntegerOperandOutOfBounds
        ))
    ) {
        return Err(Error::DijkstraUnsupported(
            "integer operand outside audited registration range",
        ));
    }
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
