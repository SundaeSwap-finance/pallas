//! Native Dijkstra evaluation with the protocol-aware backend.
use super::{
    error::Error,
    evaluator::{MachineFailure, ScriptEvalResult},
};
use amaru_kernel::{PlutusVersion, ProtocolVersion};
use amaru_uplc_native::{
    arena::Arena,
    binder::DeBruijn,
    builtin::DefaultFunction,
    bumpalo::Bump,
    constant::Constant,
    data::PlutusData as PragmaPlutusData,
    flat,
    machine::{
        CostModel, EvalResult, ExBudget, Machine, MachineError, context::Context, env::Env,
        state::MachineState, value::Value,
    },
    program::Program,
    term::Term,
};
use pallas_codec::minicbor;
use pallas_primitives::conway::{ExUnits, PlutusData};

/// Evaluate a protocol 12 Plutus V3 script, refusing a call to a builtin outside the audited set.
pub(crate) fn eval_native_v3(
    script_bytes: &[u8],
    context: &PlutusData,
    costs: &[i64],
    budget: ExUnits,
) -> Result<ScriptEvalResult, Error> {
    let arena = Arena::from_bump(Bump::with_capacity(1_024_000));
    let flat_bytes: minicbor::bytes::ByteVec = minicbor::decode(script_bytes)?;
    let (program, remainder): (&Program<DeBruijn>, _) =
        flat::decode(&arena, &flat_bytes, ProtocolVersion::new(12, 0))?;
    check_program_version(program.version)?;
    if remainder > 0 {
        return Err(amaru_uplc_native::flat::FlatDecodeError::TrailingBytes(remainder).into());
    }
    let initial = ExBudget {
        mem: i64::try_from(budget.mem)
            .map_err(|_| Error::DijkstraInvalid("memory budget overflow"))?,
        cpu: i64::try_from(budget.steps)
            .map_err(|_| Error::DijkstraInvalid("CPU budget overflow"))?,
    };
    let program = program.apply(&arena, plutus_data_to_term(&arena, context));
    let result = run(
        &arena,
        program,
        CostModel::new(PlutusVersion::V3, ProtocolVersion::new(12, 0), costs),
        initial,
    )?;
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
    let mut failure = result.term.as_ref().err().map(|err| MachineFailure {
        message: err.to_string(),
        budget: units,
        logs: logs.clone(),
    });
    let success = matches!(result.term, Ok(Term::Constant(c)) if matches!(**c, Constant::Unit))
        && units.mem <= budget.mem
        && units.steps <= budget.steps;
    if !success && failure.is_none() {
        failure = Some(MachineFailure {
            message: "Plutus V3 script did not return unit".into(),
            budget: units,
            logs: logs.clone(),
        });
    }
    Ok(ScriptEvalResult {
        success,
        units,
        logs,
        failure,
    })
}

/// Evaluate a program as `Program::eval` does, refusing a call to a builtin outside the audited set.
fn run<'a>(
    arena: &'a Arena,
    program: &'a Program<'a, DeBruijn>,
    costs: CostModel,
    initial: ExBudget,
) -> Result<EvalResult<'a, DeBruijn>, Error> {
    let startup = costs.machine_costs.startup;
    let started = ExBudget {
        mem: initial.mem.saturating_sub(startup.mem),
        cpu: initial.cpu.saturating_sub(startup.cpu),
    };
    let mut machine = Machine::new(arena, started, costs, program.version);
    let term = if started.mem < 0 || started.cpu < 0 {
        Err(MachineError::OutOfExError(started))
    } else {
        steps(arena, &mut machine, program.term)?
    };
    let mut info = machine.info();
    info.consumed_budget = initial - info.remaining_budget;
    Ok(EvalResult { term, info })
}

/// Step the machine from `term` to its result, refusing a call to a builtin outside the audited set.
fn steps<'a>(
    arena: &'a Arena,
    machine: &mut Machine<'a>,
    term: &'a Term<'a, DeBruijn>,
) -> Result<Result<&'a Term<'a, DeBruijn>, MachineError<'a, DeBruijn>>, Error> {
    let mut state =
        MachineState::compute(arena, Context::no_frame(arena), Env::new_in(arena), term);
    loop {
        let next = match *state {
            MachineState::Compute(context, env, term) => machine.compute(context, env, term),
            MachineState::Return(context, value) => {
                if called(context, value).is_some_and(|fun| !audited(fun)) {
                    return Err(Error::DijkstraUnsupported(
                        "V3 builtin outside audited protocol-12 subset",
                    ));
                }
                machine.return_compute(context, value)
            }
            MachineState::Done(term) => return Ok(Ok(term)),
        };
        match next {
            Ok(next) => state = next,
            Err(error) => return Ok(Err(error)),
        }
    }
}

/// The builtin that returning `value` to `context` calls, if the step saturates one.
fn called<'a>(
    context: &Context<'a, DeBruijn>,
    value: &Value<'a, DeBruijn>,
) -> Option<DefaultFunction> {
    match (context, value) {
        (Context::FrameForce(_), Value::Builtin(runtime)) => {
            (runtime.needs_force() && runtime.is_ready()).then_some(runtime.fun)
        }
        (Context::FrameAwaitArg(Value::Builtin(runtime), _), _)
        | (Context::FrameAwaitFunValue(_, _), Value::Builtin(runtime)) => (!runtime.needs_force()
            && runtime.args.len() + 1 == runtime.fun.arity())
        .then_some(runtime.fun),
        _ => None,
    }
}

/// Whether a builtin's protocol 12 V3 semantics and cost entries agree with the ledger on judged records.
fn audited(fun: DefaultFunction) -> bool {
    use DefaultFunction as F;
    match fun {
        F::AddInteger
        | F::SubtractInteger
        | F::MultiplyInteger
        | F::DivideInteger
        | F::QuotientInteger
        | F::ModInteger
        | F::EqualsInteger
        | F::LessThanInteger
        | F::LessThanEqualsInteger
        | F::AppendByteString
        | F::ConsByteString
        | F::SliceByteString
        | F::LengthOfByteString
        | F::IndexByteString
        | F::EqualsByteString
        | F::LessThanByteString
        | F::LessThanEqualsByteString
        | F::Blake2b_256
        | F::Blake2b_224
        | F::VerifyEd25519Signature
        | F::IfThenElse
        | F::ChooseUnit
        | F::Trace
        | F::FstPair
        | F::SndPair
        | F::ChooseList
        | F::MkCons
        | F::HeadList
        | F::TailList
        | F::NullList
        | F::DropList
        | F::ChooseData
        | F::ConstrData
        | F::MapData
        | F::ListData
        | F::IData
        | F::BData
        | F::UnConstrData
        | F::UnMapData
        | F::UnListData
        | F::UnIData
        | F::UnBData
        | F::EqualsData
        | F::SerialiseData
        | F::MkPairData => true,
        F::RemainderInteger
        | F::Sha2_256
        | F::Sha3_256
        | F::Keccak_256
        | F::VerifyEcdsaSecp256k1Signature
        | F::VerifySchnorrSecp256k1Signature
        | F::AppendString
        | F::EqualsString
        | F::EncodeUtf8
        | F::DecodeUtf8
        | F::MkNilData
        | F::MkNilPairData
        | F::Bls12_381_G1_Add
        | F::Bls12_381_G1_Neg
        | F::Bls12_381_G1_ScalarMul
        | F::Bls12_381_G1_Equal
        | F::Bls12_381_G1_Compress
        | F::Bls12_381_G1_Uncompress
        | F::Bls12_381_G1_HashToGroup
        | F::Bls12_381_G2_Add
        | F::Bls12_381_G2_Neg
        | F::Bls12_381_G2_ScalarMul
        | F::Bls12_381_G2_Equal
        | F::Bls12_381_G2_Compress
        | F::Bls12_381_G2_Uncompress
        | F::Bls12_381_G2_HashToGroup
        | F::Bls12_381_MillerLoop
        | F::Bls12_381_MulMlResult
        | F::Bls12_381_FinalVerify
        | F::IntegerToByteString
        | F::ByteStringToInteger
        | F::AndByteString
        | F::OrByteString
        | F::XorByteString
        | F::ComplementByteString
        | F::ReadBit
        | F::WriteBits
        | F::ReplicateByte
        | F::ShiftByteString
        | F::RotateByteString
        | F::CountSetBits
        | F::FindFirstSetBit
        | F::Ripemd_160
        | F::ExpModInteger
        | F::LengthOfArray
        | F::ListToArray
        | F::IndexArray
        | F::Bls12_381_G1_MultiScalarMul
        | F::Bls12_381_G2_MultiScalarMul
        | F::InsertCoin
        | F::LookupCoin
        | F::UnionValue
        | F::ValueContains
        | F::ValueData
        | F::UnValueData
        | F::ScaleValue => false,
    }
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

/// Decode introduced script bytes at the native protocol version, without execution.
pub(crate) fn check_v3_script(script: &[u8]) -> Result<(), Error> {
    let arena = Arena::from_bump(Bump::new());
    let mut decoder = minicbor::Decoder::new(script);
    let flat_bytes: minicbor::bytes::ByteVec = decoder.decode()?;
    if decoder.position() != script.len() {
        return Err(Error::DijkstraInvalid("trailing script CBOR"));
    }
    let (program, remainder): (&Program<DeBruijn>, _) =
        flat::decode(&arena, &flat_bytes, ProtocolVersion::new(12, 0))?;
    check_program_version(program.version)?;
    if remainder != 0 {
        return Err(amaru_uplc_native::flat::FlatDecodeError::TrailingBytes(remainder).into());
    }
    Ok(())
}

fn check_program_version(version: amaru_uplc_native::machine::MachineVersion) -> Result<(), Error> {
    if !matches!((version.major, version.minor, version.patch), (1, 0 | 1, 0)) {
        return Err(Error::DijkstraInvalid("unsupported V3 UPLC version"));
    }
    Ok(())
}
