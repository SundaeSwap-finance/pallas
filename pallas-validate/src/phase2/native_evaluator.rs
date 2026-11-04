//! Native Dijkstra evaluation with the protocol-aware backend.
use super::{
    error::{Error, Unsupported},
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
        CostModel, ExBudget, Machine, MachineError, MachineInfo, RuntimeError, env::Env,
        state::MachineState, value::Value,
    },
    program::Program,
    term::Term,
};
use pallas_codec::minicbor;
use pallas_primitives::{
    conway::{ExUnits, PlutusData},
    dijkstra::Language,
};

/// A builtin function of the native evaluation.
pub use amaru_uplc_native::builtin::DefaultFunction as Builtin;

/// The builtins the native evaluation runs, in tag order.
pub fn audited_builtins() -> Vec<Builtin> {
    (0..=u8::MAX)
        .filter_map(|tag| Builtin::try_from(tag).ok())
        .filter(|fun| audited(*fun))
        .collect()
}

/// Evaluate a protocol 12 Plutus script applied to `args`, with the builtins it called in order of first call, refusing a call to a builtin outside the audited set.
pub(crate) fn eval_native(
    language: Language,
    script_bytes: &[u8],
    args: &[&PlutusData],
    costs: &[i64],
    budget: ExUnits,
) -> Result<(ScriptEvalResult, Vec<Builtin>), Error> {
    let arena = Arena::from_bump(Bump::with_capacity(1_024_000));
    let flat_bytes: minicbor::bytes::ByteVec = minicbor::decode(script_bytes)?;
    let version = plutus_version(&language);
    let protocol = ProtocolVersion::new(12, 0);
    let cost_model = match language {
        Language::PlutusV1 | Language::PlutusV2 | Language::PlutusV3 => {
            CostModel::new(version, protocol, costs)
        }
        Language::PlutusV4 => CostModel::v4(costs),
    };
    let (program, remainder): (&Program<DeBruijn>, _) =
        flat::decode(&arena, &flat_bytes, version, protocol)?;
    if remainder > 0 {
        return Err(amaru_uplc_native::flat::FlatDecodeError::TrailingBytes(remainder).into());
    }
    let initial = ExBudget {
        mem: i64::try_from(budget.mem)
            .map_err(|_| Error::DijkstraInvalid("memory budget overflow"))?,
        cpu: i64::try_from(budget.steps)
            .map_err(|_| Error::DijkstraInvalid("CPU budget overflow"))?,
    };
    let program = args.iter().fold(program, |program, arg| {
        program.apply(&arena, plutus_data_to_term(&arena, arg))
    });
    let mut calls = Vec::new();
    let (value, info) = run(&arena, program, cost_model, initial, &mut calls)?;
    if matches!(
        value,
        Err(MachineError::Runtime(RuntimeError::IntegerOutOfBounds(_)))
    ) {
        return Err(Error::DijkstraUnsupported(Unsupported(
            "integer operand outside audited registration range",
        )));
    }
    let units = budget_to_ex_units(info.consumed_budget);
    let logs = info.logs;
    let mut failure = value.as_ref().err().map(|err| MachineFailure {
        message: err.to_string(),
        budget: units,
        logs: logs.clone(),
    });
    // A V1 or V2 script succeeds by returning any value, a V3 or V4 script by returning unit.
    let returned = match (&value, language) {
        (Ok(_), Language::PlutusV1 | Language::PlutusV2) => true,
        (Ok(value), Language::PlutusV3 | Language::PlutusV4) => {
            matches!(value, Value::Con(Constant::Unit))
        }
        (Err(_), _) => false,
    };
    let success = returned && units.mem <= budget.mem && units.steps <= budget.steps;
    if !success && failure.is_none() {
        failure = Some(MachineFailure {
            message: "Plutus script did not return unit or exceeded its budget".into(),
            budget: units,
            logs: logs.clone(),
        });
    }
    Ok((
        ScriptEvalResult {
            success,
            units,
            logs,
            failure,
        },
        calls,
    ))
}

/// The value a program returns, or the machine error that stops it.
type Evaluated<'a> = Result<&'a Value<'a, DeBruijn>, MachineError<'a, DeBruijn>>;

/// Evaluate a program to its result and spent budget, adding each builtin it calls to `calls`, refusing a call to a builtin outside the audited set.
fn run<'a>(
    arena: &'a Arena,
    program: &'a Program<'a, DeBruijn>,
    costs: CostModel,
    initial: ExBudget,
    calls: &mut Vec<Builtin>,
) -> Result<(Evaluated<'a>, MachineInfo), Error> {
    let startup = costs.machine_costs.startup;
    let started = ExBudget {
        mem: initial.mem.saturating_sub(startup.mem),
        cpu: initial.cpu.saturating_sub(startup.cpu),
    };
    let mut machine = program.machine(arena, costs, started);
    let value = if started.mem < 0 || started.cpu < 0 {
        Err(MachineError::OutOfExError(started))
    } else {
        steps(arena, &mut machine, program.term, calls)?
    };
    let mut info = machine.info();
    info.consumed_budget = initial - info.remaining_budget;
    Ok((value, info))
}

/// Step the machine from `term` to its result, adding each builtin it calls to `calls`, refusing a call to a builtin outside the audited set.
fn steps<'a>(
    arena: &'a Arena,
    machine: &mut Machine<'a, DeBruijn>,
    term: &'a Term<'a, DeBruijn>,
    calls: &mut Vec<Builtin>,
) -> Result<Evaluated<'a>, Error> {
    let mut state = MachineState::compute(0, Env::new_in(arena), term);
    loop {
        let next = match state {
            MachineState::Compute(context, env, term) => machine.compute(context, env, term),
            MachineState::Return(context, value) => {
                if let Some(fun) = machine.saturated_builtin(value) {
                    if !audited(fun) {
                        return Err(Error::DijkstraUnsupported(Unsupported(
                            "V3 builtin outside audited protocol-12 subset",
                        )));
                    }
                    if !calls.contains(&fun) {
                        calls.push(fun);
                    }
                }
                machine.return_compute(context, value)
            }
            MachineState::Done(value) => return Ok(Ok(value)),
        };
        match next {
            Ok(next) => state = next,
            Err(error) => return Ok(Err(error)),
        }
    }
}

/// Whether the native evaluation runs a builtin.
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

/// The version whose flat encoding and builtins a script of `language` decodes with.
fn plutus_version(language: &Language) -> PlutusVersion {
    match language {
        Language::PlutusV1 => PlutusVersion::V1,
        Language::PlutusV2 => PlutusVersion::V2,
        Language::PlutusV3 | Language::PlutusV4 => PlutusVersion::V3,
    }
}

/// Decode introduced script bytes of `language` at the native protocol version, without execution.
pub(crate) fn check_plutus_script(language: &Language, script: &[u8]) -> Result<(), Error> {
    let arena = Arena::from_bump(Bump::new());
    let mut decoder = minicbor::Decoder::new(script);
    let flat_bytes: minicbor::bytes::ByteVec = decoder.decode()?;
    if decoder.position() != script.len() {
        return Err(Error::DijkstraInvalid("trailing script CBOR"));
    }
    let (_, remainder): (&Program<DeBruijn>, _) = flat::decode(
        &arena,
        &flat_bytes,
        plutus_version(language),
        ProtocolVersion::new(12, 0),
    )?;
    if remainder != 0 {
        return Err(amaru_uplc_native::flat::FlatDecodeError::TrailingBytes(remainder).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The script bytes of `(program major.minor.0 (lam x (con unit ())))`.
    fn unit_lambda(major: u8, minor: u8) -> [u8; 6] {
        [0x45, major, minor, 0x00, 0x24, 0x99]
    }

    const LANGUAGES: [Language; 4] = [
        Language::PlutusV1,
        Language::PlutusV2,
        Language::PlutusV3,
        Language::PlutusV4,
    ];

    #[test]
    fn protocol_12_refuses_uplc_1_3_and_2_0() {
        for language in &LANGUAGES {
            for (major, minor) in [(1, 3), (2, 0)] {
                let result = check_plutus_script(language, &unit_lambda(major, minor));
                assert!(
                    matches!(
                        result,
                        Err(Error::NativeFlatDecode(
                            flat::FlatDecodeError::ProgramVersionNotAvailable { .. }
                        ))
                    ),
                    "{language:?} {major}.{minor}.0 {result:?}"
                );
            }
        }
    }

    #[test]
    fn protocol_12_accepts_uplc_1_0_to_1_2() {
        for language in &LANGUAGES {
            for minor in 0..=2 {
                let result = check_plutus_script(language, &unit_lambda(1, minor));
                assert!(result.is_ok(), "{language:?} 1.{minor}.0 {result:?}");
            }
        }
    }
}
