pub mod data;
pub mod error;
mod evaluator;
#[cfg(feature = "unstable")]
pub(crate) mod native_evaluator;
pub mod script_context;
pub mod to_plutus_data;
pub mod tx;

use error::Error;
use pallas_traverse::MultiEraTx;
use script_context::SlotConfig;

use crate::utils::{MultiEraProtocolParameters, UtxoMap};

pub type EvalReport = Vec<tx::TxEvalResult>;

pub fn evaluate_tx(
    tx: &MultiEraTx,
    pparams: &MultiEraProtocolParameters,
    utxos: &UtxoMap,
    slot_config: &SlotConfig,
) -> Result<EvalReport, Error> {
    tx::eval_tx(tx, pparams, utxos, slot_config)
}

/// Evaluate native Dijkstra using the supplied historical slot/time mappings.
/// Consensus forecast enforcement is separate from this conversion.
#[cfg(feature = "unstable")]
pub fn evaluate_tx_with_time(
    tx: &MultiEraTx,
    pparams: &MultiEraProtocolParameters,
    utxos: &UtxoMap,
    time: &crate::utils::DijkstraTimeContext,
) -> Result<EvalReport, Error> {
    let results = dijkstra::eval_tx_with_mode(tx, pparams, utxos, time, false)?;
    Ok(results.into_iter().map(|(result, _)| result).collect())
}

/// Estimate native Dijkstra with explicit historical time information. The
/// budget and admission distinctions documented on [`estimate_tx`] still apply.
#[cfg(feature = "unstable")]
pub fn estimate_tx_with_time(
    tx: &MultiEraTx,
    pparams: &MultiEraProtocolParameters,
    utxos: &UtxoMap,
    time: &crate::utils::DijkstraTimeContext,
) -> Result<EvalReport, Error> {
    let results = estimate_tx_calls_with_time(tx, pparams, utxos, time)?;
    Ok(results.into_iter().map(|(result, _)| result).collect())
}

/// [`estimate_tx_calls`] using explicit historical slot/time mappings.
#[cfg(feature = "unstable")]
pub fn estimate_tx_calls_with_time(
    tx: &MultiEraTx,
    pparams: &MultiEraProtocolParameters,
    utxos: &UtxoMap,
    time: &crate::utils::DijkstraTimeContext,
) -> Result<Vec<(tx::TxEvalResult, Vec<Builtin>)>, Error> {
    dijkstra::eval_tx_with_mode(tx, pparams, utxos, time, true)
}

/// Estimate native Dijkstra execution units without checking key witnesses or
/// enforcing declared redeemer budgets. Earlier eras return [`Error::WrongEra`].
///
/// Each redeemer independently receives the active protocol's maximum transaction
/// execution units as a finite limit. Earlier executions, including failures, do
/// not reduce later allowances. Equality with either limit is allowed. Exhaustion
/// is a failed report entry whose units include the charge that crossed the limit.
///
/// Successful estimates may sum to more than the transaction maximum. Callers
/// must check the aggregate before building a valid transaction; estimation does
/// not certify admission. [`evaluate_tx`] still checks aggregate declared budgets
/// and enforces each redeemer's declared allowance.
///
/// The transaction, script context, redeemer data and cost model are unchanged.
/// This is phase two only, not admission validation. Existing native feature and
/// protocol restrictions apply. Use [`evaluate_tx`] to enforce declared budgets.
#[cfg(feature = "unstable")]
pub fn estimate_tx(
    tx: &MultiEraTx,
    pparams: &MultiEraProtocolParameters,
    utxos: &UtxoMap,
    slot_config: &SlotConfig,
) -> Result<EvalReport, Error> {
    let estimates = estimate_tx_calls(tx, pparams, utxos, slot_config)?;
    Ok(estimates.into_iter().map(|(result, _)| result).collect())
}

/// [`estimate_tx`], with the builtins each redeemer's evaluation called in order of first call.
#[cfg(feature = "unstable")]
pub fn estimate_tx_calls(
    tx: &MultiEraTx,
    pparams: &MultiEraProtocolParameters,
    utxos: &UtxoMap,
    slot_config: &SlotConfig,
) -> Result<Vec<(tx::TxEvalResult, Vec<Builtin>)>, Error> {
    dijkstra::estimate_tx(tx, pparams, utxos, slot_config)
}

#[cfg(feature = "unstable")]
pub use native_evaluator::{Builtin, audited_builtins};

#[cfg(all(test, feature = "unstable"))]
mod dijkstra_evaluation_tests;

#[cfg(feature = "unstable")]
mod dijkstra;

#[cfg(test)]
mod v3_deposit_context_tests;

#[cfg(all(test, feature = "unstable"))]
mod registration_evaluator_tests;
