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
    dijkstra::estimate_tx(tx, pparams, utxos, slot_config)
}

#[cfg(all(test, feature = "unstable"))]
mod dijkstra_evaluation_tests;

#[cfg(feature = "unstable")]
mod dijkstra;

#[cfg(test)]
mod v3_deposit_context_tests;

#[cfg(all(test, feature = "unstable"))]
mod registration_evaluator_tests;
