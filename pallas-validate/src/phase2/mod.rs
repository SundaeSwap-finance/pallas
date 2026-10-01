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
/// Uses the active protocol's maximum transaction execution units as a shared
/// finite limit. Redeemers execute in native pointer order, each with the remaining
/// memory/steps after all preceding executions (including failures). Equality with
/// either limit is allowed. Exhaustion is a failed entry in the ordinary report;
/// its units include the machine charge that crossed the limit, so failed reports
/// may exceed the limit. Later entries still execute with the remaining budget.
/// A successful estimate requires every report entry to succeed.
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
