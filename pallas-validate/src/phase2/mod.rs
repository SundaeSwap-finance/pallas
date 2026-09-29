pub mod data;
pub mod error;
mod evaluator;
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

#[cfg(all(test, feature = "unstable"))]
mod dijkstra_evaluation_tests;

#[cfg(feature = "unstable")]
mod dijkstra;

#[cfg(test)]
mod v3_deposit_context_tests;

#[cfg(all(test, feature = "unstable"))]
mod registration_evaluator_tests;
