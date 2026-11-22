//! Ergonomic builder for constructing and signing Cardano transactions.
//!
//! The crate is organised around [`StagingTransaction`], a fluent builder
//! that collects inputs, outputs, mint, scripts, datums, and redeemers, and
//! finalises into a [`BuiltTransaction`] ready to be signed and submitted.
//!
//! Currently the only era supported for building is **Conway** (via the
//! [`BuildConway`] trait). Earlier-era builders are intentionally not
//! maintained.
//!
//! # Usage
//!
//! ```
//! use pallas_txbuilder::{BuildConway, Input, Output, StagingTransaction};
//! # use pallas_addresses::Address;
//! # use pallas_crypto::{hash::Hash, key::ed25519::SecretKey};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let prev_tx_hash = Hash::from([0u8; 32]);
//! # let recipient_address = Address::from_bech32("addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x")?;
//! # let signing_key = SecretKey::from([1u8; 32]);
//!
//! let tx = StagingTransaction::new()
//!     .input(Input::new(prev_tx_hash, 0))
//!     .output(Output::new(recipient_address, 2_000_000))
//!     .fee(170_000)
//!     .build_conway_raw()?;
//!
//! let signed = tx.sign(&signing_key)?;
//! let cbor = signed.tx_bytes;
//! # Ok(())
//! # }
//! ```
//!
//! # Overview
//!
//! - [`StagingTransaction`] — the in-progress, mutable transaction; the
//!   entry point for everything (`new`, `input`, `output`, `mint`, `fee`,
//!   `network_id`, `valid_after`, …).
//! - [`BuiltTransaction`] — the finalised, encoded body produced by
//!   [`BuildConway`]; exposes `sign(&signer)` and the raw CBOR bytes.
//! - [`Input`], [`Output`], [`ExUnits`], [`ScriptKind`], [`Bytes`],
//!   [`Bytes32`] — the value types that go into the builder.
//! - [`BuildConway`] trait — implemented for [`StagingTransaction`]; turns
//!   staging state into a Conway-encoded transaction.
//! - [`TxBuilderError`] — the unified error returned from build / sign.
//!
//! # Usage as part of `pallas`
//!
//! When depending on the umbrella [`pallas`] crate, this crate is re-exported
//! as `pallas::txbuilder`.
//!
//! [`pallas`]: https://crates.io/crates/pallas

mod conway;
mod transaction;

pub use conway::BuildConway;
pub use transaction::{
    Bytes, Bytes32,
    model::{BuiltTransaction, ExUnits, Input, Output, ScriptKind, StagingTransaction},
};

/// Errors produced while staging, building, or signing a transaction.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum TxBuilderError {
    /// Provided bytes could not be decoded into a script
    #[error("Transaction has no inputs")]
    MalformedScript,
    /// Provided bytes could not be decoded into a datum
    #[error("Could not decode datum bytes")]
    MalformedDatum,
    /// Provided datum hash was not 32 bytes in length
    #[error("Invalid bytes length for datum hash")]
    MalformedDatumHash,
    /// Input, policy, etc pointed to by a redeemer was not found in the
    /// transaction
    #[error("Input/policy pointed to by redeemer not found in tx")]
    RedeemerTargetMissing,
    /// Provided network ID is invalid (must be 0 or 1)
    #[error("Invalid network ID")]
    InvalidNetworkId,
    /// Transaction bytes in built transaction object could not be decoded
    #[error("Corrupted transaction bytes in built transaction")]
    CorruptedTxBytes,
    /// Public key generated from private key was of unexpected length
    #[error("Public key for private key is malformed")]
    MalformedKey,
    /// Asset name is too long, it must be 32 bytes or less
    #[error("Asset name must be 32 bytes or less")]
    AssetNameTooLong,
    /// Unsupported era
    #[error("Unsupported era")]
    UnsupportedEra,
}
