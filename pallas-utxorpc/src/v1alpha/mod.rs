use std::ops::Deref;

use prost_types::FieldMask;

use pallas_primitives::babbage;
use pallas_traverse as trv;
use trv::OriginalHash;

use crate::LedgerContext;

pub use utxorpc_spec::utxorpc::v1alpha as spec;

#[derive(Default, Clone)]
pub struct Mapper<C: LedgerContext> {
    pub(crate) ledger: Option<C>,
    pub(crate) _mask: FieldMask,
}

impl<C: LedgerContext> Mapper<C> {
    pub fn new(ledger: C) -> Self {
        Self {
            ledger: Some(ledger),
            _mask: FieldMask { paths: vec![] },
        }
    }

    /// Creates a clone of this mapper using a custom field mask
    pub fn masked(&self, mask: FieldMask) -> Self {
        Self {
            ledger: self.ledger.clone(),
            _mask: mask,
        }
    }
}

crate::shared::impl_cardano_mapper_shared!(utxorpc_spec::utxorpc::v1alpha::cardano);

// ---- v1alpha-specific bodies for methods that diverge from v1beta -----------

/// The u5c native script member this schema names for a required signature.
fn pubkey_clause(hash: &pallas_crypto::hash::Hash<28>) -> u5c::native_script::NativeScript {
    u5c::native_script::NativeScript::ScriptPubkey(hash.to_vec().into())
}

/// The u5c governance action this schema names for an information action. The
/// proto prescribes the value 6 and gives the member no message.
fn information_action() -> u5c::governance_action::GovernanceAction {
    u5c::governance_action::GovernanceAction::InfoAction(6)
}

impl<C: LedgerContext> Mapper<C> {
    pub fn map_tx_datum(
        &self,
        x: &trv::MultiEraOutput,
        tx: Option<&trv::MultiEraTx>,
    ) -> u5c::Datum {
        u5c::Datum {
            hash: match x.datum() {
                Some(babbage::DatumOption::Data(x)) => x.original_hash().to_vec().into(),
                Some(babbage::DatumOption::Hash(x)) => x.to_vec().into(),
                _ => vec![].into(),
            },
            payload: match x.datum() {
                Some(babbage::DatumOption::Data(x)) => self.map_plutus_datum(&x.0).into(),
                Some(babbage::DatumOption::Hash(x)) => tx
                    .and_then(|tx| tx.find_plutus_data(&x))
                    .map(|d| self.map_plutus_datum(d)),
                _ => None,
            },
            original_cbor: match x.datum() {
                Some(babbage::DatumOption::Data(x)) => x.raw_cbor().to_vec().into(),
                _ => vec![].into(),
            },
        }
    }

    pub fn map_tx_output(
        &self,
        x: &trv::MultiEraOutput,
        tx: Option<&trv::MultiEraTx>,
    ) -> u5c::TxOutput {
        u5c::TxOutput {
            address: x.address().map(|a| a.to_vec()).unwrap_or_default().into(),
            coin: u64_to_bigint(x.value().coin()),
            // TODO: this is wrong, we're crating a new item for each asset even if they share
            // the same policy id. We need to adjust Pallas' interface to make this mapping more
            // ergonomic.
            assets: x
                .value()
                .assets()
                .iter()
                .map(|x| self.map_policy_assets(x))
                .collect(),
            datum: self.map_tx_datum(x, tx).into(),
            script: self.map_output_script(x),
        }
    }

    fn map_output_script(&self, x: &trv::MultiEraOutput) -> Option<u5c::Script> {
        x.script_ref().map(|x| self.map_script_ref(&x))
    }

    pub fn map_asset(&self, x: &trv::MultiEraAsset) -> u5c::Asset {
        let quantity = if let Some(v) = x.output_coin() {
            u64_to_bigint(v).map(u5c::asset::Quantity::OutputCoin)
        } else if let Some(v) = x.mint_coin() {
            i64_to_bigint(v).map(u5c::asset::Quantity::MintCoin)
        } else {
            None
        };
        u5c::Asset {
            name: x.name().to_vec().into(),
            quantity,
        }
    }

    pub fn map_policy_assets(&self, x: &trv::MultiEraPolicyAssets) -> u5c::Multiasset {
        u5c::Multiasset {
            policy_id: x.policy().to_vec().into(),
            assets: x.assets().iter().map(|x| self.map_asset(x)).collect(),
            redeemer: None,
        }
    }

    pub fn map_tx(&self, tx: &trv::MultiEraTx) -> u5c::Tx {
        let resolved = self.ledger.as_ref().and_then(|ctx| {
            let to_resolve = self.find_related_inputs(tx);
            ctx.get_utxos(to_resolve.as_slice())
        });

        u5c::Tx {
            hash: tx.hash().to_vec().into(),
            inputs: tx
                .inputs_sorted_set()
                .iter()
                .enumerate()
                .map(|(order, i)| self.map_tx_input(i, tx, order as u32, &resolved))
                .collect(),
            outputs: tx
                .outputs()
                .iter()
                .map(|x| self.map_tx_output(x, Some(tx)))
                .collect(),
            certificates: tx
                .certs()
                .iter()
                .enumerate()
                .filter_map(|(order, x)| self.map_cert(x, tx, order as u32))
                .collect(),
            proposals: tx
                .gov_proposals()
                .iter()
                .map(|x| self.map_gov_proposal(x))
                .collect(),
            withdrawals: tx
                .withdrawals_sorted_set()
                .iter()
                .enumerate()
                .map(|(order, x)| self.map_withdrawals(x, tx, order as u32))
                .collect(),
            mint: tx
                .mints_sorted_set()
                .iter()
                .enumerate()
                .map(|(order, x)| {
                    let mut ma = self.map_policy_assets(x);

                    ma.redeemer = tx
                        .find_mint_redeemer(order as u32)
                        .map(|r| self.map_redeemer(&r));

                    ma
                })
                .collect(),
            reference_inputs: tx
                .reference_inputs()
                .iter()
                .map(|x| self.map_tx_reference_input(x, &resolved, tx))
                .collect(),
            witnesses: u5c::WitnessSet {
                vkeywitness: tx
                    .vkey_witnesses()
                    .iter()
                    .map(|x| self.map_vkey_witness(x))
                    .collect(),
                script: self.collect_all_scripts(tx),
                plutus_datums: tx
                    .plutus_data()
                    .iter()
                    .map(|x| self.map_plutus_datum(x.deref()))
                    .collect(),
            }
            .into(),
            collateral: u5c::Collateral {
                collateral: tx
                    .collateral()
                    .iter()
                    .map(|x| self.map_tx_collateral(x, &resolved, tx))
                    .collect(),
                collateral_return: tx
                    .collateral_return()
                    .map(|x| self.map_tx_output(&x, Some(tx))),
                total_collateral: u64_to_bigint(tx.total_collateral().unwrap_or_default()),
            }
            .into(),
            fee: tx.fee().and_then(u64_to_bigint),
            validity: u5c::TxValidity {
                start: tx.validity_start().unwrap_or_default(),
                ttl: tx.ttl().unwrap_or_default(),
            }
            .into(),
            successful: tx.is_valid(),
            auxiliary: u5c::AuxData {
                metadata: tx
                    .metadata()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|(l, d)| self.map_metadata(l, d))
                    .collect(),
                scripts: self.collect_all_aux_scripts(tx),
            }
            .into(),
        }
    }
}

/// The block fixtures this schema has a snapshot of, each with the snapshot
/// contents and the snapshot file name.
#[cfg(test)]
fn snapshot_cases() -> Vec<(&'static str, &'static str, &'static str)> {
    #[allow(unused_mut)]
    let mut cases = vec![(
        include_str!("../../../test_data/u5c1.block"),
        include_str!("../../../test_data/u5c_v1alpha.json"),
        "u5c_v1alpha.json",
    )];

    #[cfg(feature = "unstable")]
    cases.push((
        include_str!("../../../test_data/dijkstra6.block"),
        include_str!("../../../test_data/u5c_v1alpha_dijkstra.json"),
        "u5c_v1alpha_dijkstra.json",
    ));

    cases
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{NoLedger, conway_information};
    use pretty_assertions::assert_eq;

    #[test]
    fn a_pubkey_clause_maps_to_the_member_this_schema_names() {
        let script = trv::MultiEraNativeScript::from_decoded_alonzo_compatible(
            &pallas_primitives::alonzo::NativeScript::ScriptPubkey([0x44; 28].into()),
        );

        assert_eq!(
            Mapper::<NoLedger>::map_native_script(&script).native_script,
            Some(u5c::native_script::NativeScript::ScriptPubkey(
                [0x44; 28].to_vec().into()
            )),
            "this schema names the required signature member ScriptPubkey and carries the key hash in it"
        );
    }

    #[test]
    fn an_information_action_maps_to_the_value_this_schema_names() {
        let mapper = Mapper::new(NoLedger);

        assert_eq!(
            mapper
                .map_gov_action(&trv::MultiEraGovAction::from_conway(&conway_information()))
                .governance_action,
            Some(u5c::governance_action::GovernanceAction::InfoAction(6)),
            "this schema types the information member a uint32, and the proto prescribes the value 6"
        );
    }
}
