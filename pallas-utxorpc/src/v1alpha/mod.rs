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

/// The u5c governance action this schema names for an information action. The
/// proto prescribes the value 6 and gives the member no message.
fn information_action() -> u5c::governance_action::GovernanceAction {
    u5c::governance_action::GovernanceAction::InfoAction(6)
}

/// The u5c purpose of a guarding redeemer, for which this schema has no member.
#[cfg(feature = "unstable")]
fn guarding_purpose() -> u5c::RedeemerPurpose {
    u5c::RedeemerPurpose::Unspecified
}

/// The u5c member of a guard clause, for which this schema has no member.
#[cfg(feature = "unstable")]
fn native_script_guard(
    _: &pallas_primitives::StakeCredential,
) -> Option<u5c::native_script::NativeScript> {
    None
}

/// Returns the certificate unchanged, since this schema has no field for a pool BLS key.
#[cfg(feature = "unstable")]
fn with_pool_bls_key(
    cert: Option<u5c::certificate::Certificate>,
    _: Option<&pallas_primitives::dijkstra::BlsKey>,
) -> Option<u5c::certificate::Certificate> {
    cert
}

/// The fields of the keys only a Dijkstra update carries, for which this schema has no field.
fn dijkstra_pparams_update(_: &mut bool, _: &trv::MultiEraParamUpdate) -> u5c::PParams {
    u5c::PParams::default()
}

/// The fields of the Dijkstra parameters no other era carries, for which this schema has no field.
#[cfg(feature = "unstable")]
fn dijkstra_pparams(_: &pallas_validate::utils::DijkstraProtParams) -> u5c::PParams {
    u5c::PParams::default()
}

impl<C: LedgerContext> Mapper<C> {
    // v1alpha names this variant by what it holds; v1beta names it
    // ScriptPubkeyHash. The rest of map_native_script is identical between
    // versions and lives in shared.rs.
    fn map_native_script_pubkey(bytes: Vec<u8>) -> u5c::native_script::NativeScript {
        u5c::native_script::NativeScript::ScriptPubkey(bytes.into())
    }

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
        x.multi_era_script_ref().map(|x| self.map_script_ref(&x))
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
            Mapper::<NoLedger>::map_multi_era_native_script(&script).native_script,
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

    #[cfg(feature = "unstable")]
    #[test]
    fn a_dijkstra_pool_registration_drops_the_bls_key_it_fills() {
        use crate::testing::dijkstra_block;
        use prost::Message;

        let block = dijkstra_block(include_str!("../../../test_data/dijkstra6.block"));
        let txs = block.txs();
        let keys: Vec<Vec<u8>> = txs
            .iter()
            .flat_map(|tx| tx.certs())
            .filter_map(|cert| cert.bls_key().map(|k| k.bls_pubkey.to_vec()))
            .collect();

        assert_eq!(
            keys.len(),
            2,
            "this block's two pool registrations each fill the BLS key slot, which is what the mapper then has to drop"
        );

        let wire = Mapper::new(NoLedger).map_block(&block).encode_to_vec();

        for key in keys {
            assert!(
                !wire.windows(key.len()).any(|w| w == key.as_slice()),
                "this schema names no field for a pool registration's BLS key, so none of its bytes may reach the wire"
            );
        }
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_guarding_redeemer_maps_to_the_purpose_this_schema_leaves_unspecified() {
        let mapper = Mapper::new(NoLedger);

        assert_eq!(
            mapper.map_multi_era_purpose(&trv::MultiEraRedeemerTag::Guarding),
            u5c::RedeemerPurpose::Unspecified,
            "this schema has no guarding purpose, so a guard reads as unspecified rather than as one of the six it names"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_guard_clause_inside_a_list_maps_to_an_empty_message() {
        use pallas_primitives::{StakeCredential, dijkstra};

        let script = dijkstra::NativeScript::ScriptAll(vec![
            dijkstra::NativeScript::ScriptRequireGuard(StakeCredential::AddrKeyhash(
                [0x7a; 28].into(),
            )),
            dijkstra::NativeScript::ScriptPubkey([0x44; 28].into()),
        ]);

        let mapped = Mapper::<NoLedger>::map_multi_era_native_script(
            &trv::MultiEraNativeScript::from_decoded_dijkstra(&script),
        );

        let Some(u5c::native_script::NativeScript::ScriptAll(list)) = mapped.native_script else {
            panic!(
                "the root clause is script_all, got {:?}",
                mapped.native_script
            );
        };
        assert_eq!(
            list.items.len(),
            2,
            "a guard inside a list is carried as a member rather than dropped"
        );
        assert_eq!(
            list.items[0].native_script, None,
            "the guard has no member in this schema's oneof, so it reaches the wire as an empty message"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_dijkstra_parameter_change_of_a_key_this_schema_cannot_carry_maps_to_no_parameters() {
        let proposal = crate::testing::dijkstra_proposal(include_str!(
            "../../../test_data/proposal-param-change-key48.hex"
        ));
        let action = Mapper::new(NoLedger)
            .map_gov_action(&trv::MultiEraGovAction::from_dijkstra(&proposal.gov_action));

        let Some(u5c::governance_action::GovernanceAction::ParameterChangeAction(change)) =
            action.governance_action
        else {
            panic!("the action is a parameter change, got {action:?}");
        };
        assert_eq!(
            change.protocol_param_update, None,
            "key 48 has no field in this schema, so the update must be absent rather than a PParams whose every field reads its proto3 zero"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_dijkstra_parameter_set_maps_none_of_the_keys_this_schema_cannot_carry() {
        assert_eq!(
            dijkstra_pparams(&crate::testing::dijkstra_params()),
            u5c::PParams::default(),
            "this schema has no field for a key the era adds, so none of them reaches a field"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_dijkstra_parameter_change_of_a_carried_key_and_an_era_key_maps_the_carried_one() {
        // Key 16 is min_pool_cost, key 48 is max_ref_script_size_per_endorser_block.
        let update =
            crate::testing::dijkstra_update(&[0xa2, 0x10, 0x10, 0x18, 0x30, 0x19, 0x4e, 0x20]);

        let mapped = Mapper::new(NoLedger).map_pparams_update(&trv::MultiEraParamUpdate::Dijkstra(
            Box::new(std::borrow::Cow::Borrowed(&update)),
        ));

        assert_eq!(
            mapped,
            Some(u5c::PParams {
                min_pool_cost: u64_to_bigint(16),
                ..Default::default()
            }),
            "the key this schema carries reaches its field, and the key it cannot carry neither adds a field nor takes the update away"
        );
    }

    #[test]
    #[allow(deprecated)]
    fn the_legacy_purpose_mapper_agrees_with_the_multi_era_one() {
        use pallas_primitives::conway::RedeemerTag;
        use pallas_traverse::MultiEraRedeemerTag;

        let mapper = Mapper::new(NoLedger);
        let tags = [
            RedeemerTag::Spend,
            RedeemerTag::Mint,
            RedeemerTag::Cert,
            RedeemerTag::Reward,
            RedeemerTag::Vote,
            RedeemerTag::Propose,
        ];

        let mut seen = Vec::new();
        for tag in tags {
            let legacy = mapper.map_purpose(&tag);
            assert_eq!(
                legacy,
                mapper.map_multi_era_purpose(&MultiEraRedeemerTag::from(tag))
            );
            seen.push(legacy);
        }

        seen.dedup();
        assert_eq!(seen.len(), 6, "each tag maps to a purpose of its own");
    }

    #[test]
    #[allow(deprecated)]
    fn negative_n_of_k_threshold_maps_to_zero() {
        let mapped = Mapper::<NoLedger>::map_native_script(
            &pallas_primitives::alonzo::NativeScript::ScriptNOfK(-1, vec![]),
        );
        assert!(matches!(
            mapped.native_script,
            Some(u5c::native_script::NativeScript::ScriptNOfK(
                u5c::ScriptNOfK { k: 0, .. }
            ))
        ));
    }

    #[test]
    #[allow(deprecated)]
    fn oversized_n_of_k_threshold_maps_to_u32_max() {
        let mapped = Mapper::<NoLedger>::map_native_script(
            &pallas_primitives::alonzo::NativeScript::ScriptNOfK(i64::MAX, vec![]),
        );
        assert!(matches!(
            mapped.native_script,
            Some(u5c::native_script::NativeScript::ScriptNOfK(
                u5c::ScriptNOfK { k: u32::MAX, .. }
            ))
        ));
    }

    #[test]
    fn map_metadatum_handles_deeply_nested_metadata_on_a_small_stack() {
        use pallas_primitives::alonzo::Metadatum;
        use pallas_primitives::{Int, KeyValuePairs};

        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let depth = 20_000;
                let mut datum = Metadatum::Int(Int::from(0));
                for level in 0..depth {
                    datum = if level % 2 == 0 {
                        Metadatum::Array(vec![datum])
                    } else {
                        Metadatum::Map(KeyValuePairs::Def(vec![(
                            Metadatum::Int(Int::from(1)),
                            datum,
                        )]))
                    };
                }
                // The source Drop still recurses; leak it like the result.
                let datum = std::mem::ManuallyDrop::new(datum);

                let mapped = Mapper::<NoLedger>::map_metadatum(&datum);

                let mut seen = 0;
                let mut cursor = &mapped;
                loop {
                    cursor = match cursor.metadatum.as_ref().expect("mapped node") {
                        u5c::metadatum::Metadatum::Array(list) => list.items.first(),
                        u5c::metadatum::Metadatum::Map(map) => {
                            let pair = map.pairs.first().expect("map carries its pair");
                            assert!(matches!(
                                pair.key.as_ref().and_then(|k| k.metadatum.as_ref()),
                                Some(u5c::metadatum::Metadatum::Int(1))
                            ));
                            pair.value.as_ref()
                        }
                        u5c::metadatum::Metadatum::Int(0) => break,
                        other => panic!("unexpected node {other:?}"),
                    }
                    .expect("container carries a child");
                    seen += 1;
                }
                assert_eq!(seen, depth);

                // u5c's generated type has no custom Drop, so a chain this
                // deep would abort on the way out. Leak it deliberately.
                std::mem::forget(mapped);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn map_plutus_datum_handles_deeply_nested_data_on_a_small_stack() {
        use pallas_primitives::alonzo::{BigInt, Constr, PlutusData};
        use pallas_primitives::{Int, KeyValuePairs, MaybeIndefArray};

        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let depth = 21_000;
                let mut datum = PlutusData::BigInt(BigInt::Int(Int::from(0)));
                for level in 0..depth {
                    datum = match level % 3 {
                        0 => PlutusData::Constr(Constr {
                            tag: 121,
                            any_constructor: None,
                            fields: MaybeIndefArray::Def(vec![datum]),
                        }),
                        1 => PlutusData::Map(KeyValuePairs::Def(vec![(
                            PlutusData::BigInt(BigInt::Int(Int::from(1))),
                            datum,
                        )])),
                        _ => PlutusData::Array(MaybeIndefArray::Def(vec![datum])),
                    };
                }
                // The source Drop still recurses; leak it like the result.
                let datum = std::mem::ManuallyDrop::new(datum);

                let mapped = Mapper::new(NoLedger).map_plutus_datum(&datum);

                let mut seen = 0;
                let mut cursor = &mapped;
                loop {
                    cursor = match cursor.plutus_data.as_ref().expect("mapped node") {
                        u5c::plutus_data::PlutusData::Constr(c) => c.fields.first(),
                        u5c::plutus_data::PlutusData::Map(m) => m
                            .pairs
                            .first()
                            .expect("map carries its pair")
                            .value
                            .as_ref(),
                        u5c::plutus_data::PlutusData::Array(a) => a.items.first(),
                        u5c::plutus_data::PlutusData::BigInt(_) => break,
                        other => panic!("unexpected node {other:?}"),
                    }
                    .expect("container carries a child");
                    seen += 1;
                }
                assert_eq!(seen, depth);

                // u5c's generated type has no custom Drop, so a chain this
                // deep would abort on the way out. Leak it deliberately.
                std::mem::forget(mapped);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    #[allow(deprecated)]
    fn map_native_script_handles_deeply_nested_scripts_on_a_small_stack() {
        // Depth and stack size are load-bearing, not just generous: both must
        // stay far enough apart that the old recursive mapping (one call
        // frame per level) would abort here, or this test stops proving
        // anything the moment either constant drifts.
        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let mut script =
                    pallas_primitives::alonzo::NativeScript::ScriptPubkey([0; 28].into());
                for _ in 0..20_000 {
                    script = pallas_primitives::alonzo::NativeScript::ScriptAll(vec![script]);
                }

                let mapped = Mapper::<NoLedger>::map_native_script(&script);

                let mut depth = 0;
                let mut cursor = &mapped;
                while let Some(u5c::native_script::NativeScript::ScriptAll(list)) =
                    &cursor.native_script
                {
                    cursor = list.items.first().expect("ScriptAll must carry a child");
                    depth += 1;
                }
                assert_eq!(depth, 20_000);
                assert!(matches!(
                    cursor.native_script,
                    Some(u5c::native_script::NativeScript::ScriptPubkey(_))
                ));

                // u5c's generated type has no custom Drop (unlike the source
                // NativeScript, stack-safe since pallas#802), so dropping a
                // chain this deep would abort the same way the unfixed mapping
                // did. Leak it deliberately: this test is only about the
                // mapping, and the leak is a few MB, thread-local, test-only.
                std::mem::forget(mapped);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    #[allow(deprecated)]
    fn map_native_script_preserves_mixed_shape_trees() {
        use pallas_primitives::alonzo::NativeScript;

        // Width > 1 at more than one level: the iterative rewrite pairs
        // mapped children with source children positionally, so a bug there
        // would only show up once a node has more than one child.
        let script = NativeScript::ScriptNOfK(
            2,
            vec![
                NativeScript::ScriptPubkey([1; 28].into()),
                NativeScript::ScriptAll(vec![
                    NativeScript::ScriptPubkey([2; 28].into()),
                    NativeScript::ScriptAny(vec![
                        NativeScript::InvalidBefore(100),
                        NativeScript::InvalidHereafter(200),
                    ]),
                ]),
                NativeScript::ScriptPubkey([3; 28].into()),
            ],
        );

        let mapped = Mapper::<NoLedger>::map_native_script(&script);
        let Some(u5c::native_script::NativeScript::ScriptNOfK(n_of_k)) = &mapped.native_script
        else {
            panic!("expected ScriptNOfK, got {:?}", mapped.native_script);
        };
        assert_eq!(n_of_k.k, 2);
        assert_eq!(n_of_k.scripts.len(), 3);

        assert!(matches!(
            n_of_k.scripts[0].native_script,
            Some(u5c::native_script::NativeScript::ScriptPubkey(ref b)) if b.as_ref() == [1; 28]
        ));
        assert!(matches!(
            n_of_k.scripts[2].native_script,
            Some(u5c::native_script::NativeScript::ScriptPubkey(ref b)) if b.as_ref() == [3; 28]
        ));

        let Some(u5c::native_script::NativeScript::ScriptAll(all)) =
            &n_of_k.scripts[1].native_script
        else {
            panic!(
                "expected ScriptAll, got {:?}",
                n_of_k.scripts[1].native_script
            );
        };
        assert_eq!(all.items.len(), 2);
        assert!(matches!(
            all.items[0].native_script,
            Some(u5c::native_script::NativeScript::ScriptPubkey(ref b)) if b.as_ref() == [2; 28]
        ));

        let Some(u5c::native_script::NativeScript::ScriptAny(any)) = &all.items[1].native_script
        else {
            panic!("expected ScriptAny, got {:?}", all.items[1].native_script);
        };
        assert_eq!(any.items.len(), 2);
        assert!(matches!(
            any.items[0].native_script,
            Some(u5c::native_script::NativeScript::InvalidBefore(100))
        ));
        assert!(matches!(
            any.items[1].native_script,
            Some(u5c::native_script::NativeScript::InvalidHereafter(200))
        ));
    }
}
