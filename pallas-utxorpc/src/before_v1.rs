/// Emits the parts of `Mapper<C>` that the schemas before v1 share and v1 does not.
macro_rules! impl_cardano_mapper_before_v1 {
    () => {
        impl<C: $crate::LedgerContext> Mapper<C> {
            #[deprecated(
                since = "1.5.0",
                note = "use map_multi_era_purpose. This method cannot represent the Dijkstra Guarding tag"
            )]
            pub fn map_purpose(
                &self,
                x: &pallas_primitives::conway::RedeemerTag,
            ) -> u5c::RedeemerPurpose {
                use pallas_primitives::conway;
                match x {
                    conway::RedeemerTag::Spend => u5c::RedeemerPurpose::Spend,
                    conway::RedeemerTag::Mint => u5c::RedeemerPurpose::Mint,
                    conway::RedeemerTag::Cert => u5c::RedeemerPurpose::Cert,
                    conway::RedeemerTag::Reward => u5c::RedeemerPurpose::Reward,
                    conway::RedeemerTag::Vote => u5c::RedeemerPurpose::Vote,
                    conway::RedeemerTag::Propose => u5c::RedeemerPurpose::Propose,
                }
            }

            // The released signature returned parameters whose every field is
            // its proto3 zero for a change that proposes no key u5c carries.
            #[deprecated(since = "1.5.0", note = "use Mapper::map_gov_action")]
            pub fn map_conway_gov_action(
                &self,
                x: &pallas_primitives::conway::GovAction,
            ) -> u5c::GovernanceAction {
                let mut out =
                    self.map_gov_action(&pallas_traverse::MultiEraGovAction::from_conway(x));

                if let Some(u5c::governance_action::GovernanceAction::ParameterChangeAction(
                    change,
                )) = out.governance_action.as_mut()
                {
                    change
                        .protocol_param_update
                        .get_or_insert_with(u5c::PParams::default);
                }

                out
            }

            #[deprecated(
                since = "1.5.0",
                note = "use Mapper::map_multi_era_native_script. This method cannot represent a Dijkstra script"
            )]
            pub fn map_native_script(
                x: &pallas_primitives::alonzo::NativeScript,
            ) -> u5c::NativeScript {
                use pallas_primitives::babbage;

                // Folded bottom-up rather than recursed: scripts nest as deep
                // as a transaction has bytes.
                pallas_codec::tree::fold_tree(x, |x, children: Vec<u5c::NativeScript>| {
                    let inner = match x {
                        babbage::NativeScript::ScriptPubkey(x) => {
                            Self::map_native_script_pubkey(x.to_vec())
                        }
                        babbage::NativeScript::ScriptAll(_) => {
                            u5c::native_script::NativeScript::ScriptAll(u5c::NativeScriptList {
                                items: children,
                            })
                        }
                        babbage::NativeScript::ScriptAny(_) => {
                            u5c::native_script::NativeScript::ScriptAny(u5c::NativeScriptList {
                                items: children,
                            })
                        }
                        babbage::NativeScript::ScriptNOfK(n, _) => {
                            u5c::native_script::NativeScript::ScriptNOfK(u5c::ScriptNOfK {
                                // u5c's `k` is wire-fixed at uint32, the ledger's threshold is
                                // i64: clamp rather than cast, or a negative value wraps into
                                // an unsatisfiable one instead of the satisfiable 0 it means.
                                k: (*n).clamp(0, i64::from(u32::MAX)) as u32,
                                scripts: children,
                            })
                        }
                        babbage::NativeScript::InvalidBefore(s) => {
                            u5c::native_script::NativeScript::InvalidBefore(*s)
                        }
                        babbage::NativeScript::InvalidHereafter(s) => {
                            u5c::native_script::NativeScript::InvalidHereafter(*s)
                        }
                    };
                    u5c::NativeScript {
                        native_script: Some(inner),
                    }
                })
            }

            #[deprecated(since = "1.5.0", note = "use Mapper::map_script_ref")]
            pub fn map_any_script(&self, x: &pallas_primitives::conway::ScriptRef) -> u5c::Script {
                self.map_script_ref(&pallas_traverse::MultiEraScriptRef::from_conway(x))
            }

            #[deprecated(
                since = "1.5.0",
                note = "use Mapper::map_cert or Mapper::map_cert_kind"
            )]
            pub fn map_alonzo_compatible_cert(
                &self,
                x: &pallas_primitives::alonzo::Certificate,
                tx: &pallas_traverse::MultiEraTx,
                order: u32,
            ) -> u5c::Certificate {
                let cert = pallas_traverse::MultiEraCert::AlonzoCompatible(Box::new(
                    std::borrow::Cow::Borrowed(x),
                ));

                self.map_cert(&cert, tx, order)
                    .expect("an Alonzo compatible certificate is always applicable")
            }

            #[deprecated(
                since = "1.5.0",
                note = "use Mapper::map_cert or Mapper::map_cert_kind"
            )]
            pub fn map_conway_cert(
                &self,
                x: &pallas_primitives::conway::Certificate,
                tx: &pallas_traverse::MultiEraTx,
                order: u32,
            ) -> u5c::Certificate {
                let cert = pallas_traverse::MultiEraCert::Conway(Box::new(
                    std::borrow::Cow::Borrowed(x),
                ));

                self.map_cert(&cert, tx, order)
                    .expect("a Conway certificate is always applicable")
            }

            // An update that proposes no key reached this signature as a
            // PParams of default fields, which is what None becomes here.
            #[deprecated(since = "1.5.0", note = "use Mapper::map_pparams_update")]
            pub fn map_conway_pparams_update(
                &self,
                x: &pallas_primitives::conway::ProtocolParamUpdate,
            ) -> u5c::PParams {
                let update = pallas_traverse::MultiEraParamUpdate::Conway(Box::new(
                    std::borrow::Cow::Borrowed(x),
                ));

                self.map_pparams_update(&update).unwrap_or_default()
            }
        }

        #[cfg(test)]
        mod before_v1_tests {
            use super::*;

            use pallas_primitives::{alonzo, conway};
            use pallas_traverse as trv;
            use pallas_traverse::MultiEraTx;
            use pretty_assertions::assert_eq;

            use super::cert_tests::{
                CREDENTIAL, EPOCH, POOL, credential, key_credential, tx_with_redeemers,
            };
            use super::mapper_tests::{every_key_as_pparams, parameter_change};
            use $crate::testing::*;

            #[test]
            #[allow(deprecated)]
            fn the_era_specific_mappers_map_through_the_certificate_view() {
                let raw = tx_with_redeemers(vec![conway::Redeemer {
                    tag: conway::RedeemerTag::Cert,
                    index: 1,
                    data: pallas_primitives::PlutusData::BoundedBytes(vec![0x0f].into()),
                    ex_units: pallas_primitives::ExUnits {
                        mem: 11,
                        steps: 22,
                    },
                }]);
                let tx = MultiEraTx::from_conway(&raw);
                let mapper = Mapper::new(NoLedger);

                let conway_certificate = conway::Certificate::StakeRegistration(credential());

                assert_eq!(
                    mapper.map_conway_cert(&conway_certificate, &tx, 0),
                    u5c::Certificate {
                        certificate: Some(
                            u5c::certificate::Certificate::StakeRegistration(key_credential(
                                CREDENTIAL
                            ))
                        ),
                        redeemer: None,
                    }
                );
                assert_eq!(
                    mapper
                        .map_conway_cert(&conway_certificate, &tx, 1)
                        .redeemer
                        .map(|r| r.index),
                    Some(1),
                    "position one is indexed by a certificate redeemer"
                );

                let alonzo_certificate = alonzo::Certificate::PoolRetirement(POOL.into(), EPOCH);

                assert_eq!(
                    mapper.map_alonzo_compatible_cert(&alonzo_certificate, &tx, 0),
                    u5c::Certificate {
                        certificate: Some(u5c::certificate::Certificate::PoolRetirement(
                            u5c::PoolRetirementCert {
                                pool_keyhash: POOL.to_vec().into(),
                                epoch: EPOCH,
                            }
                        )),
                        redeemer: None,
                    }
                );
                assert_eq!(
                    mapper
                        .map_alonzo_compatible_cert(&alonzo_certificate, &tx, 1)
                        .redeemer
                        .map(|r| r.index),
                    Some(1),
                    "position one is indexed by a certificate redeemer"
                );
            }

            #[test]
            #[allow(deprecated)]
            fn the_deprecated_pparams_update_mapper_answers_as_v1_4_0_did() {
                let mapper = Mapper::new(NoLedger);

                let every = conway_update_of_every_key();
                assert_eq!(
                    mapper.map_conway_pparams_update(&every),
                    every_key_as_pparams(None),
                    "every key this signature read before must still reach the u5c field that key means"
                );

                let blank = conway_update_of_no_key();
                assert_eq!(
                    mapper.map_conway_pparams_update(&blank),
                    u5c::PParams::default(),
                    "an update proposing no key reached this signature as parameters whose every field is its proto3 zero"
                );
                assert_eq!(
                    mapper.map_pparams_update(&trv::MultiEraParamUpdate::Conway(Box::new(
                        std::borrow::Cow::Borrowed(&blank)
                    ))),
                    None,
                    "the era neutral signature tells that update apart from one proposing zeros, which is the distinction the deprecated return type cannot carry"
                );
            }

            #[test]
            #[allow(deprecated)]
            fn the_deprecated_gov_action_mapper_answers_as_v1_4_0_did() {
                let mapper = Mapper::new(NoLedger);

                let empty = conway_parameter_change(&[0xa0]);
                assert_eq!(
                    parameter_change(mapper.map_conway_gov_action(&empty)).protocol_param_update,
                    Some(u5c::PParams::default()),
                    "a parameter change proposing no key reached this signature carrying parameters whose every field is its proto3 zero"
                );
                assert_eq!(
                    parameter_change(
                        mapper.map_gov_action(&trv::MultiEraGovAction::from_conway(&empty))
                    )
                    .protocol_param_update,
                    None,
                    "the era neutral signature reports that same action as proposing no parameters, and only the deprecated one fills the field"
                );

                let one_key = conway_parameter_change(&[0xa1, 0x00, 0x19, 0x03, 0xe8]);
                assert_eq!(
                    mapper.map_conway_gov_action(&one_key),
                    mapper.map_gov_action(&trv::MultiEraGovAction::from_conway(&one_key)),
                    "an action that does propose a key maps the same through either signature"
                );
            }

            #[test]
            #[allow(deprecated)]
            fn the_deprecated_any_script_mapper_answers_as_v1_4_0_did() {
                let mapper = Mapper::new(NoLedger);

                let native = conway_native_script_ref([0x71; 28]);
                assert_eq!(
                    mapper.map_any_script(&native).script,
                    Some(u5c::script::Script::Native(
                        Mapper::<NoLedger>::map_native_script(
                            &pallas_primitives::alonzo::NativeScript::ScriptPubkey(
                                [0x71; 28].into()
                            )
                        )
                    )),
                    "a native reference script reaches the native field carrying what the alonzo walk makes of the same script"
                );

                let plutus = [
                    (
                        1u8,
                        [0x01u8, 0xaa],
                        u5c::script::Script::PlutusV1(vec![0x01u8, 0xaa].into()),
                        u5c::script::Script::PlutusV1(vec![0x01u8, 0x55].into()),
                    ),
                    (
                        2,
                        [0x02, 0xbb],
                        u5c::script::Script::PlutusV2(vec![0x02u8, 0xbb].into()),
                        u5c::script::Script::PlutusV2(vec![0x02u8, 0x44].into()),
                    ),
                    (
                        3,
                        [0x03, 0xcc],
                        u5c::script::Script::PlutusV3(vec![0x03u8, 0xcc].into()),
                        u5c::script::Script::PlutusV3(vec![0x03u8, 0x33].into()),
                    ),
                ];

                for (language, bytes, expected, other_bytes) in plutus {
                    let script_ref = conway_plutus_script_ref(language, &bytes);

                    assert_eq!(
                        mapper.map_any_script(&script_ref).script,
                        Some(expected),
                        "a Plutus reference script of language {language} reaches the field of that language carrying its own bytes"
                    );
                    assert_ne!(
                        mapper.map_any_script(&script_ref).script,
                        Some(other_bytes),
                        "the field carries the script's own bytes, so bytes it did not carry must not match"
                    );
                }
            }
        }
    };
}

pub(crate) use impl_cardano_mapper_before_v1;
