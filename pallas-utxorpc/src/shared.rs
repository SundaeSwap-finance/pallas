/// Emits the version-agnostic body of `Mapper<C: LedgerContext>` for a given
/// `utxorpc_spec::utxorpc::vXxxx::cardano` module path. A method the two
/// schemas write differently (`map_tx_datum`, `map_tx_output`, `map_asset`,
/// `map_policy_assets`, `map_tx`) is defined by each version's `mod.rs` in a
/// separate impl block. A method differing in one expression is emitted here
/// and calls a per version leaf that module defines.
macro_rules! impl_cardano_mapper_shared {
    ($u5c:path) => {
        use $u5c as u5c;

        fn rational_number_to_u5c(value: pallas_primitives::RationalNumber) -> u5c::RationalNumber {
            u5c::RationalNumber {
                numerator: value.numerator as i32,
                denominator: value.denominator as u32,
            }
        }

        fn u64_to_bigint(value: u64) -> Option<u5c::BigInt> {
            if value <= i64::MAX as u64 {
                Some(u5c::BigInt {
                    big_int: Some(u5c::big_int::BigInt::Int(value as i64)),
                })
            } else {
                Some(u5c::BigInt {
                    big_int: Some(u5c::big_int::BigInt::BigUInt(
                        value.to_be_bytes().to_vec().into(),
                    )),
                })
            }
        }

        fn i64_to_bigint(value: i64) -> Option<u5c::BigInt> {
            Some(u5c::BigInt {
                big_int: Some(u5c::big_int::BigInt::Int(value)),
            })
        }

        fn execution_prices_to_u5c(value: pallas_primitives::ExUnitPrices) -> u5c::ExPrices {
            u5c::ExPrices {
                steps: Some(rational_number_to_u5c(value.step_price)),
                memory: Some(rational_number_to_u5c(value.mem_price)),
            }
        }

        fn execution_units_to_u5c(value: pallas_primitives::ExUnits) -> u5c::ExUnits {
            u5c::ExUnits {
                memory: value.mem,
                steps: value.steps,
            }
        }

        /// Wrap one script of a named language in the u5c envelope.
        fn envelope(inner: u5c::script::Script) -> u5c::Script {
            u5c::Script {
                script: Some(inner),
            }
        }

        /// Map every script of one Plutus version, under the variant that names
        /// it. The variant is a tuple constructor, so it is passed as the
        /// function it is.
        fn plutus<'a, const V: usize, B: From<Vec<u8>> + 'a>(
            scripts: &'a [pallas_primitives::PlutusScript<V>],
            wrap: fn(B) -> u5c::script::Script,
        ) -> impl Iterator<Item = u5c::Script> + 'a {
            scripts.iter().map(move |x| {
                let inner = wrap(x.0.to_vec().into());
                envelope(inner)
            })
        }

        /// Pass a key's value through, noting whether the update set it. Every
        /// accessor the parameter mapper reads uses this, so one list of keys
        /// serves both the mapped value and the decision to report no update at
        /// all.
        fn read_key<T>(any_set: &mut bool, value: Option<T>) -> Option<T> {
            *any_set |= value.is_some();
            value
        }

        /// One native script node without its children, in the terms u5c
        /// names. An era's enum is read into this once, so the mapping from a
        /// clause to its u5c member is written once for every era.
        enum NativeClause<'a> {
            Pubkey(&'a pallas_crypto::hash::Hash<28>),
            All,
            Any,
            NOfK(i64),
            InvalidBefore(u64),
            InvalidHereafter(u64),
            /// The clause Dijkstra adds, which u5c has no member for.
            #[cfg(feature = "unstable")]
            Guard,
        }

        /// Map an anchor, whose type every era carrying one shares.
        fn map_anchor(x: &pallas_primitives::conway::Anchor) -> u5c::Anchor {
            u5c::Anchor {
                url: x.url.clone(),
                content_hash: x.content_hash.to_vec().into(),
            }
        }

        /// Map the metadata a pool registration points at, whose type every era
        /// carrying one shares.
        fn map_pool_metadata(x: &pallas_primitives::PoolMetadata) -> u5c::PoolMetadata {
            u5c::PoolMetadata {
                url: x.url.clone(),
                hash: x.hash.to_vec().into(),
            }
        }

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

            pub fn map_multi_era_purpose(
                &self,
                x: &pallas_traverse::MultiEraRedeemerTag,
            ) -> u5c::RedeemerPurpose {
                use pallas_traverse::MultiEraRedeemerTag;

                match x {
                    MultiEraRedeemerTag::Spend => u5c::RedeemerPurpose::Spend,
                    MultiEraRedeemerTag::Mint => u5c::RedeemerPurpose::Mint,
                    MultiEraRedeemerTag::Cert => u5c::RedeemerPurpose::Cert,
                    MultiEraRedeemerTag::Reward => u5c::RedeemerPurpose::Reward,
                    MultiEraRedeemerTag::Vote => u5c::RedeemerPurpose::Vote,
                    MultiEraRedeemerTag::Propose => u5c::RedeemerPurpose::Propose,
                    // u5c has no guarding purpose.
                    #[cfg(feature = "unstable")]
                    MultiEraRedeemerTag::Guarding => u5c::RedeemerPurpose::Unspecified,
                    _ => unimplemented!("map_multi_era_purpose has no arm for this purpose"),
                }
            }

            pub fn map_redeemer(&self, x: &pallas_traverse::MultiEraRedeemer) -> u5c::Redeemer {
                u5c::Redeemer {
                    purpose: self.map_multi_era_purpose(&x.multi_era_tag()).into(),
                    payload: self.map_plutus_datum(x.data()).into(),
                    index: x.index(),
                    ex_units: Some(u5c::ExUnits {
                        steps: x.ex_units().steps,
                        memory: x.ex_units().mem,
                    }),
                    original_cbor: x.encode().into(),
                }
            }

            fn decode_resolved_utxo(
                &self,
                resolved: &Option<$crate::UtxoMap>,
                input: &pallas_traverse::MultiEraInput,
                tx: &pallas_traverse::MultiEraTx,
            ) -> Option<u5c::TxOutput> {
                let as_txref = (*input.hash(), input.index() as u32);

                resolved
                    .as_ref()
                    .and_then(|x| x.get(&as_txref))
                    .and_then(|(era, cbor)| {
                        let o =
                            pallas_traverse::MultiEraOutput::decode(*era, cbor.as_slice()).ok()?;
                        Some(self.map_tx_output(&o, Some(tx)))
                    })
            }

            pub fn map_tx_input(
                &self,
                input: &pallas_traverse::MultiEraInput,
                tx: &pallas_traverse::MultiEraTx,
                order: u32,
                resolved: &Option<$crate::UtxoMap>,
            ) -> u5c::TxInput {
                u5c::TxInput {
                    tx_hash: input.hash().to_vec().into(),
                    output_index: input.index() as u32,
                    as_output: self.decode_resolved_utxo(resolved, input, tx),
                    redeemer: tx.find_spend_redeemer(order).map(|x| self.map_redeemer(&x)),
                }
            }

            pub fn map_tx_reference_input(
                &self,
                input: &pallas_traverse::MultiEraInput,
                resolved: &Option<$crate::UtxoMap>,
                tx: &pallas_traverse::MultiEraTx,
            ) -> u5c::TxInput {
                u5c::TxInput {
                    tx_hash: input.hash().to_vec().into(),
                    output_index: input.index() as u32,
                    as_output: self.decode_resolved_utxo(resolved, input, tx),
                    redeemer: None,
                }
            }

            pub fn map_tx_collateral(
                &self,
                input: &pallas_traverse::MultiEraInput,
                resolved: &Option<$crate::UtxoMap>,
                tx: &pallas_traverse::MultiEraTx,
            ) -> u5c::TxInput {
                u5c::TxInput {
                    tx_hash: input.hash().to_vec().into(),
                    output_index: input.index() as u32,
                    as_output: self.decode_resolved_utxo(resolved, input, tx),
                    redeemer: None,
                }
            }

            pub fn map_script_ref(&self, x: &pallas_traverse::MultiEraScriptRef) -> u5c::Script {
                use pallas_traverse::script_ref::ScriptLanguage;

                let bytes = || x.plutus_bytes().unwrap_or_default().to_vec();

                let inner = match x.language() {
                    ScriptLanguage::Native => {
                        u5c::script::Script::Native(Self::map_multi_era_native_script(
                            &x.native_script().expect(
                                "a script whose language is native carries a native script",
                            ),
                        ))
                    }
                    ScriptLanguage::PlutusV1 => u5c::script::Script::PlutusV1(bytes().into()),
                    ScriptLanguage::PlutusV2 => u5c::script::Script::PlutusV2(bytes().into()),
                    ScriptLanguage::PlutusV3 => u5c::script::Script::PlutusV3(bytes().into()),
                    #[cfg(feature = "unstable")]
                    ScriptLanguage::PlutusV4 => u5c::script::Script::PlutusV4(bytes().into()),
                    other => panic!("u5c has no script field for {other:?}"),
                };

                envelope(inner)
            }

            /// A guard clause has no u5c field and maps to an empty message.
            /// Rebuild one node over children already mapped.
            fn native_script_node(
                clause: NativeClause,
                children: Vec<u5c::NativeScript>,
            ) -> u5c::NativeScript {
                let inner = match clause {
                    NativeClause::Pubkey(x) => Self::map_native_script_pubkey(x.to_vec()),
                    NativeClause::All => {
                        u5c::native_script::NativeScript::ScriptAll(u5c::NativeScriptList {
                            items: children,
                        })
                    }
                    NativeClause::Any => {
                        u5c::native_script::NativeScript::ScriptAny(u5c::NativeScriptList {
                            items: children,
                        })
                    }
                    NativeClause::NOfK(k) => {
                        u5c::native_script::NativeScript::ScriptNOfK(u5c::ScriptNOfK {
                            // u5c's `k` is wire-fixed at uint32, the ledger's threshold is
                            // i64: clamp rather than cast, or a negative value wraps into
                            // an unsatisfiable one instead of the satisfiable 0 it means.
                            k: k.clamp(0, i64::from(u32::MAX)) as u32,
                            scripts: children,
                        })
                    }
                    NativeClause::InvalidBefore(s) => {
                        u5c::native_script::NativeScript::InvalidBefore(s)
                    }
                    NativeClause::InvalidHereafter(s) => {
                        u5c::native_script::NativeScript::InvalidHereafter(s)
                    }
                    #[cfg(feature = "unstable")]
                    NativeClause::Guard => {
                        return u5c::NativeScript {
                            native_script: None,
                        };
                    }
                };

                u5c::NativeScript {
                    native_script: Some(inner),
                }
            }

            pub fn map_multi_era_native_script(
                x: &pallas_traverse::MultiEraNativeScript,
            ) -> u5c::NativeScript {
                // Folded bottom-up rather than recursed: scripts nest as deep
                // as a transaction has bytes.
                if let Some(x) = x.as_alonzo_compatible() {
                    return pallas_codec::tree::fold_tree(x, |node, children| {
                        use pallas_primitives::alonzo::NativeScript;

                        Self::native_script_node(
                            match node {
                                NativeScript::ScriptPubkey(x) => NativeClause::Pubkey(x),
                                NativeScript::ScriptAll(_) => NativeClause::All,
                                NativeScript::ScriptAny(_) => NativeClause::Any,
                                NativeScript::ScriptNOfK(k, _) => NativeClause::NOfK(*k),
                                NativeScript::InvalidBefore(s) => NativeClause::InvalidBefore(*s),
                                NativeScript::InvalidHereafter(s) => {
                                    NativeClause::InvalidHereafter(*s)
                                }
                            },
                            children,
                        )
                    });
                }

                #[cfg(feature = "unstable")]
                if let Some(x) = x.as_dijkstra() {
                    return pallas_codec::tree::fold_tree(x, |node, children| {
                        use pallas_primitives::dijkstra::NativeScript;

                        Self::native_script_node(
                            match node {
                                NativeScript::ScriptPubkey(x) => NativeClause::Pubkey(x),
                                NativeScript::ScriptAll(_) => NativeClause::All,
                                NativeScript::ScriptAny(_) => NativeClause::Any,
                                NativeScript::ScriptNOfK(k, _) => NativeClause::NOfK(*k),
                                NativeScript::InvalidBefore(s) => NativeClause::InvalidBefore(*s),
                                NativeScript::InvalidHereafter(s) => {
                                    NativeClause::InvalidHereafter(*s)
                                }
                                NativeScript::ScriptRequireGuard(_) => NativeClause::Guard,
                            },
                            children,
                        )
                    });
                }

                unimplemented!("map_multi_era_native_script has no arm for this era")
            }

            pub fn map_gov_action(
                &self,
                x: &pallas_traverse::MultiEraGovAction,
            ) -> u5c::GovernanceAction {
                use pallas_traverse::MultiEraGovActionKind;

                let inner = match x.kind() {
                    MultiEraGovActionKind::ParameterChange(gov_id, params, script) => {
                        u5c::governance_action::GovernanceAction::ParameterChangeAction(
                            u5c::ParameterChangeAction {
                                gov_action_id: self.map_gov_action_id(&gov_id.cloned()),
                                protocol_param_update: self.map_pparams_update(&params),
                                policy_hash: script
                                    .map(|x| x.to_vec())
                                    .unwrap_or_default()
                                    .into(),
                            },
                        )
                    }
                    MultiEraGovActionKind::HardForkInitiation(gov_id, version) => {
                        u5c::governance_action::GovernanceAction::HardForkInitiationAction(
                            u5c::HardForkInitiationAction {
                                gov_action_id: self.map_gov_action_id(&gov_id.cloned()),
                                protocol_version: Some(u5c::ProtocolVersion {
                                    major: version.0 as u32,
                                    minor: version.1 as u32,
                                }),
                            },
                        )
                    }
                    MultiEraGovActionKind::TreasuryWithdrawals(withdrawals, script) => {
                        u5c::governance_action::GovernanceAction::TreasuryWithdrawalsAction(
                            u5c::TreasuryWithdrawalsAction {
                                withdrawals: withdrawals
                                    .iter()
                                    .map(|(k, v)| u5c::WithdrawalAmount {
                                        reward_account: k.to_vec().into(),
                                        coin: u64_to_bigint(*v),
                                    })
                                    .collect(),
                                policy_hash: script
                                    .map(|x| x.to_vec())
                                    .unwrap_or_default()
                                    .into(),
                            },
                        )
                    }
                    MultiEraGovActionKind::NoConfidence(gov_id) => {
                        u5c::governance_action::GovernanceAction::NoConfidenceAction(
                            u5c::NoConfidenceAction {
                                gov_action_id: self.map_gov_action_id(&gov_id.cloned()),
                            },
                        )
                    }
                    MultiEraGovActionKind::UpdateCommittee(gov_id, remove, add, threshold) => {
                        u5c::governance_action::GovernanceAction::UpdateCommitteeAction(
                            u5c::UpdateCommitteeAction {
                                gov_action_id: self.map_gov_action_id(&gov_id.cloned()),
                                remove_committee_credentials: remove
                                    .iter()
                                    .map(|x| self.map_stake_credential(x))
                                    .collect(),
                                new_committee_credentials: add
                                    .iter()
                                    .map(|(cred, epoch)| u5c::NewCommitteeCredentials {
                                        committee_cold_credential: Some(
                                            self.map_stake_credential(cred),
                                        ),
                                        expires_epoch: *epoch as u32,
                                    })
                                    .collect(),
                                new_committee_threshold: Some(rational_number_to_u5c(
                                    threshold.clone(),
                                )),
                            },
                        )
                    }
                    MultiEraGovActionKind::NewConstitution(gov_id, constitution) => {
                        u5c::governance_action::GovernanceAction::NewConstitutionAction(
                            u5c::NewConstitutionAction {
                                gov_action_id: self.map_gov_action_id(&gov_id.cloned()),
                                constitution: Some(u5c::Constitution {
                                    anchor: Some(map_anchor(&constitution.anchor)),
                                    hash: constitution
                                        .guardrail_script
                                        .map(|x| x.to_vec())
                                        .unwrap_or_default()
                                        .into(),
                                }),
                            },
                        )
                    }
                    MultiEraGovActionKind::Information => information_action(),
                    _ => unimplemented!("map_gov_action has no arm for this governance action"),
                };

                u5c::GovernanceAction {
                    governance_action: Some(inner),
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

            pub fn map_stake_credential(
                &self,
                x: &pallas_primitives::babbage::StakeCredential,
            ) -> u5c::StakeCredential {
                use pallas_primitives::babbage;
                let inner = match x {
                    babbage::StakeCredential::AddrKeyhash(x) => {
                        u5c::stake_credential::StakeCredential::AddrKeyHash(x.to_vec().into())
                    }
                    babbage::StakeCredential::ScriptHash(x) => {
                        u5c::stake_credential::StakeCredential::ScriptHash(x.to_vec().into())
                    }
                };

                u5c::StakeCredential {
                    stake_credential: inner.into(),
                }
            }

            pub fn map_relay(&self, x: &pallas_primitives::alonzo::Relay) -> u5c::Relay {
                use pallas_primitives::babbage;
                match x {
                    babbage::Relay::SingleHostAddr(port, v4, v6) => u5c::Relay {
                        ip_v4: v4.clone().map(|x| x.to_vec().into()).unwrap_or_default(),
                        ip_v6: v6.clone().map(|x| x.to_vec().into()).unwrap_or_default(),
                        dns_name: String::default(),
                        port: (*port).unwrap_or_default(),
                    },
                    babbage::Relay::SingleHostName(port, name) => u5c::Relay {
                        ip_v4: Default::default(),
                        ip_v6: Default::default(),
                        dns_name: name.clone(),
                        port: (*port).unwrap_or_default(),
                    },
                    babbage::Relay::MultiHostName(name) => u5c::Relay {
                        ip_v4: Default::default(),
                        ip_v6: Default::default(),
                        dns_name: name.clone(),
                        port: Default::default(),
                    },
                }
            }

            pub fn map_withdrawals(
                &self,
                x: &(&[u8], u64),
                tx: &pallas_traverse::MultiEraTx,
                order: u32,
            ) -> u5c::Withdrawal {
                u5c::Withdrawal {
                    reward_account: Vec::from(x.0).into(),
                    coin: u64_to_bigint(x.1),
                    redeemer: tx
                        .find_withdrawal_redeemer(order)
                        .map(|x| self.map_redeemer(&x)),
                }
            }

            pub fn map_vkey_witness(
                &self,
                x: &pallas_primitives::alonzo::VKeyWitness,
            ) -> u5c::VKeyWitness {
                u5c::VKeyWitness {
                    vkey: x.vkey.to_vec().into(),
                    signature: x.signature.to_vec().into(),
                }
            }

            fn collect_all_scripts(&self, tx: &pallas_traverse::MultiEraTx) -> Vec<u5c::Script> {
                let ns = tx
                    .multi_era_native_scripts()
                    .into_iter()
                    .map(|x| {
                        let inner =
                            u5c::script::Script::Native(Self::map_multi_era_native_script(&x));
                        envelope(inner)
                    })
                    .collect::<Vec<_>>()
                    .into_iter();

                ns.chain(plutus(
                    tx.plutus_v1_scripts(),
                    u5c::script::Script::PlutusV1,
                ))
                .chain(plutus(
                    tx.plutus_v2_scripts(),
                    u5c::script::Script::PlutusV2,
                ))
                .chain(plutus(
                    tx.plutus_v3_scripts(),
                    u5c::script::Script::PlutusV3,
                ))
                .collect()
            }

            pub fn map_plutus_constr(
                &self,
                x: &pallas_primitives::alonzo::Constr<pallas_primitives::alonzo::PlutusData>,
            ) -> u5c::Constr {
                u5c::Constr {
                    tag: x.tag as u32,
                    any_constructor: x.any_constructor.unwrap_or_default(),
                    fields: x.fields.iter().map(|x| self.map_plutus_datum(x)).collect(),
                }
            }

            pub fn map_plutus_map(
                &self,
                x: &pallas_codec::utils::KeyValuePairs<
                    pallas_primitives::alonzo::PlutusData,
                    pallas_primitives::alonzo::PlutusData,
                >,
            ) -> u5c::PlutusDataMap {
                u5c::PlutusDataMap {
                    pairs: x
                        .iter()
                        .map(|(k, v)| u5c::PlutusDataPair {
                            key: self.map_plutus_datum(k).into(),
                            value: self.map_plutus_datum(v).into(),
                        })
                        .collect(),
                }
            }

            pub fn map_plutus_array(
                &self,
                x: &[pallas_primitives::alonzo::PlutusData],
            ) -> u5c::PlutusDataArray {
                u5c::PlutusDataArray {
                    items: x.iter().map(|x| self.map_plutus_datum(x)).collect(),
                }
            }

            pub fn map_plutus_bigint(&self, x: &pallas_primitives::alonzo::BigInt) -> u5c::BigInt {
                use pallas_primitives::babbage;
                let inner = match x {
                    babbage::BigInt::Int(x) => u5c::big_int::BigInt::Int(i128::from(x.0) as i64),
                    babbage::BigInt::BigUInt(x) => {
                        u5c::big_int::BigInt::BigUInt(Vec::<u8>::from(x.clone()).into())
                    }
                    babbage::BigInt::BigNInt(x) => {
                        u5c::big_int::BigInt::BigNInt(Vec::<u8>::from(x.clone()).into())
                    }
                };

                u5c::BigInt {
                    big_int: inner.into(),
                }
            }

            pub fn map_plutus_datum(
                &self,
                x: &pallas_primitives::alonzo::PlutusData,
            ) -> u5c::PlutusData {
                use pallas_primitives::babbage;

                // Folded bottom-up rather than recursed: datums nest as deep
                // as a transaction has bytes.
                pallas_codec::tree::fold_tree(x, |x, children: Vec<u5c::PlutusData>| {
                    let inner = match x {
                        babbage::PlutusData::Constr(x) => {
                            u5c::plutus_data::PlutusData::Constr(u5c::Constr {
                                tag: x.tag as u32,
                                any_constructor: x.any_constructor.unwrap_or_default(),
                                fields: children,
                            })
                        }
                        babbage::PlutusData::Map(_) => {
                            let mut children = children.into_iter();
                            let mut pairs = Vec::with_capacity(children.len() / 2);
                            while let (Some(key), Some(value)) = (children.next(), children.next())
                            {
                                pairs.push(u5c::PlutusDataPair {
                                    key: key.into(),
                                    value: value.into(),
                                });
                            }
                            u5c::plutus_data::PlutusData::Map(u5c::PlutusDataMap { pairs })
                        }
                        babbage::PlutusData::Array(_) => {
                            u5c::plutus_data::PlutusData::Array(u5c::PlutusDataArray {
                                items: children,
                            })
                        }
                        babbage::PlutusData::BigInt(x) => {
                            u5c::plutus_data::PlutusData::BigInt(self.map_plutus_bigint(x))
                        }
                        babbage::PlutusData::BoundedBytes(x) => {
                            u5c::plutus_data::PlutusData::BoundedBytes(x.to_vec().into())
                        }
                    };

                    u5c::PlutusData {
                        plutus_data: inner.into(),
                    }
                })
            }

            pub fn map_gov_action_id(
                &self,
                x: &Option<pallas_primitives::conway::GovActionId>,
            ) -> Option<u5c::GovernanceActionId> {
                x.as_ref().map(|inner| u5c::GovernanceActionId {
                    transaction_id: inner.transaction_id.to_vec().into(),
                    governance_action_index: inner.action_index,
                })
            }

            pub fn map_gov_proposal(
                &self,
                x: &pallas_traverse::MultiEraProposal,
            ) -> u5c::GovernanceActionProposal {
                u5c::GovernanceActionProposal {
                    deposit: u64_to_bigint(x.deposit()),
                    reward_account: x.reward_account().to_vec().into(),
                    gov_action: Some(self.map_gov_action(&x.gov_action())),
                    anchor: Some(map_anchor(x.anchor())),
                }
            }

            pub fn map_metadatum(x: &pallas_primitives::alonzo::Metadatum) -> u5c::Metadatum {
                use pallas_primitives::babbage;

                // Folded bottom-up rather than recursed: metadata nests as
                // deep as a transaction has bytes.
                pallas_codec::tree::fold_tree(x, |x, children: Vec<u5c::Metadatum>| {
                    let inner = match x {
                        babbage::Metadatum::Int(x) => {
                            u5c::metadatum::Metadatum::Int(i128::from(x.0) as i64)
                        }
                        babbage::Metadatum::Bytes(x) => {
                            u5c::metadatum::Metadatum::Bytes(Vec::<u8>::from(x.clone()).into())
                        }
                        babbage::Metadatum::Text(x) => u5c::metadatum::Metadatum::Text(x.clone()),
                        babbage::Metadatum::Array(_) => {
                            u5c::metadatum::Metadatum::Array(u5c::MetadatumArray {
                                items: children,
                            })
                        }
                        babbage::Metadatum::Map(_) => {
                            let mut children = children.into_iter();
                            let mut pairs = Vec::with_capacity(children.len() / 2);
                            while let (Some(key), Some(value)) = (children.next(), children.next())
                            {
                                pairs.push(u5c::MetadatumPair {
                                    key: key.into(),
                                    value: value.into(),
                                });
                            }
                            u5c::metadatum::Metadatum::Map(u5c::MetadatumMap { pairs })
                        }
                    };

                    u5c::Metadatum {
                        metadatum: inner.into(),
                    }
                })
            }

            pub fn map_metadata(
                &self,
                label: u64,
                datum: &pallas_primitives::alonzo::Metadatum,
            ) -> u5c::Metadata {
                u5c::Metadata {
                    label,
                    value: Self::map_metadatum(datum).into(),
                }
            }

            fn collect_all_aux_scripts(
                &self,
                tx: &pallas_traverse::MultiEraTx,
            ) -> Vec<u5c::Script> {
                let ns = tx
                    .multi_era_aux_native_scripts()
                    .into_iter()
                    .map(|x| {
                        let inner =
                            u5c::script::Script::Native(Self::map_multi_era_native_script(&x));
                        envelope(inner)
                    })
                    .collect::<Vec<_>>()
                    .into_iter();

                ns.chain(plutus(
                    tx.aux_plutus_v1_scripts(),
                    u5c::script::Script::PlutusV1,
                ))
                .chain(plutus(
                    tx.aux_plutus_v2_scripts(),
                    u5c::script::Script::PlutusV2,
                ))
                .chain(plutus(
                    tx.aux_plutus_v3_scripts(),
                    u5c::script::Script::PlutusV3,
                ))
                .chain(plutus(
                    tx.aux_plutus_v4_scripts(),
                    u5c::script::Script::PlutusV4,
                ))
                .collect()
            }

            fn find_related_inputs(&self, tx: &pallas_traverse::MultiEraTx) -> Vec<$crate::TxoRef> {
                let inputs = tx
                    .inputs()
                    .into_iter()
                    .map(|x| (*x.hash(), x.index() as u32));

                let collateral = tx
                    .collateral()
                    .into_iter()
                    .map(|x| (*x.hash(), x.index() as u32));

                let reference_inputs = tx
                    .reference_inputs()
                    .into_iter()
                    .map(|x| (*x.hash(), x.index() as u32));

                inputs.chain(collateral).chain(reference_inputs).collect()
            }

            pub fn map_block(&self, block: &pallas_traverse::MultiEraBlock) -> u5c::Block {
                u5c::Block {
                    header: u5c::BlockHeader {
                        slot: block.slot(),
                        hash: block.hash().to_vec().into(),
                        height: block.number(),
                    }
                    .into(),
                    body: u5c::BlockBody {
                        tx: block.txs().iter().map(|x| self.map_tx(x)).collect(),
                    }
                    .into(),
                    // The spec declares `Block.timestamp` as milliseconds;
                    // `get_slot_timestamp` returns UNIX seconds.
                    timestamp: self
                        .ledger
                        .as_ref()
                        .and_then(|ledger| ledger.get_slot_timestamp(block.slot()))
                        .map(|seconds| seconds * 1000)
                        .unwrap_or(0),
                }
            }

            pub fn map_block_cbor(&self, raw: &[u8]) -> u5c::Block {
                let block = pallas_traverse::MultiEraBlock::decode(raw).unwrap();
                self.map_block(&block)
            }
        }

        // ---- certificates ----------------------------------------------------

        impl<C: $crate::LedgerContext> Mapper<C> {
            /// Close a mapped certificate over the redeemer the transaction
            /// pairs with the certificate at this position.
            fn certificate(
                &self,
                inner: Option<u5c::certificate::Certificate>,
                tx: &pallas_traverse::MultiEraTx,
                order: u32,
            ) -> u5c::Certificate {
                u5c::Certificate {
                    certificate: inner,
                    redeemer: tx
                        .find_certificate_redeemer(order)
                        .map(|r| self.map_redeemer(&r)),
                }
            }

            pub fn map_drep(&self, x: &pallas_primitives::conway::DRep) -> u5c::DRep {
                use pallas_primitives::conway;
                u5c::DRep {
                    drep: match x {
                        conway::DRep::Key(x) => {
                            u5c::d_rep::Drep::AddrKeyHash(x.to_vec().into()).into()
                        }
                        conway::DRep::Script(x) => {
                            u5c::d_rep::Drep::ScriptHash(x.to_vec().into()).into()
                        }
                        conway::DRep::Abstain => u5c::d_rep::Drep::Abstain(true).into(),
                        conway::DRep::NoConfidence => u5c::d_rep::Drep::NoConfidence(true).into(),
                    },
                }
            }

            /// Map what a certificate of any era certifies, read through the
            /// era neutral certificate view. Returns None for a kind the u5c
            /// schema names no message for.
            pub fn map_cert_kind(
                &self,
                x: &pallas_traverse::MultiEraCertKind,
            ) -> Option<u5c::certificate::Certificate> {
                use pallas_primitives::alonzo;
                use pallas_traverse::MultiEraCertKind;
                let inner = match x {
                    MultiEraCertKind::StakeRegistration(cred) => {
                        u5c::certificate::Certificate::StakeRegistration(
                            self.map_stake_credential(cred),
                        )
                    }
                    MultiEraCertKind::StakeDeregistration(cred) => {
                        u5c::certificate::Certificate::StakeDeregistration(
                            self.map_stake_credential(cred),
                        )
                    }
                    MultiEraCertKind::StakeDelegation(cred, pool) => {
                        u5c::certificate::Certificate::StakeDelegation(u5c::StakeDelegationCert {
                            stake_credential: self.map_stake_credential(cred).into(),
                            pool_keyhash: pool.to_vec().into(),
                        })
                    }
                    MultiEraCertKind::PoolRegistration(pool) => {
                        // The u5c `PoolRegistrationCert` has no field for the BLS key
                        // the Dijkstra era adds, so `pool.bls_key` is not mapped.
                        u5c::certificate::Certificate::PoolRegistration(u5c::PoolRegistrationCert {
                            operator: pool.operator.to_vec().into(),
                            vrf_keyhash: pool.vrf_keyhash.to_vec().into(),
                            pledge: u64_to_bigint(pool.pledge),
                            cost: u64_to_bigint(pool.cost),
                            margin: rational_number_to_u5c(pool.margin.clone()).into(),
                            reward_account: pool.reward_account.to_vec().into(),
                            pool_owners: pool
                                .pool_owners
                                .iter()
                                .map(|x| x.to_vec().into())
                                .collect(),
                            relays: pool.relays.iter().map(|x| self.map_relay(x)).collect(),
                            pool_metadata: pool.pool_metadata.map(map_pool_metadata),
                        })
                    }
                    MultiEraCertKind::PoolRetirement(pool, epoch) => {
                        u5c::certificate::Certificate::PoolRetirement(u5c::PoolRetirementCert {
                            pool_keyhash: pool.to_vec().into(),
                            epoch: *epoch,
                        })
                    }
                    MultiEraCertKind::Reg(cred, coin) => {
                        u5c::certificate::Certificate::RegCert(u5c::RegCert {
                            stake_credential: self.map_stake_credential(cred).into(),
                            coin: u64_to_bigint(*coin),
                        })
                    }
                    MultiEraCertKind::UnReg(cred, coin) => {
                        u5c::certificate::Certificate::UnregCert(u5c::UnRegCert {
                            stake_credential: self.map_stake_credential(cred).into(),
                            coin: u64_to_bigint(*coin),
                        })
                    }
                    MultiEraCertKind::VoteDeleg(cred, drep) => {
                        u5c::certificate::Certificate::VoteDelegCert(u5c::VoteDelegCert {
                            stake_credential: self.map_stake_credential(cred).into(),
                            drep: self.map_drep(drep).into(),
                        })
                    }
                    MultiEraCertKind::StakeVoteDeleg(stake_cred, pool_id, drep) => {
                        u5c::certificate::Certificate::StakeVoteDelegCert(u5c::StakeVoteDelegCert {
                            stake_credential: self.map_stake_credential(stake_cred).into(),
                            pool_keyhash: pool_id.to_vec().into(),
                            drep: self.map_drep(drep).into(),
                        })
                    }
                    MultiEraCertKind::StakeRegDeleg(stake_cred, pool_id, coin) => {
                        u5c::certificate::Certificate::StakeRegDelegCert(u5c::StakeRegDelegCert {
                            stake_credential: self.map_stake_credential(stake_cred).into(),
                            pool_keyhash: pool_id.to_vec().into(),
                            coin: u64_to_bigint(*coin),
                        })
                    }
                    MultiEraCertKind::VoteRegDeleg(vote_cred, drep, coin) => {
                        u5c::certificate::Certificate::VoteRegDelegCert(u5c::VoteRegDelegCert {
                            stake_credential: self.map_stake_credential(vote_cred).into(),
                            drep: self.map_drep(drep).into(),
                            coin: u64_to_bigint(*coin),
                        })
                    }
                    MultiEraCertKind::StakeVoteRegDeleg(stake_cred, pool_id, drep, coin) => {
                        u5c::certificate::Certificate::StakeVoteRegDelegCert(
                            u5c::StakeVoteRegDelegCert {
                                stake_credential: self.map_stake_credential(stake_cred).into(),
                                pool_keyhash: pool_id.to_vec().into(),
                                drep: self.map_drep(drep).into(),
                                coin: u64_to_bigint(*coin),
                            },
                        )
                    }
                    MultiEraCertKind::AuthCommitteeHot(cold_cred, hot_cred) => {
                        u5c::certificate::Certificate::AuthCommitteeHotCert(
                            u5c::AuthCommitteeHotCert {
                                committee_cold_credential: self
                                    .map_stake_credential(cold_cred)
                                    .into(),
                                committee_hot_credential: self
                                    .map_stake_credential(hot_cred)
                                    .into(),
                            },
                        )
                    }
                    MultiEraCertKind::ResignCommitteeCold(cold_cred, anchor) => {
                        u5c::certificate::Certificate::ResignCommitteeColdCert(
                            u5c::ResignCommitteeColdCert {
                                committee_cold_credential: self
                                    .map_stake_credential(cold_cred)
                                    .into(),
                                anchor: anchor.map(map_anchor),
                            },
                        )
                    }
                    MultiEraCertKind::RegDRep(cred, coin, anchor) => {
                        u5c::certificate::Certificate::RegDrepCert(u5c::RegDRepCert {
                            drep_credential: self.map_stake_credential(cred).into(),
                            coin: u64_to_bigint(*coin),
                            anchor: anchor.map(map_anchor),
                        })
                    }
                    MultiEraCertKind::UnRegDRep(cred, coin) => {
                        u5c::certificate::Certificate::UnregDrepCert(u5c::UnRegDRepCert {
                            drep_credential: self.map_stake_credential(cred).into(),
                            coin: u64_to_bigint(*coin),
                        })
                    }
                    MultiEraCertKind::UpdateDRep(cred, anchor) => {
                        u5c::certificate::Certificate::UpdateDrepCert(u5c::UpdateDRepCert {
                            drep_credential: self.map_stake_credential(cred).into(),
                            anchor: anchor.map(map_anchor),
                        })
                    }
                    MultiEraCertKind::GenesisKeyDelegation(genesis, delegate, vrf) => {
                        u5c::certificate::Certificate::GenesisKeyDelegation(
                            u5c::GenesisKeyDelegationCert {
                                genesis_hash: genesis.to_vec().into(),
                                genesis_delegate_hash: delegate.to_vec().into(),
                                vrf_keyhash: vrf.to_vec().into(),
                            },
                        )
                    }
                    MultiEraCertKind::MoveInstantaneousRewards(rewards) => {
                        u5c::certificate::Certificate::MirCert(u5c::MirCert {
                            from: match &rewards.source {
                                alonzo::InstantaneousRewardSource::Reserves => {
                                    u5c::MirSource::Reserves.into()
                                }
                                alonzo::InstantaneousRewardSource::Treasury => {
                                    u5c::MirSource::Treasury.into()
                                }
                            },
                            to: match &rewards.target {
                                alonzo::InstantaneousRewardTarget::StakeCredentials(x) => x
                                    .iter()
                                    .map(|(k, v)| u5c::MirTarget {
                                        stake_credential: self.map_stake_credential(k).into(),
                                        delta_coin: i64_to_bigint(*v),
                                    })
                                    .collect(),
                                _ => Default::default(),
                            },
                            other_pot: match &rewards.target {
                                alonzo::InstantaneousRewardTarget::OtherAccountingPot(x) => *x,
                                _ => Default::default(),
                            },
                        })
                    }
                    // The u5c schema names no message for a kind this mapper
                    // does not name.
                    _ => return None,
                };

                Some(inner)
            }

            pub fn map_cert(
                &self,
                x: &pallas_traverse::MultiEraCert,
                tx: &pallas_traverse::MultiEraTx,
                order: u32,
            ) -> Option<u5c::Certificate> {
                let inner = self.map_cert_kind(&x.kind()?);
                Some(self.certificate(inner, tx, order))
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
        }

        #[cfg(test)]
        mod cert_tests {
            use super::*;

            use pallas_primitives::{alonzo, conway};
            use pallas_traverse::{MultiEraBlock, MultiEraCert, MultiEraTx};
            use pretty_assertions::assert_eq;
            use std::borrow::Cow;
            use std::collections::BTreeMap;

            use $crate::testing::NoLedger;

            const CREDENTIAL: [u8; 28] = [0x01; 28];
            const POOL: [u8; 28] = [0x02; 28];
            const OWNER: [u8; 28] = [0x04; 28];
            const VRF: [u8; 32] = [0x06; 32];
            const HOT: [u8; 28] = [0x07; 28];
            const GENESIS: [u8; 28] = [0x08; 28];
            const DELEGATE: [u8; 28] = [0x09; 28];
            const REWARD_ACCOUNT: [u8; 29] = [0xe0; 29];
            const ANCHOR_HASH: [u8; 32] = [0x22; 32];
            const METADATA_HASH: [u8; 32] = [0x33; 32];
            const ANCHOR_URL: &str = "https://example.invalid/anchor";
            const METADATA_URL: &str = "https://example.invalid/pool.json";
            const RELAY_NAME: &str = "relay.example.invalid";
            const PLEDGE: u64 = 500;
            const COST: u64 = 340;
            const DEPOSIT: u64 = 5;
            const EPOCH: u64 = 9;
            const REWARD: i64 = 7;

            fn credential() -> conway::StakeCredential {
                conway::StakeCredential::AddrKeyhash(CREDENTIAL.into())
            }

            fn hot_credential() -> conway::StakeCredential {
                conway::StakeCredential::AddrKeyhash(HOT.into())
            }

            fn anchor() -> conway::Anchor {
                conway::Anchor {
                    url: ANCHOR_URL.into(),
                    content_hash: ANCHOR_HASH.into(),
                }
            }

            fn margin() -> pallas_primitives::RationalNumber {
                pallas_primitives::RationalNumber {
                    numerator: 1,
                    denominator: 50,
                }
            }

            fn relays() -> Vec<pallas_primitives::Relay> {
                vec![pallas_primitives::Relay::MultiHostName(RELAY_NAME.into())]
            }

            fn metadata() -> pallas_primitives::PoolMetadata {
                pallas_primitives::PoolMetadata {
                    url: METADATA_URL.into(),
                    hash: METADATA_HASH.to_vec().into(),
                }
            }

            /// The u5c message for a credential holding the key hash given.
            fn key_credential(hash: [u8; 28]) -> u5c::StakeCredential {
                u5c::StakeCredential {
                    stake_credential: Some(u5c::stake_credential::StakeCredential::AddrKeyHash(
                        hash.to_vec().into(),
                    )),
                }
            }

            /// The u5c message for a count that fits in a signed 64 bit field.
            fn bigint(value: i64) -> Option<u5c::BigInt> {
                Some(u5c::BigInt {
                    big_int: Some(u5c::big_int::BigInt::Int(value)),
                })
            }

            fn mapped_anchor() -> u5c::Anchor {
                u5c::Anchor {
                    url: ANCHOR_URL.to_string(),
                    content_hash: ANCHOR_HASH.to_vec().into(),
                }
            }

            fn abstain() -> Option<u5c::DRep> {
                Some(u5c::DRep {
                    drep: Some(u5c::d_rep::Drep::Abstain(true)),
                })
            }

            fn no_confidence() -> Option<u5c::DRep> {
                Some(u5c::DRep {
                    drep: Some(u5c::d_rep::Drep::NoConfidence(true)),
                })
            }

            /// A Conway transaction carrying the redeemers given and nothing
            /// else, to stand as the transaction a certificate is read against.
            fn tx_with_redeemers(redeemers: Vec<conway::Redeemer>) -> conway::Tx<'static> {
                let body = conway::TransactionBody {
                    inputs: Vec::new().into(),
                    outputs: Vec::new(),
                    fee: 0,
                    ttl: None,
                    certificates: None,
                    withdrawals: None,
                    auxiliary_data_hash: None,
                    validity_interval_start: None,
                    mint: None,
                    script_data_hash: None,
                    collateral: None,
                    required_signers: None,
                    network_id: None,
                    collateral_return: None,
                    total_collateral: None,
                    reference_inputs: None,
                    voting_procedures: None,
                    proposal_procedures: None,
                    treasury_value: None,
                    donation: None,
                };

                let witness_set = conway::WitnessSet {
                    vkeywitness: None,
                    native_script: None,
                    bootstrap_witness: None,
                    plutus_v1_script: None,
                    plutus_data: None,
                    redeemer: Some(conway::Redeemers::List(redeemers).into()),
                    plutus_v2_script: None,
                    plutus_v3_script: None,
                };

                conway::Tx {
                    transaction_body: body.into(),
                    transaction_witness_set: witness_set.into(),
                    success: true,
                    auxiliary_data: pallas_primitives::Nullable::Null,
                }
            }

            fn babbage10_block() -> Vec<u8> {
                let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../test_data/babbage10.block");
                let hex_str = std::fs::read_to_string(&path).expect("the fixture is readable");
                hex::decode(hex_str.trim()).expect("the fixture holds hex")
            }

            #[test]
            fn every_conway_certificate_maps_to_the_u5c_message_naming_it() {
                let cases: Vec<(conway::Certificate, u5c::certificate::Certificate)> = vec![
                    (
                        conway::Certificate::StakeRegistration(credential()),
                        u5c::certificate::Certificate::StakeRegistration(key_credential(
                            CREDENTIAL,
                        )),
                    ),
                    (
                        conway::Certificate::StakeDeregistration(credential()),
                        u5c::certificate::Certificate::StakeDeregistration(key_credential(
                            CREDENTIAL,
                        )),
                    ),
                    (
                        conway::Certificate::StakeDelegation(credential(), POOL.into()),
                        u5c::certificate::Certificate::StakeDelegation(u5c::StakeDelegationCert {
                            stake_credential: Some(key_credential(CREDENTIAL)),
                            pool_keyhash: POOL.to_vec().into(),
                        }),
                    ),
                    (
                        conway::Certificate::PoolRegistration {
                            operator: POOL.into(),
                            vrf_keyhash: VRF.into(),
                            pledge: PLEDGE,
                            cost: COST,
                            margin: margin(),
                            reward_account: REWARD_ACCOUNT.to_vec().into(),
                            pool_owners: vec![OWNER.into()].into(),
                            relays: relays(),
                            pool_metadata: Some(metadata()),
                        },
                        u5c::certificate::Certificate::PoolRegistration(
                            u5c::PoolRegistrationCert {
                                operator: POOL.to_vec().into(),
                                vrf_keyhash: VRF.to_vec().into(),
                                pledge: bigint(PLEDGE as i64),
                                cost: bigint(COST as i64),
                                margin: Some(u5c::RationalNumber {
                                    numerator: 1,
                                    denominator: 50,
                                }),
                                reward_account: REWARD_ACCOUNT.to_vec().into(),
                                pool_owners: vec![OWNER.to_vec().into()],
                                relays: vec![u5c::Relay {
                                    ip_v4: Default::default(),
                                    ip_v6: Default::default(),
                                    dns_name: RELAY_NAME.to_string(),
                                    port: 0,
                                }],
                                pool_metadata: Some(u5c::PoolMetadata {
                                    url: METADATA_URL.to_string(),
                                    hash: METADATA_HASH.to_vec().into(),
                                }),
                            },
                        ),
                    ),
                    (
                        conway::Certificate::PoolRetirement(POOL.into(), EPOCH),
                        u5c::certificate::Certificate::PoolRetirement(u5c::PoolRetirementCert {
                            pool_keyhash: POOL.to_vec().into(),
                            epoch: EPOCH,
                        }),
                    ),
                    (
                        conway::Certificate::Reg(credential(), DEPOSIT),
                        u5c::certificate::Certificate::RegCert(u5c::RegCert {
                            stake_credential: Some(key_credential(CREDENTIAL)),
                            coin: bigint(DEPOSIT as i64),
                        }),
                    ),
                    (
                        conway::Certificate::UnReg(credential(), DEPOSIT),
                        u5c::certificate::Certificate::UnregCert(u5c::UnRegCert {
                            stake_credential: Some(key_credential(CREDENTIAL)),
                            coin: bigint(DEPOSIT as i64),
                        }),
                    ),
                    (
                        conway::Certificate::VoteDeleg(credential(), conway::DRep::Abstain),
                        u5c::certificate::Certificate::VoteDelegCert(u5c::VoteDelegCert {
                            stake_credential: Some(key_credential(CREDENTIAL)),
                            drep: abstain(),
                        }),
                    ),
                    (
                        conway::Certificate::StakeVoteDeleg(
                            credential(),
                            POOL.into(),
                            conway::DRep::NoConfidence,
                        ),
                        u5c::certificate::Certificate::StakeVoteDelegCert(
                            u5c::StakeVoteDelegCert {
                                stake_credential: Some(key_credential(CREDENTIAL)),
                                pool_keyhash: POOL.to_vec().into(),
                                drep: no_confidence(),
                            },
                        ),
                    ),
                    (
                        conway::Certificate::StakeRegDeleg(credential(), POOL.into(), DEPOSIT),
                        u5c::certificate::Certificate::StakeRegDelegCert(u5c::StakeRegDelegCert {
                            stake_credential: Some(key_credential(CREDENTIAL)),
                            pool_keyhash: POOL.to_vec().into(),
                            coin: bigint(DEPOSIT as i64),
                        }),
                    ),
                    (
                        conway::Certificate::VoteRegDeleg(
                            credential(),
                            conway::DRep::Abstain,
                            DEPOSIT,
                        ),
                        u5c::certificate::Certificate::VoteRegDelegCert(u5c::VoteRegDelegCert {
                            stake_credential: Some(key_credential(CREDENTIAL)),
                            drep: abstain(),
                            coin: bigint(DEPOSIT as i64),
                        }),
                    ),
                    (
                        conway::Certificate::StakeVoteRegDeleg(
                            credential(),
                            POOL.into(),
                            conway::DRep::Abstain,
                            DEPOSIT,
                        ),
                        u5c::certificate::Certificate::StakeVoteRegDelegCert(
                            u5c::StakeVoteRegDelegCert {
                                stake_credential: Some(key_credential(CREDENTIAL)),
                                pool_keyhash: POOL.to_vec().into(),
                                drep: abstain(),
                                coin: bigint(DEPOSIT as i64),
                            },
                        ),
                    ),
                    (
                        conway::Certificate::AuthCommitteeHot(credential(), hot_credential()),
                        u5c::certificate::Certificate::AuthCommitteeHotCert(
                            u5c::AuthCommitteeHotCert {
                                committee_cold_credential: Some(key_credential(CREDENTIAL)),
                                committee_hot_credential: Some(key_credential(HOT)),
                            },
                        ),
                    ),
                    (
                        conway::Certificate::ResignCommitteeCold(credential(), Some(anchor())),
                        u5c::certificate::Certificate::ResignCommitteeColdCert(
                            u5c::ResignCommitteeColdCert {
                                committee_cold_credential: Some(key_credential(CREDENTIAL)),
                                anchor: Some(mapped_anchor()),
                            },
                        ),
                    ),
                    (
                        conway::Certificate::RegDRepCert(credential(), DEPOSIT, Some(anchor())),
                        u5c::certificate::Certificate::RegDrepCert(u5c::RegDRepCert {
                            drep_credential: Some(key_credential(CREDENTIAL)),
                            coin: bigint(DEPOSIT as i64),
                            anchor: Some(mapped_anchor()),
                        }),
                    ),
                    (
                        conway::Certificate::UnRegDRepCert(credential(), DEPOSIT),
                        u5c::certificate::Certificate::UnregDrepCert(u5c::UnRegDRepCert {
                            drep_credential: Some(key_credential(CREDENTIAL)),
                            coin: bigint(DEPOSIT as i64),
                        }),
                    ),
                    (
                        conway::Certificate::UpdateDRepCert(credential(), None),
                        u5c::certificate::Certificate::UpdateDrepCert(u5c::UpdateDRepCert {
                            drep_credential: Some(key_credential(CREDENTIAL)),
                            anchor: None,
                        }),
                    ),
                ];

                assert_eq!(cases.len(), 17, "Conway's type names seventeen certificates");

                let raw = tx_with_redeemers(Vec::new());
                let tx = MultiEraTx::from_conway(&raw);
                let mapper = Mapper::new(NoLedger);

                for (order, (certificate, expected)) in cases.iter().enumerate() {
                    let cert = MultiEraCert::Conway(Box::new(Cow::Borrowed(certificate)));
                    let mapped = mapper
                        .map_cert(&cert, &tx, order as u32)
                        .expect("a Conway certificate maps");

                    assert_eq!(
                        mapped.certificate.as_ref(),
                        Some(expected),
                        "the Conway certificate at position {order}"
                    );
                    assert!(
                        mapped.redeemer.is_none(),
                        "position {order} pairs no redeemer, this transaction carries none"
                    );
                }
            }

            #[test]
            fn every_alonzo_certificate_maps_to_the_u5c_message_naming_it() {
                let cases: Vec<(alonzo::Certificate, u5c::certificate::Certificate)> = vec![
                    (
                        alonzo::Certificate::StakeRegistration(credential()),
                        u5c::certificate::Certificate::StakeRegistration(key_credential(
                            CREDENTIAL,
                        )),
                    ),
                    (
                        alonzo::Certificate::StakeDeregistration(credential()),
                        u5c::certificate::Certificate::StakeDeregistration(key_credential(
                            CREDENTIAL,
                        )),
                    ),
                    (
                        alonzo::Certificate::StakeDelegation(credential(), POOL.into()),
                        u5c::certificate::Certificate::StakeDelegation(u5c::StakeDelegationCert {
                            stake_credential: Some(key_credential(CREDENTIAL)),
                            pool_keyhash: POOL.to_vec().into(),
                        }),
                    ),
                    (
                        alonzo::Certificate::PoolRegistration {
                            operator: POOL.into(),
                            vrf_keyhash: VRF.into(),
                            pledge: PLEDGE,
                            cost: COST,
                            margin: margin(),
                            reward_account: REWARD_ACCOUNT.to_vec().into(),
                            pool_owners: vec![OWNER.into()],
                            relays: relays(),
                            pool_metadata: Some(metadata()),
                        },
                        u5c::certificate::Certificate::PoolRegistration(
                            u5c::PoolRegistrationCert {
                                operator: POOL.to_vec().into(),
                                vrf_keyhash: VRF.to_vec().into(),
                                pledge: bigint(PLEDGE as i64),
                                cost: bigint(COST as i64),
                                margin: Some(u5c::RationalNumber {
                                    numerator: 1,
                                    denominator: 50,
                                }),
                                reward_account: REWARD_ACCOUNT.to_vec().into(),
                                pool_owners: vec![OWNER.to_vec().into()],
                                relays: vec![u5c::Relay {
                                    ip_v4: Default::default(),
                                    ip_v6: Default::default(),
                                    dns_name: RELAY_NAME.to_string(),
                                    port: 0,
                                }],
                                pool_metadata: Some(u5c::PoolMetadata {
                                    url: METADATA_URL.to_string(),
                                    hash: METADATA_HASH.to_vec().into(),
                                }),
                            },
                        ),
                    ),
                    (
                        alonzo::Certificate::PoolRetirement(POOL.into(), EPOCH),
                        u5c::certificate::Certificate::PoolRetirement(u5c::PoolRetirementCert {
                            pool_keyhash: POOL.to_vec().into(),
                            epoch: EPOCH,
                        }),
                    ),
                    (
                        alonzo::Certificate::GenesisKeyDelegation(
                            GENESIS.to_vec().into(),
                            DELEGATE.to_vec().into(),
                            VRF.into(),
                        ),
                        u5c::certificate::Certificate::GenesisKeyDelegation(
                            u5c::GenesisKeyDelegationCert {
                                genesis_hash: GENESIS.to_vec().into(),
                                genesis_delegate_hash: DELEGATE.to_vec().into(),
                                vrf_keyhash: VRF.to_vec().into(),
                            },
                        ),
                    ),
                    (
                        alonzo::Certificate::MoveInstantaneousRewardsCert(
                            alonzo::MoveInstantaneousReward {
                                source: alonzo::InstantaneousRewardSource::Reserves,
                                target: alonzo::InstantaneousRewardTarget::OtherAccountingPot(
                                    REWARD as u64,
                                ),
                            },
                        ),
                        u5c::certificate::Certificate::MirCert(u5c::MirCert {
                            from: u5c::MirSource::Reserves as i32,
                            to: Vec::new(),
                            other_pot: REWARD as u64,
                        }),
                    ),
                ];

                assert_eq!(
                    cases.len(),
                    7,
                    "the type serving Shelley through Babbage names seven certificates"
                );

                let raw = tx_with_redeemers(Vec::new());
                let tx = MultiEraTx::from_conway(&raw);
                let mapper = Mapper::new(NoLedger);

                for (order, (certificate, expected)) in cases.iter().enumerate() {
                    let cert = MultiEraCert::AlonzoCompatible(Box::new(Cow::Borrowed(certificate)));
                    let mapped = mapper
                        .map_cert(&cert, &tx, order as u32)
                        .expect("an Alonzo certificate maps");

                    assert_eq!(
                        mapped.certificate.as_ref(),
                        Some(expected),
                        "the Alonzo certificate at position {order}"
                    );
                    assert!(
                        mapped.redeemer.is_none(),
                        "position {order} pairs no redeemer, this transaction carries none"
                    );
                }
            }

            #[test]
            fn a_move_instantaneous_rewards_certificate_maps_the_pot_and_every_target() {
                let certificate = alonzo::Certificate::MoveInstantaneousRewardsCert(
                    alonzo::MoveInstantaneousReward {
                        source: alonzo::InstantaneousRewardSource::Treasury,
                        target: alonzo::InstantaneousRewardTarget::StakeCredentials(
                            BTreeMap::from([(credential(), REWARD)]),
                        ),
                    },
                );

                let raw = tx_with_redeemers(Vec::new());
                let tx = MultiEraTx::from_conway(&raw);
                let mapper = Mapper::new(NoLedger);
                let cert = MultiEraCert::AlonzoCompatible(Box::new(Cow::Borrowed(&certificate)));

                let mapped = mapper
                    .map_cert(&cert, &tx, 0)
                    .expect("an Alonzo certificate maps");

                assert_eq!(
                    mapped.certificate,
                    Some(u5c::certificate::Certificate::MirCert(u5c::MirCert {
                        from: u5c::MirSource::Treasury as i32,
                        to: vec![u5c::MirTarget {
                            stake_credential: Some(key_credential(CREDENTIAL)),
                            delta_coin: bigint(REWARD),
                        }],
                        other_pot: 0,
                    }))
                );
            }

            #[test]
            fn a_pool_registration_read_from_a_block_maps_every_parameter() {
                let cbor = babbage10_block();
                let decoded = MultiEraBlock::decode(&cbor).expect("the fixture decodes");
                let txs = decoded.txs();
                let certs: Vec<_> = txs.iter().flat_map(|tx| tx.certs()).collect();
                assert_eq!(certs.len(), 1, "this fixture writes one certificate");

                let mapper = Mapper::new(NoLedger);
                let mapped = mapper
                    .map_cert(&certs[0], &txs[0], 0)
                    .expect("a pool registration maps");

                assert_eq!(
                    mapped.certificate,
                    Some(u5c::certificate::Certificate::PoolRegistration(
                        u5c::PoolRegistrationCert {
                            operator: hex::decode(
                                "129a187287eb6c65e57af2a1ac5750113ecc1a1e658b960358fcaa59"
                            )
                            .unwrap()
                            .into(),
                            vrf_keyhash: hex::decode(
                                "cf027ebfbfec5c3f964b05341519180003e2ed092829a402f775efec666d78e1"
                            )
                            .unwrap()
                            .into(),
                            // The pledge is above i64::MAX, which the schema
                            // carries as unsigned big endian bytes.
                            pledge: Some(u5c::BigInt {
                                big_int: Some(u5c::big_int::BigInt::BigUInt(
                                    hex::decode("8000000000000001").unwrap().into()
                                )),
                            }),
                            cost: bigint(340_000_000),
                            // The fixture's margin is 9223372036854775809 over
                            // 10000000000000000000 and the schema's two fields
                            // are 32 bits wide, so both arrive cut to their low
                            // 32 bits.
                            margin: Some(u5c::RationalNumber {
                                numerator: 1,
                                denominator: 2_313_682_944,
                            }),
                            reward_account: hex::decode(
                                "e0b04dff59ee3b964a7d9f4fda04d98ef43de3abc832112cc37a35d138"
                            )
                            .unwrap()
                            .into(),
                            pool_owners: vec![
                                hex::decode(
                                    "b04dff59ee3b964a7d9f4fda04d98ef43de3abc832112cc37a35d138"
                                )
                                .unwrap()
                                .into()
                            ],
                            relays: vec![
                                u5c::Relay {
                                    ip_v4: hex::decode("05a14bd4").unwrap().into(),
                                    ip_v6: Default::default(),
                                    dns_name: String::new(),
                                    port: 5003,
                                },
                                u5c::Relay {
                                    ip_v4: hex::decode("64646464").unwrap().into(),
                                    ip_v6: Default::default(),
                                    dns_name: String::new(),
                                    port: 100,
                                },
                                u5c::Relay {
                                    ip_v4: hex::decode("c8c8c8c8").unwrap().into(),
                                    ip_v6: Default::default(),
                                    dns_name: String::new(),
                                    port: 200,
                                },
                            ],
                            pool_metadata: Some(u5c::PoolMetadata {
                                url: "https://raw.githubusercontent.com/stakelovelace/pub/main/s2.json"
                                    .to_string(),
                                hash: hex::decode(
                                    "b3ac275b0568c3b7d63f889f896086fe4cb61d0f156cbfa18b5466a8480e012a"
                                )
                                .unwrap()
                                .into(),
                            }),
                        }
                    ))
                );
            }

            #[test]
            fn a_certificate_carries_the_redeemer_the_transaction_indexes_at_its_position() {
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
                let certificate = conway::Certificate::StakeRegistration(credential());
                let cert = MultiEraCert::Conway(Box::new(Cow::Borrowed(&certificate)));

                let paired = mapper
                    .map_cert(&cert, &tx, 1)
                    .expect("a Conway certificate maps");
                let redeemer = paired
                    .redeemer
                    .expect("position one is indexed by a certificate redeemer");

                assert_eq!(redeemer.index, 1);
                assert_eq!(redeemer.purpose, u5c::RedeemerPurpose::Cert as i32);
                assert_eq!(
                    redeemer.ex_units,
                    Some(u5c::ExUnits {
                        memory: 11,
                        steps: 22,
                    })
                );

                let unpaired = mapper
                    .map_cert(&cert, &tx, 0)
                    .expect("a Conway certificate maps");
                assert!(
                    unpaired.redeemer.is_none(),
                    "position zero is indexed by no redeemer"
                );
            }

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
        }

        #[cfg(test)]
        mod mapper_tests {
            use super::*;

            use pallas_primitives::conway;
            use pretty_assertions::assert_eq;

            use $crate::testing::*;

            /// The guardrails script a parameter change may name.
            const GUARDRAILS_SCRIPT: [u8; 28] = [0x5c; 28];

            /// Count the witness set scripts of each Plutus version.
            fn plutus_script_counts(scripts: &[u5c::Script]) -> (usize, usize, usize) {
                let mut counts = (0usize, 0usize, 0usize);
                for entry in scripts {
                    match entry.script {
                        Some(u5c::script::Script::PlutusV1(_)) => counts.0 += 1,
                        Some(u5c::script::Script::PlutusV2(_)) => counts.1 += 1,
                        Some(u5c::script::Script::PlutusV3(_)) => counts.2 += 1,
                        _ => {}
                    }
                }
                counts
            }

            /// The bytes of every PlutusV3 witness script the mapper reported.
            fn plutus_v3_bytes(scripts: &[u5c::Script]) -> Vec<Vec<u8>> {
                scripts
                    .iter()
                    .filter_map(|entry| match &entry.script {
                        Some(u5c::script::Script::PlutusV3(bytes)) => Some(bytes.to_vec()),
                        _ => None,
                    })
                    .collect()
            }

            /// Names the u5c certificate variant of a mapped certificate.
            #[cfg(feature = "unstable")]
            fn certificate_kind(x: &u5c::Certificate) -> &'static str {
                match x.certificate {
                    Some(u5c::certificate::Certificate::StakeDelegation(_)) => "stake delegation",
                    Some(u5c::certificate::Certificate::RegCert(_)) => "registration",
                    Some(u5c::certificate::Certificate::UnregCert(_)) => "deregistration",
                    Some(u5c::certificate::Certificate::PoolRegistration(_)) => "pool registration",
                    Some(u5c::certificate::Certificate::PoolRetirement(_)) => "pool retirement",
                    Some(_) => "another kind",
                    None => "no certificate at all",
                }
            }

            #[cfg(feature = "unstable")]
            #[test]
            fn a_dijkstra_block_maps_every_certificate() {
                let block = dijkstra_block(include_str!("../../../test_data/dijkstra6.block"));
                let mapper = Mapper::new(NoLedger);
                let mapped = mapper.map_block(&block);

                let certs: usize = mapped
                    .body
                    .as_ref()
                    .unwrap()
                    .tx
                    .iter()
                    .map(|t| t.certificates.len())
                    .sum();

                assert_eq!(certs, 5, "every certificate in the block must be mapped");

                let kinds: Vec<&str> = mapped
                    .body
                    .as_ref()
                    .unwrap()
                    .tx
                    .iter()
                    .flat_map(|t| t.certificates.iter())
                    .map(certificate_kind)
                    .collect();

                assert_eq!(
                    kinds,
                    [
                        "stake delegation",
                        "registration",
                        "pool registration",
                        "registration",
                        "pool registration"
                    ],
                    "the block writes certificate tags 2, 7, 3, 7, 3 in that order, and each names a different u5c certificate"
                );
            }

            #[cfg(feature = "unstable")]
            #[test]
            fn a_dijkstra_pool_registration_drops_the_bls_key_it_fills() {
                use prost::Message;

                let block = dijkstra_block(include_str!("../../../test_data/dijkstra6.block"));
                let txs = block.txs();
                let keys: Vec<Vec<u8>> = txs
                    .iter()
                    .flat_map(|tx| tx.certs())
                    .filter_map(|cert| cert.bls_key().key().map(|k| k.bls_pubkey.to_vec()))
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
                        "u5c names no field for a pool registration's BLS key, so none of its bytes may reach the wire"
                    );
                }
            }

            #[cfg(feature = "unstable")]
            #[test]
            fn a_dijkstra_block_with_no_certificates_maps_none() {
                let block = dijkstra_block(include_str!("../../../test_data/dijkstra3.block"));
                let mapper = Mapper::new(NoLedger);
                let mapped = mapper.map_block(&block);

                let certs: usize = mapped
                    .body
                    .as_ref()
                    .unwrap()
                    .tx
                    .iter()
                    .map(|t| t.certificates.len())
                    .sum();
                assert_eq!(certs, 0);
            }

            #[cfg(feature = "unstable")]
            #[test]
            fn a_dijkstra_proposal_maps_its_governance_action() {
                let tx = dijkstra_tx(include_str!("../../../test_data/dijkstra-proposal.tx"));
                let mapper = Mapper::new(NoLedger);
                let mapped = mapper.map_tx(&tx);

                assert_eq!(mapped.proposals.len(), 1);
                let proposal = &mapped.proposals[0];

                assert_eq!(proposal.deposit, u64_to_bigint(1_000_000));
                assert_eq!(proposal.reward_account.to_vec(), vec![0xe0; 29]);
                assert_eq!(
                    proposal.anchor,
                    Some(u5c::Anchor {
                        url: "https://example.invalid/anchor".to_string(),
                        content_hash: vec![0x00; 32].into(),
                    }),
                    "the anchor the proposal carries must reach the schema"
                );
                assert_eq!(
                    proposal.gov_action,
                    Some(u5c::GovernanceAction {
                        governance_action: Some(
                            u5c::governance_action::GovernanceAction::ParameterChangeAction(
                                u5c::ParameterChangeAction {
                                    gov_action_id: None,
                                    protocol_param_update: None,
                                    policy_hash: Default::default(),
                                }
                            )
                        ),
                    }),
                    "the action is a parameter change naming no earlier action and no guardrails script, and its one key, 48, is one u5c has no field for"
                );
            }

            #[test]
            fn a_conway_parameter_change_maps_its_update_through_the_view() {
                let action = conway_parameter_change(&[0xa1, 0x00, 0x19, 0x03, 0xe8]);
                let mapper = Mapper::new(NoLedger);
                let change = parameter_change(
                    mapper.map_gov_action(&trv::MultiEraGovAction::from_conway(&action)),
                );

                assert_eq!(
                    change.protocol_param_update,
                    Some(u5c::PParams {
                        min_fee_coefficient: u64_to_bigint(1000),
                        ..Default::default()
                    }),
                    "key 0 is min_fee_coefficient, and it is the only field this update sets"
                );
            }

            #[test]
            fn a_conway_parameter_change_of_nothing_u5c_carries_maps_to_no_parameters() {
                let action = conway_parameter_change(&[0xa0]);
                let mapper = Mapper::new(NoLedger);
                let change = parameter_change(
                    mapper.map_gov_action(&trv::MultiEraGovAction::from_conway(&action)),
                );

                assert_eq!(
                    change.protocol_param_update, None,
                    "an update u5c has no field for must be absent rather than a PParams whose every field reads its proto3 zero"
                );
            }

            #[test]
            fn a_conway_parameter_change_setting_a_key_to_zero_maps_to_that_key() {
                // Key 27 is min_committee_size, and 0 is a legal value for it.
                let action = conway_parameter_change(&[0xa1, 0x18, 0x1b, 0x00]);
                let mapper = Mapper::new(NoLedger);
                let change = parameter_change(
                    mapper.map_gov_action(&trv::MultiEraGovAction::from_conway(&action)),
                );

                assert_eq!(
                    change.protocol_param_update,
                    Some(u5c::PParams {
                        min_committee_size: 0,
                        ..Default::default()
                    }),
                    "a proposal to seat no committee members sets a key u5c carries, so the update is present and carries that key's value"
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

            fn parameter_change(action: u5c::GovernanceAction) -> u5c::ParameterChangeAction {
                match action.governance_action {
                    Some(u5c::governance_action::GovernanceAction::ParameterChangeAction(x)) => x,
                    other => {
                        panic!(
                            "a parameter change must map to a ParameterChangeAction, got {other:?}"
                        )
                    }
                }
            }

            fn no_confidence(action: u5c::GovernanceAction) -> u5c::NoConfidenceAction {
                match action.governance_action {
                    Some(u5c::governance_action::GovernanceAction::NoConfidenceAction(x)) => x,
                    other => {
                        panic!(
                            "a no confidence action must map to a NoConfidenceAction, got {other:?}"
                        )
                    }
                }
            }

            fn key_credential(hash: [u8; 28]) -> u5c::StakeCredential {
                u5c::StakeCredential {
                    stake_credential: Some(
                        u5c::stake_credential::StakeCredential::AddrKeyHash(hash.to_vec().into()),
                    ),
                }
            }

            #[test]
            fn every_governance_action_kind_maps_the_payload_it_carries() {
                use u5c::governance_action::GovernanceAction as Action;

                let mapper = Mapper::new(NoLedger);
                let mapped = |action: &conway::GovAction| {
                    mapper
                        .map_gov_action(&trv::MultiEraGovAction::from_conway(action))
                        .governance_action
                        .expect("every governance action must map to a u5c action")
                };

                let named_change = conway::GovAction::ParameterChange(
                    Some(enacted_action_id()),
                    Box::new(conway_update_of_no_key()),
                    Some(GUARDRAILS_SCRIPT.into()),
                );
                assert_eq!(
                    mapped(&named_change),
                    Action::ParameterChangeAction(u5c::ParameterChangeAction {
                        gov_action_id: Some(u5c::GovernanceActionId {
                            transaction_id: enacted_action_id().transaction_id.to_vec().into(),
                            governance_action_index: enacted_action_id().action_index,
                        }),
                        protocol_param_update: None,
                        policy_hash: GUARDRAILS_SCRIPT.to_vec().into(),
                    }),
                    "a parameter change carries the action it follows and the guardrails script it names"
                );

                assert_eq!(
                    mapped(&conway_hard_fork_initiation()),
                    Action::HardForkInitiationAction(u5c::HardForkInitiationAction {
                        gov_action_id: None,
                        protocol_version: Some(u5c::ProtocolVersion {
                            major: HARD_FORK_VERSION.0 as u32,
                            minor: HARD_FORK_VERSION.1 as u32,
                        }),
                    }),
                    "a hard fork initiation carries the major and the minor of the version it proposes, each in its own field"
                );

                assert_eq!(
                    mapped(&conway_treasury_withdrawal()),
                    Action::TreasuryWithdrawalsAction(u5c::TreasuryWithdrawalsAction {
                        withdrawals: vec![u5c::WithdrawalAmount {
                            reward_account: WITHDRAWAL_REWARD_ACCOUNT.to_vec().into(),
                            coin: u64_to_bigint(WITHDRAWAL_COIN),
                        }],
                        policy_hash: Default::default(),
                    }),
                    "a treasury withdrawal carries the account it pays and the amount it pays it"
                );

                assert_eq!(
                    mapped(&conway_no_confidence(None)),
                    Action::NoConfidenceAction(u5c::NoConfidenceAction {
                        gov_action_id: None,
                    }),
                    "a no confidence action naming no earlier action carries none"
                );

                assert_eq!(
                    mapped(&conway_update_committee()),
                    Action::UpdateCommitteeAction(u5c::UpdateCommitteeAction {
                        gov_action_id: None,
                        remove_committee_credentials: vec![key_credential(COMMITTEE_REMOVED)],
                        new_committee_credentials: vec![u5c::NewCommitteeCredentials {
                            committee_cold_credential: Some(key_credential(COMMITTEE_SEATED)),
                            expires_epoch: COMMITTEE_SEATED_UNTIL as u32,
                        }],
                        new_committee_threshold: Some(u5c_ratio(1, 2)),
                    }),
                    "a committee update carries the credentials it removes, the ones it seats with their terms, and the threshold it sets"
                );

                assert_eq!(
                    mapped(&conway_new_constitution()),
                    Action::NewConstitutionAction(u5c::NewConstitutionAction {
                        gov_action_id: None,
                        constitution: Some(u5c::Constitution {
                            anchor: Some(u5c::Anchor {
                                url: CONSTITUTION_ANCHOR_URL.to_string(),
                                content_hash: CONSTITUTION_ANCHOR_HASH.to_vec().into(),
                            }),
                            hash: Default::default(),
                        }),
                    }),
                    "a new constitution carries the anchor it points at and, here, no guardrails script"
                );
            }

            #[test]
            fn a_governance_action_carries_the_action_id_it_names() {
                let mapper = Mapper::new(NoLedger);
                let id = enacted_action_id();

                let named = no_confidence(mapper.map_gov_action(
                    &trv::MultiEraGovAction::from_conway(&conway_no_confidence(Some(id.clone()))),
                ));
                assert_eq!(
                    named.gov_action_id,
                    Some(u5c::GovernanceActionId {
                        transaction_id: id.transaction_id.to_vec().into(),
                        governance_action_index: id.action_index,
                    }),
                    "the action most recently enacted of this kind must reach the schema by its own bytes and index"
                );

                let unnamed = no_confidence(mapper.map_gov_action(
                    &trv::MultiEraGovAction::from_conway(&conway_no_confidence(None)),
                ));
                assert_eq!(
                    unnamed.gov_action_id, None,
                    "and an action naming none carries none"
                );
            }

            #[test]
            fn every_redeemer_tag_the_eras_share_maps_to_the_purpose_it_names() {
                use pallas_traverse::MultiEraRedeemerTag as Tag;

                let mapper = Mapper::new(NoLedger);

                assert_eq!(
                    mapper.map_multi_era_purpose(&Tag::Spend),
                    u5c::RedeemerPurpose::Spend
                );
                assert_eq!(
                    mapper.map_multi_era_purpose(&Tag::Mint),
                    u5c::RedeemerPurpose::Mint
                );
                assert_eq!(
                    mapper.map_multi_era_purpose(&Tag::Cert),
                    u5c::RedeemerPurpose::Cert
                );
                assert_eq!(
                    mapper.map_multi_era_purpose(&Tag::Reward),
                    u5c::RedeemerPurpose::Reward
                );
                assert_eq!(
                    mapper.map_multi_era_purpose(&Tag::Vote),
                    u5c::RedeemerPurpose::Vote
                );
                assert_eq!(
                    mapper.map_multi_era_purpose(&Tag::Propose),
                    u5c::RedeemerPurpose::Propose
                );
            }

            #[cfg(feature = "unstable")]
            #[test]
            fn a_guarding_redeemer_maps_to_the_purpose_u5c_leaves_unspecified() {
                let mapper = Mapper::new(NoLedger);

                assert_eq!(
                    mapper.map_multi_era_purpose(&pallas_traverse::MultiEraRedeemerTag::Guarding),
                    u5c::RedeemerPurpose::Unspecified,
                    "u5c has no guarding purpose, so a guard reads as unspecified rather than as one of the six it names"
                );
            }

            #[test]
            fn a_certificate_carries_the_redeemer_paired_with_its_own_position() {
                let tx = conway_tx_with_certificate_redeemers();
                let cert = conway_stake_registration(0x22);
                let multi =
                    pallas_traverse::MultiEraCert::Conway(Box::new(std::borrow::Cow::Borrowed(
                        &cert,
                    )));
                let mapper = Mapper::new(NoLedger);

                let redeemer_at = |order: u32| {
                    mapper
                        .map_cert(&multi, &tx, order)
                        .expect("a Conway certificate must map")
                        .redeemer
                };

                let first =
                    redeemer_at(0).expect("the certificate at position 0 is paired with a redeemer");
                assert_eq!(first.index, 0);
                assert_eq!(first.purpose, u5c::RedeemerPurpose::Cert as i32);
                assert_eq!(
                    first.ex_units,
                    Some(u5c::ExUnits {
                        memory: 1_000,
                        steps: 2_000
                    })
                );

                let second =
                    redeemer_at(1).expect("the certificate at position 1 is paired with a redeemer");
                assert_eq!(second.index, 1);
                assert_eq!(
                    second.ex_units,
                    Some(u5c::ExUnits {
                        memory: 3_000,
                        steps: 4_000
                    }),
                    "each position reads its own redeemer, so an off by one cannot pass"
                );

                assert_eq!(
                    redeemer_at(2),
                    None,
                    "and a position the transaction pairs no redeemer with carries none"
                );
            }

            /// The u5c rational of these two numbers, written in the u5c types so the
            /// expectation does not repeat the cast the mapper performs.
            fn u5c_ratio(numerator: i32, denominator: u32) -> u5c::RationalNumber {
                u5c::RationalNumber {
                    numerator,
                    denominator,
                }
            }

            #[test]
            fn execution_prices_map_memory_and_steps_to_the_fields_their_names_give() {
                let mapped = execution_prices_to_u5c(pallas_primitives::ExUnitPrices {
                    mem_price: ratio(1, 2),
                    step_price: ratio(3, 4),
                });

                assert_eq!(
                    mapped,
                    u5c::ExPrices {
                        memory: Some(u5c_ratio(1, 2)),
                        steps: Some(u5c_ratio(3, 4)),
                    },
                    "the price of a memory unit and the price of a step reach the fields their own names give"
                );
            }

            /// The parameters an update of every key must map to, written from what
            /// each key means rather than from what the mapper does. The V4 cost model
            /// is the one entry only a Dijkstra update can propose, so the caller says
            /// whether to expect it.
            fn every_key_as_pparams(plutus_v4: Option<u5c::CostModel>) -> u5c::PParams {
                u5c::PParams {
                    min_fee_coefficient: u64_to_bigint(1),
                    min_fee_constant: u64_to_bigint(2),
                    max_block_body_size: 3,
                    max_tx_size: 4,
                    max_block_header_size: 5,
                    stake_key_deposit: u64_to_bigint(6),
                    pool_deposit: u64_to_bigint(7),
                    pool_retirement_epoch_bound: 8,
                    desired_number_of_pools: 9,
                    pool_influence: Some(u5c_ratio(10, 11)),
                    monetary_expansion: Some(u5c_ratio(12, 13)),
                    treasury_expansion: Some(u5c_ratio(14, 15)),
                    min_pool_cost: u64_to_bigint(16),
                    coins_per_utxo_byte: u64_to_bigint(17),
                    cost_models: Some(u5c::CostModels {
                        plutus_v1: Some(u5c::CostModel { values: vec![181] }),
                        plutus_v2: Some(u5c::CostModel { values: vec![182] }),
                        plutus_v3: Some(u5c::CostModel { values: vec![183] }),
                        plutus_v4,
                    }),
                    prices: Some(u5c::ExPrices {
                        memory: Some(u5c_ratio(19, 20)),
                        steps: Some(u5c_ratio(21, 22)),
                    }),
                    max_execution_units_per_transaction: Some(u5c::ExUnits {
                        memory: 23,
                        steps: 24,
                    }),
                    max_execution_units_per_block: Some(u5c::ExUnits {
                        memory: 25,
                        steps: 26,
                    }),
                    max_value_size: 27,
                    collateral_percentage: 28,
                    max_collateral_inputs: 29,
                    pool_voting_thresholds: Some(u5c::VotingThresholds {
                        thresholds: vec![
                            u5c_ratio(30, 31),
                            u5c_ratio(32, 33),
                            u5c_ratio(34, 35),
                            u5c_ratio(36, 37),
                            u5c_ratio(38, 39),
                        ],
                    }),
                    drep_voting_thresholds: Some(u5c::VotingThresholds {
                        thresholds: vec![
                            u5c_ratio(40, 41),
                            u5c_ratio(42, 43),
                            u5c_ratio(44, 45),
                            u5c_ratio(46, 47),
                            u5c_ratio(48, 49),
                            u5c_ratio(50, 51),
                            u5c_ratio(52, 53),
                            u5c_ratio(54, 55),
                            u5c_ratio(56, 57),
                            u5c_ratio(58, 59),
                        ],
                    }),
                    min_committee_size: 60,
                    committee_term_limit: 61,
                    governance_action_validity_period: 62,
                    governance_action_deposit: u64_to_bigint(63),
                    drep_deposit: u64_to_bigint(64),
                    drep_inactivity_period: 65,
                    min_fee_script_ref_cost_per_byte: Some(u5c_ratio(66, 67)),
                    // Neither era this mapper's parameter update admits has a
                    // protocol version key, so this field has no key to read and stays
                    // unset. A hard fork initiation action proposes the version.
                    protocol_version: None,
                }
            }

            #[test]
            fn a_conway_parameter_change_maps_every_key_u5c_carries() {
                let update = conway_update_of_every_key();
                let mapper = Mapper::new(NoLedger);

                let mapped =
                    mapper.map_pparams_update(&pallas_traverse::MultiEraParamUpdate::Conway(
                        Box::new(std::borrow::Cow::Borrowed(&update)),
                    ));

                assert_eq!(
                    mapped,
                    Some(every_key_as_pparams(None)),
                    "every key a Conway update sets must reach the u5c field that key means, carrying that key's own value"
                );
            }

            #[cfg(feature = "unstable")]
            #[test]
            fn a_dijkstra_parameter_change_maps_every_key_u5c_carries() {
                let update = dijkstra_update_of_every_key();
                let mapper = Mapper::new(NoLedger);

                let mapped =
                    mapper.map_pparams_update(&pallas_traverse::MultiEraParamUpdate::Dijkstra(
                        Box::new(std::borrow::Cow::Borrowed(&update)),
                    ));

                assert_eq!(
                    mapped,
                    Some(every_key_as_pparams(Some(u5c::CostModel {
                        values: vec![184]
                    }))),
                    "the same keys read the same u5c fields under Dijkstra, and the V4 cost model reaches the field only this era can fill"
                );
            }

            #[test]
            fn an_update_setting_any_one_key_to_zero_is_still_an_update() {
                let mapper = Mapper::new(NoLedger);
                let cases = conway_updates_of_one_zero_key();

                assert_eq!(
                    cases.len(),
                    KEYS_THE_UPDATE_MAPPER_READS,
                    "one case per key the mapper reads, so a key that stops going through the read helper cannot hide behind a short list"
                );

                let blank = conway_update_of_no_key();
                assert_eq!(
                    mapper.map_pparams_update(&pallas_traverse::MultiEraParamUpdate::Conway(
                        Box::new(std::borrow::Cow::Borrowed(&blank)),
                    )),
                    None,
                    "an update setting no key at all is no update, which is what the per key cases below have to be told apart from"
                );

                for (key, update) in cases {
                    let mapped =
                        mapper.map_pparams_update(&pallas_traverse::MultiEraParamUpdate::Conway(
                            Box::new(std::borrow::Cow::Borrowed(&update)),
                        ));

                    assert!(
                        mapped.is_some(),
                        "the key {key}, set alone to its own zero, is one u5c carries, so the update must map to parameters rather than to no update at all"
                    );
                }
            }

            #[cfg(feature = "unstable")]
            #[test]
            fn a_dijkstra_update_setting_any_one_key_to_zero_is_still_an_update() {
                let mapper = Mapper::new(NoLedger);
                let cases = dijkstra_updates_of_one_zero_key();

                assert_eq!(
                    cases.len(),
                    KEYS_THE_UPDATE_MAPPER_READS,
                    "one case per key the mapper reads, so a key that stops going through the read helper cannot hide behind a short list"
                );

                let blank = dijkstra_update_of_no_key();
                assert_eq!(
                    mapper.map_pparams_update(&pallas_traverse::MultiEraParamUpdate::Dijkstra(
                        Box::new(std::borrow::Cow::Borrowed(&blank)),
                    )),
                    None,
                    "an update setting no key at all is no update, which is what the per key cases below have to be told apart from"
                );

                for (key, update) in cases {
                    let mapped =
                        mapper.map_pparams_update(&pallas_traverse::MultiEraParamUpdate::Dijkstra(
                            Box::new(std::borrow::Cow::Borrowed(&update)),
                        ));

                    assert!(
                        mapped.is_some(),
                        "the key {key}, set alone to its own zero, is one u5c carries under Dijkstra too, so the update must map to parameters rather than to no update at all"
                    );
                }
            }

            #[cfg(feature = "unstable")]
            #[test]
            fn a_dijkstra_parameter_change_maps_a_key_u5c_carries() {
                let proposal =
                    dijkstra_proposal(include_str!("../../../test_data/proposal-param-change-key0.hex"));
                let mapper = Mapper::new(NoLedger);
                let change = parameter_change(
                    mapper.map_gov_action(&trv::MultiEraGovAction::from_dijkstra(
                        &proposal.gov_action,
                    )),
                );

                assert_eq!(
                    change.protocol_param_update,
                    Some(u5c::PParams {
                        min_fee_coefficient: u64_to_bigint(1000),
                        ..Default::default()
                    }),
                    "key 0 is min_fee_coefficient, and it is the only field this update sets"
                );
            }

            #[cfg(feature = "unstable")]
            #[test]
            fn a_dijkstra_parameter_change_of_a_key_u5c_cannot_carry_maps_to_no_parameters() {
                let proposal =
                    dijkstra_proposal(include_str!("../../../test_data/proposal-param-change-key48.hex"));
                let mapper = Mapper::new(NoLedger);
                let change = parameter_change(
                    mapper.map_gov_action(&trv::MultiEraGovAction::from_dijkstra(
                        &proposal.gov_action,
                    )),
                );

                assert_eq!(
                    change.protocol_param_update, None,
                    "key 48 has no u5c field, so the update must be absent rather than a PParams whose every field reads its proto3 zero"
                );
            }

            #[cfg(feature = "unstable")]
            #[test]
            fn a_dijkstra_parameter_change_of_a_carried_key_and_an_era_key_maps_the_carried_one() {
                // Key 16 is min_pool_cost, key 48 is max_ref_script_size_per_endorser_block.
                let update = dijkstra_update(&[0xa2, 0x10, 0x10, 0x18, 0x30, 0x19, 0x4e, 0x20]);
                let mapper = Mapper::new(NoLedger);

                let mapped =
                    mapper.map_pparams_update(&pallas_traverse::MultiEraParamUpdate::Dijkstra(
                        Box::new(std::borrow::Cow::Borrowed(&update)),
                    ));

                assert_eq!(
                    mapped,
                    Some(u5c::PParams {
                        min_pool_cost: u64_to_bigint(16),
                        ..Default::default()
                    }),
                    "the key u5c carries reaches its field, and the key it cannot carry neither adds a field nor takes the update away"
                );
            }

            #[cfg(feature = "unstable")]
            #[test]
            fn a_dijkstra_transaction_maps_every_script_it_carries() {
                let tx = dijkstra_tx(include_str!("../../../test_data/dijkstra-scripts.tx"));
                let mapper = Mapper::new(NoLedger);
                let mapped = mapper.map_tx(&tx);

                let v4_bytes = || {
                    Some(u5c::script::Script::PlutusV4(
                        hex::decode("d87980").unwrap().into(),
                    ))
                };

                let witness = &mapped.witnesses.as_ref().unwrap().script;
                assert_eq!(witness.len(), 1, "the witness set carries one script");
                let Some(u5c::script::Script::Native(clause)) = &witness[0].script else {
                    panic!(
                        "the witness set script is a native script, got {:?}",
                        witness[0].script
                    );
                };
                assert_eq!(
                    clause.native_script, None,
                    "a guard clause has no member in the u5c native_script oneof, so it reaches the wire as an empty message, which is this mapper's known limit"
                );

                let aux = &mapped.auxiliary.as_ref().unwrap().scripts;
                assert_eq!(
                    aux.len(),
                    2,
                    "the auxiliary data carries a native script and a V4 script"
                );
                let Some(u5c::script::Script::Native(aux_clause)) = &aux[0].script else {
                    panic!(
                        "the first auxiliary script is a native script, got {:?}",
                        aux[0].script
                    );
                };
                assert_eq!(
                    aux_clause.native_script, None,
                    "the same guard clause reaches the auxiliary list as the same empty message"
                );
                assert_eq!(
                    aux[1].script,
                    v4_bytes(),
                    "the auxiliary V4 script must reach the V4 field carrying its own bytes"
                );

                let output = &mapped.outputs[0];
                let script = output
                    .script
                    .as_ref()
                    .expect("the output carries a reference script");
                assert_eq!(
                    script.script,
                    v4_bytes(),
                    "a V4 reference script must reach the V4 field carrying its own bytes"
                );
            }

            #[cfg(feature = "unstable")]
            #[test]
            fn a_dijkstra_transaction_maps_its_auxiliary_plutus_scripts() {
                let tx = dijkstra_tx_with_aux_plutus_scripts();
                let mapped = Mapper::new(NoLedger).map_tx(&tx);

                let aux = &mapped.auxiliary.as_ref().unwrap().scripts;
                let scripts: Vec<Option<u5c::script::Script>> =
                    aux.iter().map(|x| x.script.clone()).collect();

                assert_eq!(
                    scripts,
                    vec![
                        Some(u5c::script::Script::PlutusV1(AUX_PLUTUS_V1.to_vec().into())),
                        Some(u5c::script::Script::PlutusV2(AUX_PLUTUS_V2.to_vec().into())),
                        Some(u5c::script::Script::PlutusV3(AUX_PLUTUS_V3.to_vec().into())),
                    ],
                    "each auxiliary Plutus script must reach the field of its own version carrying its own bytes"
                );
            }

            #[test]
            fn every_reference_script_language_maps_to_the_field_it_names() {
                let mapper = Mapper::new(NoLedger);

                let plutus: Vec<Option<u5c::script::Script>> = [1u8, 2, 3]
                    .iter()
                    .map(|language| {
                        let script = conway_plutus_script_ref(*language, &[*language, 0xaa, 0xbb]);
                        mapper
                            .map_script_ref(&pallas_traverse::MultiEraScriptRef::from_conway(
                                &script,
                            ))
                            .script
                    })
                    .collect();

                assert_eq!(
                    plutus,
                    vec![
                        Some(u5c::script::Script::PlutusV1(
                            vec![1u8, 0xaa, 0xbb].into()
                        )),
                        Some(u5c::script::Script::PlutusV2(
                            vec![2u8, 0xaa, 0xbb].into()
                        )),
                        Some(u5c::script::Script::PlutusV3(
                            vec![3u8, 0xaa, 0xbb].into()
                        )),
                    ],
                    "a reference script of one Plutus version must reach the field of that version carrying its own bytes"
                );

                let native = conway_native_script_ref([0x71; 28]);
                let multi = pallas_traverse::MultiEraScriptRef::from_conway(&native);
                let Some(u5c::script::Script::Native(clause)) = mapper.map_script_ref(&multi).script
                else {
                    panic!(
                        "a native reference script must reach the native field, got {:?}",
                        mapper.map_script_ref(&multi).script
                    );
                };
                assert_eq!(
                    Some(clause),
                    multi
                        .native_script()
                        .map(|x| Mapper::<NoLedger>::map_multi_era_native_script(&x)),
                    "a native reference script maps to what its own native script maps to, rather than to an empty or a Plutus message"
                );
            }

            #[cfg(feature = "unstable")]
            #[test]
            fn a_dijkstra_reference_script_maps_the_language_only_this_era_names() {
                let script = dijkstra_plutus_v4_script_ref(&[0x04, 0xaa, 0xbb]);
                let mapped = Mapper::new(NoLedger)
                    .map_script_ref(&pallas_traverse::MultiEraScriptRef::from_dijkstra(&script));

                assert_eq!(
                    mapped.script,
                    Some(u5c::script::Script::PlutusV4(
                        vec![0x04u8, 0xaa, 0xbb].into()
                    )),
                    "a PlutusV4 reference script must reach the V4 field carrying its own bytes"
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
                    &pallas_traverse::MultiEraNativeScript::from_decoded_dijkstra(&script),
                );

                let Some(u5c::native_script::NativeScript::ScriptAll(list)) = mapped.native_script
                else {
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
                    "the guard has no member in the u5c oneof, so it reaches the wire as an empty message"
                );
                assert!(
                    list.items[1].native_script.is_some(),
                    "and the clause beside it keeps its own member"
                );
                assert_ne!(
                    list.items[0].native_script, list.items[1].native_script,
                    "so the guard must not read as the clause beside it"
                );
            }

            #[test]
            fn a_conway_transaction_maps_its_plutus_v3_witness_script() {
                let tx = conway_tx(include_str!("../../../test_data/conway9.tx"));
                let mapper = Mapper::new(NoLedger);
                let mapped = mapper.map_tx(&tx);

                let scripts = &mapped.witnesses.as_ref().unwrap().script;

                assert_eq!(
                    plutus_script_counts(scripts),
                    (1, 1, 1),
                    "the witness set carries one V1, one V2 and one V3 script, and each must be mapped"
                );

                assert_eq!(
                    plutus_v3_bytes(scripts),
                    vec![hex::decode("450101002499").unwrap()],
                    "the V3 witness script must reach the V3 field carrying its own bytes"
                );
            }

            #[test]
            fn a_conway_transaction_without_a_v3_witness_script_reports_no_v3() {
                let tx = conway_tx(include_str!("../../../test_data/conway2.tx"));
                let mapper = Mapper::new(NoLedger);
                let mapped = mapper.map_tx(&tx);

                let scripts = &mapped.witnesses.as_ref().unwrap().script;

                assert_eq!(
                    plutus_script_counts(scripts),
                    (2, 0, 0),
                    "a witness set of two V1 scripts must map two V1 scripts and no V2 or V3"
                );

                assert_eq!(
                    plutus_v3_bytes(scripts),
                    Vec::<Vec<u8>>::new(),
                    "no script of another version may be reported as a V3 script"
                );
            }

            #[test]
            fn snapshot() {
                let mapper = Mapper::new(NoLedger);

                for (block_str, json_str, file) in snapshot_cases() {
                    let cbor = hex::decode(block_str).unwrap();
                    let block = pallas_traverse::MultiEraBlock::decode(&cbor).unwrap();
                    let current = serde_json::json!(mapper.map_block(&block));

                    // Set REGENERATE_SNAPSHOTS=1 to overwrite the snapshot file in place.
                    if std::env::var("REGENERATE_SNAPSHOTS").is_ok() {
                        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                            .join("../test_data")
                            .join(file);
                        std::fs::write(&path, serde_json::to_string_pretty(&current).unwrap())
                            .unwrap();
                        eprintln!("regenerated {}", path.display());
                        continue;
                    }

                    let expected: serde_json::Value = serde_json::from_str(json_str).unwrap();

                    assert_eq!(expected, current, "{file}")
                }
            }

            #[test]
            fn the_era_neutral_walk_clamps_a_negative_n_of_k_threshold_to_zero() {
                let negative = pallas_traverse::MultiEraNativeScript::from_decoded_alonzo_compatible(
                    &pallas_primitives::alonzo::NativeScript::ScriptNOfK(-1, vec![]),
                );
                assert!(matches!(
                    Mapper::<NoLedger>::map_multi_era_native_script(&negative).native_script,
                    Some(u5c::native_script::NativeScript::ScriptNOfK(
                        u5c::ScriptNOfK { k: 0, .. }
                    ))
                ));

                let positive = pallas_traverse::MultiEraNativeScript::from_decoded_alonzo_compatible(
                    &pallas_primitives::alonzo::NativeScript::ScriptNOfK(2, vec![]),
                );
                assert!(
                    matches!(
                        Mapper::<NoLedger>::map_multi_era_native_script(&positive).native_script,
                        Some(u5c::native_script::NativeScript::ScriptNOfK(
                            u5c::ScriptNOfK { k: 2, .. }
                        ))
                    ),
                    "a threshold the u5c field can hold reaches it unclamped"
                );
            }

            #[test]
            fn the_era_neutral_walk_preserves_mixed_shape_trees() {
                use pallas_primitives::alonzo::NativeScript;

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
                let script =
                    pallas_traverse::MultiEraNativeScript::from_decoded_alonzo_compatible(&script);

                let mapped = Mapper::<NoLedger>::map_multi_era_native_script(&script);
                let Some(u5c::native_script::NativeScript::ScriptNOfK(n_of_k)) =
                    &mapped.native_script
                else {
                    panic!("expected ScriptNOfK, got {:?}", mapped.native_script);
                };
                assert_eq!(n_of_k.k, 2);
                assert_eq!(n_of_k.scripts.len(), 3);

                // Two levels are wider than one child, so a walk that pairs a
                // mapped child with the wrong source child keeps every count
                // right and still fails here.
                assert_eq!(
                    n_of_k.scripts[0].native_script,
                    Some(Mapper::<NoLedger>::map_native_script_pubkey(vec![1u8; 28]))
                );
                assert_eq!(
                    n_of_k.scripts[2].native_script,
                    Some(Mapper::<NoLedger>::map_native_script_pubkey(vec![3u8; 28]))
                );

                let Some(u5c::native_script::NativeScript::ScriptAll(all)) =
                    &n_of_k.scripts[1].native_script
                else {
                    panic!(
                        "expected ScriptAll, got {:?}",
                        n_of_k.scripts[1].native_script
                    );
                };
                assert_eq!(all.items.len(), 2);
                assert_eq!(
                    all.items[0].native_script,
                    Some(Mapper::<NoLedger>::map_native_script_pubkey(vec![2u8; 28]))
                );

                let Some(u5c::native_script::NativeScript::ScriptAny(any)) =
                    &all.items[1].native_script
                else {
                    panic!("expected ScriptAny, got {:?}", all.items[1].native_script);
                };
                assert_eq!(any.items.len(), 2);
                assert_eq!(
                    any.items[0].native_script,
                    Some(u5c::native_script::NativeScript::InvalidBefore(100))
                );
                assert_eq!(
                    any.items[1].native_script,
                    Some(u5c::native_script::NativeScript::InvalidHereafter(200))
                );
            }

            #[test]
            fn the_era_neutral_walk_handles_deeply_nested_scripts_on_a_small_stack() {
                // Depth and stack size are load-bearing, not just generous:
                // both must stay far enough apart that a mapping of one call
                // frame per level aborts here, or this test stops proving
                // anything the moment either constant drifts.
                std::thread::Builder::new()
                    .stack_size(128 * 1024)
                    .spawn(|| {
                        let mut script =
                            pallas_primitives::alonzo::NativeScript::ScriptPubkey([0; 28].into());
                        for _ in 0..20_000 {
                            script =
                                pallas_primitives::alonzo::NativeScript::ScriptAll(vec![script]);
                        }
                        let script =
                            pallas_traverse::MultiEraNativeScript::from_decoded_alonzo_compatible(
                                &script,
                            );

                        let mapped = Mapper::<NoLedger>::map_multi_era_native_script(&script);

                        let mut depth = 0;
                        let mut cursor = &mapped;
                        while let Some(u5c::native_script::NativeScript::ScriptAll(list)) =
                            &cursor.native_script
                        {
                            cursor = list.items.first().expect("ScriptAll must carry a child");
                            depth += 1;
                        }
                        assert_eq!(depth, 20_000);
                        assert_eq!(
                            cursor.native_script,
                            Some(Mapper::<NoLedger>::map_native_script_pubkey(vec![0u8; 28])),
                            "the walk reaches the leaf the source put at the bottom"
                        );

                        // u5c's generated type has no custom Drop, so dropping
                        // a chain this deep aborts the way a recursive mapping
                        // does. Leak it: this test is about the mapping, and
                        // the leak is a few MB, thread local and test only.
                        std::mem::forget(mapped);
                    })
                    .unwrap()
                    .join()
                    .unwrap();
            }

            #[cfg(feature = "unstable")]
            #[test]
            fn the_era_neutral_walk_handles_a_deeply_nested_dijkstra_script() {
                std::thread::Builder::new()
                    .stack_size(128 * 1024)
                    .spawn(|| {
                        let mut script =
                            pallas_primitives::dijkstra::NativeScript::ScriptPubkey([0; 28].into());
                        for _ in 0..20_000 {
                            script =
                                pallas_primitives::dijkstra::NativeScript::ScriptAll(vec![script]);
                        }
                        let script =
                            pallas_traverse::MultiEraNativeScript::from_decoded_dijkstra(&script);

                        let mapped = Mapper::<NoLedger>::map_multi_era_native_script(&script);

                        let mut depth = 0;
                        let mut cursor = &mapped;
                        while let Some(u5c::native_script::NativeScript::ScriptAll(list)) =
                            &cursor.native_script
                        {
                            cursor = list.items.first().expect("ScriptAll must carry a child");
                            depth += 1;
                        }
                        assert_eq!(depth, 20_000);
                        assert_eq!(
                            cursor.native_script,
                            Some(Mapper::<NoLedger>::map_native_script_pubkey(vec![0u8; 28]))
                        );

                        std::mem::forget(mapped);
                    })
                    .unwrap()
                    .join()
                    .unwrap();
            }

            #[cfg(feature = "unstable")]
            #[test]
            fn a_guard_clause_nested_in_a_dijkstra_script_maps_to_an_empty_message() {
                use pallas_primitives::dijkstra::{NativeScript, StakeCredential};

                let guard = NativeScript::ScriptRequireGuard(StakeCredential::AddrKeyhash(
                    [9u8; 28].into(),
                ));
                let script = NativeScript::ScriptAll(vec![
                    NativeScript::ScriptPubkey([8; 28].into()),
                    guard,
                ]);
                let script = pallas_traverse::MultiEraNativeScript::from_decoded_dijkstra(&script);

                let mapped = Mapper::<NoLedger>::map_multi_era_native_script(&script);
                let Some(u5c::native_script::NativeScript::ScriptAll(all)) = &mapped.native_script
                else {
                    panic!("expected ScriptAll, got {:?}", mapped.native_script);
                };

                assert_eq!(all.items.len(), 2, "a guard clause keeps its position");
                assert_eq!(
                    all.items[0].native_script,
                    Some(Mapper::<NoLedger>::map_native_script_pubkey(vec![8u8; 28])),
                    "the clause beside a guard maps to what it means"
                );
                assert_eq!(
                    all.items[1].native_script, None,
                    "a guard clause has no u5c field and maps to an empty message"
                );
            }

            #[cfg(feature = "unstable")]
            #[test]
            fn a_sub_transaction_reaches_none_of_the_mapped_transaction() {
                let tx = dijkstra_tx(include_str!("../../../test_data/dijkstra-subtx.tx"));
                let subs = tx.sub_transactions();
                assert_eq!(
                    subs.len(),
                    1,
                    "this fixture must carry the case the test is about"
                );
                assert_eq!(
                    subs[0].inputs().len(),
                    1,
                    "the sub transaction spends an input of its own, which is the one this test watches for"
                );

                let mapped = Mapper::new(NoLedger).map_tx(&tx);

                let inputs: Vec<(String, u32)> = mapped
                    .inputs
                    .iter()
                    .map(|x| (hex::encode(&x.tx_hash), x.output_index))
                    .collect();
                assert_eq!(
                    inputs,
                    vec![(
                        "737549420add1f19d144809aa02e2ae68a89b1761368e3294fbb30ee1467e3e4"
                            .to_string(),
                        12
                    )],
                    "the outer body's one input is the whole of the mapped inputs"
                );

                let outputs: Vec<i64> = mapped
                    .outputs
                    .iter()
                    .map(|x| match x.coin.as_ref().and_then(|c| c.big_int.as_ref()) {
                        Some(u5c::big_int::BigInt::Int(v)) => *v,
                        other => panic!("an output lovelace amount arrives as an int: {other:?}"),
                    })
                    .collect();
                assert_eq!(
                    outputs,
                    vec![1_903_631],
                    "the outer body's one output is the whole of the mapped outputs"
                );

                // The sub transaction spends `2ed1285c..#0`, which the outer body also
                // names at key 18.
                let sub_input =
                    "2ed1285cced47acb5f08502843d980d7231665af9d90ef33fe6751e0f9e0b171";
                let references: Vec<(String, u32)> = mapped
                    .reference_inputs
                    .iter()
                    .map(|x| (hex::encode(&x.tx_hash), x.output_index))
                    .collect();
                assert_eq!(
                    references,
                    vec![
                        (sub_input.to_string(), 0),
                        (
                            "c095234678d98a74cd1488bda1971fbd2e9c828acf57f7673c679ec601abf7a6"
                                .to_string(),
                            0
                        )
                    ],
                    "the outer body's two reference inputs reach u5c"
                );

                let collateral: Vec<(String, u32)> = mapped
                    .collateral
                    .as_ref()
                    .expect("the outer body carries key 13")
                    .collateral
                    .iter()
                    .map(|x| (hex::encode(&x.tx_hash), x.output_index))
                    .collect();
                assert_eq!(
                    collateral,
                    vec![(
                        "7727ec1dfb0f84f2ffeb51935f35850cf84cfabfca1957e8c74cf8fde871dd34"
                            .to_string(),
                        12
                    )],
                    "the outer body's one collateral input reaches u5c"
                );
            }

            #[cfg(feature = "unstable")]
            #[test]
            fn a_sub_transaction_maps_to_its_own_body() {
                let tx = dijkstra_tx(include_str!("../../../test_data/dijkstra-subtx.tx"));
                let subs = tx.sub_transactions();
                assert_eq!(
                    subs.len(),
                    1,
                    "this fixture must carry the case the test is about"
                );

                let mapped = Mapper::new(NoLedger).map_tx(&subs[0]);

                let inputs: Vec<(String, u32)> = mapped
                    .inputs
                    .iter()
                    .map(|x| (hex::encode(&x.tx_hash), x.output_index))
                    .collect();
                assert_eq!(
                    inputs,
                    vec![(
                        "2ed1285cced47acb5f08502843d980d7231665af9d90ef33fe6751e0f9e0b171"
                            .to_string(),
                        0
                    )],
                    "the sub body's one input is the whole of the mapped inputs"
                );

                let outputs: Vec<i64> = mapped
                    .outputs
                    .iter()
                    .map(|x| match x.coin.as_ref().and_then(|c| c.big_int.as_ref()) {
                        Some(u5c::big_int::BigInt::Int(v)) => *v,
                        other => panic!("an output lovelace amount arrives as an int: {other:?}"),
                    })
                    .collect();
                assert_eq!(
                    outputs,
                    vec![3_000_000],
                    "the sub body's one output is the whole of the mapped outputs"
                );

                assert_eq!(
                    mapped.fee, None,
                    "a sub body has no fee key, so it reports no fee rather than a fee of zero"
                );

                let enclosing = Mapper::new(NoLedger).map_tx(&tx);
                assert!(
                    enclosing.fee.is_some(),
                    "and the enclosing body carries the one fee the whole transaction pays, so the absent fee above is the sub body's own state rather than a mapper reporting no fee at all"
                );
            }
        }

        // ---- protocol parameters --------------------------------------------

        impl<C: $crate::LedgerContext> Mapper<C> {
            pub fn map_pparams(
                &self,
                pparams: pallas_validate::utils::MultiEraProtocolParameters,
            ) -> u5c::PParams {
                use pallas_primitives::alonzo::Language;
                use pallas_validate::utils::MultiEraProtocolParameters;
                match pparams {
                    MultiEraProtocolParameters::Alonzo(params) => u5c::PParams {
                        max_tx_size: params.max_transaction_size.into(),
                        max_block_body_size: params.max_block_body_size.into(),
                        max_block_header_size: params.max_block_header_size.into(),
                        min_fee_coefficient: u64_to_bigint(params.minfee_a.into()),
                        min_fee_constant: u64_to_bigint(params.minfee_b.into()),
                        coins_per_utxo_byte: u64_to_bigint(params.ada_per_utxo_byte),
                        stake_key_deposit: u64_to_bigint(params.key_deposit),
                        pool_deposit: u64_to_bigint(params.pool_deposit),
                        desired_number_of_pools: params.desired_number_of_stake_pools.into(),
                        pool_influence: Some(rational_number_to_u5c(params.pool_pledge_influence)),
                        monetary_expansion: Some(rational_number_to_u5c(params.expansion_rate)),
                        treasury_expansion: Some(rational_number_to_u5c(
                            params.treasury_growth_rate,
                        )),
                        min_pool_cost: u64_to_bigint(params.min_pool_cost),
                        protocol_version: Some(u5c::ProtocolVersion {
                            major: params.protocol_version.0 as u32,
                            minor: params.protocol_version.1 as u32,
                        }),
                        max_value_size: params.max_value_size.into(),
                        collateral_percentage: params.collateral_percentage.into(),
                        max_collateral_inputs: params.max_collateral_inputs.into(),
                        prices: Some(execution_prices_to_u5c(params.execution_costs)),
                        max_execution_units_per_transaction: Some(execution_units_to_u5c(
                            params.max_tx_ex_units,
                        )),
                        max_execution_units_per_block: Some(execution_units_to_u5c(
                            params.max_block_ex_units,
                        )),
                        cost_models: u5c::CostModels {
                            plutus_v1: params
                                .cost_models_for_script_languages
                                .get_key_value(&Language::PlutusV1)
                                .map(|(_, data)| u5c::CostModel {
                                    values: data.to_vec(),
                                }),
                            ..Default::default()
                        }
                        .into(),
                        ..Default::default()
                    },
                    MultiEraProtocolParameters::Shelley(params) => u5c::PParams {
                        max_tx_size: params.max_transaction_size.into(),
                        max_block_body_size: params.max_block_body_size.into(),
                        max_block_header_size: params.max_block_header_size.into(),
                        min_fee_coefficient: u64_to_bigint(params.minfee_a.into()),
                        min_fee_constant: u64_to_bigint(params.minfee_b.into()),
                        stake_key_deposit: u64_to_bigint(params.key_deposit),
                        pool_deposit: u64_to_bigint(params.pool_deposit),
                        desired_number_of_pools: params.desired_number_of_stake_pools.into(),
                        pool_influence: Some(rational_number_to_u5c(params.pool_pledge_influence)),
                        monetary_expansion: Some(rational_number_to_u5c(params.expansion_rate)),
                        treasury_expansion: Some(rational_number_to_u5c(
                            params.treasury_growth_rate,
                        )),
                        min_pool_cost: u64_to_bigint(params.min_pool_cost),
                        protocol_version: Some(u5c::ProtocolVersion {
                            major: params.protocol_version.0 as u32,
                            minor: params.protocol_version.1 as u32,
                        }),
                        ..Default::default()
                    },
                    MultiEraProtocolParameters::Babbage(params) => u5c::PParams {
                        max_tx_size: params.max_transaction_size.into(),
                        max_block_body_size: params.max_block_body_size.into(),
                        max_block_header_size: params.max_block_header_size.into(),
                        min_fee_coefficient: u64_to_bigint(params.minfee_a.into()),
                        min_fee_constant: u64_to_bigint(params.minfee_b.into()),
                        coins_per_utxo_byte: u64_to_bigint(params.ada_per_utxo_byte),
                        stake_key_deposit: u64_to_bigint(params.key_deposit),
                        pool_deposit: u64_to_bigint(params.pool_deposit),
                        desired_number_of_pools: params.desired_number_of_stake_pools.into(),
                        pool_influence: Some(rational_number_to_u5c(params.pool_pledge_influence)),
                        monetary_expansion: Some(rational_number_to_u5c(params.expansion_rate)),
                        treasury_expansion: Some(rational_number_to_u5c(
                            params.treasury_growth_rate,
                        )),
                        min_pool_cost: u64_to_bigint(params.min_pool_cost),
                        protocol_version: u5c::ProtocolVersion {
                            major: params.protocol_version.0 as u32,
                            minor: params.protocol_version.1 as u32,
                        }
                        .into(),
                        max_value_size: params.max_value_size.into(),
                        collateral_percentage: params.collateral_percentage.into(),
                        max_collateral_inputs: params.max_collateral_inputs.into(),
                        prices: Some(execution_prices_to_u5c(params.execution_costs)),
                        max_execution_units_per_transaction: Some(execution_units_to_u5c(
                            params.max_tx_ex_units,
                        )),
                        max_execution_units_per_block: Some(execution_units_to_u5c(
                            params.max_block_ex_units,
                        )),
                        cost_models: u5c::CostModels {
                            plutus_v1: params
                                .cost_models_for_script_languages
                                .plutus_v1
                                .map(|values| u5c::CostModel { values }),
                            plutus_v2: params
                                .cost_models_for_script_languages
                                .plutus_v2
                                .map(|values| u5c::CostModel { values }),
                            ..Default::default()
                        }
                        .into(),
                        ..Default::default()
                    },
                    MultiEraProtocolParameters::Byron(params) => u5c::PParams {
                        max_tx_size: params.max_tx_size,
                        max_block_body_size: params.max_block_size - params.max_header_size,
                        max_block_header_size: params.max_header_size,
                        ..Default::default()
                    },
                    MultiEraProtocolParameters::Conway(params) => u5c::PParams {
                        max_tx_size: params.max_transaction_size.into(),
                        max_block_body_size: params.max_block_body_size.into(),
                        max_block_header_size: params.max_block_header_size.into(),
                        min_fee_coefficient: u64_to_bigint(params.minfee_a.into()),
                        min_fee_constant: u64_to_bigint(params.minfee_b.into()),
                        coins_per_utxo_byte: u64_to_bigint(params.ada_per_utxo_byte),
                        stake_key_deposit: u64_to_bigint(params.key_deposit),
                        pool_deposit: u64_to_bigint(params.pool_deposit),
                        desired_number_of_pools: params.desired_number_of_stake_pools.into(),
                        pool_influence: Some(rational_number_to_u5c(params.pool_pledge_influence)),
                        monetary_expansion: Some(rational_number_to_u5c(params.expansion_rate)),
                        treasury_expansion: Some(rational_number_to_u5c(
                            params.treasury_growth_rate,
                        )),
                        min_pool_cost: u64_to_bigint(params.min_pool_cost),
                        protocol_version: u5c::ProtocolVersion {
                            major: params.protocol_version.0 as u32,
                            minor: params.protocol_version.1 as u32,
                        }
                        .into(),
                        max_value_size: params.max_value_size.into(),
                        collateral_percentage: params.collateral_percentage.into(),
                        max_collateral_inputs: params.max_collateral_inputs.into(),
                        prices: Some(execution_prices_to_u5c(params.execution_costs)),
                        max_execution_units_per_transaction: Some(execution_units_to_u5c(
                            params.max_tx_ex_units,
                        )),
                        max_execution_units_per_block: Some(execution_units_to_u5c(
                            params.max_block_ex_units,
                        )),
                        min_fee_script_ref_cost_per_byte: Some(rational_number_to_u5c(
                            params.minfee_refscript_cost_per_byte,
                        )),
                        pool_voting_thresholds: Some(u5c::VotingThresholds {
                            thresholds: vec![
                                rational_number_to_u5c(
                                    params.pool_voting_thresholds.motion_no_confidence,
                                ),
                                rational_number_to_u5c(
                                    params.pool_voting_thresholds.committee_normal,
                                ),
                                rational_number_to_u5c(
                                    params.pool_voting_thresholds.committee_no_confidence,
                                ),
                                rational_number_to_u5c(
                                    params.pool_voting_thresholds.hard_fork_initiation,
                                ),
                                rational_number_to_u5c(
                                    params.pool_voting_thresholds.security_voting_threshold,
                                ),
                            ],
                        }),
                        drep_voting_thresholds: Some(u5c::VotingThresholds {
                            thresholds: vec![
                                rational_number_to_u5c(
                                    params.drep_voting_thresholds.motion_no_confidence,
                                ),
                                rational_number_to_u5c(
                                    params.drep_voting_thresholds.committee_normal,
                                ),
                                rational_number_to_u5c(
                                    params.drep_voting_thresholds.committee_no_confidence,
                                ),
                                rational_number_to_u5c(
                                    params.drep_voting_thresholds.update_constitution,
                                ),
                                rational_number_to_u5c(
                                    params.drep_voting_thresholds.hard_fork_initiation,
                                ),
                                rational_number_to_u5c(
                                    params.drep_voting_thresholds.pp_network_group,
                                ),
                                rational_number_to_u5c(
                                    params.drep_voting_thresholds.pp_economic_group,
                                ),
                                rational_number_to_u5c(
                                    params.drep_voting_thresholds.pp_technical_group,
                                ),
                                rational_number_to_u5c(
                                    params.drep_voting_thresholds.pp_governance_group,
                                ),
                                rational_number_to_u5c(
                                    params.drep_voting_thresholds.treasury_withdrawal,
                                ),
                            ],
                        }),
                        min_committee_size: params.min_committee_size as u32,
                        committee_term_limit: params.committee_term_limit,
                        governance_action_validity_period: params.governance_action_validity_period,
                        governance_action_deposit: u64_to_bigint(params.governance_action_deposit),
                        drep_deposit: u64_to_bigint(params.drep_deposit),
                        drep_inactivity_period: params.drep_inactivity_period,
                        cost_models: u5c::CostModels {
                            plutus_v1: params
                                .cost_models_for_script_languages
                                .plutus_v1
                                .map(|values| u5c::CostModel { values }),
                            plutus_v2: params
                                .cost_models_for_script_languages
                                .plutus_v2
                                .map(|values| u5c::CostModel { values }),
                            plutus_v3: params
                                .cost_models_for_script_languages
                                .plutus_v3
                                .map(|values| u5c::CostModel { values }),
                            ..Default::default()
                        }
                        .into(),
                        ..Default::default()
                    },
                    _ => {
                        unimplemented!("map_pparams has no arm for this era's protocol parameters")
                    }
                }
            }

            /// Map a protocol parameter update of any era. Returns `None` for an
            /// update that sets no key `u5c::PParams` has a field for.
            pub fn map_pparams_update(
                &self,
                x: &pallas_traverse::MultiEraParamUpdate,
            ) -> Option<u5c::PParams> {
                let mut any_set = false;
                let seen = &mut any_set;

                let mapped = u5c::PParams {
                    coins_per_utxo_byte: read_key(seen, x.ada_per_utxo_byte())
                        .and_then(u64_to_bigint),
                    max_tx_size: read_key(seen, x.max_transaction_size()).unwrap_or_default(),
                    min_fee_coefficient: read_key(seen, x.minfee_a()).and_then(u64_to_bigint),
                    min_fee_constant: read_key(seen, x.minfee_b()).and_then(u64_to_bigint),
                    max_block_body_size: read_key(seen, x.max_block_body_size())
                        .unwrap_or_default(),
                    max_block_header_size: read_key(seen, x.max_block_header_size())
                        .unwrap_or_default(),
                    stake_key_deposit: read_key(seen, x.key_deposit()).and_then(u64_to_bigint),
                    pool_deposit: read_key(seen, x.pool_deposit()).and_then(u64_to_bigint),
                    pool_retirement_epoch_bound: read_key(seen, x.maximum_epoch())
                        .unwrap_or_default(),
                    desired_number_of_pools: read_key(seen, x.desired_number_of_stake_pools())
                        .unwrap_or_default(),
                    pool_influence: read_key(seen, x.pool_pledge_influence())
                        .map(rational_number_to_u5c),
                    monetary_expansion: read_key(seen, x.expansion_rate())
                        .map(rational_number_to_u5c),
                    treasury_expansion: read_key(seen, x.treasury_growth_rate())
                        .map(rational_number_to_u5c),
                    min_pool_cost: read_key(seen, x.min_pool_cost()).and_then(u64_to_bigint),
                    protocol_version: None,
                    max_value_size: read_key(seen, x.max_value_size()).unwrap_or_default(),
                    collateral_percentage: read_key(seen, x.collateral_percentage())
                        .unwrap_or_default(),
                    max_collateral_inputs: read_key(seen, x.max_collateral_inputs())
                        .unwrap_or_default(),
                    cost_models: read_key(seen, x.cost_models_for_script_languages()).map(|cm| {
                        u5c::CostModels {
                            plutus_v1: cm.plutus_v1.map(|values| u5c::CostModel { values }),
                            plutus_v2: cm.plutus_v2.map(|values| u5c::CostModel { values }),
                            plutus_v3: cm.plutus_v3.map(|values| u5c::CostModel { values }),
                            plutus_v4: cm.plutus_v4.map(|values| u5c::CostModel { values }),
                        }
                    }),
                    prices: read_key(seen, x.execution_costs()).map(|p| u5c::ExPrices {
                        memory: Some(rational_number_to_u5c(p.mem_price)),
                        steps: Some(rational_number_to_u5c(p.step_price)),
                    }),
                    max_execution_units_per_transaction: read_key(seen, x.max_tx_ex_units()).map(
                        |u| u5c::ExUnits {
                            memory: u.mem,
                            steps: u.steps,
                        },
                    ),
                    max_execution_units_per_block: read_key(seen, x.max_block_ex_units()).map(
                        |u| u5c::ExUnits {
                            memory: u.mem,
                            steps: u.steps,
                        },
                    ),
                    min_fee_script_ref_cost_per_byte: read_key(
                        seen,
                        x.minfee_refscript_cost_per_byte(),
                    )
                    .map(rational_number_to_u5c),
                    pool_voting_thresholds: read_key(seen, x.pool_voting_thresholds()).map(|t| {
                        u5c::VotingThresholds {
                            thresholds: vec![
                                rational_number_to_u5c(t.motion_no_confidence),
                                rational_number_to_u5c(t.committee_normal),
                                rational_number_to_u5c(t.committee_no_confidence),
                                rational_number_to_u5c(t.hard_fork_initiation),
                                rational_number_to_u5c(t.security_voting_threshold),
                            ],
                        }
                    }),
                    drep_voting_thresholds: read_key(seen, x.drep_voting_thresholds()).map(|t| {
                        u5c::VotingThresholds {
                            thresholds: vec![
                                rational_number_to_u5c(t.motion_no_confidence),
                                rational_number_to_u5c(t.committee_normal),
                                rational_number_to_u5c(t.committee_no_confidence),
                                rational_number_to_u5c(t.update_constitution),
                                rational_number_to_u5c(t.hard_fork_initiation),
                                rational_number_to_u5c(t.pp_network_group),
                                rational_number_to_u5c(t.pp_economic_group),
                                rational_number_to_u5c(t.pp_technical_group),
                                rational_number_to_u5c(t.pp_governance_group),
                                rational_number_to_u5c(t.treasury_withdrawal),
                            ],
                        }
                    }),
                    min_committee_size: read_key(seen, x.min_committee_size()).unwrap_or_default()
                        as u32,
                    committee_term_limit: read_key(seen, x.committee_term_limit())
                        .unwrap_or_default(),
                    governance_action_validity_period: read_key(
                        seen,
                        x.governance_action_validity_period(),
                    )
                    .unwrap_or_default(),
                    governance_action_deposit: read_key(seen, x.governance_action_deposit())
                        .and_then(u64_to_bigint),
                    drep_deposit: read_key(seen, x.drep_deposit()).and_then(u64_to_bigint),
                    drep_inactivity_period: read_key(seen, x.drep_inactivity_period())
                        .unwrap_or_default(),
                };

                if !any_set {
                    return None;
                }

                Some(mapped)
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
    };
}

pub(crate) use impl_cardano_mapper_shared;
