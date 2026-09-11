use std::ops::Deref;

use prost_types::FieldMask;

use pallas_primitives::{alonzo, babbage, conway};
use pallas_traverse as trv;
use trv::OriginalHash;

use crate::LedgerContext;

pub use utxorpc_spec::utxorpc::v1beta as spec;

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

crate::shared::impl_cardano_mapper_shared!(utxorpc_spec::utxorpc::v1beta::cardano);

// ---- v1beta-specific bodies for methods that diverge from v1alpha -----------

/// The u5c native script member this schema names for a required signature.
fn pubkey_clause(hash: &pallas_crypto::hash::Hash<28>) -> u5c::native_script::NativeScript {
    u5c::native_script::NativeScript::ScriptPubkeyHash(hash.to_vec().into())
}

/// The u5c governance action this schema names for an information action,
/// whose message has no field.
fn information_action() -> u5c::governance_action::GovernanceAction {
    u5c::governance_action::GovernanceAction::InfoAction(u5c::InfoAction {})
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
                Some(babbage::DatumOption::Data(x)) => Some(x.raw_cbor().to_vec().into()),
                _ => None,
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
            original_cbor: Some(x.encode().into()),
        }
    }

    fn map_output_script(&self, x: &trv::MultiEraOutput) -> Option<u5c::Script> {
        x.script_ref().map(|x| self.map_script_ref(&x))
    }

    pub fn map_asset(&self, x: &trv::MultiEraAsset) -> u5c::Asset {
        let quantity = if let Some(v) = x.output_coin() {
            u64_to_bigint(v)
        } else if let Some(v) = x.mint_coin() {
            i64_to_bigint(v)
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
            votes: self.map_votes(tx),
            withdrawals: tx
                .withdrawals_sorted_set()
                .iter()
                .enumerate()
                .map(|(order, x)| self.map_withdrawals(x, tx, order as u32))
                .collect(),
            mint: tx
                .mints_sorted_set()
                .iter()
                .map(|x| self.map_policy_assets(x))
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
                redeemers: tx
                    .redeemers()
                    .iter()
                    .map(|x| self.map_redeemer(x))
                    .collect(),
                bootstrap_witnesses: tx
                    .bootstrap_witnesses()
                    .iter()
                    .map(|x| self.map_bootstrap_witness(x))
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

    // ---- v1beta-only types (no v1alpha counterpart) -------------------------

    pub fn map_bootstrap_witness(&self, x: &alonzo::BootstrapWitness) -> u5c::BootstrapWitness {
        u5c::BootstrapWitness {
            vkey: x.public_key.to_vec().into(),
            signature: x.signature.to_vec().into(),
            chain_code: x.chain_code.to_vec().into(),
            attributes: x.attributes.to_vec().into(),
        }
    }

    pub fn map_vote(&self, x: &conway::Vote) -> u5c::Vote {
        match x {
            conway::Vote::No => u5c::Vote::No,
            conway::Vote::Yes => u5c::Vote::Yes,
            conway::Vote::Abstain => u5c::Vote::Abstain,
        }
    }

    pub fn map_voting_procedure(
        &self,
        gov_action_id: &conway::GovActionId,
        x: &conway::VotingProcedure,
    ) -> u5c::VotingProcedure {
        u5c::VotingProcedure {
            gov_action_id: Some(u5c::GovernanceActionId {
                transaction_id: gov_action_id.transaction_id.to_vec().into(),
                governance_action_index: gov_action_id.action_index,
            }),
            vote: self.map_vote(&x.vote) as i32,
            anchor: x.anchor.as_ref().map(map_anchor),
        }
    }

    fn map_voter(&self, voter: &conway::Voter) -> u5c::voter_votes::Voter {
        match voter {
            conway::Voter::ConstitutionalCommitteeKey(hash) => {
                u5c::voter_votes::Voter::ConstitutionalCommittee(u5c::StakeCredential {
                    stake_credential: u5c::stake_credential::StakeCredential::AddrKeyHash(
                        hash.to_vec().into(),
                    )
                    .into(),
                })
            }
            conway::Voter::ConstitutionalCommitteeScript(hash) => {
                u5c::voter_votes::Voter::ConstitutionalCommittee(u5c::StakeCredential {
                    stake_credential: u5c::stake_credential::StakeCredential::ScriptHash(
                        hash.to_vec().into(),
                    )
                    .into(),
                })
            }
            conway::Voter::DRepKey(hash) => u5c::voter_votes::Voter::Drep(u5c::StakeCredential {
                stake_credential: u5c::stake_credential::StakeCredential::AddrKeyHash(
                    hash.to_vec().into(),
                )
                .into(),
            }),
            conway::Voter::DRepScript(hash) => {
                u5c::voter_votes::Voter::Drep(u5c::StakeCredential {
                    stake_credential: u5c::stake_credential::StakeCredential::ScriptHash(
                        hash.to_vec().into(),
                    )
                    .into(),
                })
            }
            conway::Voter::StakePoolKey(hash) => u5c::voter_votes::Voter::Spo(hash.to_vec().into()),
        }
    }

    /// Map the transaction's voting procedures into the v1beta `votes` field.
    /// Conway and Dijkstra share the type.
    pub fn map_votes(&self, tx: &trv::MultiEraTx) -> Vec<u5c::VoterVotes> {
        let Some(procedures) = tx.voting_procedures() else {
            return Vec::new();
        };

        procedures
            .iter()
            .map(|(voter, ballots)| u5c::VoterVotes {
                voter: Some(self.map_voter(voter)),
                votes: ballots
                    .iter()
                    .map(|(gov_id, procedure)| self.map_voting_procedure(gov_id, procedure))
                    .collect(),
            })
            .collect()
    }
}

/// The block fixtures this schema has a snapshot of, each with the snapshot
/// contents and the snapshot file name.
#[cfg(test)]
fn snapshot_cases() -> Vec<(&'static str, &'static str, &'static str)> {
    #[allow(unused_mut)]
    let mut cases = vec![(
        include_str!("../../../test_data/u5c1.block"),
        include_str!("../../../test_data/u5c_v1beta.json"),
        "u5c_v1beta.json",
    )];

    #[cfg(feature = "unstable")]
    cases.push((
        include_str!("../../../test_data/dijkstra6.block"),
        include_str!("../../../test_data/u5c_v1beta_dijkstra.json"),
        "u5c_v1beta_dijkstra.json",
    ));

    cases
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_pubkey_clause_maps_to_the_member_this_schema_names() {
        let script = trv::MultiEraNativeScript::from_decoded_alonzo_compatible(
            &alonzo::NativeScript::ScriptPubkey([0x44; 28].into()),
        );

        assert_eq!(
            Mapper::<NoLedger>::map_native_script(&script).native_script,
            Some(u5c::native_script::NativeScript::ScriptPubkeyHash(
                [0x44; 28].to_vec().into()
            )),
            "this schema names the required signature member ScriptPubkeyHash and carries the key hash in it"
        );
    }

    #[test]
    fn an_information_action_maps_to_the_value_this_schema_names() {
        let mapper = Mapper::new(NoLedger);

        assert_eq!(
            mapper
                .map_gov_action(&trv::MultiEraGovAction::from_conway(&conway_information()))
                .governance_action,
            Some(u5c::governance_action::GovernanceAction::InfoAction(
                u5c::InfoAction {}
            )),
            "this schema types the information member a message with no field"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_dijkstra_transaction_with_no_votes_maps_none() {
        let tx = dijkstra_tx(include_str!("../../../test_data/dijkstra-proposal.tx"));
        let mapper = Mapper::new(NoLedger);
        assert!(mapper.map_votes(&tx).is_empty());
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_dijkstra_transaction_with_one_vote_maps_it() {
        let tx = dijkstra_tx_with_one_vote();
        let mapper = Mapper::new(NoLedger);
        let votes = mapper.map_votes(&tx);

        assert_eq!(votes.len(), 1, "the body names one voter");

        assert_eq!(
            votes[0].voter,
            Some(u5c::voter_votes::Voter::Drep(u5c::StakeCredential {
                stake_credential: Some(u5c::stake_credential::StakeCredential::AddrKeyHash(
                    VOTING_DREP_KEY_HASH.to_vec().into()
                )),
            })),
            "a DRep key voter reaches u5c as a DRep credential holding that key hash"
        );

        assert_eq!(votes[0].votes.len(), 1, "that voter casts one vote");
        let procedure = &votes[0].votes[0];

        assert_eq!(
            procedure.gov_action_id,
            Some(u5c::GovernanceActionId {
                transaction_id: VOTED_ACTION_TX_HASH.to_vec().into(),
                governance_action_index: VOTED_ACTION_INDEX,
            }),
            "the action voted on reaches u5c by its transaction and its index"
        );

        assert_eq!(
            procedure.vote,
            u5c::Vote::Yes as i32,
            "a yes vote must not reach u5c as any other vote"
        );

        assert_eq!(
            procedure.anchor,
            Some(u5c::Anchor {
                url: VOTE_ANCHOR_URL.to_string(),
                content_hash: VOTE_ANCHOR_HASH.to_vec().into(),
            }),
            "the anchor of that vote reaches u5c"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_committee_key_and_a_committee_script_vote_as_their_own_credential_kinds() {
        let tx = dijkstra_tx_with_committee_votes();
        let votes = Mapper::new(NoLedger).map_votes(&tx);

        assert_eq!(votes.len(), 2, "the body names two voters");

        let expected = [
            (
                u5c::voter_votes::Voter::ConstitutionalCommittee(u5c::StakeCredential {
                    stake_credential: Some(u5c::stake_credential::StakeCredential::AddrKeyHash(
                        COMMITTEE_VOTER_KEY_HASH.to_vec().into(),
                    )),
                }),
                u5c::VotingProcedure {
                    gov_action_id: Some(u5c::GovernanceActionId {
                        transaction_id: COMMITTEE_KEY_ACTION_TX_HASH.to_vec().into(),
                        governance_action_index: 0,
                    }),
                    vote: u5c::Vote::No as i32,
                    anchor: None,
                },
            ),
            (
                u5c::voter_votes::Voter::ConstitutionalCommittee(u5c::StakeCredential {
                    stake_credential: Some(u5c::stake_credential::StakeCredential::ScriptHash(
                        COMMITTEE_VOTER_SCRIPT_HASH.to_vec().into(),
                    )),
                }),
                u5c::VotingProcedure {
                    gov_action_id: Some(u5c::GovernanceActionId {
                        transaction_id: COMMITTEE_SCRIPT_ACTION_TX_HASH.to_vec().into(),
                        governance_action_index: 0,
                    }),
                    vote: u5c::Vote::Abstain as i32,
                    anchor: None,
                },
            ),
        ];

        for (voter, procedure) in expected {
            let found = votes
                .iter()
                .find(|x| x.voter.as_ref() == Some(&voter))
                .unwrap_or_else(|| panic!("this voter must reach u5c: {voter:?}"));

            assert_eq!(
                found.votes,
                vec![procedure],
                "a committee member's one vote must reach u5c as the vote it cast, on the action it named"
            );
        }
    }
}
