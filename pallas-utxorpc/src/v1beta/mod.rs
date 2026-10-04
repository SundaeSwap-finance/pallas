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

/// The u5c governance action this schema names for an information action,
/// whose message has no field.
fn information_action() -> u5c::governance_action::GovernanceAction {
    u5c::governance_action::GovernanceAction::InfoAction(u5c::InfoAction {})
}

/// The u5c purpose of a guarding redeemer.
#[cfg(feature = "unstable")]
fn guarding_purpose() -> u5c::RedeemerPurpose {
    u5c::RedeemerPurpose::Guarding
}

/// The u5c member of a guard clause.
#[cfg(feature = "unstable")]
fn native_script_guard(
    x: &pallas_primitives::StakeCredential,
) -> Option<u5c::native_script::NativeScript> {
    Some(u5c::native_script::NativeScript::ScriptRequireGuard(
        map_credential(x),
    ))
}

/// Adds the pool BLS key to a pool registration certificate.
#[cfg(feature = "unstable")]
fn with_pool_bls_key(
    cert: Option<u5c::certificate::Certificate>,
    key: Option<&pallas_primitives::dijkstra::BlsKey>,
) -> Option<u5c::certificate::Certificate> {
    match cert {
        Some(u5c::certificate::Certificate::PoolRegistration(x)) => Some(
            u5c::certificate::Certificate::PoolRegistration(u5c::PoolRegistrationCert {
                bls_key: key.map(|k| u5c::PoolBlsKey {
                    bls_pubkey: k.bls_pubkey.to_vec().into(),
                    bls_possession_proof: k.bls_possession_proof.to_vec().into(),
                }),
                ..x
            }),
        ),
        other => other,
    }
}

/// The fields of the keys only a Dijkstra update carries, noting in `seen` each key it sets.
#[cfg(feature = "unstable")]
fn dijkstra_pparams_update(seen: &mut bool, x: &trv::MultiEraParamUpdate) -> u5c::PParams {
    // A nil key 38 proposes removing the cap, which this field cannot hold
    // apart from an absent one, so it counts as a set key with no value.
    let max_pledge_leverage = match read_key(seen, x.max_pledge_leverage().proposed()) {
        Some(pallas_primitives::Nullable::Some(x)) => Some(rational_number_to_u5c(x)),
        _ => None,
    };

    u5c::PParams {
        max_ref_script_size_per_block: read_key(seen, x.max_ref_script_size_per_block().proposed())
            .unwrap_or_default(),
        max_ref_script_size_per_tx: read_key(seen, x.max_ref_script_size_per_tx().proposed())
            .unwrap_or_default(),
        ref_script_cost_stride: read_key(seen, x.ref_script_cost_stride().proposed())
            .unwrap_or_default(),
        ref_script_cost_multiplier: read_key(seen, x.ref_script_cost_multiplier().proposed())
            .map(rational_number_to_u5c),
        max_pledge_leverage,
        min_pool_margin: read_key(seen, x.min_pool_margin().proposed()).map(rational_number_to_u5c),
        leios_announcement_period_length: read_key(
            seen,
            x.leios_announcement_period_length().proposed(),
        )
        .unwrap_or_default(),
        leios_vote_period_length: read_key(seen, x.leios_vote_period_length().proposed())
            .unwrap_or_default(),
        leios_diffusion_period_length: read_key(seen, x.leios_diffusion_period_length().proposed())
            .unwrap_or_default(),
        leios_committee_size: read_key(seen, x.leios_committee_size().proposed())
            .unwrap_or_default() as u32,
        leios_quorum_stake_threshold: read_key(seen, x.leios_quorum_stake_threshold().proposed())
            .map(rational_number_to_u5c),
        max_endorser_block_references_size: read_key(
            seen,
            x.max_endorser_block_references_size().proposed(),
        )
        .unwrap_or_default(),
        max_endorser_block_txs_size: read_key(seen, x.max_endorser_block_txs_size().proposed())
            .unwrap_or_default(),
        max_endorser_block_execution_units: read_key(
            seen,
            x.max_endorser_block_execution_units().proposed(),
        )
        .map(execution_units_to_u5c),
        max_ref_script_size_per_endorser_block: read_key(
            seen,
            x.max_ref_script_size_per_endorser_block().proposed(),
        )
        .unwrap_or_default(),
        ..Default::default()
    }
}

/// The fields of the keys only a Dijkstra update carries, all unset when the
/// Dijkstra accessors are not built.
#[cfg(not(feature = "unstable"))]
fn dijkstra_pparams_update(_: &mut bool, _: &trv::MultiEraParamUpdate) -> u5c::PParams {
    u5c::PParams::default()
}

/// The fields of the Dijkstra parameters no other era carries.
#[cfg(feature = "unstable")]
fn dijkstra_pparams(x: &pallas_validate::utils::DijkstraProtParams) -> u5c::PParams {
    u5c::PParams {
        max_ref_script_size_per_block: x.max_ref_script_size_per_block.into(),
        max_ref_script_size_per_tx: x.max_ref_script_size_per_tx.into(),
        ref_script_cost_stride: x.ref_script_cost_stride.into(),
        ref_script_cost_multiplier: Some(rational_number_to_u5c(
            x.ref_script_cost_multiplier.clone(),
        )),
        max_pledge_leverage: x.max_pledge_leverage.clone().map(rational_number_to_u5c),
        min_pool_margin: Some(rational_number_to_u5c(x.min_pool_margin.clone())),
        leios_announcement_period_length: x.leios_announcement_period_length.into(),
        leios_vote_period_length: x.leios_vote_period_length.into(),
        leios_diffusion_period_length: x.leios_diffusion_period_length.into(),
        leios_committee_size: x.leios_committee_size.into(),
        leios_quorum_stake_threshold: Some(rational_number_to_u5c(
            x.leios_quorum_stake_threshold.clone(),
        )),
        max_endorser_block_references_size: x.max_endorser_block_references_size.into(),
        max_endorser_block_txs_size: x.max_endorser_block_txs_size.into(),
        max_endorser_block_execution_units: Some(execution_units_to_u5c(
            x.max_endorser_block_ex_units,
        )),
        max_ref_script_size_per_endorser_block: x.max_ref_script_size_per_endorser_block.into(),
        ..Default::default()
    }
}

/// The deposit of one coin into one reward account.
#[cfg(feature = "unstable")]
fn map_direct_deposit(
    (account, coin): (&pallas_primitives::RewardAccount, &pallas_primitives::Coin),
) -> u5c::DirectDeposit {
    u5c::DirectDeposit {
        reward_account: account.to_vec().into(),
        coin: u64_to_bigint(*coin),
    }
}

/// The interval one reward account balance must fall within.
#[cfg(feature = "unstable")]
fn map_account_balance_interval(
    (account, interval): (
        &pallas_primitives::RewardAccount,
        &pallas_primitives::dijkstra::AccountBalanceInterval,
    ),
) -> u5c::AccountBalanceInterval {
    use pallas_primitives::dijkstra::AccountBalanceInterval;
    use u5c::account_balance_interval::Interval;

    let range = |lower: Option<u64>, upper: Option<u64>| {
        Some(Interval::Range(u5c::AccountBalanceRange {
            inclusive_lower_bound: lower.and_then(u64_to_bigint),
            exclusive_upper_bound: upper.and_then(u64_to_bigint),
        }))
    };

    u5c::AccountBalanceInterval {
        reward_account: account.to_vec().into(),
        interval: match *interval {
            AccountBalanceInterval::LowerBound(l) => range(Some(l), None),
            AccountBalanceInterval::Bounded(l, u) => range(Some(l), Some(u)),
            AccountBalanceInterval::UpperBound(u) => range(None, Some(u)),
            AccountBalanceInterval::Exact(c) => u64_to_bigint(c).map(Interval::Exact),
        },
    }
}

impl<C: LedgerContext> Mapper<C> {
    // v1beta names this variant ScriptPubkeyHash; v1alpha names it
    // ScriptPubkey. The rest of map_native_script is identical between
    // versions and lives in shared.rs.
    fn map_native_script_pubkey(bytes: Vec<u8>) -> u5c::native_script::NativeScript {
        u5c::native_script::NativeScript::ScriptPubkeyHash(bytes.into())
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
        x.multi_era_script_ref().map(|x| self.map_script_ref(&x))
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
            ..self.map_dijkstra_tx_fields(tx)
        }
    }

    /// The fields of a transaction that only the Dijkstra era fills.
    #[cfg(feature = "unstable")]
    fn map_dijkstra_tx_fields(&self, tx: &trv::MultiEraTx) -> u5c::Tx {
        let starting = tx.as_dijkstra().and_then(|x| {
            x.transaction_body
                .starting_account_balance_intervals
                .as_ref()
        });

        u5c::Tx {
            sub_transactions: tx
                .sub_transactions()
                .iter()
                .map(|x| self.map_tx(x))
                .collect(),
            direct_deposits: tx
                .direct_deposits()
                .into_iter()
                .flatten()
                .map(map_direct_deposit)
                .collect(),
            account_balance_intervals: tx
                .account_balance_intervals()
                .into_iter()
                .flatten()
                .map(map_account_balance_interval)
                .collect(),
            starting_account_balance_intervals: starting
                .into_iter()
                .flatten()
                .map(map_account_balance_interval)
                .collect(),
            ..Default::default()
        }
    }

    /// The fields of a transaction that only the Dijkstra era fills, all empty
    /// when the Dijkstra accessors are not built.
    #[cfg(not(feature = "unstable"))]
    fn map_dijkstra_tx_fields(&self, _: &trv::MultiEraTx) -> u5c::Tx {
        u5c::Tx::default()
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
            Mapper::<NoLedger>::map_multi_era_native_script(&script).native_script,
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

    #[cfg(feature = "unstable")]
    #[test]
    fn a_transaction_without_sub_transactions_maps_none() {
        let conway =
            Mapper::new(NoLedger).map_tx(&conway_tx(include_str!("../../../test_data/conway9.tx")));
        let dijkstra = Mapper::new(NoLedger).map_tx(&dijkstra_tx(include_str!(
            "../../../test_data/dijkstra-proposal.tx"
        )));

        assert_eq!(
            (
                conway.sub_transactions.len(),
                dijkstra.sub_transactions.len(),
                dijkstra.direct_deposits.len(),
                dijkstra.account_balance_intervals.len(),
                dijkstra.starting_account_balance_intervals.len(),
            ),
            (0, 0, 0, 0, 0),
            "a Conway transaction and a Dijkstra one whose body has none of keys 23, 25, 26 or 27 map to empty lists"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_sub_transaction_maps_to_a_transaction_of_its_own() {
        let tx = dijkstra_tx(include_str!("../../../test_data/dijkstra-subtx.tx"));
        let mapped = Mapper::new(NoLedger).map_tx(&tx);

        assert_eq!(
            mapped.sub_transactions.len(),
            1,
            "the body carries one sub transaction"
        );
        let sub = &mapped.sub_transactions[0];

        assert_eq!(
            sub.hash.to_vec(),
            tx.sub_transactions()[0].hash().to_vec(),
            "the sub transaction's id is the hash of its own body"
        );
        assert_ne!(
            sub.hash, mapped.hash,
            "and differs from the id of the transaction that carries it"
        );

        let inputs: Vec<(String, u32)> = sub
            .inputs
            .iter()
            .map(|x| (hex::encode(&x.tx_hash), x.output_index))
            .collect();
        assert_eq!(
            inputs,
            vec![(
                "2ed1285cced47acb5f08502843d980d7231665af9d90ef33fe6751e0f9e0b171".to_string(),
                0
            )],
            "the sub body's one input reaches the sub transaction"
        );

        assert_eq!(
            sub.outputs
                .iter()
                .map(|x| x.coin.clone())
                .collect::<Vec<_>>(),
            vec![u64_to_bigint(3_000_000)],
            "the sub body's one output reaches the sub transaction"
        );

        assert_eq!(
            (sub.successful, mapped.successful),
            (true, true),
            "a sub transaction is valid exactly when the transaction carrying it is"
        );

        let mut owned = tx.as_dijkstra().unwrap().clone();
        owned.success = false;
        let failed = trv::MultiEraTx::Dijkstra(Box::new(std::borrow::Cow::Owned(owned)));
        let mapped = Mapper::new(NoLedger).map_tx(&failed);
        assert_eq!(
            (mapped.sub_transactions[0].successful, mapped.successful),
            (false, false),
            "a sub transaction carried by a failed transaction fails with it"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn deposits_and_intervals_map_with_their_accounts() {
        use u5c::account_balance_interval::Interval;

        let mapped = Mapper::new(NoLedger).map_tx(&dijkstra_tx_with_account_fields());

        let range = |lower: Option<u64>, upper: Option<u64>| {
            Some(Interval::Range(u5c::AccountBalanceRange {
                inclusive_lower_bound: lower.and_then(u64_to_bigint),
                exclusive_upper_bound: upper.and_then(u64_to_bigint),
            }))
        };
        let interval =
            |account: [u8; 29], interval: Option<Interval>| u5c::AccountBalanceInterval {
                reward_account: account.to_vec().into(),
                interval,
            };

        assert_eq!(
            mapped.direct_deposits,
            vec![u5c::DirectDeposit {
                reward_account: DEPOSIT_ACCOUNT.to_vec().into(),
                coin: u64_to_bigint(DEPOSIT_COIN),
            }],
            "the body's one deposit reaches u5c with its account and its coin"
        );

        assert_eq!(
            mapped.account_balance_intervals,
            vec![
                interval(LOWER_BOUND_ACCOUNT, range(Some(5), None)),
                interval(UPPER_BOUND_ACCOUNT, range(None, Some(6))),
                interval(BOUNDED_ACCOUNT, range(Some(7), Some(8))),
                interval(COIN_ACCOUNT, u64_to_bigint(9).map(Interval::Exact)),
            ],
            "each interval keeps the bounds it was written with, and a bare coin maps to an exact balance"
        );

        assert_eq!(
            mapped.starting_account_balance_intervals,
            vec![interval(STARTING_ACCOUNT, range(Some(10), None))],
            "the starting intervals reach their own field"
        );

        assert_eq!(
            mapped.sub_transactions.len(),
            1,
            "the body carries one sub transaction"
        );
        let sub = &mapped.sub_transactions[0];
        assert_eq!(
            (
                sub.direct_deposits.clone(),
                sub.account_balance_intervals.clone(),
                sub.starting_account_balance_intervals.len(),
            ),
            (
                vec![u5c::DirectDeposit {
                    reward_account: SUB_DEPOSIT_ACCOUNT.to_vec().into(),
                    coin: u64_to_bigint(12),
                }],
                vec![interval(SUB_INTERVAL_ACCOUNT, range(None, Some(13)))],
                0,
            ),
            "the sub body's deposit and interval reach the sub transaction and not the one carrying it"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_guarding_redeemer_maps_to_the_guarding_purpose() {
        assert_eq!(
            Mapper::new(NoLedger).map_multi_era_purpose(&trv::MultiEraRedeemerTag::Guarding),
            u5c::RedeemerPurpose::Guarding,
            "a guarding redeemer reaches the purpose of the same name"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_guard_clause_maps_to_the_credential_it_names() {
        use pallas_primitives::{StakeCredential, dijkstra};

        let script = dijkstra::NativeScript::ScriptAll(vec![
            dijkstra::NativeScript::ScriptRequireGuard(StakeCredential::ScriptHash(
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
            list.items[0].native_script,
            Some(u5c::native_script::NativeScript::ScriptRequireGuard(
                u5c::StakeCredential {
                    stake_credential: Some(u5c::stake_credential::StakeCredential::ScriptHash(
                        [0x7a; 28].to_vec().into()
                    )),
                }
            )),
            "the guard reaches u5c as the credential it requires, of the kind it names"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_dijkstra_pool_registration_maps_the_bls_key_it_fills() {
        let block = dijkstra_block(include_str!("../../../test_data/dijkstra6.block"));
        let txs = block.txs();
        let expected: Vec<u5c::PoolBlsKey> = txs
            .iter()
            .flat_map(|tx| tx.certs())
            .filter_map(|cert| {
                cert.bls_key().map(|k| u5c::PoolBlsKey {
                    bls_pubkey: k.bls_pubkey.to_vec().into(),
                    bls_possession_proof: k.bls_possession_proof.to_vec().into(),
                })
            })
            .collect();
        assert_eq!(
            expected.len(),
            2,
            "this block's two pool registrations each fill the BLS key slot"
        );

        let mapped = Mapper::new(NoLedger).map_block(&block);
        let found: Vec<u5c::PoolBlsKey> = mapped
            .body
            .iter()
            .flat_map(|body| body.tx.iter())
            .flat_map(|tx| tx.certificates.iter())
            .filter_map(|cert| match &cert.certificate {
                Some(u5c::certificate::Certificate::PoolRegistration(x)) => x.bls_key.clone(),
                _ => None,
            })
            .collect();

        assert_eq!(
            found, expected,
            "each pool registration's key and proof reach its certificate"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_dijkstra_update_maps_every_key_the_era_adds() {
        let update = dijkstra_update_of_every_era_key();
        let mapped = Mapper::new(NoLedger).map_pparams_update(&trv::MultiEraParamUpdate::Dijkstra(
            Box::new(std::borrow::Cow::Borrowed(&update)),
        ));

        assert_eq!(
            mapped,
            Some(u5c::PParams {
                max_ref_script_size_per_block: 34,
                max_ref_script_size_per_tx: 35,
                ref_script_cost_stride: 36,
                ref_script_cost_multiplier: Some(rational_number_to_u5c(ratio(37, 1))),
                max_pledge_leverage: Some(rational_number_to_u5c(ratio(38, 1))),
                min_pool_margin: Some(rational_number_to_u5c(ratio(1, 39))),
                leios_announcement_period_length: 40,
                leios_vote_period_length: 41,
                leios_diffusion_period_length: 42,
                leios_committee_size: 43,
                leios_quorum_stake_threshold: Some(rational_number_to_u5c(ratio(1, 44))),
                max_endorser_block_references_size: 45,
                max_endorser_block_txs_size: 46,
                max_endorser_block_execution_units: Some(u5c::ExUnits {
                    memory: 47,
                    steps: 470,
                }),
                max_ref_script_size_per_endorser_block: 48,
                ..Default::default()
            }),
            "each key from 34 to 48 reaches the u5c field it means, carrying its own value"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_dijkstra_update_setting_any_one_era_key_to_zero_is_still_an_update() {
        let cases = dijkstra_updates_of_one_zero_era_key();
        assert_eq!(cases.len(), 15, "one case per key from 34 to 48");

        for (key, update) in cases {
            let mapped = Mapper::new(NoLedger).map_pparams_update(
                &trv::MultiEraParamUpdate::Dijkstra(Box::new(std::borrow::Cow::Borrowed(&update))),
            );

            assert!(
                mapped.is_some(),
                "the key {key}, set alone to its zero, is a proposed change, so the update must map to parameters"
            );
        }
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_dijkstra_parameter_change_of_key_48_maps_its_field() {
        let proposal = dijkstra_proposal(include_str!(
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
            change.protocol_param_update,
            Some(u5c::PParams {
                max_ref_script_size_per_endorser_block: 20_000,
                ..Default::default()
            }),
            "key 48 reaches its field and no other"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_dijkstra_parameter_set_maps_every_key_the_era_adds() {
        let mapped = dijkstra_pparams(&dijkstra_params());

        assert_eq!(
            mapped,
            u5c::PParams {
                max_ref_script_size_per_block: 1_048_576,
                max_ref_script_size_per_tx: 204_800,
                ref_script_cost_stride: 25_600,
                ref_script_cost_multiplier: Some(rational_number_to_u5c(ratio(6, 5))),
                max_pledge_leverage: Some(rational_number_to_u5c(ratio(38, 1))),
                min_pool_margin: Some(rational_number_to_u5c(ratio(1, 39))),
                leios_announcement_period_length: 1_000,
                leios_vote_period_length: 4_000,
                leios_diffusion_period_length: 7_000,
                leios_committee_size: 900,
                leios_quorum_stake_threshold: Some(rational_number_to_u5c(ratio(3, 4))),
                max_endorser_block_references_size: 100_000,
                max_endorser_block_txs_size: 1_000_000,
                max_endorser_block_execution_units: Some(u5c::ExUnits {
                    memory: 310_000_000,
                    steps: 100_000_000_000,
                }),
                max_ref_script_size_per_endorser_block: 4_000_000,
                ..Default::default()
            },
            "each key the era adds reaches the u5c field it means, carrying its own value"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_dijkstra_parameter_set_without_a_pledge_leverage_cap_maps_none() {
        let mut params = dijkstra_params();
        params.max_pledge_leverage = None;

        assert_eq!(
            dijkstra_pparams(&params).max_pledge_leverage,
            None,
            "a set with no pledge leverage cap leaves the field absent"
        );
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
                    Some(u5c::native_script::NativeScript::ScriptPubkeyHash(_))
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
            Some(u5c::native_script::NativeScript::ScriptPubkeyHash(ref b)) if b.as_ref() == [1; 28]
        ));
        assert!(matches!(
            n_of_k.scripts[2].native_script,
            Some(u5c::native_script::NativeScript::ScriptPubkeyHash(ref b)) if b.as_ref() == [3; 28]
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
            Some(u5c::native_script::NativeScript::ScriptPubkeyHash(ref b)) if b.as_ref() == [2; 28]
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
