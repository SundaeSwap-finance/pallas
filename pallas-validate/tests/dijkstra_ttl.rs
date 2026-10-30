#![cfg(all(feature = "unstable", feature = "phase2"))]

use pallas_primitives::{conway as c, dijkstra as n};
use pallas_traverse::{Era, MultiEraInput, MultiEraOutput, MultiEraTx};
use pallas_validate::{phase1, phase2, utils::*};
use serde_json::Value;
use std::path::PathBuf;

fn number(v: &Value) -> u64 {
    match v {
        Value::String(s) => s.parse().unwrap(),
        Value::Object(_) => number(&v["int"]),
        _ => v.as_u64().unwrap(),
    }
}

fn ratio(v: &Value) -> n::RationalNumber {
    n::RationalNumber {
        numerator: number(&v["numerator"]),
        denominator: number(&v["denominator"]),
    }
}

fn units(v: &Value) -> n::ExUnits {
    n::ExUnits {
        mem: number(&v["memory"]),
        steps: number(&v["steps"]),
    }
}

struct Fixture {
    transaction: Vec<u8>,
    transaction_id: String,
    inputs: Vec<(n::TransactionInput, Vec<u8>)>,
    env: Environment,
    slots: phase2::script_context::SlotConfig,
    expected: n::ExUnits,
}

fn fixture_root() -> PathBuf {
    std::env::var_os("PALLAS_TTL_FIXTURE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test_data/musashi-ttl")
        })
}

impl Fixture {
    fn load() -> Self {
        Self::load_from(fixture_root().join("confirmed-ttl"))
    }

    fn load_from(root: PathBuf) -> Self {
        let json = |name| -> Value {
            serde_json::from_slice(&std::fs::read(root.join(name)).unwrap()).unwrap()
        };
        let parameters = json("parameters.json");
        let p = &parameters["values"]["cardano"];
        let g = json("genesis.json");
        let replay = json("replay.json");
        // The original RPC omitted these later API fields. Use the retained
        // configured genesis only for unused Peras/reference-input parameters;
        // their historical live values are unknown (see fixture README).
        let supplemental: Value = serde_json::from_slice(
            &std::fs::read(fixture_root().join("genesis/dijkstra.json")).unwrap(),
        )
        .unwrap();
        let whole_ratio = |name: &str| n::RationalNumber {
            numerator: number(&supplemental[name]),
            denominator: 1,
        };
        let pv = &p["poolVotingThresholds"]["thresholds"];
        let dv = &p["drepVotingThresholds"]["thresholds"];
        let cost = |name: &str| {
            p["costModels"][name]["values"].as_array().map(|xs| {
                xs.iter()
                    .map(|x| {
                        x.as_str()
                            .map(|x| x.parse().unwrap())
                            .unwrap_or_else(|| x.as_i64().unwrap())
                    })
                    .collect()
            })
        };
        let pp = DijkstraProtParams {
            system_start: chrono::DateTime::from_timestamp(number(&g["system_start"]) as i64, 0)
                .unwrap()
                .fixed_offset(),
            epoch_length: number(&g["epoch_length"]),
            slot_length: number(&g["slot_length"]),
            minfee_a: number(&p["minFeeCoefficient"]) as u32,
            minfee_b: number(&p["minFeeConstant"]) as u32,
            max_block_body_size: number(&p["maxBlockBodySize"]) as u32,
            max_transaction_size: number(&p["maxTxSize"]) as u32,
            max_block_header_size: number(&p["maxBlockHeaderSize"]) as u32,
            key_deposit: number(&p["stakeKeyDeposit"]),
            pool_deposit: number(&p["poolDeposit"]),
            desired_number_of_stake_pools: number(&p["desiredNumberOfPools"]) as u32,
            protocol_version: (
                number(&p["protocolVersion"]["major"]),
                p["protocolVersion"]["minor"].as_u64().unwrap_or(0),
            ),
            min_pool_cost: number(&p["minPoolCost"]),
            ada_per_utxo_byte: number(&p["coinsPerUtxoByte"]),
            cost_models_for_script_languages: n::CostModels {
                plutus_v1: cost("plutusV1"),
                plutus_v2: cost("plutusV2"),
                plutus_v3: cost("plutusV3"),
                plutus_v4: cost("plutusV4"),
                unknown: Default::default(),
            },
            execution_costs: pallas_primitives::ExUnitPrices {
                mem_price: ratio(&p["prices"]["memory"]),
                step_price: ratio(&p["prices"]["steps"]),
            },
            max_tx_ex_units: units(&p["maxExecutionUnitsPerTransaction"]),
            max_block_ex_units: units(&p["maxExecutionUnitsPerBlock"]),
            max_value_size: number(&p["maxValueSize"]) as u32,
            collateral_percentage: number(&p["collateralPercentage"]) as u32,
            max_collateral_inputs: number(&p["maxCollateralInputs"]) as u32,
            expansion_rate: ratio(&p["monetaryExpansion"]),
            treasury_growth_rate: ratio(&p["treasuryExpansion"]),
            maximum_epoch: number(&p["poolRetirementEpochBound"]),
            pool_pledge_influence: ratio(&p["poolInfluence"]),
            pool_voting_thresholds: c::PoolVotingThresholds {
                motion_no_confidence: ratio(&pv[0]),
                committee_normal: ratio(&pv[1]),
                committee_no_confidence: ratio(&pv[2]),
                hard_fork_initiation: ratio(&pv[3]),
                security_voting_threshold: ratio(&pv[4]),
            },
            drep_voting_thresholds: c::DRepVotingThresholds {
                motion_no_confidence: ratio(&dv[0]),
                committee_normal: ratio(&dv[1]),
                committee_no_confidence: ratio(&dv[2]),
                update_constitution: ratio(&dv[3]),
                hard_fork_initiation: ratio(&dv[4]),
                pp_network_group: ratio(&dv[5]),
                pp_economic_group: ratio(&dv[6]),
                pp_technical_group: ratio(&dv[7]),
                pp_governance_group: ratio(&dv[8]),
                treasury_withdrawal: ratio(&dv[9]),
            },
            min_committee_size: number(&p["minCommitteeSize"]),
            committee_term_limit: number(&p["committeeTermLimit"]),
            governance_action_validity_period: number(&p["governanceActionValidityPeriod"]),
            governance_action_deposit: number(&p["governanceActionDeposit"]),
            drep_deposit: number(&p["drepDeposit"]),
            drep_inactivity_period: number(&p["drepInactivityPeriod"]),
            minfee_refscript_cost_per_byte: ratio(&p["minFeeScriptRefCostPerByte"]),
            max_ref_script_size_per_block: number(&p["maxRefScriptSizePerBlock"]) as u32,
            max_ref_script_size_per_tx: number(&p["maxRefScriptSizePerTx"]) as u32,
            ref_script_cost_stride: number(&p["refScriptCostStride"]) as u32,
            ref_script_cost_multiplier: ratio(&p["refScriptCostMultiplier"]),
            max_pledge_leverage: p.get("maxPledgeLeverage").map(ratio),
            min_pool_margin: ratio(&p["minPoolMargin"]),
            leios_announcement_period_length: number(&p["leiosAnnouncementPeriodLength"]) as u32,
            leios_vote_period_length: number(&p["leiosVotePeriodLength"]) as u32,
            leios_diffusion_period_length: number(&p["leiosDiffusionPeriodLength"]) as u32,
            leios_committee_size: number(&p["leiosCommitteeSize"]) as u16,
            leios_quorum_stake_threshold: ratio(&p["leiosQuorumStakeThreshold"]),
            max_endorser_block_references_size: number(&p["maxEndorserBlockReferencesSize"]) as u32,
            max_endorser_block_txs_size: number(&p["maxEndorserBlockTxsSize"]) as u32,
            max_endorser_block_ex_units: units(&p["maxEndorserBlockExecutionUnits"]),
            max_ref_script_size_per_endorser_block: number(&p["maxRefScriptSizePerEndorserBlock"])
                as u32,
            peras_min_candidate_block_age: number(&supplemental["perasMinCandidateBlockAge"])
                as u32,
            peras_healing_factor: whole_ratio("perasHealingFactor"),
            peras_cert_boost: number(&supplemental["perasCertBoost"]) as u16,
            peras_target_committee_size: number(&supplemental["perasTargetCommitteeSize"]) as u16,
            peras_bootstrap_round: supplemental["perasBootstrapRound"]
                .as_u64()
                .map(|x| x as u32),
            peras_quorum_threshold_safety_margin: whole_ratio("perasQuorumThresholdSafetyMargin"),
            ref_inputs_cost_per_multi_asset_policy: number(
                &supplemental["refInputsCostPerMultiAssetPolicy"],
            ),
            ref_inputs_cost_per_datum_byte: number(&supplemental["refInputsCostPerDatumByte"]),
        };
        assert_eq!(number(&g["network_magic"]), 164);
        Self {
            transaction_id: replay["txid"].as_str().unwrap().to_owned(),
            transaction: hex::decode(
                std::fs::read_to_string(root.join("transaction.hex"))
                    .unwrap()
                    .trim(),
            )
            .unwrap(),
            inputs: json("inputs.json")
                .as_array()
                .unwrap()
                .iter()
                .map(|x| {
                    (
                        n::TransactionInput {
                            transaction_id: x["hash"].as_str().unwrap().parse().unwrap(),
                            index: number(&x["index"]),
                        },
                        hex::decode(x["output_cbor_hex"].as_str().unwrap()).unwrap(),
                    )
                })
                .collect(),
            env: Environment {
                prot_params: MultiEraProtocolParameters::Dijkstra(pp),
                prot_magic: 164,
                block_slot: number(&replay["validation_slot"]),
                network_id: 0,
                acnt: None,
            },
            slots: phase2::script_context::SlotConfig {
                zero_slot: 0,
                zero_time: number(&g["system_start"]) * 1000,
                slot_length: number(&g["slot_length"]) * 1000,
            },
            expected: units(&replay["reference_execution_units"]),
        }
    }

    fn phase_two_inputs(&self) -> UtxoMap {
        self.inputs
            .iter()
            .map(|(i, bytes)| {
                (
                    TxoRef(i.transaction_id, i.index as u32),
                    EraCbor(Era::Dijkstra, bytes.clone()),
                )
            })
            .collect()
    }

    fn time(&self) -> DijkstraTimeContext {
        DijkstraTimeContext::new(
            vec![EraTime {
                start_slot: self.slots.zero_slot,
                start_time_ms: self.slots.zero_time,
                slot_length_ms: self.slots.slot_length,
            }],
            self.env.block_slot,
        )
        .unwrap()
    }
}

#[test]
fn captured_ttl_phase_one_succeeds() {
    let f = Fixture::load();
    let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &f.transaction).unwrap();
    let inputs = f
        .inputs
        .iter()
        .map(|(i, raw)| {
            (
                MultiEraInput::from_alonzo_compatible(i),
                MultiEraOutput::decode(Era::Dijkstra, raw).unwrap(),
            )
        })
        .collect();
    let result = phase1::validate_tx_with_time(
        &tx,
        0,
        &f.env,
        &inputs,
        &mut CertState::default(),
        &f.time(),
    );
    assert!(
        result.is_ok(),
        "captured bounded native transaction must pass phase one: {result:?}"
    );
}

#[test]
fn captured_ttl_phase_two_succeeds() {
    let f = Fixture::load();
    let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &f.transaction).unwrap();
    let report =
        phase2::evaluate_tx_with_time(&tx, &f.env.prot_params, &f.phase_two_inputs(), &f.time())
            .expect("captured bounded native transaction must evaluate");
    assert_eq!(report.len(), 1);
    assert!(report[0].success, "{report:?}");
    assert_eq!(report[0].units, f.expected, "reference CLI execution units");
}

#[test]
fn captured_ttl_estimation_succeeds() {
    let f = Fixture::load();
    let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &f.transaction).unwrap();
    let report =
        phase2::estimate_tx_with_time(&tx, &f.env.prot_params, &f.phase_two_inputs(), &f.time())
            .expect("captured bounded native transaction must estimate");
    assert_eq!(report.len(), 1);
    assert!(report[0].success, "{report:?}");
    assert_eq!(report[0].units, f.expected, "reference CLI execution units");
}

#[test]
fn captured_ttl_signatures_are_valid() {
    let f = Fixture::load();
    let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &f.transaction).unwrap();
    assert_eq!(tx.hash().to_string(), f.transaction_id);
    let native = tx.as_dijkstra().unwrap();
    let witnesses = native.transaction_witness_set.vkeywitness.as_ref().unwrap();
    assert_eq!(witnesses.len(), 1);
    assert!(verify_signature(&witnesses[0], tx.hash().as_slice()));
    assert_eq!(native.transaction_body.inputs.len(), 1);
    assert_eq!(
        native.transaction_body.collateral.as_ref().unwrap().len(),
        1
    );
    assert!(native.transaction_body.certificates.is_none());
    assert!(native.transaction_body.mint.is_none());
    assert!(native.transaction_body.withdrawals.is_none());
    assert!(native.transaction_body.sub_transactions.is_none());
}

#[test]
fn confirmed_native_proof_matches_signed_transaction() {
    use pallas_crypto::hash::Hasher;
    use pallas_traverse::MultiEraBlock;

    let root = fixture_root().join("confirmed-ttl");
    let read =
        |name: &str| hex::decode(std::fs::read_to_string(root.join(name)).unwrap().trim()).unwrap();
    let ranking_bytes = read("peer.block");
    let ranking = MultiEraBlock::decode(&ranking_bytes).unwrap();
    let parent_bytes = read("announcing-parent.block");
    let parent = MultiEraBlock::decode(&parent_bytes).unwrap();
    let inclusion: Value =
        serde_json::from_slice(&std::fs::read(root.join("inclusion.json")).unwrap()).unwrap();
    assert_eq!(
        ranking.hash().to_string(),
        inclusion["block"].as_str().unwrap()
    );
    assert_eq!(ranking.slot(), number(&inclusion["slot"]));
    assert_eq!(ranking.header().previous_hash(), Some(parent.hash()));
    assert_eq!(
        ranking.header().block_body_contains_leios_cert(),
        Some(true)
    );
    assert!(matches!(
        ranking.as_dijkstra().unwrap().block_body.leios_certificate,
        pallas_primitives::Nullable::Some(_)
    ));

    let body = read("endorser.ebbody");
    let header = parent.header();
    let announcement = header.eb_announcement().unwrap();
    assert_eq!(Hasher::<256>::hash(&body), announcement.eb_hash);
    assert_eq!(body.len(), announcement.eb_size as usize);
    let entries: n::EndorserBlock = pallas_codec::minicbor::decode(&body).unwrap();
    let selected = read("selected-endorser-transaction.hex");
    let commitment = Hasher::<256>::hash(&selected);
    let (_, size) = entries
        .iter()
        .find(|(hash, _)| *hash == commitment)
        .unwrap();
    assert_eq!(selected.len(), *size as usize);

    let original_bytes = read("transaction.hex");
    let original = MultiEraTx::decode_for_era(Era::Dijkstra, &original_bytes).unwrap();
    let executed = MultiEraTx::decode_for_era(Era::Dijkstra, &selected).unwrap();
    assert!(executed.is_valid());
    assert_eq!(executed.hash(), original.hash());
    assert_eq!(
        original.hash().to_string(),
        inclusion["transaction"].as_str().unwrap()
    );
    let original = original.as_dijkstra().unwrap();
    let executed = executed.as_dijkstra().unwrap();
    assert_eq!(
        executed.transaction_body.raw_cbor(),
        original.transaction_body.raw_cbor()
    );
    assert_eq!(
        executed.transaction_witness_set.raw_cbor(),
        original.transaction_witness_set.raw_cbor()
    );
    assert_eq!(executed.auxiliary_data, original.auxiliary_data);
}

#[test]
fn synthetic_validation_at_exact_upper_slot_expires() {
    for root in [
        fixture_root().join("confirmed-ttl"),
        fixture_root().join("cross-epoch-ttl"),
    ] {
        let mut f = Fixture::load_from(root);
        let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &f.transaction).unwrap();
        f.env.block_slot = tx.ttl().unwrap();
        let inputs = f
            .inputs
            .iter()
            .map(|(i, raw)| {
                (
                    MultiEraInput::from_alonzo_compatible(i),
                    MultiEraOutput::decode(Era::Dijkstra, raw).unwrap(),
                )
            })
            .collect();
        let result = phase1::validate_tx_with_time(
            &tx,
            0,
            &f.env,
            &inputs,
            &mut CertState::default(),
            &f.time(),
        );
        assert!(
            matches!(
                result,
                Err(ValidationError::PostAlonzo(
                    PostAlonzoError::BlockExceedsValInt
                ))
            ),
            "{result:?}"
        );
    }
}

#[test]
fn synthetic_missing_or_incorrect_upper_bound_fails_the_validator() {
    let f = Fixture::load();
    let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &f.transaction).unwrap();
    let mut without = tx.as_dijkstra().unwrap().clone();
    without.transaction_body.ttl = None;
    let report = phase2::evaluate_tx_with_time(
        &MultiEraTx::from_dijkstra(&without),
        &f.env.prot_params,
        &f.phase_two_inputs(),
        &f.time(),
    )
    .unwrap();
    assert!(!report[0].success);
    let incorrect = DijkstraTimeContext::new(
        vec![EraTime {
            start_slot: 0,
            start_time_ms: f.slots.zero_time + 1000,
            slot_length_ms: 1000,
        }],
        f.env.block_slot,
    )
    .unwrap();
    let report =
        phase2::evaluate_tx_with_time(&tx, &f.env.prot_params, &f.phase_two_inputs(), &incorrect)
            .unwrap();
    assert!(!report[0].success);
}

#[test]
fn historical_replay_does_not_use_current_expiry_or_spendability() {
    let f = Fixture::load();
    let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &f.transaction).unwrap();
    // A historical era with a different slot length still reaches the captured
    // current-era anchor exactly. Replaying needs no current UTxO/RPC lookup.
    let time = DijkstraTimeContext::new(
        vec![
            EraTime {
                start_slot: 0,
                start_time_ms: f.slots.zero_time - 100_000,
                slot_length_ms: 2000,
            },
            EraTime {
                start_slot: 100,
                start_time_ms: f.slots.zero_time + 100_000,
                slot_length_ms: 1000,
            },
        ],
        f.env.block_slot,
    )
    .unwrap();
    assert_eq!(time.slot_to_posix_ms(50).unwrap(), f.slots.zero_time);
    let report =
        phase2::evaluate_tx_with_time(&tx, &f.env.prot_params, &f.phase_two_inputs(), &time)
            .unwrap();
    assert!(report[0].success);
    assert_eq!(report[0].units, f.expected);
}

#[test]
fn supplied_linear_slot_config_preserves_the_captured_upper_bound() {
    let f = Fixture::load();
    let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &f.transaction).unwrap();
    let report =
        phase2::evaluate_tx(&tx, &f.env.prot_params, &f.phase_two_inputs(), &f.slots).unwrap();
    assert!(report[0].success);
    assert_eq!(report[0].units, f.expected);
}

#[test]
fn synthetic_time_conversion_failure_and_mismatched_basis_reject() {
    let f = Fixture::load();
    let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &f.transaction).unwrap();
    let inputs = f
        .inputs
        .iter()
        .map(|(i, raw)| {
            (
                MultiEraInput::from_alonzo_compatible(i),
                MultiEraOutput::decode(Era::Dijkstra, raw).unwrap(),
            )
        })
        .collect();
    let overflow = DijkstraTimeContext::new(
        vec![EraTime {
            start_slot: f.env.block_slot,
            start_time_ms: u64::MAX - 1000,
            slot_length_ms: 1000,
        }],
        f.env.block_slot,
    )
    .unwrap();
    let result = phase1::validate_tx_with_time(
        &tx,
        0,
        &f.env,
        &inputs,
        &mut CertState::default(),
        &overflow,
    );
    assert!(format!("{:?}", result.unwrap_err()).contains("Overflow"));
    let result =
        phase2::evaluate_tx_with_time(&tx, &f.env.prot_params, &f.phase_two_inputs(), &overflow);
    assert!(format!("{:?}", result.unwrap_err()).contains("Overflow"));
    let wrong_basis = DijkstraTimeContext::new(
        vec![EraTime {
            start_slot: 0,
            start_time_ms: f.slots.zero_time,
            slot_length_ms: 1000,
        }],
        f.env.block_slot + 1,
    )
    .unwrap();
    let result = phase1::validate_tx_with_time(
        &tx,
        0,
        &f.env,
        &inputs,
        &mut CertState::default(),
        &wrong_basis,
    );
    assert!(format!("{:?}", result.unwrap_err()).contains("WrongValidationSlot"));
    // As in earlier eras, phase one can check validity slots without a forecast.
    let result = phase1::validate_tx(&tx, 0, &f.env, &inputs, &mut CertState::default());
    assert!(
        result.is_ok(),
        "phase one must not require a consensus forecast: {result:?}"
    );
}

#[test]
fn earlier_era_conversion_matches_for_distant_and_absent_bounds() {
    use pallas_validate::phase2::script_context::{SlotConfig, get_validity_range_info};
    let slots = SlotConfig {
        zero_slot: 50,
        zero_time: 1_000_000,
        slot_length: 1000,
    };
    let time = DijkstraTimeContext::new(
        vec![EraTime {
            start_slot: slots.zero_slot,
            start_time_ms: slots.zero_time,
            slot_length_ms: slots.slot_length,
        }],
        75,
    )
    .unwrap();
    for (lower, upper) in [
        (None, None),
        (Some(50), None),
        (None, Some(1_000_000)),
        (Some(75), Some(1_000_000)),
    ] {
        // Explicitly synthetic Conway body used only to exercise its existing
        // time conversion. No captured native Dijkstra bytes are relabeled.
        let mut encoder = pallas_codec::minicbor::Encoder::new(Vec::new());
        encoder
            .map(3 + u64::from(lower.is_some()) + u64::from(upper.is_some()))
            .unwrap()
            .u8(0)
            .unwrap()
            .array(0)
            .unwrap()
            .u8(1)
            .unwrap()
            .array(0)
            .unwrap()
            .u8(2)
            .unwrap()
            .u64(0)
            .unwrap();
        if let Some(ttl) = upper {
            encoder.u8(3).unwrap().u64(ttl).unwrap();
        }
        if let Some(start) = lower {
            encoder.u8(8).unwrap().u64(start).unwrap();
        }
        let bytes = encoder.into_writer();
        let body: c::TransactionBody = pallas_codec::minicbor::decode(&bytes).unwrap();
        let earlier = get_validity_range_info(&body, &slots).unwrap();
        assert_eq!(
            time.validity_bounds(lower, upper).unwrap(),
            (earlier.lower_bound, earlier.upper_bound)
        );
    }
}

#[test]
fn cross_epoch_signed_spend_admits_evaluates_and_estimates() {
    let f = Fixture::load_from(fixture_root().join("cross-epoch-ttl"));
    let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &f.transaction).unwrap();
    assert_eq!(tx.hash().to_string(), f.transaction_id);
    let epoch_length = f.env.prot_params.epoch_length();
    assert!(f.env.block_slot / epoch_length < tx.ttl().unwrap() / epoch_length);
    let inputs = f
        .inputs
        .iter()
        .map(|(i, raw)| {
            (
                MultiEraInput::from_alonzo_compatible(i),
                MultiEraOutput::decode(Era::Dijkstra, raw).unwrap(),
            )
        })
        .collect();
    let result = phase1::validate_tx_with_time(
        &tx,
        0,
        &f.env,
        &inputs,
        &mut CertState::default(),
        &f.time(),
    );
    assert!(
        result.is_ok(),
        "cross-epoch TTL must pass phase one: {result:?}"
    );
    for result in [
        phase2::evaluate_tx_with_time(&tx, &f.env.prot_params, &f.phase_two_inputs(), &f.time()),
        phase2::estimate_tx_with_time(&tx, &f.env.prot_params, &f.phase_two_inputs(), &f.time()),
        phase2::evaluate_tx(&tx, &f.env.prot_params, &f.phase_two_inputs(), &f.slots),
    ] {
        let report = result.expect("cross-epoch TTL conversion must succeed");
        assert_eq!(report.len(), 1);
        assert!(report[0].success, "{report:?}");
        assert_eq!(report[0].units, f.expected);
    }
}
