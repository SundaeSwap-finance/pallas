use std::collections::HashMap;

use pallas_codec::utils::Nullable;
use pallas_primitives::{ExUnitPrices, ExUnits, RationalNumber, StakeCredential, conway, dijkstra};
use pallas_traverse::OriginalHash;
use pallas_utxorpc::v1beta::spec::cardano as u5c;
use pallas_validate::utils::{ConwayProtParams, DijkstraProtParams};
use serde_json::{Value, json};

use crate::effects::natural;
use crate::node::Pool;

/// One transaction id the node reported for a chain case.
#[derive(Clone, Debug)]
pub struct Case {
    pub name: String,
    pub id: [u8; 32],
}

/// Reads the chain case list, an array of objects with a name and a hex id.
pub fn cases(x: &Value) -> Vec<Case> {
    x.as_array()
        .expect("a case list")
        .iter()
        .map(|c| Case {
            name: c["name"].as_str().expect("a name").to_owned(),
            id: hex::decode(c["id"].as_str().expect("an id"))
                .expect("hex")
                .try_into()
                .expect("a 32 byte id"),
        })
        .collect()
}

/// Where the source chain holds a transaction id, its block number and the top level transaction when it is a sub transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Found {
    pub block: u64,
    pub parent: Option<[u8; 32]>,
}

/// How u5c answers for one chain case id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdVerdict {
    Carried(Found),
    NotCarried(Found),
    NotInSource,
}

/// Lists the source transaction ids of a Dijkstra block, top level and sub transactions.
pub fn source_ids(block: &dijkstra::Block, number: u64) -> Vec<([u8; 32], Found)> {
    let mut out = Vec::new();
    for tx in block.block_body.transactions.iter() {
        let top = *tx.transaction_body.original_hash();
        out.push((
            top,
            Found {
                block: number,
                parent: None,
            },
        ));
        for sub in tx
            .transaction_body
            .sub_transactions
            .iter()
            .flat_map(|s| s.iter())
        {
            out.push((
                *sub.sub_transaction_body.original_hash(),
                Found {
                    block: number,
                    parent: Some(top),
                },
            ));
        }
    }
    out
}

/// Tells for each chain case whether u5c carries its id where the source holds it, a top level id in the block and a sub transaction id under its parent.
pub fn tx_ids<'a>(
    cases: &'a [Case],
    found: &HashMap<[u8; 32], Found>,
    blocks: &HashMap<u64, u5c::Block>,
) -> Vec<(&'a Case, IdVerdict)> {
    cases
        .iter()
        .map(|c| {
            let Some(at) = found.get(&c.id) else {
                return (c, IdVerdict::NotInSource);
            };
            let txs = blocks
                .get(&at.block)
                .and_then(|b| b.body.as_ref())
                .map(|b| b.tx.as_slice())
                .unwrap_or(&[]);
            let carries = |t: &u5c::Tx| t.hash.as_ref() == c.id;
            let carried = match at.parent {
                None => txs.iter().any(carries),
                Some(parent) => txs
                    .iter()
                    .filter(|t| t.hash.as_ref() == parent)
                    .any(|t| t.sub_transactions.iter().any(carries)),
            };
            if carried {
                (c, IdVerdict::Carried(*at))
            } else {
                (c, IdVerdict::NotCarried(*at))
            }
        })
        .collect()
}

/// Tells whether there is a chain case and u5c carries every chain case id.
pub fn ids_agree(ids: &[(&Case, IdVerdict)]) -> bool {
    !ids.is_empty() && ids.iter().all(|(_, v)| matches!(v, IdVerdict::Carried(_)))
}

/// Reads a decimal the node prints as a JSON number into the exact rational it writes.
pub fn rational(x: &Value) -> RationalNumber {
    let text = x.to_string();
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((m, e)) => (m.to_owned(), e.parse::<i32>().expect("an exponent")),
        None => (text.clone(), 0),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((&mantissa, ""));
    let digits: u64 = format!("{whole}{fraction}")
        .parse()
        .expect("a nonnegative decimal");
    let scale = exponent - fraction.len() as i32;
    let (numerator, denominator) = if scale >= 0 {
        (digits * 10u64.pow(scale as u32), 1)
    } else {
        (digits, 10u64.pow((-scale) as u32))
    };
    let g = gcd(numerator, denominator);
    RationalNumber {
        numerator: numerator / g,
        denominator: denominator / g,
    }
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a.max(1) } else { gcd(b, a % b) }
}

fn int(x: &Value, key: &str) -> u64 {
    x[key]
        .as_u64()
        .unwrap_or_else(|| panic!("an integer at {key}"))
}

fn units(x: &Value) -> ExUnits {
    ExUnits {
        mem: int(x, "memory"),
        steps: int(x, "steps"),
    }
}

fn prices(x: &Value) -> ExUnitPrices {
    ExUnitPrices {
        mem_price: rational(&x["priceMemory"]),
        step_price: rational(&x["priceSteps"]),
    }
}

fn cost_model(x: &Value, language: &str) -> Option<Vec<i64>> {
    x["costModels"][language].as_array().map(|v| {
        v.iter()
            .map(|c| c.as_i64().expect("a cost model entry"))
            .collect()
    })
}

/// Reads the system start, epoch length and slot length a Shelley genesis file names.
pub fn timing(genesis: &Value) -> (chrono::DateTime<chrono::FixedOffset>, u64, u64) {
    let start = chrono::DateTime::parse_from_rfc3339(
        genesis["systemStart"].as_str().expect("a system start"),
    )
    .expect("an RFC 3339 time");
    let slot_seconds = genesis["slotLength"].as_f64().expect("a slot length");
    (
        start,
        int(genesis, "epochLength"),
        slot_seconds.round() as u64,
    )
}

/// Builds Conway era parameters from `query protocol-parameters`, keeping the PlutusV4 cost model under its language key 3.
pub fn conway_params(x: &Value, genesis: &Value) -> ConwayProtParams {
    let (system_start, epoch_length, slot_length) = timing(genesis);
    let pool = &x["poolVotingThresholds"];
    let drep = &x["dRepVotingThresholds"];
    ConwayProtParams {
        system_start,
        epoch_length,
        slot_length,
        minfee_a: int(x, "txFeePerByte") as u32,
        minfee_b: int(x, "txFeeFixed") as u32,
        max_block_body_size: int(x, "maxBlockBodySize") as u32,
        max_transaction_size: int(x, "maxTxSize") as u32,
        max_block_header_size: int(x, "maxBlockHeaderSize") as u32,
        key_deposit: int(x, "stakeAddressDeposit"),
        pool_deposit: int(x, "stakePoolDeposit"),
        desired_number_of_stake_pools: int(x, "stakePoolTargetNum") as u32,
        protocol_version: (
            int(&x["protocolVersion"], "major"),
            int(&x["protocolVersion"], "minor"),
        ),
        min_pool_cost: int(x, "minPoolCost"),
        ada_per_utxo_byte: int(x, "utxoCostPerByte"),
        cost_models_for_script_languages: conway::CostModels {
            plutus_v1: cost_model(x, "PlutusV1"),
            plutus_v2: cost_model(x, "PlutusV2"),
            plutus_v3: cost_model(x, "PlutusV3"),
            unknown: cost_model(x, "PlutusV4")
                .map(|v| (3, v))
                .into_iter()
                .collect(),
        },
        execution_costs: prices(&x["executionUnitPrices"]),
        max_tx_ex_units: units(&x["maxTxExecutionUnits"]),
        max_block_ex_units: units(&x["maxBlockExecutionUnits"]),
        max_value_size: int(x, "maxValueSize") as u32,
        collateral_percentage: int(x, "collateralPercentage") as u32,
        max_collateral_inputs: int(x, "maxCollateralInputs") as u32,
        expansion_rate: rational(&x["monetaryExpansion"]),
        treasury_growth_rate: rational(&x["treasuryCut"]),
        maximum_epoch: int(x, "poolRetireMaxEpoch"),
        pool_pledge_influence: rational(&x["poolPledgeInfluence"]),
        pool_voting_thresholds: conway::PoolVotingThresholds {
            motion_no_confidence: rational(&pool["motionNoConfidence"]),
            committee_normal: rational(&pool["committeeNormal"]),
            committee_no_confidence: rational(&pool["committeeNoConfidence"]),
            hard_fork_initiation: rational(&pool["hardForkInitiation"]),
            security_voting_threshold: rational(&pool["ppSecurityGroup"]),
        },
        drep_voting_thresholds: conway::DRepVotingThresholds {
            motion_no_confidence: rational(&drep["motionNoConfidence"]),
            committee_normal: rational(&drep["committeeNormal"]),
            committee_no_confidence: rational(&drep["committeeNoConfidence"]),
            update_constitution: rational(&drep["updateToConstitution"]),
            hard_fork_initiation: rational(&drep["hardForkInitiation"]),
            pp_network_group: rational(&drep["ppNetworkGroup"]),
            pp_economic_group: rational(&drep["ppEconomicGroup"]),
            pp_technical_group: rational(&drep["ppTechnicalGroup"]),
            pp_governance_group: rational(&drep["ppGovGroup"]),
            treasury_withdrawal: rational(&drep["treasuryWithdrawal"]),
        },
        min_committee_size: int(x, "committeeMinSize"),
        committee_term_limit: int(x, "committeeMaxTermLength"),
        governance_action_validity_period: int(x, "govActionLifetime"),
        governance_action_deposit: int(x, "govActionDeposit"),
        drep_deposit: int(x, "dRepDeposit"),
        drep_inactivity_period: int(x, "dRepActivity"),
        minfee_refscript_cost_per_byte: rational(&x["minFeeRefScriptCostPerByte"]),
    }
}

/// Builds the Dijkstra era parameters from `query protocol-parameters`.
pub fn dijkstra_params(x: &Value, genesis: &Value) -> DijkstraProtParams {
    let c = conway_params(x, genesis);
    DijkstraProtParams {
        system_start: c.system_start,
        epoch_length: c.epoch_length,
        slot_length: c.slot_length,
        minfee_a: c.minfee_a,
        minfee_b: c.minfee_b,
        max_block_body_size: c.max_block_body_size,
        max_transaction_size: c.max_transaction_size,
        max_block_header_size: c.max_block_header_size,
        key_deposit: c.key_deposit,
        pool_deposit: c.pool_deposit,
        desired_number_of_stake_pools: c.desired_number_of_stake_pools,
        protocol_version: c.protocol_version,
        min_pool_cost: c.min_pool_cost,
        ada_per_utxo_byte: c.ada_per_utxo_byte,
        cost_models_for_script_languages: dijkstra::CostModels {
            plutus_v1: cost_model(x, "PlutusV1"),
            plutus_v2: cost_model(x, "PlutusV2"),
            plutus_v3: cost_model(x, "PlutusV3"),
            plutus_v4: cost_model(x, "PlutusV4"),
            unknown: Default::default(),
        },
        execution_costs: c.execution_costs,
        max_tx_ex_units: c.max_tx_ex_units,
        max_block_ex_units: c.max_block_ex_units,
        max_value_size: c.max_value_size,
        collateral_percentage: c.collateral_percentage,
        max_collateral_inputs: c.max_collateral_inputs,
        expansion_rate: c.expansion_rate,
        treasury_growth_rate: c.treasury_growth_rate,
        maximum_epoch: c.maximum_epoch,
        pool_pledge_influence: c.pool_pledge_influence,
        pool_voting_thresholds: c.pool_voting_thresholds,
        drep_voting_thresholds: c.drep_voting_thresholds,
        min_committee_size: c.min_committee_size,
        committee_term_limit: c.committee_term_limit,
        governance_action_validity_period: c.governance_action_validity_period,
        governance_action_deposit: c.governance_action_deposit,
        drep_deposit: c.drep_deposit,
        drep_inactivity_period: c.drep_inactivity_period,
        minfee_refscript_cost_per_byte: c.minfee_refscript_cost_per_byte,
        max_ref_script_size_per_block: int(x, "maxRefScriptSizePerBlock") as u32,
        max_ref_script_size_per_tx: int(x, "maxRefScriptSizePerTx") as u32,
        ref_script_cost_stride: int(x, "refScriptCostStride") as u32,
        ref_script_cost_multiplier: rational(&x["refScriptCostMultiplier"]),
        max_pledge_leverage: match &x["maxPledgeLeverage"] {
            Value::Null => None,
            cap => Some(rational(cap)),
        },
        min_pool_margin: rational(&x["minPoolMargin"]),
        leios_announcement_period_length: int(x, "leiosAnnouncementPeriodLength") as u32,
        leios_vote_period_length: int(x, "leiosVotePeriodLength") as u32,
        leios_diffusion_period_length: int(x, "leiosDiffusionPeriodLength") as u32,
        leios_committee_size: int(x, "leiosCommitteeSize") as u16,
        leios_quorum_stake_threshold: rational(&x["leiosQuorumStakeThreshold"]),
        max_endorser_block_references_size: int(x, "maxEndorserBlockReferencesSize") as u32,
        max_endorser_block_txs_size: int(x, "maxEndorserBlockTxsSize") as u32,
        max_endorser_block_ex_units: units(&x["maxEndorserBlockExecutionUnits"]),
        max_ref_script_size_per_endorser_block: int(x, "maxRefScriptSizePerEndorserBlock") as u32,
    }
}

fn ratio(x: &Option<u5c::RationalNumber>) -> Value {
    match x {
        Some(r) => json!(f64::from(r.numerator) / f64::from(r.denominator)),
        None => Value::Null,
    }
}

fn coin(x: &Option<u5c::BigInt>) -> Value {
    match x {
        Some(_) => json!(natural(x.as_ref())),
        None => Value::Null,
    }
}

fn ex_units(x: &Option<u5c::ExUnits>) -> Value {
    match x {
        Some(u) => json!({"memory": u.memory, "steps": u.steps}),
        None => Value::Null,
    }
}

fn thresholds(x: &Option<u5c::VotingThresholds>) -> Value {
    match x {
        Some(t) => Value::Array(
            t.thresholds
                .iter()
                .map(|r| ratio(&Some(r.clone())))
                .collect(),
        ),
        None => Value::Null,
    }
}

fn model(x: Option<&u5c::CostModel>) -> Value {
    match x {
        Some(m) => json!(m.values),
        None => Value::Null,
    }
}

fn pick(x: &Value, keys: &[&str]) -> Value {
    Value::Array(keys.iter().map(|k| x[*k].clone()).collect())
}

/// Lists each u5c parameter field beside the value the node reports for it, as the u5c field name, the u5c value and the node value.
pub fn param_pairs(p: &u5c::PParams, x: &Value) -> Vec<(&'static str, Value, Value)> {
    let models = p.cost_models.clone().unwrap_or_default();
    let version = p.protocol_version.clone().unwrap_or_default();
    let prices = p.prices.clone().unwrap_or_default();
    vec![
        (
            "coins_per_utxo_byte",
            coin(&p.coins_per_utxo_byte),
            x["utxoCostPerByte"].clone(),
        ),
        ("max_tx_size", json!(p.max_tx_size), x["maxTxSize"].clone()),
        (
            "min_fee_coefficient",
            coin(&p.min_fee_coefficient),
            x["txFeePerByte"].clone(),
        ),
        (
            "min_fee_constant",
            coin(&p.min_fee_constant),
            x["txFeeFixed"].clone(),
        ),
        (
            "max_block_body_size",
            json!(p.max_block_body_size),
            x["maxBlockBodySize"].clone(),
        ),
        (
            "max_block_header_size",
            json!(p.max_block_header_size),
            x["maxBlockHeaderSize"].clone(),
        ),
        (
            "stake_key_deposit",
            coin(&p.stake_key_deposit),
            x["stakeAddressDeposit"].clone(),
        ),
        (
            "pool_deposit",
            coin(&p.pool_deposit),
            x["stakePoolDeposit"].clone(),
        ),
        (
            "pool_retirement_epoch_bound",
            json!(p.pool_retirement_epoch_bound),
            x["poolRetireMaxEpoch"].clone(),
        ),
        (
            "desired_number_of_pools",
            json!(p.desired_number_of_pools),
            x["stakePoolTargetNum"].clone(),
        ),
        (
            "pool_influence",
            ratio(&p.pool_influence),
            x["poolPledgeInfluence"].clone(),
        ),
        (
            "monetary_expansion",
            ratio(&p.monetary_expansion),
            x["monetaryExpansion"].clone(),
        ),
        (
            "treasury_expansion",
            ratio(&p.treasury_expansion),
            x["treasuryCut"].clone(),
        ),
        (
            "min_pool_cost",
            coin(&p.min_pool_cost),
            x["minPoolCost"].clone(),
        ),
        (
            "protocol_version",
            json!({"major": version.major, "minor": version.minor}),
            x["protocolVersion"].clone(),
        ),
        (
            "max_value_size",
            json!(p.max_value_size),
            x["maxValueSize"].clone(),
        ),
        (
            "collateral_percentage",
            json!(p.collateral_percentage),
            x["collateralPercentage"].clone(),
        ),
        (
            "max_collateral_inputs",
            json!(p.max_collateral_inputs),
            x["maxCollateralInputs"].clone(),
        ),
        (
            "cost_models.plutus_v1",
            model(models.plutus_v1.as_ref()),
            x["costModels"]["PlutusV1"].clone(),
        ),
        (
            "cost_models.plutus_v2",
            model(models.plutus_v2.as_ref()),
            x["costModels"]["PlutusV2"].clone(),
        ),
        (
            "cost_models.plutus_v3",
            model(models.plutus_v3.as_ref()),
            x["costModels"]["PlutusV3"].clone(),
        ),
        (
            "cost_models.plutus_v4",
            model(models.plutus_v4.as_ref()),
            x["costModels"]["PlutusV4"].clone(),
        ),
        (
            "prices",
            json!({"priceMemory": ratio(&prices.memory), "priceSteps": ratio(&prices.steps)}),
            x["executionUnitPrices"].clone(),
        ),
        (
            "max_execution_units_per_transaction",
            ex_units(&p.max_execution_units_per_transaction),
            x["maxTxExecutionUnits"].clone(),
        ),
        (
            "max_execution_units_per_block",
            ex_units(&p.max_execution_units_per_block),
            x["maxBlockExecutionUnits"].clone(),
        ),
        (
            "min_fee_script_ref_cost_per_byte",
            ratio(&p.min_fee_script_ref_cost_per_byte),
            x["minFeeRefScriptCostPerByte"].clone(),
        ),
        (
            "pool_voting_thresholds",
            thresholds(&p.pool_voting_thresholds),
            pick(
                &x["poolVotingThresholds"],
                &[
                    "motionNoConfidence",
                    "committeeNormal",
                    "committeeNoConfidence",
                    "hardForkInitiation",
                    "ppSecurityGroup",
                ],
            ),
        ),
        (
            "drep_voting_thresholds",
            thresholds(&p.drep_voting_thresholds),
            pick(
                &x["dRepVotingThresholds"],
                &[
                    "motionNoConfidence",
                    "committeeNormal",
                    "committeeNoConfidence",
                    "updateToConstitution",
                    "hardForkInitiation",
                    "ppNetworkGroup",
                    "ppEconomicGroup",
                    "ppTechnicalGroup",
                    "ppGovGroup",
                    "treasuryWithdrawal",
                ],
            ),
        ),
        (
            "min_committee_size",
            json!(p.min_committee_size),
            x["committeeMinSize"].clone(),
        ),
        (
            "committee_term_limit",
            json!(p.committee_term_limit),
            x["committeeMaxTermLength"].clone(),
        ),
        (
            "governance_action_validity_period",
            json!(p.governance_action_validity_period),
            x["govActionLifetime"].clone(),
        ),
        (
            "governance_action_deposit",
            coin(&p.governance_action_deposit),
            x["govActionDeposit"].clone(),
        ),
        (
            "drep_deposit",
            coin(&p.drep_deposit),
            x["dRepDeposit"].clone(),
        ),
        (
            "drep_inactivity_period",
            json!(p.drep_inactivity_period),
            x["dRepActivity"].clone(),
        ),
        (
            "max_ref_script_size_per_block",
            json!(p.max_ref_script_size_per_block),
            x["maxRefScriptSizePerBlock"].clone(),
        ),
        (
            "max_ref_script_size_per_tx",
            json!(p.max_ref_script_size_per_tx),
            x["maxRefScriptSizePerTx"].clone(),
        ),
        (
            "ref_script_cost_stride",
            json!(p.ref_script_cost_stride),
            x["refScriptCostStride"].clone(),
        ),
        (
            "ref_script_cost_multiplier",
            ratio(&p.ref_script_cost_multiplier),
            x["refScriptCostMultiplier"].clone(),
        ),
        (
            "max_pledge_leverage",
            ratio(&p.max_pledge_leverage),
            x["maxPledgeLeverage"].clone(),
        ),
        (
            "min_pool_margin",
            ratio(&p.min_pool_margin),
            x["minPoolMargin"].clone(),
        ),
        (
            "leios_announcement_period_length",
            json!(p.leios_announcement_period_length),
            x["leiosAnnouncementPeriodLength"].clone(),
        ),
        (
            "leios_vote_period_length",
            json!(p.leios_vote_period_length),
            x["leiosVotePeriodLength"].clone(),
        ),
        (
            "leios_diffusion_period_length",
            json!(p.leios_diffusion_period_length),
            x["leiosDiffusionPeriodLength"].clone(),
        ),
        (
            "leios_committee_size",
            json!(p.leios_committee_size),
            x["leiosCommitteeSize"].clone(),
        ),
        (
            "leios_quorum_stake_threshold",
            ratio(&p.leios_quorum_stake_threshold),
            x["leiosQuorumStakeThreshold"].clone(),
        ),
        (
            "max_endorser_block_references_size",
            json!(p.max_endorser_block_references_size),
            x["maxEndorserBlockReferencesSize"].clone(),
        ),
        (
            "max_endorser_block_txs_size",
            json!(p.max_endorser_block_txs_size),
            x["maxEndorserBlockTxsSize"].clone(),
        ),
        (
            "max_endorser_block_execution_units",
            ex_units(&p.max_endorser_block_execution_units),
            x["maxEndorserBlockExecutionUnits"].clone(),
        ),
        (
            "max_ref_script_size_per_endorser_block",
            json!(p.max_ref_script_size_per_endorser_block),
            x["maxRefScriptSizePerEndorserBlock"].clone(),
        ),
    ]
}

/// The node parameter keys that `param_pairs` reads.
pub const NODE_KEYS_WITH_FIELD: [&str; 46] = [
    "utxoCostPerByte",
    "maxTxSize",
    "txFeePerByte",
    "txFeeFixed",
    "maxBlockBodySize",
    "maxBlockHeaderSize",
    "stakeAddressDeposit",
    "stakePoolDeposit",
    "poolRetireMaxEpoch",
    "stakePoolTargetNum",
    "poolPledgeInfluence",
    "monetaryExpansion",
    "treasuryCut",
    "minPoolCost",
    "protocolVersion",
    "maxValueSize",
    "collateralPercentage",
    "maxCollateralInputs",
    "costModels",
    "executionUnitPrices",
    "maxTxExecutionUnits",
    "maxBlockExecutionUnits",
    "minFeeRefScriptCostPerByte",
    "poolVotingThresholds",
    "dRepVotingThresholds",
    "committeeMinSize",
    "committeeMaxTermLength",
    "govActionLifetime",
    "govActionDeposit",
    "dRepDeposit",
    "dRepActivity",
    "maxRefScriptSizePerBlock",
    "maxRefScriptSizePerTx",
    "refScriptCostStride",
    "refScriptCostMultiplier",
    "maxPledgeLeverage",
    "minPoolMargin",
    "leiosAnnouncementPeriodLength",
    "leiosVotePeriodLength",
    "leiosDiffusionPeriodLength",
    "leiosCommitteeSize",
    "leiosQuorumStakeThreshold",
    "maxEndorserBlockReferencesSize",
    "maxEndorserBlockTxsSize",
    "maxEndorserBlockExecutionUnits",
    "maxRefScriptSizePerEndorserBlock",
];

/// Tells whether two parameter values are both present and agree, numbers to a relative tolerance of one part in a billion.
pub fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, _) | (_, Value::Null) => false,
        (Value::Number(x), Value::Number(y)) => {
            let (x, y) = (x.as_f64().expect("a number"), y.as_f64().expect("a number"));
            (x - y).abs() <= 1e-9 * x.abs().max(y.abs())
        }
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(a, b)| same(a, b))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w)))
        }
        _ => a == b,
    }
}

/// The u5c fields that are absent when the ledger holds no value, each beside the node key that reports that value as null.
pub const NULLABLE_FIELDS: [(&str, &str); 1] = [("max_pledge_leverage", "maxPledgeLeverage")];

/// Tells whether u5c leaves a nullable field absent and the node reports its key with a null.
fn both_hold_no_value(field: &str, a: &Value, x: &Value) -> bool {
    NULLABLE_FIELDS
        .iter()
        .any(|(f, k)| *f == field && a.is_null() && x.get(*k).is_some_and(Value::is_null))
}

/// Lists the u5c fields whose value differs from the node's.
pub fn param_mismatches(p: &u5c::PParams, x: &Value) -> Vec<(&'static str, Value, Value)> {
    param_pairs(p, x)
        .into_iter()
        .filter(|(f, a, b)| !(same(a, b) || both_hold_no_value(f, a, x)))
        .collect()
}

/// Lists the node parameter keys that no u5c field holds.
pub fn node_keys_without_field(x: &Value) -> Vec<String> {
    x.as_object()
        .expect("a parameter object")
        .keys()
        .filter(|k| !NODE_KEYS_WITH_FIELD.contains(&k.as_str()))
        .cloned()
        .collect()
}

/// One guard credential, its script flag and its hash, or None for a u5c credential with neither.
pub type Guard = Option<(bool, Vec<u8>)>;

/// The guard credentials of one source body, in body order.
fn source_guards(x: Option<&dijkstra::Guards>) -> Vec<Guard> {
    match x {
        None => vec![],
        Some(dijkstra::Guards::AddrKeyhashes(x)) => {
            x.iter().map(|h| Some((false, h.to_vec()))).collect()
        }
        Some(dijkstra::Guards::Credentials(x)) => x
            .iter()
            .map(|c| match c {
                StakeCredential::AddrKeyhash(h) => Some((false, h.to_vec())),
                StakeCredential::ScriptHash(h) => Some((true, h.to_vec())),
            })
            .collect(),
    }
}

/// The guard credentials of one u5c transaction, in field order.
pub fn u5c_guards(tx: Option<&u5c::Tx>) -> Vec<Guard> {
    use u5c::stake_credential::StakeCredential as C;
    tx.into_iter()
        .flat_map(|t| &t.guards)
        .map(|c| match c.stake_credential.as_ref() {
            Some(C::AddrKeyHash(h)) => Some((false, h.to_vec())),
            Some(C::ScriptHash(h)) => Some((true, h.to_vec())),
            None => None,
        })
        .collect()
}

/// How the guards of every source body compare with the u5c guards of the transaction at the same place.
#[derive(Clone, Debug, Default)]
pub struct GuardReport {
    pub bodies: usize,
    pub with_guards: usize,
    pub differences: Vec<(u64, [u8; 32])>,
}

impl GuardReport {
    /// Tells whether a body has guards and u5c holds the guards of every body, none where the source has none.
    pub fn agrees(&self) -> bool {
        self.with_guards > 0 && self.differences.is_empty()
    }

    /// Counts one body and notes it when u5c holds other guards than the source.
    fn compare(&mut self, number: u64, id: [u8; 32], source: Vec<Guard>, mapped: Option<&u5c::Tx>) {
        self.bodies += 1;
        if !source.is_empty() {
            self.with_guards += 1;
        }
        if source != u5c_guards(mapped) {
            self.differences.push((number, id));
        }
    }

    /// Compares each body of a Dijkstra block, top level and sub transactions, with the u5c transaction at the same place.
    pub fn add(&mut self, block: &dijkstra::Block, number: u64, mapped: &u5c::Block) {
        let txs = mapped.body.as_ref().map(|b| b.tx.as_slice()).unwrap_or(&[]);
        for (i, tx) in block.block_body.transactions.iter().enumerate() {
            let body = &tx.transaction_body;
            let u5c_tx = txs.get(i);
            let source = source_guards(body.guards.as_ref());
            self.compare(number, *body.original_hash(), source, u5c_tx);
            for (j, sub) in body
                .sub_transactions
                .iter()
                .flat_map(|s| s.iter())
                .enumerate()
            {
                let sub_body = &sub.sub_transaction_body;
                let source = source_guards(sub_body.guards.as_ref());
                let u5c_sub = u5c_tx.and_then(|t| t.sub_transactions.get(j));
                self.compare(number, *sub_body.original_hash(), source, u5c_sub);
            }
        }
    }
}

/// One pool registration of a Dijkstra block beside its u5c mapping.
#[derive(Clone, Debug)]
pub struct Registration {
    pub block: u64,
    pub tx: [u8; 32],
    pub operator: [u8; 28],
    pub vrf: Vec<u8>,
    pub bls: Option<(Vec<u8>, Vec<u8>)>,
    pub mapped: Option<u5c::PoolRegistrationCert>,
}

/// Pairs each pool registration of a Dijkstra block with the u5c registration at the same place.
pub fn registrations(
    block: &dijkstra::Block,
    number: u64,
    mapped: &u5c::Block,
) -> Vec<Registration> {
    let txs = mapped.body.as_ref().map(|b| b.tx.as_slice()).unwrap_or(&[]);
    let mut out = Vec::new();
    for (i, tx) in block.block_body.transactions.iter().enumerate() {
        let u5c_tx = txs.get(i);
        let mut u5c_pools =
            u5c_tx
                .into_iter()
                .flat_map(|t| &t.certificates)
                .filter_map(|c| match c.certificate.as_ref() {
                    Some(u5c::certificate::Certificate::PoolRegistration(p)) => Some(p.clone()),
                    _ => None,
                });
        for cert in tx
            .transaction_body
            .certificates
            .iter()
            .flat_map(|c| c.iter())
        {
            if let dijkstra::Certificate::PoolRegistration {
                operator,
                vrf_keyhash,
                bls_key,
                ..
            } = cert
            {
                out.push(Registration {
                    block: number,
                    tx: *tx.transaction_body.original_hash(),
                    operator: **operator,
                    vrf: vrf_keyhash.to_vec(),
                    bls: match bls_key {
                        Some(Nullable::Some(k)) => {
                            Some((k.bls_pubkey.to_vec(), k.bls_possession_proof.to_vec()))
                        }
                        _ => None,
                    },
                    mapped: u5c_pools.next(),
                });
            }
        }
    }
    out
}

/// Tells whether the u5c BLS key of a registration holds the source's public key and possession proof.
pub fn u5c_holds_bls(r: &Registration) -> bool {
    let Some((key, proof)) = &r.bls else {
        return false;
    };
    r.mapped
        .as_ref()
        .and_then(|m| m.bls_key.as_ref())
        .is_some_and(|k| k.bls_pubkey.as_ref() == key && k.bls_possession_proof.as_ref() == proof)
}

/// How the pool registrations of the chain compare with u5c and the node.
#[derive(Clone, Debug, Default)]
pub struct PoolReport {
    pub registrations: usize,
    pub with_bls: usize,
    pub bls_in_u5c: usize,
    pub latest_at_node: usize,
    pub node_bls_agrees: usize,
    pub vrf_agrees: usize,
    pub vrf_differs: Vec<[u8; 28]>,
}

impl PoolReport {
    /// Tells whether a registration has a BLS key and u5c holds the BLS key of every registration that has one.
    pub fn agrees(&self) -> bool {
        self.with_bls > 0 && self.bls_in_u5c == self.with_bls
    }
}

/// Compares each pool's latest registration with u5c and with the node's pool state.
pub fn pool_report(regs: &[Registration], pools: &HashMap<[u8; 28], Pool>) -> PoolReport {
    let mut latest: HashMap<[u8; 28], &Registration> = HashMap::new();
    let mut report = PoolReport {
        registrations: regs.len(),
        ..Default::default()
    };
    for r in regs {
        if r.bls.is_some() {
            report.with_bls += 1;
            if u5c_holds_bls(r) {
                report.bls_in_u5c += 1;
            }
        }
        latest.insert(r.operator, r);
    }
    for (operator, r) in latest {
        let Some(pool) = pools.get(&operator) else {
            continue;
        };
        report.latest_at_node += 1;
        if pool.bls == r.bls {
            report.node_bls_agrees += 1;
        }
        if r.mapped.as_ref().map(|m| m.vrf_keyhash.to_vec()) == Some(pool.vrf.clone()) {
            report.vrf_agrees += 1;
        } else {
            report.vrf_differs.push(operator);
        }
    }
    report
}
