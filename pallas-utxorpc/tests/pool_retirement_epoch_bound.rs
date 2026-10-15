use pallas_primitives::{
    ExUnitPrices, ExUnits, Nonce, NonceVariant, RationalNumber, babbage,
    conway::{self, DRepVotingThresholds, PoolVotingThresholds},
};
use pallas_utxorpc::{LedgerContext, TxoRef, UtxoMap, v1alpha, v1beta};
use pallas_validate::utils::{
    AlonzoProtParams, BabbageProtParams, ByronProtParams, ConwayProtParams,
    MultiEraProtocolParameters, ShelleyProtParams,
};

#[derive(Clone)]
struct NoLedger;

impl LedgerContext for NoLedger {
    fn get_utxos(&self, _refs: &[TxoRef]) -> Option<UtxoMap> {
        None
    }

    fn get_slot_timestamp(&self, _slot: u64) -> Option<u64> {
        None
    }
}

fn ratio(numerator: u64, denominator: u64) -> RationalNumber {
    RationalNumber {
        numerator,
        denominator,
    }
}

fn shelley_params(maximum_epoch: u64) -> MultiEraProtocolParameters {
    MultiEraProtocolParameters::Shelley(ShelleyProtParams {
        system_start: "2017-09-23T21:44:51Z".parse().unwrap(),
        epoch_length: 432_000,
        slot_length: 1,
        minfee_a: 44,
        minfee_b: 155_381,
        max_block_body_size: 65_536,
        max_transaction_size: 16_384,
        max_block_header_size: 1_100,
        key_deposit: 2_000_000,
        pool_deposit: 500_000_000,
        desired_number_of_stake_pools: 150,
        protocol_version: (2, 0),
        min_utxo_value: 1_000_000,
        min_pool_cost: 340_000_000,
        expansion_rate: ratio(3, 1_000),
        treasury_growth_rate: ratio(1, 5),
        maximum_epoch,
        pool_pledge_influence: ratio(3, 10),
        decentralization_constant: ratio(1, 1),
        extra_entropy: Nonce {
            variant: NonceVariant::NeutralNonce,
            hash: None,
        },
    })
}

fn prices() -> ExUnitPrices {
    ExUnitPrices {
        mem_price: ratio(577, 10_000),
        step_price: ratio(721, 10_000_000),
    }
}

fn units() -> ExUnits {
    ExUnits {
        mem: 14_000_000,
        steps: 10_000_000_000,
    }
}

fn neutral() -> Nonce {
    Nonce {
        variant: NonceVariant::NeutralNonce,
        hash: None,
    }
}

fn alonzo_params(maximum_epoch: u64) -> MultiEraProtocolParameters {
    MultiEraProtocolParameters::Alonzo(AlonzoProtParams {
        system_start: "2017-09-23T21:44:51Z".parse().unwrap(),
        epoch_length: 432_000,
        slot_length: 1,
        minfee_a: 44,
        minfee_b: 155_381,
        max_block_body_size: 65_536,
        max_transaction_size: 16_384,
        max_block_header_size: 1_100,
        key_deposit: 2_000_000,
        pool_deposit: 500_000_000,
        desired_number_of_stake_pools: 500,
        protocol_version: (6, 0),
        min_pool_cost: 340_000_000,
        ada_per_utxo_byte: 34_482,
        cost_models_for_script_languages: Default::default(),
        execution_costs: prices(),
        max_tx_ex_units: units(),
        max_block_ex_units: units(),
        max_value_size: 5_000,
        collateral_percentage: 150,
        max_collateral_inputs: 3,
        expansion_rate: ratio(3, 1_000),
        treasury_growth_rate: ratio(1, 5),
        maximum_epoch,
        pool_pledge_influence: ratio(3, 10),
        decentralization_constant: ratio(0, 1),
        extra_entropy: neutral(),
    })
}

fn babbage_params(maximum_epoch: u64) -> MultiEraProtocolParameters {
    MultiEraProtocolParameters::Babbage(BabbageProtParams {
        system_start: "2017-09-23T21:44:51Z".parse().unwrap(),
        epoch_length: 432_000,
        slot_length: 1,
        minfee_a: 44,
        minfee_b: 155_381,
        max_block_body_size: 90_112,
        max_transaction_size: 16_384,
        max_block_header_size: 1_100,
        key_deposit: 2_000_000,
        pool_deposit: 500_000_000,
        desired_number_of_stake_pools: 500,
        protocol_version: (8, 0),
        min_pool_cost: 340_000_000,
        ada_per_utxo_byte: 4_310,
        cost_models_for_script_languages: babbage::CostModels {
            plutus_v1: None,
            plutus_v2: None,
        },
        execution_costs: prices(),
        max_tx_ex_units: units(),
        max_block_ex_units: units(),
        max_value_size: 5_000,
        collateral_percentage: 150,
        max_collateral_inputs: 3,
        expansion_rate: ratio(3, 1_000),
        treasury_growth_rate: ratio(1, 5),
        maximum_epoch,
        pool_pledge_influence: ratio(3, 10),
        decentralization_constant: ratio(0, 1),
        extra_entropy: neutral(),
    })
}

fn conway_params(maximum_epoch: u64) -> MultiEraProtocolParameters {
    let half = ratio(1, 2);
    MultiEraProtocolParameters::Conway(ConwayProtParams {
        system_start: "2017-09-23T21:44:51Z".parse().unwrap(),
        epoch_length: 432_000,
        slot_length: 1,
        minfee_a: 44,
        minfee_b: 155_381,
        max_block_body_size: 90_112,
        max_transaction_size: 16_384,
        max_block_header_size: 1_100,
        key_deposit: 2_000_000,
        pool_deposit: 500_000_000,
        desired_number_of_stake_pools: 500,
        protocol_version: (9, 0),
        min_pool_cost: 170_000_000,
        ada_per_utxo_byte: 4_310,
        cost_models_for_script_languages: conway::CostModels {
            plutus_v1: None,
            plutus_v2: None,
            plutus_v3: None,
            unknown: Default::default(),
        },
        execution_costs: prices(),
        max_tx_ex_units: units(),
        max_block_ex_units: units(),
        max_value_size: 5_000,
        collateral_percentage: 150,
        max_collateral_inputs: 3,
        expansion_rate: ratio(3, 1_000),
        treasury_growth_rate: ratio(1, 5),
        maximum_epoch,
        pool_pledge_influence: ratio(3, 10),
        pool_voting_thresholds: PoolVotingThresholds {
            motion_no_confidence: half.clone(),
            committee_normal: half.clone(),
            committee_no_confidence: half.clone(),
            hard_fork_initiation: half.clone(),
            security_voting_threshold: half.clone(),
        },
        drep_voting_thresholds: DRepVotingThresholds {
            motion_no_confidence: half.clone(),
            committee_normal: half.clone(),
            committee_no_confidence: half.clone(),
            update_constitution: half.clone(),
            hard_fork_initiation: half.clone(),
            pp_network_group: half.clone(),
            pp_economic_group: half.clone(),
            pp_technical_group: half.clone(),
            pp_governance_group: half.clone(),
            treasury_withdrawal: half.clone(),
        },
        min_committee_size: 7,
        committee_term_limit: 146,
        governance_action_validity_period: 6,
        governance_action_deposit: 100_000_000_000,
        drep_deposit: 500_000_000,
        drep_inactivity_period: 20,
        minfee_refscript_cost_per_byte: ratio(15, 1),
    })
}

fn byron_params() -> MultiEraProtocolParameters {
    MultiEraProtocolParameters::Byron(ByronProtParams {
        block_version: (0, 2, 0),
        start_time: 1_506_203_091,
        script_version: 0,
        slot_duration: 20_000,
        max_block_size: 2_000_000,
        max_header_size: 2_000,
        max_tx_size: 4_096,
        max_proposal_size: 700,
        mpc_thd: 20_000_000_000_000,
        heavy_del_thd: 300_000_000_000,
        update_vote_thd: 1_000_000_000_000,
        update_proposal_thd: 100_000_000_000_000,
        update_implicit: 10_000,
        soft_fork_rule: (900_000_000_000_000, 600_000_000_000_000, 50_000_000_000_000),
        summand: 155_381_000_000_000,
        multiplier: 43_946_000_000,
        unlock_stake_epoch: 18_446_744_073_709_551_615,
    })
}

#[test]
fn a_shelley_parameter_set_maps_its_pool_retirement_bound() {
    let alpha = v1alpha::Mapper::new(NoLedger).map_pparams(shelley_params(18));
    let beta = v1beta::Mapper::new(NoLedger).map_pparams(shelley_params(18));

    assert_eq!(alpha.pool_retirement_epoch_bound, 18);
    assert_eq!(beta.pool_retirement_epoch_bound, 18);
}

#[test]
fn an_alonzo_parameter_set_maps_its_pool_retirement_bound() {
    let alpha = v1alpha::Mapper::new(NoLedger).map_pparams(alonzo_params(19));
    let beta = v1beta::Mapper::new(NoLedger).map_pparams(alonzo_params(19));

    assert_eq!(alpha.pool_retirement_epoch_bound, 19);
    assert_eq!(beta.pool_retirement_epoch_bound, 19);
}

#[test]
fn a_babbage_parameter_set_maps_its_pool_retirement_bound() {
    let alpha = v1alpha::Mapper::new(NoLedger).map_pparams(babbage_params(20));
    let beta = v1beta::Mapper::new(NoLedger).map_pparams(babbage_params(20));

    assert_eq!(alpha.pool_retirement_epoch_bound, 20);
    assert_eq!(beta.pool_retirement_epoch_bound, 20);
}

#[test]
fn a_conway_parameter_set_maps_its_pool_retirement_bound() {
    let alpha = v1alpha::Mapper::new(NoLedger).map_pparams(conway_params(21));
    let beta = v1beta::Mapper::new(NoLedger).map_pparams(conway_params(21));

    assert_eq!(alpha.pool_retirement_epoch_bound, 21);
    assert_eq!(beta.pool_retirement_epoch_bound, 21);
}

#[test]
fn a_byron_parameter_set_maps_no_pool_retirement_bound() {
    let alpha = v1alpha::Mapper::new(NoLedger).map_pparams(byron_params());
    let beta = v1beta::Mapper::new(NoLedger).map_pparams(byron_params());

    assert_eq!(alpha.pool_retirement_epoch_bound, 0);
    assert_eq!(beta.pool_retirement_epoch_bound, 0);
}
