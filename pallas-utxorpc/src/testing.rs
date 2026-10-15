//! Fixture decoders and transaction builders for the schema test modules.

use std::collections::BTreeMap;

use pallas_codec::minicbor::{self, data::Tag};
use pallas_primitives::conway;
use pallas_traverse as trv;

use crate::{LedgerContext, TxoRef, UtxoMap};

/// A mapper context that resolves no output.
#[derive(Clone)]
pub struct NoLedger;

impl LedgerContext for NoLedger {
    fn get_utxos(&self, _refs: &[TxoRef]) -> Option<UtxoMap> {
        None
    }

    fn get_slot_timestamp(&self, _slot: u64) -> Option<u64> {
        None
    }
}

/// The Conway redeemer tag of a certificate's redeemer.
const CERTIFICATE_REDEEMER_TAG: u8 = 2;

/// Decodes a hex encoded Conway transaction.
pub fn conway_tx(tx_str: &str) -> trv::MultiEraTx<'_> {
    let cbor: &'static [u8] = Box::leak(hex::decode(tx_str).unwrap().into_boxed_slice());
    trv::MultiEraTx::decode_for_era(trv::Era::Conway, cbor).unwrap()
}

/// A Conway parameter change around an update read from the CBOR map given,
/// so a test reads the bytes a proposal would encode.
pub fn conway_parameter_change(update_cbor: &[u8]) -> conway::GovAction {
    let update = minicbor::decode(update_cbor).expect("a parameter update map must decode");
    conway::GovAction::ParameterChange(None, Box::new(update), None)
}

/// The action a test names as the one most recently enacted of its kind.
pub fn enacted_action_id() -> conway::GovActionId {
    conway::GovActionId {
        transaction_id: [0x33; 32].into(),
        action_index: 7,
    }
}

/// The protocol version a hard fork initiation proposes.
pub const HARD_FORK_VERSION: (u64, u64) = (11, 0);

/// A hard fork initiation to `HARD_FORK_VERSION`.
pub fn conway_hard_fork_initiation() -> conway::GovAction {
    conway::GovAction::HardForkInitiation(None, HARD_FORK_VERSION)
}

/// The reward account a treasury withdrawal pays.
pub const WITHDRAWAL_REWARD_ACCOUNT: [u8; 29] = [0xe0; 29];

/// The amount that withdrawal pays into it.
pub const WITHDRAWAL_COIN: u64 = 42_000_000;

/// A treasury withdrawal paying one reward account.
pub fn conway_treasury_withdrawal() -> conway::GovAction {
    let mut withdrawals = BTreeMap::new();
    withdrawals.insert(
        conway::RewardAccount::from(WITHDRAWAL_REWARD_ACCOUNT.to_vec()),
        WITHDRAWAL_COIN,
    );
    conway::GovAction::TreasuryWithdrawals(withdrawals, None)
}

/// A no confidence action, naming the action given as the one most recently
/// enacted of its kind.
pub fn conway_no_confidence(previous: Option<conway::GovActionId>) -> conway::GovAction {
    conway::GovAction::NoConfidence(previous)
}

/// The credential a committee update removes.
pub const COMMITTEE_REMOVED: [u8; 28] = [0x44; 28];

/// The credential it seats.
pub const COMMITTEE_SEATED: [u8; 28] = [0x55; 28];

/// The epoch the seated credential's term ends in.
pub const COMMITTEE_SEATED_UNTIL: u64 = 900;

/// A committee update removing one credential, seating another until an epoch
/// and setting the committee threshold.
pub fn conway_update_committee() -> conway::GovAction {
    let mut terms = BTreeMap::new();
    terms.insert(
        conway::StakeCredential::AddrKeyhash(COMMITTEE_SEATED.into()),
        COMMITTEE_SEATED_UNTIL,
    );

    conway::GovAction::UpdateCommittee(
        None,
        conway::Set::from(vec![conway::StakeCredential::AddrKeyhash(
            COMMITTEE_REMOVED.into(),
        )]),
        terms,
        ratio(1, 2),
    )
}

/// The url of a new constitution's anchor.
pub const CONSTITUTION_ANCHOR_URL: &str = "https://example.invalid/constitution";

/// The content hash of that anchor.
pub const CONSTITUTION_ANCHOR_HASH: [u8; 32] = [0x66; 32];

/// A new constitution with an anchor and no guardrails script.
pub fn conway_new_constitution() -> conway::GovAction {
    conway::GovAction::NewConstitution(
        None,
        conway::Constitution {
            anchor: conway::Anchor {
                url: CONSTITUTION_ANCHOR_URL.to_string(),
                content_hash: CONSTITUTION_ANCHOR_HASH.into(),
            },
            guardrail_script: None,
        },
    )
}

/// An information action, which proposes nothing.
pub fn conway_information() -> conway::GovAction {
    conway::GovAction::Information
}

/// A Conway stake registration for the key hash given.
pub fn conway_stake_registration(keyhash: u8) -> conway::Certificate {
    conway::Certificate::StakeRegistration(conway::StakeCredential::AddrKeyhash(
        [keyhash; 28].into(),
    ))
}

/// A Conway transaction whose witness set has a redeemer for the
/// certificate at position 0 and another for the one at position 1, each with
/// its own execution units, so a test reading one back can tell it from the
/// other and from none.
pub fn conway_tx_with_certificate_redeemers() -> trv::MultiEraTx<'static> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(4).unwrap();

    // One input, no outputs, a fee.
    e.map(3).unwrap();
    e.u8(0).unwrap();
    e.tag(Tag::new(258)).unwrap();
    e.array(1).unwrap();
    e.array(2).unwrap();
    e.bytes(&[0x11; 32]).unwrap();
    e.u8(0).unwrap();
    e.u8(1).unwrap();
    e.array(0).unwrap();
    e.u8(2).unwrap();
    e.u32(1_000).unwrap();

    // The redeemer map, keyed by purpose and position.
    e.map(1).unwrap();
    e.u8(5).unwrap();
    e.map(2).unwrap();
    for (order, memory, steps) in [(0u32, 1_000u64, 2_000u64), (1, 3_000, 4_000)] {
        e.array(2).unwrap();
        e.u8(CERTIFICATE_REDEEMER_TAG).unwrap();
        e.u32(order).unwrap();

        e.array(2).unwrap();
        e.tag(Tag::new(121)).unwrap();
        e.array(0).unwrap();
        e.array(2).unwrap();
        e.u64(memory).unwrap();
        e.u64(steps).unwrap();
    }

    e.bool(true).unwrap();
    e.null().unwrap();

    let cbor: &'static [u8] = Box::leak(e.into_writer().into_boxed_slice());
    trv::MultiEraTx::decode_for_era(trv::Era::Conway, cbor).unwrap()
}

/// A Conway reference script of the Plutus script bytes given, under the
/// language index given, where 1, 2 and 3 are PlutusV1, V2 and V3.
pub fn conway_plutus_script_ref(language: u8, script: &[u8]) -> conway::ScriptRef<'static> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(2).unwrap();
    e.u8(language).unwrap();
    e.bytes(script).unwrap();
    decode_leaked(e.into_writer())
}

/// A Conway reference script of a native script that requires the key hash
/// given.
pub fn conway_native_script_ref(keyhash: [u8; 28]) -> conway::ScriptRef<'static> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(2).unwrap();
    e.u8(0).unwrap();
    e.array(2).unwrap();
    e.u8(0).unwrap();
    e.bytes(&keyhash).unwrap();
    decode_leaked(e.into_writer())
}

/// Decodes the bytes given, leaked so the decoded value borrows for the whole
/// run rather than from a local.
fn decode_leaked<'a, T: minicbor::Decode<'a, ()>>(cbor: Vec<u8>) -> T {
    let bytes: &'static [u8] = Box::leak(cbor.into_boxed_slice());
    minicbor::decode(bytes).expect("the bytes a builder wrote must decode")
}

/// A rational of the two numbers given, so a parameter update can set a
/// distinct one per key.
pub fn ratio(numerator: u64, denominator: u64) -> pallas_primitives::RationalNumber {
    pallas_primitives::RationalNumber {
        numerator,
        denominator,
    }
}

/// The number of keys the parameter update mapper reads, one per key it passes
/// through its read helper.
pub const KEYS_THE_UPDATE_MAPPER_READS: usize = 30;

/// One parameter update of the era named, setting the field named to the value
/// given and taking every other field from the update given.
macro_rules! zero_key {
    ($era:ident, $blank:expr, $field:ident = $value:expr) => {
        (
            stringify!($field),
            pallas_primitives::$era::ProtocolParamUpdate {
                $field: Some($value),
                ..$blank
            },
        )
    };
}

/// Every key the parameter update mapper reads, each paired with an update of
/// the era named setting that key alone, to the zero or empty value of the
/// key's own type. A key set alone is the only input that shows whether that
/// key still counts as a set key, whichever u5c field type it maps to.
macro_rules! updates_of_one_zero_key {
    ($era:ident, $blank:ident, $cost_models:expr) => {
        vec![
            zero_key!($era, $blank.clone(), minfee_a = 0),
            zero_key!($era, $blank.clone(), minfee_b = 0),
            zero_key!($era, $blank.clone(), max_block_body_size = 0),
            zero_key!($era, $blank.clone(), max_transaction_size = 0),
            zero_key!($era, $blank.clone(), max_block_header_size = 0),
            zero_key!($era, $blank.clone(), key_deposit = 0),
            zero_key!($era, $blank.clone(), pool_deposit = 0),
            zero_key!($era, $blank.clone(), maximum_epoch = 0),
            zero_key!($era, $blank.clone(), desired_number_of_stake_pools = 0),
            zero_key!($era, $blank.clone(), pool_pledge_influence = ratio(0, 1)),
            zero_key!($era, $blank.clone(), expansion_rate = ratio(0, 1)),
            zero_key!($era, $blank.clone(), treasury_growth_rate = ratio(0, 1)),
            zero_key!($era, $blank.clone(), min_pool_cost = 0),
            zero_key!($era, $blank.clone(), ada_per_utxo_byte = 0),
            zero_key!(
                $era,
                $blank.clone(),
                cost_models_for_script_languages = $cost_models
            ),
            zero_key!(
                $era,
                $blank.clone(),
                execution_costs = pallas_primitives::$era::ExUnitPrices {
                    mem_price: ratio(0, 1),
                    step_price: ratio(0, 1),
                }
            ),
            zero_key!(
                $era,
                $blank.clone(),
                max_tx_ex_units = pallas_primitives::ExUnits { mem: 0, steps: 0 }
            ),
            zero_key!(
                $era,
                $blank.clone(),
                max_block_ex_units = pallas_primitives::ExUnits { mem: 0, steps: 0 }
            ),
            zero_key!($era, $blank.clone(), max_value_size = 0),
            zero_key!($era, $blank.clone(), collateral_percentage = 0),
            zero_key!($era, $blank.clone(), max_collateral_inputs = 0),
            zero_key!(
                $era,
                $blank.clone(),
                pool_voting_thresholds = pallas_primitives::$era::PoolVotingThresholds {
                    motion_no_confidence: ratio(0, 1),
                    committee_normal: ratio(0, 1),
                    committee_no_confidence: ratio(0, 1),
                    hard_fork_initiation: ratio(0, 1),
                    security_voting_threshold: ratio(0, 1),
                }
            ),
            zero_key!(
                $era,
                $blank.clone(),
                drep_voting_thresholds = pallas_primitives::$era::DRepVotingThresholds {
                    motion_no_confidence: ratio(0, 1),
                    committee_normal: ratio(0, 1),
                    committee_no_confidence: ratio(0, 1),
                    update_constitution: ratio(0, 1),
                    hard_fork_initiation: ratio(0, 1),
                    pp_network_group: ratio(0, 1),
                    pp_economic_group: ratio(0, 1),
                    pp_technical_group: ratio(0, 1),
                    pp_governance_group: ratio(0, 1),
                    treasury_withdrawal: ratio(0, 1),
                }
            ),
            zero_key!($era, $blank.clone(), min_committee_size = 0),
            zero_key!($era, $blank.clone(), committee_term_limit = 0),
            zero_key!($era, $blank.clone(), governance_action_validity_period = 0),
            zero_key!($era, $blank.clone(), governance_action_deposit = 0),
            zero_key!($era, $blank.clone(), drep_deposit = 0),
            zero_key!($era, $blank.clone(), drep_inactivity_period = 0),
            zero_key!(
                $era,
                $blank.clone(),
                minfee_refscript_cost_per_byte = ratio(0, 1)
            ),
        ]
    };
}

/// An update of the era named that sets every key the mapper reads, each to a
/// value no other key of the update takes, so a mapper reading the wrong key
/// cannot agree with an expectation written from the key meanings. A key the
/// era adds past the ones u5c has a field for is named by the caller and left
/// unset.
macro_rules! update_of_every_key {
    ($era:ident, $cost_models:expr $(, $era_only:ident)* $(,)?) => {
        pallas_primitives::$era::ProtocolParamUpdate {
            minfee_a: Some(1),
            minfee_b: Some(2),
            max_block_body_size: Some(3),
            max_transaction_size: Some(4),
            max_block_header_size: Some(5),
            key_deposit: Some(6),
            pool_deposit: Some(7),
            maximum_epoch: Some(8),
            desired_number_of_stake_pools: Some(9),
            pool_pledge_influence: Some(ratio(10, 11)),
            expansion_rate: Some(ratio(12, 13)),
            treasury_growth_rate: Some(ratio(14, 15)),
            min_pool_cost: Some(16),
            ada_per_utxo_byte: Some(17),
            cost_models_for_script_languages: Some($cost_models),
            execution_costs: Some(pallas_primitives::$era::ExUnitPrices {
                mem_price: ratio(19, 20),
                step_price: ratio(21, 22),
            }),
            max_tx_ex_units: Some(pallas_primitives::ExUnits { mem: 23, steps: 24 }),
            max_block_ex_units: Some(pallas_primitives::ExUnits { mem: 25, steps: 26 }),
            max_value_size: Some(27),
            collateral_percentage: Some(28),
            max_collateral_inputs: Some(29),
            pool_voting_thresholds: Some(pallas_primitives::$era::PoolVotingThresholds {
                motion_no_confidence: ratio(30, 31),
                committee_normal: ratio(32, 33),
                committee_no_confidence: ratio(34, 35),
                hard_fork_initiation: ratio(36, 37),
                security_voting_threshold: ratio(38, 39),
            }),
            drep_voting_thresholds: Some(pallas_primitives::$era::DRepVotingThresholds {
                motion_no_confidence: ratio(40, 41),
                committee_normal: ratio(42, 43),
                committee_no_confidence: ratio(44, 45),
                update_constitution: ratio(46, 47),
                hard_fork_initiation: ratio(48, 49),
                pp_network_group: ratio(50, 51),
                pp_economic_group: ratio(52, 53),
                pp_technical_group: ratio(54, 55),
                pp_governance_group: ratio(56, 57),
                treasury_withdrawal: ratio(58, 59),
            }),
            min_committee_size: Some(60),
            committee_term_limit: Some(61),
            governance_action_validity_period: Some(62),
            governance_action_deposit: Some(63),
            drep_deposit: Some(64),
            drep_inactivity_period: Some(65),
            minfee_refscript_cost_per_byte: Some(ratio(66, 67)),
            $($era_only: None,)*
        }
    };
}

/// An update setting no key at all, decoded from the empty CBOR map so a key
/// an era adds later needs no edit here. The base a case setting exactly one
/// key is built on.
pub fn conway_update_of_no_key() -> conway::ProtocolParamUpdate {
    minicbor::decode(&[0xa0]).expect("the empty parameter update map must decode")
}

/// Every key the parameter update mapper reads, each set alone in a Conway
/// update to the zero or empty value of the key's own type.
pub fn conway_updates_of_one_zero_key() -> Vec<(&'static str, conway::ProtocolParamUpdate)> {
    let blank = conway_update_of_no_key();

    updates_of_one_zero_key!(
        conway,
        blank,
        conway::CostModels {
            plutus_v1: None,
            plutus_v2: None,
            plutus_v3: None,
            unknown: Default::default(),
        }
    )
}

/// A Conway update that sets every key the era names, each to a value no other
/// key of the update takes.
pub fn conway_update_of_every_key() -> conway::ProtocolParamUpdate {
    update_of_every_key!(
        conway,
        conway::CostModels {
            plutus_v1: Some(vec![181]),
            plutus_v2: Some(vec![182]),
            plutus_v3: Some(vec![183]),
            unknown: Default::default(),
        }
    )
}
