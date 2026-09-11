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

/// Decodes a hex encoded Dijkstra block.
#[cfg(feature = "unstable")]
pub fn dijkstra_block(block_str: &str) -> trv::MultiEraBlock<'_> {
    let cbor: &'static [u8] = Box::leak(hex::decode(block_str).unwrap().into_boxed_slice());
    trv::MultiEraBlock::decode(cbor).unwrap()
}

/// Decodes a hex encoded Dijkstra transaction.
#[cfg(feature = "unstable")]
pub fn dijkstra_tx(tx_str: &str) -> trv::MultiEraTx<'_> {
    let cbor: &'static [u8] = Box::leak(hex::decode(tx_str).unwrap().into_boxed_slice());
    trv::MultiEraTx::decode_for_era(trv::Era::Dijkstra, cbor).unwrap()
}

/// Decodes a hex encoded Dijkstra proposal procedure.
#[cfg(feature = "unstable")]
pub fn dijkstra_proposal(hex_str: &str) -> pallas_primitives::dijkstra::ProposalProcedure {
    let cbor = hex::decode(hex_str.trim()).unwrap();
    pallas_codec::minicbor::decode(&cbor).unwrap()
}

/// A Conway parameter change around an update read from the CBOR map given,
/// so a test reads the bytes a proposal would encode.
pub fn conway_parameter_change(update_cbor: &[u8]) -> conway::GovAction {
    let update = minicbor::decode(update_cbor).expect("a parameter update map must decode");
    conway::GovAction::ParameterChange(None, Box::new(update), None)
}

/// A Dijkstra parameter update read from the CBOR map given.
#[cfg(feature = "unstable")]
pub fn dijkstra_update(update_cbor: &[u8]) -> pallas_primitives::dijkstra::ProtocolParamUpdate {
    minicbor::decode(update_cbor).expect("a parameter update map must decode")
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

/// The DRep key hash that casts the vote in `dijkstra_tx_with_one_vote`.
#[cfg(feature = "unstable")]
pub const VOTING_DREP_KEY_HASH: [u8; 28] = [0x77; 28];

/// The transaction of the governance action that vote is cast on.
#[cfg(feature = "unstable")]
pub const VOTED_ACTION_TX_HASH: [u8; 32] = [0x88; 32];

/// The index of that governance action inside its transaction.
#[cfg(feature = "unstable")]
pub const VOTED_ACTION_INDEX: u32 = 3;

/// The anchor url of that vote.
#[cfg(feature = "unstable")]
pub const VOTE_ANCHOR_URL: &str = "https://example.invalid/vote";

/// The anchor content hash of that vote.
#[cfg(feature = "unstable")]
pub const VOTE_ANCHOR_HASH: [u8; 32] = [0x99; 32];

/// The key hash of the committee member voting in
/// `dijkstra_tx_with_committee_votes`.
#[cfg(feature = "unstable")]
pub const COMMITTEE_VOTER_KEY_HASH: [u8; 28] = [0x6a; 28];

/// The script hash of the committee member voting beside it.
#[cfg(feature = "unstable")]
pub const COMMITTEE_VOTER_SCRIPT_HASH: [u8; 28] = [0x6b; 28];

/// The action the committee key votes no on.
#[cfg(feature = "unstable")]
pub const COMMITTEE_KEY_ACTION_TX_HASH: [u8; 32] = [0x6c; 32];

/// The action the committee script abstains on.
#[cfg(feature = "unstable")]
pub const COMMITTEE_SCRIPT_ACTION_TX_HASH: [u8; 32] = [0x6d; 32];

/// The CBOR index of the Dijkstra voter variant for a committee key.
#[cfg(feature = "unstable")]
const COMMITTEE_KEY_VOTER: u8 = 0;

/// The CBOR index of the Dijkstra voter variant for a committee script.
#[cfg(feature = "unstable")]
const COMMITTEE_SCRIPT_VOTER: u8 = 1;

/// The CBOR index of the Dijkstra voter variant for a DRep key.
#[cfg(feature = "unstable")]
const DREP_KEY_VOTER: u8 = 2;

/// The CBOR index of a no vote.
#[cfg(feature = "unstable")]
const NO_VOTE: u8 = 0;

/// The CBOR index of a yes vote.
#[cfg(feature = "unstable")]
const YES_VOTE: u8 = 1;

/// The CBOR index of an abstain vote.
#[cfg(feature = "unstable")]
const ABSTAIN_VOTE: u8 = 2;

/// Writes a Dijkstra body of one input, no outputs, a fee, and the voting
/// procedures the writer given adds at body key 19.
#[cfg(feature = "unstable")]
fn dijkstra_tx_voting(
    voters: usize,
    write_votes: impl Fn(&mut minicbor::Encoder<Vec<u8>>),
) -> trv::MultiEraTx<'static> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(4).unwrap();

    e.map(4).unwrap();
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

    // voting_procedures is a map from a voter to a map from a governance
    // action id to a voting procedure.
    e.u8(19).unwrap();
    e.map(voters as u64).unwrap();
    write_votes(&mut e);

    // An empty witness set, no auxiliary data, and a valid transaction.
    e.map(0).unwrap();
    e.null().unwrap();
    e.bool(true).unwrap();

    let cbor: &'static [u8] = Box::leak(e.into_writer().into_boxed_slice());
    trv::MultiEraTx::decode_for_era(trv::Era::Dijkstra, cbor).unwrap()
}

/// A Dijkstra transaction whose body has one voting procedure at body key
/// 19: a DRep key voter casting one yes vote on one governance action, with an
/// anchor.
#[cfg(feature = "unstable")]
pub fn dijkstra_tx_with_one_vote() -> trv::MultiEraTx<'static> {
    dijkstra_tx_voting(1, |e| {
        // voter = [2, addr_keyhash], the flat encoding of the DRep key variant.
        e.array(2).unwrap();
        e.u8(DREP_KEY_VOTER).unwrap();
        e.bytes(&VOTING_DREP_KEY_HASH).unwrap();

        e.map(1).unwrap();

        // gov_action_id = [transaction_id, action_index]
        e.array(2).unwrap();
        e.bytes(&VOTED_ACTION_TX_HASH).unwrap();
        e.u32(VOTED_ACTION_INDEX).unwrap();

        // voting_procedure = [vote, anchor], anchor = [url, content_hash]
        e.array(2).unwrap();
        e.u8(YES_VOTE).unwrap();
        e.array(2).unwrap();
        e.str(VOTE_ANCHOR_URL).unwrap();
        e.bytes(&VOTE_ANCHOR_HASH).unwrap();
    })
}

/// A Dijkstra transaction whose body has two voting procedures, a committee
/// key voting no and a committee script abstaining, each on an action of its
/// own and neither with an anchor.
#[cfg(feature = "unstable")]
pub fn dijkstra_tx_with_committee_votes() -> trv::MultiEraTx<'static> {
    dijkstra_tx_voting(2, |e| {
        for (variant, hash, action, vote) in [
            (
                COMMITTEE_KEY_VOTER,
                COMMITTEE_VOTER_KEY_HASH,
                COMMITTEE_KEY_ACTION_TX_HASH,
                NO_VOTE,
            ),
            (
                COMMITTEE_SCRIPT_VOTER,
                COMMITTEE_VOTER_SCRIPT_HASH,
                COMMITTEE_SCRIPT_ACTION_TX_HASH,
                ABSTAIN_VOTE,
            ),
        ] {
            e.array(2).unwrap();
            e.u8(variant).unwrap();
            e.bytes(&hash).unwrap();

            e.map(1).unwrap();

            e.array(2).unwrap();
            e.bytes(&action).unwrap();
            e.u32(0).unwrap();

            e.array(2).unwrap();
            e.u8(vote).unwrap();
            e.null().unwrap();
        }
    })
}

/// The auxiliary PlutusV1 script of `dijkstra_tx_with_aux_plutus_scripts`.
#[cfg(feature = "unstable")]
pub const AUX_PLUTUS_V1: [u8; 3] = [0x01, 0x11, 0x11];

/// Its auxiliary PlutusV2 script.
#[cfg(feature = "unstable")]
pub const AUX_PLUTUS_V2: [u8; 3] = [0x02, 0x22, 0x22];

/// Its auxiliary PlutusV3 script.
#[cfg(feature = "unstable")]
pub const AUX_PLUTUS_V3: [u8; 3] = [0x03, 0x33, 0x33];

/// A Dijkstra transaction whose auxiliary data has one Plutus script of each of
/// the three versions an earlier era's auxiliary type also names, each with
/// bytes no other of the three has.
#[cfg(feature = "unstable")]
pub fn dijkstra_tx_with_aux_plutus_scripts() -> trv::MultiEraTx<'static> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(4).unwrap();

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

    e.map(0).unwrap();

    // Auxiliary data keys 2, 3 and 4 are the V1, V2 and V3 script lists.
    e.tag(Tag::new(259)).unwrap();
    e.map(3).unwrap();
    for (key, script) in [
        (2u8, AUX_PLUTUS_V1.as_slice()),
        (3, AUX_PLUTUS_V2.as_slice()),
        (4, AUX_PLUTUS_V3.as_slice()),
    ] {
        e.u8(key).unwrap();
        e.array(1).unwrap();
        e.bytes(script).unwrap();
    }

    e.bool(true).unwrap();

    let cbor: &'static [u8] = Box::leak(e.into_writer().into_boxed_slice());
    trv::MultiEraTx::decode_for_era(trv::Era::Dijkstra, cbor).unwrap()
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

/// A Dijkstra reference script of the PlutusV4 script bytes given.
#[cfg(feature = "unstable")]
pub fn dijkstra_plutus_v4_script_ref(
    script: &[u8],
) -> pallas_primitives::dijkstra::ScriptRef<'static> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(2).unwrap();
    e.u8(4).unwrap();
    e.bytes(script).unwrap();
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

/// A Dijkstra update setting no key at all.
#[cfg(feature = "unstable")]
pub fn dijkstra_update_of_no_key() -> pallas_primitives::dijkstra::ProtocolParamUpdate {
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

/// The same keys set alone in a Dijkstra update. The keys this era adds past
/// 33 stay unset, since u5c has no field for them.
#[cfg(feature = "unstable")]
pub fn dijkstra_updates_of_one_zero_key() -> Vec<(
    &'static str,
    pallas_primitives::dijkstra::ProtocolParamUpdate,
)> {
    use pallas_primitives::dijkstra;

    let blank = dijkstra_update_of_no_key();

    updates_of_one_zero_key!(
        dijkstra,
        blank,
        dijkstra::CostModels {
            plutus_v1: None,
            plutus_v2: None,
            plutus_v3: None,
            plutus_v4: None,
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

/// A Dijkstra update setting the same keys to the same values, plus the V4
/// cost model only this era names. The keys this era adds past 33 stay unset,
/// since u5c has no field for them.
#[cfg(feature = "unstable")]
pub fn dijkstra_update_of_every_key() -> pallas_primitives::dijkstra::ProtocolParamUpdate {
    use pallas_primitives::dijkstra;

    update_of_every_key!(
        dijkstra,
        dijkstra::CostModels {
            plutus_v1: Some(vec![181]),
            plutus_v2: Some(vec![182]),
            plutus_v3: Some(vec![183]),
            plutus_v4: Some(vec![184]),
            unknown: Default::default(),
        },
        max_ref_script_size_per_block,
        max_ref_script_size_per_tx,
        ref_script_cost_stride,
        ref_script_cost_multiplier,
        max_pledge_leverage,
        min_pool_margin,
        leios_announcement_period_length,
        leios_vote_period_length,
        leios_diffusion_period_length,
        leios_committee_size,
        leios_quorum_stake_threshold,
        max_endorser_block_references_size,
        max_endorser_block_txs_size,
        max_endorser_block_execution_units,
        max_ref_script_size_per_endorser_block,
    )
}
