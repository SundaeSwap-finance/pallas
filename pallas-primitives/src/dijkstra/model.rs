//! Ledger primitives and cbor codec for the Dijkstra era
//!
//! Handcrafted, idiomatic rust artifacts based on the [Dijkstra CDDL](https://github.com/IntersectMBO/cardano-ledger/blob/9df9f98cce86c5f2195142b2c02dd9b39dd9dc7c/eras/dijkstra/impl/cddl/data/dijkstra.cddl) file in the IntersectMBO repo, vendored beside this one as `defs.cddl`.

use serde::{Deserialize, Serialize};

use pallas_codec::minicbor::{self, Decode, Encode};
use pallas_codec::utils::{CborWrap, decode_array};

pub use pallas_codec::codec_by_datatype;

pub use crate::{
    AddrKeyhash, AssetName, Bytes, Coin, CostModel, DnsName, Epoch, GenesisDelegateHash,
    Genesishash, Hash, IPv4, IPv6, KeepRaw, MaybeIndefArray, Metadata, Metadatum, MetadatumLabel,
    NetworkId, NonZeroInt, Nonce, NonceVariant, Nullable, PlutusScript, PolicyId, PoolKeyhash,
    PoolMetadata, PoolMetadataHash, Port, RationalNumber, Relay, RewardAccount, ScriptHash,
    StakeCredential, VrfCert, VrfKeyhash, plutus_data::*,
};

use crate::{BTreeMap, KeyValuePairs};

use crate::babbage;

/// Which arm of `set<a0> = #6.258([* a0])/ [* a0]` (`defs.cddl`) a value was read from.
#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default, Serialize, Deserialize, Hash,
)]
pub enum SetArm {
    #[default]
    Tagged,
    Bare,
}

/// Compared here so a zero minimum is a value rather than a constant comparison.
fn at_least(len: usize, minimum: usize, rule: &str) -> Result<(), minicbor::decode::Error> {
    if len < minimum {
        return Err(minicbor::decode::Error::message(format!(
            "too few elements for {rule}: {len} of at least {minimum}"
        )));
    }

    Ok(())
}

/// An element type of a decoded set, compared by the identity the ledger gives it.
pub trait SetElement {
    /// Whether the ledger counts the two values as one element.
    fn same_element(&self, other: &Self) -> bool;
}

/// Implements [`SetElement`] by value equality for each type listed.
macro_rules! set_element_by_value {
    ($($element:ty),+ $(,)?) => {
        $(
            impl SetElement for $element {
                fn same_element(&self, other: &Self) -> bool {
                    self == other
                }
            }
        )+
    };
}

set_element_by_value!(
    TransactionInput,
    Certificate,
    AddrKeyhash,
    StakeCredential,
    ProposalProcedure,
    VKeyWitness,
);

impl<const VERSION: usize> SetElement for PlutusScript<VERSION> {
    fn same_element(&self, other: &Self) -> bool {
        self == other
    }
}

/// The ledger keys a bootstrap witness by the hash of its key, chain code and attributes.
impl SetElement for BootstrapWitness {
    fn same_element(&self, other: &Self) -> bool {
        self.public_key == other.public_key
            && self.chain_code == other.chain_code
            && self.attributes == other.attributes
    }
}

/// The ledger keys a script or a datum in a witness set by the hash of the bytes it was read from.
impl<T> SetElement for KeepRaw<'_, T> {
    fn same_element(&self, other: &Self) -> bool {
        self.raw_cbor() == other.raw_cbor()
    }
}

/// The ledger keys a sub transaction by its id, the hash of the body bytes it was read from.
impl SetElement for SubTransaction<'_> {
    fn same_element(&self, other: &Self) -> bool {
        self.sub_transaction_body.raw_cbor() == other.sub_transaction_body.raw_cbor()
    }
}

/// Refuses the first element that is the same element as one before it.
fn no_repeated_element<T: SetElement>(
    items: &[T],
    rule: &str,
) -> Result<(), minicbor::decode::Error> {
    for (position, item) in items.iter().enumerate() {
        if items[..position].iter().any(|seen| seen.same_element(item)) {
            return Err(minicbor::decode::Error::message(format!(
                "a repeated element in {rule} at position {position}"
            )));
        }
    }

    Ok(())
}

macro_rules! tag_preserving_set {
    ($name:ident, $rule:literal, $minimum:expr) => {
        impl<T> $name<T> {
            /// The arm the bytes carried, or [`SetArm::Tagged`] if this value was built.
            pub fn arm(&self) -> SetArm {
                self.arm
            }

            pub fn with_arm(self, arm: SetArm) -> Self {
                Self { arm, ..self }
            }

            pub fn into_vec(self) -> Vec<T> {
                self.items
            }
        }

        impl<T> std::ops::Deref for $name<T> {
            type Target = Vec<T>;

            fn deref(&self) -> &Self::Target {
                &self.items
            }
        }

        impl<'a, T> IntoIterator for &'a $name<T> {
            type Item = &'a T;
            type IntoIter = std::slice::Iter<'a, T>;

            fn into_iter(self) -> Self::IntoIter {
                self.items.iter()
            }
        }

        impl<T> From<$name<KeepRaw<'_, T>>> for $name<T> {
            fn from(value: $name<KeepRaw<'_, T>>) -> Self {
                Self {
                    arm: value.arm,
                    items: value.items.into_iter().map(|x| x.unwrap()).collect(),
                }
            }
        }

        impl<'b, C, T> minicbor::decode::Decode<'b, C> for $name<T>
        where
            T: Decode<'b, C> + SetElement,
        {
            fn decode(
                d: &mut minicbor::Decoder<'b>,
                ctx: &mut C,
            ) -> Result<Self, minicbor::decode::Error> {
                let arm = if d.datatype()? == minicbor::data::Type::Tag {
                    let found = d.tag()?;
                    if found != minicbor::data::Tag::new(258) {
                        return Err(minicbor::decode::Error::message(format!(
                            concat!("unrecognised tag on ", $rule, ": {:?}"),
                            found
                        )));
                    }
                    SetArm::Tagged
                } else {
                    SetArm::Bare
                };

                let items: Vec<T> = d.decode_with(ctx)?;
                at_least(items.len(), $minimum, $rule)?;
                no_repeated_element(&items, $rule)?;

                Ok(Self { arm, items })
            }
        }

        impl<C, T> minicbor::encode::Encode<C> for $name<T>
        where
            T: Encode<C>,
        {
            fn encode<W: minicbor::encode::Write>(
                &self,
                e: &mut minicbor::Encoder<W>,
                ctx: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                if self.arm == SetArm::Tagged {
                    e.tag(minicbor::data::Tag::new(258))?;
                }
                e.encode_with(&self.items, ctx)?;

                Ok(())
            }
        }
    };
}

/// `set<a0> = #6.258([* a0])/ [* a0]` (`defs.cddl`). Both arms are legal here,
/// so the arm is kept: a transaction id is the hash of the body bytes.
#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Set<T> {
    #[serde(skip)]
    arm: SetArm,
    items: Vec<T>,
}

impl<T> From<Vec<T>> for Set<T> {
    fn from(items: Vec<T>) -> Self {
        Self {
            arm: SetArm::default(),
            items,
        }
    }
}

tag_preserving_set!(Set, "a set", 0);

/// `nonempty_set<a0> = #6.258([+ a0])/ [+ a0]` (`defs.cddl`). Carries its arm like [`Set`].
#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NonEmptySet<T> {
    #[serde(skip)]
    arm: SetArm,
    items: Vec<T>,
}

impl<T> NonEmptySet<T> {
    pub fn from_vec(items: Vec<T>) -> Option<Self> {
        if items.is_empty() {
            None
        } else {
            Some(Self {
                arm: SetArm::default(),
                items,
            })
        }
    }
}

impl<T> TryFrom<Vec<T>> for NonEmptySet<T> {
    type Error = Vec<T>;

    fn try_from(items: Vec<T>) -> Result<Self, Self::Error> {
        if items.is_empty() {
            Err(items)
        } else {
            Ok(Self {
                arm: SetArm::default(),
                items,
            })
        }
    }
}

tag_preserving_set!(NonEmptySet, "a nonempty set", 1);

/// Reads `#6.30([n, d])` in either length form.
fn decode_fraction<C>(
    d: &mut minicbor::Decoder<'_>,
    _ctx: &mut C,
) -> Result<RationalNumber, minicbor::decode::Error> {
    let tag = d.tag()?.as_u64();
    if tag != 30 {
        return Err(minicbor::decode::Error::message(format!(
            "a fraction is tagged 30, found tag {tag}"
        )));
    }

    let mut numbers = Vec::with_capacity(2);
    for number in d.array_iter::<u64>()? {
        numbers.push(number?);
        if numbers.len() > 2 {
            break;
        }
    }

    match numbers[..] {
        [numerator, denominator] => Ok(RationalNumber {
            numerator,
            denominator,
        }),
        _ => Err(minicbor::decode::Error::message(
            "a fraction holds exactly two numbers",
        )),
    }
}

/// Implements the conversions and codec of a type that holds the values of `$shared` that `$holds` admits.
macro_rules! bounded {
    (@read $d:ident, $ctx:ident) => {
        $d.decode_with($ctx)?
    };
    (@read $d:ident, $ctx:ident, $by:path) => {
        $by($d, $ctx)?
    };
    ($name:ident, $shared:ty, $holds:expr $(, by $by:path)?) => {
        impl TryFrom<$shared> for $name {
            type Error = $shared;

            fn try_from(value: $shared) -> Result<Self, Self::Error> {
                let holds: fn(&$shared) -> bool = $holds;
                if holds(&value) {
                    Ok(Self(value))
                } else {
                    Err(value)
                }
            }
        }

        impl From<$name> for $shared {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl std::ops::Deref for $name {
            type Target = $shared;

            fn deref(&self) -> &$shared {
                &self.0
            }
        }

        impl<'b, C> minicbor::Decode<'b, C> for $name {
            fn decode(
                d: &mut minicbor::Decoder<'b>,
                ctx: &mut C,
            ) -> Result<Self, minicbor::decode::Error> {
                let value: $shared = bounded!(@read d, ctx $(, $by)?);
                Self::try_from(value).map_err(|value| {
                    minicbor::decode::Error::message(format!(
                        "decoding {value:?} as {}",
                        stringify!($name)
                    ))
                })
            }
        }

        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                e: &mut minicbor::Encoder<W>,
                ctx: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                e.encode_with(&self.0, ctx)?;
                Ok(())
            }
        }
    };
}

/// `unit_interval = #6.30([uint, uint])` (`defs.cddl`), a fraction from zero to one.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(transparent)]
pub struct UnitInterval(RationalNumber);

bounded!(
    UnitInterval,
    RationalNumber,
    |fraction| fraction.denominator != 0 && fraction.numerator <= fraction.denominator,
    by decode_fraction
);

/// `nonnegative_interval = #6.30([uint, positive_int])` (`defs.cddl`), a fraction of zero or more.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(transparent)]
pub struct NonNegativeInterval(RationalNumber);

bounded!(
    NonNegativeInterval,
    RationalNumber,
    |fraction| fraction.denominator != 0,
    by decode_fraction
);

/// `positive_interval = #6.30([positive_int, positive_int])` (`defs.cddl`), a fraction of at least one in ten to the nineteenth.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(transparent)]
pub struct PositiveInterval(RationalNumber);

bounded!(
    PositiveInterval,
    RationalNumber,
    |fraction| fraction.denominator != 0
        && u128::from(fraction.numerator) * 10u128.pow(19) >= u128::from(fraction.denominator),
    by decode_fraction
);

/// The largest count `ex_units` admits, `max_int64` (`defs.cddl`).
const MAX_INT64: u64 = i64::MAX.unsigned_abs();

/// `transaction_input` (`defs.cddl`), whose index is at most two bytes.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, std::hash::Hash)]
#[serde(transparent)]
pub struct TransactionInput(crate::TransactionInput);

bounded!(TransactionInput, crate::TransactionInput, |input| {
    input.index <= u64::from(u16::MAX)
});

impl TransactionInput {
    /// The input that spends the output at an index of a transaction.
    pub fn new(transaction_id: Hash<32>, index: u16) -> Self {
        Self(crate::TransactionInput {
            transaction_id,
            index: u64::from(index),
        })
    }
}

/// `positive_coin` (`defs.cddl`), a coin of at least one.
#[derive(
    Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, std::hash::Hash,
)]
#[serde(transparent)]
pub struct PositiveCoin(crate::PositiveCoin);

bounded!(PositiveCoin, crate::PositiveCoin, |coin| u64::from(coin)
    != 0);

/// True when every asset quantity is at least one.
fn every_quantity_positive<A: Copy + Into<u64>>(
    assets: &BTreeMap<PolicyId, BTreeMap<AssetName, A>>,
) -> bool {
    assets
        .values()
        .all(|names| names.values().all(|quantity| (*quantity).into() != 0))
}

/// `value` (`defs.cddl`), whose every asset quantity is a `positive_coin`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(transparent)]
pub struct Value(crate::conway::Value);

bounded!(Value, crate::conway::Value, |value| match value {
    crate::conway::Value::Coin(_) => true,
    crate::conway::Value::Multiasset(_, assets) => every_quantity_positive(assets),
});

/// `alonzo_transaction_output` (`defs.cddl`), whose every asset quantity is a `positive_coin`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(transparent)]
pub struct LegacyTransactionOutput(crate::alonzo::TransactionOutput);

bounded!(
    LegacyTransactionOutput,
    crate::alonzo::TransactionOutput,
    |output| match &output.amount {
        crate::alonzo::Value::Coin(_) => true,
        crate::alonzo::Value::Multiasset(_, assets) => every_quantity_positive(assets),
    }
);

/// `gov_action_id` (`defs.cddl`), whose index is at most two bytes.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[serde(transparent)]
pub struct GovActionId(crate::conway::GovActionId);

bounded!(GovActionId, crate::conway::GovActionId, action_index_fits);

impl GovActionId {
    /// The id of the proposal at an index of a transaction.
    pub fn new(transaction_id: Hash<32>, action_index: u16) -> Self {
        Self(crate::conway::GovActionId {
            transaction_id,
            action_index: u32::from(action_index),
        })
    }
}

/// True when the index of the action is at most two bytes.
fn action_index_fits(id: &crate::conway::GovActionId) -> bool {
    id.action_index <= u32::from(u16::MAX)
}

/// `voting_procedures` (`defs.cddl`), whose every `gov_action_id` index is at most two bytes.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(transparent)]
pub struct VotingProcedures(crate::conway::VotingProcedures);

bounded!(
    VotingProcedures,
    crate::conway::VotingProcedures,
    |procedures| {
        procedures
            .values()
            .all(|votes| votes.keys().all(action_index_fits))
    }
);

/// The relays of `pool_params` (`defs.cddl`), whose every `port` is at most two bytes.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(transparent)]
pub struct Relays(Vec<Relay>);

bounded!(Relays, Vec<Relay>, |relays| relays.iter().all(
    |relay| match relay {
        Relay::SingleHostAddr(port, ..) | Relay::SingleHostName(port, ..) => {
            port.is_none_or(|port| port <= u32::from(u16::MAX))
        }
        Relay::MultiHostName(_) => true,
    }
));

/// `protocol_version` (`defs.cddl`), a `major_protocol_version` and a minor version of at most four bytes.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
#[serde(transparent)]
pub struct ProtocolVersion(crate::ProtocolVersion);

bounded!(
    ProtocolVersion,
    crate::ProtocolVersion,
    |&(major, minor)| major <= 13 && minor <= u64::from(u32::MAX),
    by crate::protocol_version::decode
);

/// `ex_units` (`defs.cddl`), whose memory and steps are each at most `max_int64`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
#[serde(transparent)]
pub struct ExUnits(crate::ExUnits);

bounded!(ExUnits, crate::ExUnits, |units| {
    units.mem <= MAX_INT64 && units.steps <= MAX_INT64
});

pub use crate::babbage::OperationalCert;

/// `header_version_info = [highest_supported_major_version : uint .size 4, self_reported_software_tag : uint .size 4]` (`defs.cddl`).
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct HeaderVersionInfo {
    #[n(0)]
    pub highest_supported_major_version: u32,

    #[n(1)]
    pub self_reported_software_tag: u32,
}

pub use crate::babbage::HeaderBody as PraosHeaderBody;

/// `header_body` (`defs.cddl`) has `header_version_info` where Conway's has `protocol_version`, and appends `block_body_contains_leios_cert` and `eb_references_announcement`.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct LeiosHeaderBody {
    #[n(0)]
    pub block_number: u64,

    #[n(1)]
    pub slot: u64,

    #[n(2)]
    pub prev_hash: Option<Hash<32>>,

    #[n(3)]
    pub issuer_vkey: Bytes,

    #[n(4)]
    pub vrf_vkey: Bytes,

    #[n(5)]
    pub vrf_result: VrfCert,

    #[n(6)]
    pub block_body_size: u64,

    #[n(7)]
    pub block_body_hash: Hash<32>,

    #[n(8)]
    pub operational_cert: OperationalCert,

    #[n(9)]
    pub header_version_info: HeaderVersionInfo,

    // -- NEW IN DIJKSTRA
    #[n(10)]
    pub block_body_contains_leios_cert: bool,

    #[n(11)]
    pub eb_announcement: Nullable<EbAnnouncement>,
}

impl LeiosHeaderBody {
    pub fn leader_vrf_output(&self) -> Vec<u8> {
        babbage::derive_tagged_vrf_output(&self.vrf_result.0, babbage::VrfDerivation::Leader)
    }

    pub fn nonce_vrf_output(&self) -> Vec<u8> {
        babbage::derive_tagged_vrf_output(&self.vrf_result.0, babbage::VrfDerivation::Nonce)
    }
}

/// A header body in the Praos form of ten fields or the Leios form of twelve.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum HeaderBody {
    Praos(PraosHeaderBody),
    Leios(LeiosHeaderBody),
}

/// The number of fields of the Praos form.
const PRAOS_HEADER_BODY_FIELDS: u64 = 10;

/// The number of elements of the array at the decoder's position, in either length form.
fn array_len(d: &mut minicbor::Decoder<'_>) -> Result<u64, minicbor::decode::Error> {
    let mut probe = d.probe();
    match probe.array()? {
        Some(len) => Ok(len),
        None => {
            let mut len = 0;
            while probe.datatype()? != minicbor::data::Type::Break {
                probe.skip()?;
                len += 1;
            }
            Ok(len)
        }
    }
}

impl<'b, C> minicbor::Decode<'b, C> for HeaderBody {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        if array_len(d)? == PRAOS_HEADER_BODY_FIELDS {
            Ok(HeaderBody::Praos(d.decode_with(ctx)?))
        } else {
            Ok(HeaderBody::Leios(d.decode_with(ctx)?))
        }
    }
}

impl<C> minicbor::Encode<C> for HeaderBody {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            HeaderBody::Praos(x) => e.encode_with(x, ctx)?,
            HeaderBody::Leios(x) => e.encode_with(x, ctx)?,
        };
        Ok(())
    }
}

impl HeaderBody {
    pub fn block_number(&self) -> u64 {
        match self {
            HeaderBody::Praos(x) => x.block_number,
            HeaderBody::Leios(x) => x.block_number,
        }
    }

    pub fn slot(&self) -> u64 {
        match self {
            HeaderBody::Praos(x) => x.slot,
            HeaderBody::Leios(x) => x.slot,
        }
    }

    pub fn prev_hash(&self) -> Option<Hash<32>> {
        match self {
            HeaderBody::Praos(x) => x.prev_hash,
            HeaderBody::Leios(x) => x.prev_hash,
        }
    }

    pub fn issuer_vkey(&self) -> &Bytes {
        match self {
            HeaderBody::Praos(x) => &x.issuer_vkey,
            HeaderBody::Leios(x) => &x.issuer_vkey,
        }
    }

    pub fn vrf_vkey(&self) -> &Bytes {
        match self {
            HeaderBody::Praos(x) => &x.vrf_vkey,
            HeaderBody::Leios(x) => &x.vrf_vkey,
        }
    }

    pub fn block_body_size(&self) -> u64 {
        match self {
            HeaderBody::Praos(x) => x.block_body_size,
            HeaderBody::Leios(x) => x.block_body_size,
        }
    }

    pub fn block_body_hash(&self) -> Hash<32> {
        match self {
            HeaderBody::Praos(x) => x.block_body_hash,
            HeaderBody::Leios(x) => x.block_body_hash,
        }
    }

    pub fn leader_vrf_output(&self) -> Vec<u8> {
        match self {
            HeaderBody::Praos(x) => x.leader_vrf_output(),
            HeaderBody::Leios(x) => x.leader_vrf_output(),
        }
    }

    pub fn nonce_vrf_output(&self) -> Vec<u8> {
        match self {
            HeaderBody::Praos(x) => x.nonce_vrf_output(),
            HeaderBody::Leios(x) => x.nonce_vrf_output(),
        }
    }
}

/// `header = [header_body, body_signature]` (`defs.cddl`).
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct Header {
    #[n(0)]
    pub header_body: HeaderBody,

    #[n(1)]
    pub body_signature: Bytes,
}

pub use crate::conway::Multiasset;

pub use crate::conway::Mint;

pub use crate::conway::Withdrawals;

pub use crate::conway::DRep;

pub use crate::conway::DRepCredential;

pub use crate::conway::CommitteeColdCredential;

pub use crate::conway::CommitteeHotCredential;

pub use crate::conway::Vote;

pub use crate::conway::VotingProcedure;

pub use crate::conway::Constitution;

pub use crate::conway::Voter;

pub use crate::conway::Anchor;

/// `pool_voting_thresholds` (`defs.cddl`).
#[derive(Encode, Decode, Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct PoolVotingThresholds {
    #[n(0)]
    pub motion_no_confidence: UnitInterval,
    #[n(1)]
    pub committee_normal: UnitInterval,
    #[n(2)]
    pub committee_no_confidence: UnitInterval,
    #[n(3)]
    pub hard_fork_initiation: UnitInterval,
    #[n(4)]
    pub security_voting_threshold: UnitInterval,
}

impl From<PoolVotingThresholds> for crate::conway::PoolVotingThresholds {
    fn from(value: PoolVotingThresholds) -> Self {
        Self {
            motion_no_confidence: value.motion_no_confidence.into(),
            committee_normal: value.committee_normal.into(),
            committee_no_confidence: value.committee_no_confidence.into(),
            hard_fork_initiation: value.hard_fork_initiation.into(),
            security_voting_threshold: value.security_voting_threshold.into(),
        }
    }
}

/// `drep_voting_thresholds` (`defs.cddl`).
#[derive(Encode, Decode, Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct DRepVotingThresholds {
    #[n(0)]
    pub motion_no_confidence: UnitInterval,
    #[n(1)]
    pub committee_normal: UnitInterval,
    #[n(2)]
    pub committee_no_confidence: UnitInterval,
    #[n(3)]
    pub update_constitution: UnitInterval,
    #[n(4)]
    pub hard_fork_initiation: UnitInterval,
    #[n(5)]
    pub pp_network_group: UnitInterval,
    #[n(6)]
    pub pp_economic_group: UnitInterval,
    #[n(7)]
    pub pp_technical_group: UnitInterval,
    #[n(8)]
    pub pp_governance_group: UnitInterval,
    #[n(9)]
    pub treasury_withdrawal: UnitInterval,
}

impl From<DRepVotingThresholds> for crate::conway::DRepVotingThresholds {
    fn from(value: DRepVotingThresholds) -> Self {
        Self {
            motion_no_confidence: value.motion_no_confidence.into(),
            committee_normal: value.committee_normal.into(),
            committee_no_confidence: value.committee_no_confidence.into(),
            update_constitution: value.update_constitution.into(),
            hard_fork_initiation: value.hard_fork_initiation.into(),
            pp_network_group: value.pp_network_group.into(),
            pp_economic_group: value.pp_economic_group.into(),
            pp_technical_group: value.pp_technical_group.into(),
            pp_governance_group: value.pp_governance_group.into(),
            treasury_withdrawal: value.treasury_withdrawal.into(),
        }
    }
}

/// `ex_unit_prices` (`defs.cddl`).
#[derive(Encode, Decode, Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct ExUnitPrices {
    #[n(0)]
    pub mem_price: NonNegativeInterval,
    #[n(1)]
    pub step_price: NonNegativeInterval,
}

impl From<ExUnitPrices> for crate::conway::ExUnitPrices {
    fn from(value: ExUnitPrices) -> Self {
        Self {
            mem_price: value.mem_price.into(),
            step_price: value.step_price.into(),
        }
    }
}

pub use crate::conway::VKeyWitness;

pub use crate::conway::BootstrapWitness;

pub use crate::conway::DatumHash;

pub use crate::conway::DatumOption;

/// `eb_references_announcement = [eb_hash : hash32, eb_size : uint .size 4]` (`defs.cddl`).
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct EbAnnouncement {
    #[n(0)]
    pub eb_hash: Hash<32>,

    #[n(1)]
    pub eb_size: u32,
}

/// `endorser_block = { + base.hash => base.word32 }`
/// (leios-fetch `messages.cddl`), each key the blake2b-256 of a transaction's
/// `block_transaction` encoding and each value the size of that encoding.
pub type EndorserBlock = KeyValuePairs<Hash<32>, u32>;

/// `bls_key = [bls_pubkey : bytes .size 96, bls_possession_proof : bytes .size 48]` (`defs.cddl`).
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct BlsKey {
    #[n(0)]
    pub bls_pubkey: Bytes,

    #[n(1)]
    pub bls_possession_proof: Bytes,
}

/// `leios_signature = bytes .size 48` (`defs.cddl`).
pub type LeiosSignature = Bytes;

/// `leios_certificate = [signers : bytes .size (0 .. 8192), signature : leios_signature]` (`defs.cddl`).
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct LeiosCertificate {
    /// Bitfield naming the signers.
    #[n(0)]
    pub signers: Bytes,

    #[n(1)]
    pub signature: LeiosSignature,
}

/// `peras_certificate = bytes` (`defs.cddl`).
pub type PerasCertificate = Bytes;

/// `certificate` (`defs.cddl`) drops Conway's `account_registration_cert` (0)
/// and `account_unregistration_cert` (1), and `pool_params` gains an optional
/// `bls_key` at position 3. The slot is absent, `nil` or populated, and all
/// three re-encode differently, which is why it is an optional nullable.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum Certificate {
    StakeDelegation(StakeCredential, PoolKeyhash),
    PoolRegistration {
        operator: PoolKeyhash,
        vrf_keyhash: VrfKeyhash,
        bls_key: Option<Nullable<BlsKey>>,
        pledge: Coin,
        cost: Coin,
        margin: UnitInterval,
        reward_account: RewardAccount,
        pool_owners: Set<AddrKeyhash>,
        relays: Relays,
        pool_metadata: Option<PoolMetadata>,
    },
    PoolRetirement(PoolKeyhash, Epoch),
    Reg(StakeCredential, Coin),
    UnReg(StakeCredential, Coin),
    VoteDeleg(StakeCredential, DRep),
    StakeVoteDeleg(StakeCredential, PoolKeyhash, DRep),
    StakeRegDeleg(StakeCredential, PoolKeyhash, Coin),
    VoteRegDeleg(StakeCredential, DRep, Coin),
    StakeVoteRegDeleg(StakeCredential, PoolKeyhash, DRep, Coin),
    AuthCommitteeHot(CommitteeColdCredential, CommitteeHotCredential),
    ResignCommitteeCold(CommitteeColdCredential, Option<Anchor>),
    RegDRepCert(DRepCredential, Coin, Option<Anchor>),
    UnRegDRepCert(DRepCredential, Coin),
    UpdateDRepCert(DRepCredential, Option<Anchor>),
}

impl<'b, C> minicbor::Decode<'b, C> for Certificate {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        decode_array(d, |a| {
            let variant: u16 = a.decode_with(ctx)?;

            match variant {
                2 => Ok(Certificate::StakeDelegation(
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                )),
                3 => {
                    let operator = a.decode_with(ctx)?;
                    let vrf_keyhash = a.decode_with(ctx)?;

                    // `pledge` is a coin, so a uint in this slot means the optional
                    // `bls_key` was omitted, and an array or a null means it was supplied.
                    let bls_key = match a.datatype()? {
                        minicbor::data::Type::Array | minicbor::data::Type::ArrayIndef => {
                            Some(Nullable::Some(a.decode_with(ctx)?))
                        }
                        minicbor::data::Type::Null => Some(a.decode_with(ctx)?),
                        _ => None,
                    };

                    Ok(Certificate::PoolRegistration {
                        operator,
                        vrf_keyhash,
                        bls_key,
                        pledge: a.decode_with(ctx)?,
                        cost: a.decode_with(ctx)?,
                        margin: a.decode_with(ctx)?,
                        reward_account: a.decode_with(ctx)?,
                        pool_owners: a.decode_with(ctx)?,
                        relays: a.decode_with(ctx)?,
                        pool_metadata: a.decode_with(ctx)?,
                    })
                }
                4 => Ok(Certificate::PoolRetirement(
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                )),
                7 => Ok(Certificate::Reg(a.decode_with(ctx)?, a.decode_with(ctx)?)),
                8 => Ok(Certificate::UnReg(a.decode_with(ctx)?, a.decode_with(ctx)?)),
                9 => Ok(Certificate::VoteDeleg(
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                )),
                10 => Ok(Certificate::StakeVoteDeleg(
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                )),
                11 => Ok(Certificate::StakeRegDeleg(
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                )),
                12 => Ok(Certificate::VoteRegDeleg(
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                )),
                13 => Ok(Certificate::StakeVoteRegDeleg(
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                )),
                14 => Ok(Certificate::AuthCommitteeHot(
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                )),
                15 => Ok(Certificate::ResignCommitteeCold(
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                )),
                16 => Ok(Certificate::RegDRepCert(
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                )),
                17 => Ok(Certificate::UnRegDRepCert(
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                )),
                18 => Ok(Certificate::UpdateDRepCert(
                    a.decode_with(ctx)?,
                    a.decode_with(ctx)?,
                )),
                0 | 1 => Err(minicbor::decode::Error::message(format!(
                    "certificate variant {variant} was removed in Dijkstra"
                ))),
                _ => Err(minicbor::decode::Error::message(format!(
                    "unknown certificate variant {variant}"
                ))),
            }
        })
    }
}

impl<C> minicbor::Encode<C> for Certificate {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Certificate::StakeDelegation(a, b) => {
                e.array(3)?;
                e.encode_with(2u16, ctx)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            Certificate::PoolRegistration {
                operator,
                vrf_keyhash,
                bls_key,
                pledge,
                cost,
                margin,
                reward_account,
                pool_owners,
                relays,
                pool_metadata,
            } => {
                e.array(if bls_key.is_some() { 11 } else { 10 })?;
                e.encode_with(3u16, ctx)?;
                e.encode_with(operator, ctx)?;
                e.encode_with(vrf_keyhash, ctx)?;
                match bls_key {
                    Some(Nullable::Some(k)) => {
                        e.encode_with(k, ctx)?;
                    }
                    Some(_) => {
                        e.null()?;
                    }
                    None => {}
                }
                e.encode_with(pledge, ctx)?;
                e.encode_with(cost, ctx)?;
                e.encode_with(margin, ctx)?;
                e.encode_with(reward_account, ctx)?;
                e.encode_with(pool_owners, ctx)?;
                e.encode_with(relays, ctx)?;
                e.encode_with(pool_metadata, ctx)?;
            }
            Certificate::PoolRetirement(a, b) => {
                e.array(3)?;
                e.encode_with(4u16, ctx)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            Certificate::Reg(a, b) => {
                e.array(3)?;
                e.encode_with(7u16, ctx)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            Certificate::UnReg(a, b) => {
                e.array(3)?;
                e.encode_with(8u16, ctx)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            Certificate::VoteDeleg(a, b) => {
                e.array(3)?;
                e.encode_with(9u16, ctx)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            Certificate::StakeVoteDeleg(a, b, c) => {
                e.array(4)?;
                e.encode_with(10u16, ctx)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
                e.encode_with(c, ctx)?;
            }
            Certificate::StakeRegDeleg(a, b, c) => {
                e.array(4)?;
                e.encode_with(11u16, ctx)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
                e.encode_with(c, ctx)?;
            }
            Certificate::VoteRegDeleg(a, b, c) => {
                e.array(4)?;
                e.encode_with(12u16, ctx)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
                e.encode_with(c, ctx)?;
            }
            Certificate::StakeVoteRegDeleg(a, b, c, dd) => {
                e.array(5)?;
                e.encode_with(13u16, ctx)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
                e.encode_with(c, ctx)?;
                e.encode_with(dd, ctx)?;
            }
            Certificate::AuthCommitteeHot(a, b) => {
                e.array(3)?;
                e.encode_with(14u16, ctx)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            Certificate::ResignCommitteeCold(a, b) => {
                e.array(3)?;
                e.encode_with(15u16, ctx)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            Certificate::RegDRepCert(a, b, c) => {
                e.array(4)?;
                e.encode_with(16u16, ctx)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
                e.encode_with(c, ctx)?;
            }
            Certificate::UnRegDRepCert(a, b) => {
                e.array(3)?;
                e.encode_with(17u16, ctx)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            Certificate::UpdateDRepCert(a, b) => {
                e.array(3)?;
                e.encode_with(18u16, ctx)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
        }

        Ok(())
    }
}

/// `language = 0 .. 3` (`defs.cddl`), widened from Conway's `0 .. 2`.
#[derive(
    Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, PartialOrd, Ord, Hash,
)]
#[cbor(index_only)]
pub enum Language {
    #[n(0)]
    PlutusV1,

    #[n(1)]
    PlutusV2,

    #[n(2)]
    PlutusV3,

    #[n(3)]
    PlutusV4,
}

/// `cost_models` (`defs.cddl`) names key 3 for PlutusV4, leaving Conway's wildcard at `4 .. 255`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct CostModels {
    pub plutus_v1: Option<CostModel>,

    pub plutus_v2: Option<CostModel>,

    pub plutus_v3: Option<CostModel>,

    pub plutus_v4: Option<CostModel>,

    /// Cost models under the keys the CDDL wildcard permits, 4 to 255.
    pub unknown: BTreeMap<u8, CostModel>,
}

impl CostModels {
    /// Every key to write, ascending, a named field before the wildcard.
    fn entries(&self) -> BTreeMap<u8, &CostModel> {
        let mut entries: BTreeMap<u8, &CostModel> =
            self.unknown.iter().map(|(k, v)| (*k, v)).collect();

        let named = [
            (0u8, &self.plutus_v1),
            (1, &self.plutus_v2),
            (2, &self.plutus_v3),
            (3, &self.plutus_v4),
        ];

        for (key, model) in named {
            if let Some(model) = model {
                entries.insert(key, model);
            }
        }

        entries
    }
}

impl<C> minicbor::Encode<C> for CostModels {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let entries = self.entries();

        e.map(entries.len() as u64)?;
        for (key, model) in entries {
            e.u8(key)?;
            e.encode_with(model, ctx)?;
        }

        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for CostModels {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let models: BTreeMap<u8, CostModel> = d.decode_with(ctx)?;

        let mut plutus_v1 = None;
        let mut plutus_v2 = None;
        let mut plutus_v3 = None;
        let mut plutus_v4 = None;
        let mut unknown: Vec<(u8, CostModel)> = Vec::new();

        for (k, v) in models.iter() {
            match k {
                0 => plutus_v1 = Some(v.clone()),
                1 => plutus_v2 = Some(v.clone()),
                2 => plutus_v3 = Some(v.clone()),
                3 => plutus_v4 = Some(v.clone()),
                _ => unknown.push((*k, v.clone())),
            }
        }

        Ok(Self {
            plutus_v1,
            plutus_v2,
            plutus_v3,
            plutus_v4,
            unknown: unknown.into_iter().collect(),
        })
    }
}

/// Decodes a map value written `x/ nil`, reading a nil as `Some(Nullable::Null)`.
fn decode_nullable_value<'b, Ctx, T>(
    d: &mut minicbor::Decoder<'b>,
    ctx: &mut Ctx,
) -> Result<Option<Nullable<T>>, minicbor::decode::Error>
where
    T: Decode<'b, Ctx> + Clone,
{
    Nullable::decode(d, ctx).map(Some)
}

/// `protocol_param_update` (`defs.cddl`) gains keys 34 through 56.
#[derive(Serialize, Deserialize, Encode, Debug, PartialEq, Eq, Clone)]
#[cbor(map)]
pub struct ProtocolParamUpdate {
    #[n(0)]
    pub minfee_a: Option<u64>,
    #[n(1)]
    pub minfee_b: Option<u64>,
    #[n(2)]
    pub max_block_body_size: Option<u32>,
    #[n(3)]
    pub max_transaction_size: Option<u32>,
    #[n(4)]
    pub max_block_header_size: Option<u16>,
    #[n(5)]
    pub key_deposit: Option<Coin>,
    #[n(6)]
    pub pool_deposit: Option<Coin>,
    #[n(7)]
    pub maximum_epoch: Option<u32>,
    #[n(8)]
    pub desired_number_of_stake_pools: Option<u16>,
    #[n(9)]
    pub pool_pledge_influence: Option<NonNegativeInterval>,
    #[n(10)]
    pub expansion_rate: Option<UnitInterval>,
    #[n(11)]
    pub treasury_growth_rate: Option<UnitInterval>,

    #[n(16)]
    pub min_pool_cost: Option<Coin>,
    #[n(17)]
    pub ada_per_utxo_byte: Option<Coin>,
    #[n(18)]
    pub cost_models_for_script_languages: Option<CostModels>,
    #[n(19)]
    pub execution_costs: Option<ExUnitPrices>,
    #[n(20)]
    pub max_tx_ex_units: Option<ExUnits>,
    #[n(21)]
    pub max_block_ex_units: Option<ExUnits>,
    #[n(22)]
    pub max_value_size: Option<u32>,
    #[n(23)]
    pub collateral_percentage: Option<u16>,
    #[n(24)]
    pub max_collateral_inputs: Option<u16>,

    #[n(25)]
    pub pool_voting_thresholds: Option<PoolVotingThresholds>,
    #[n(26)]
    pub drep_voting_thresholds: Option<DRepVotingThresholds>,
    #[n(27)]
    pub min_committee_size: Option<u16>,
    #[n(28)]
    pub committee_term_limit: Option<u32>,
    #[n(29)]
    pub governance_action_validity_period: Option<u32>,
    #[n(30)]
    pub governance_action_deposit: Option<Coin>,
    #[n(31)]
    pub drep_deposit: Option<Coin>,
    #[n(32)]
    pub drep_inactivity_period: Option<u32>,
    #[n(33)]
    pub minfee_refscript_cost_per_byte: Option<NonNegativeInterval>,

    // -- NEW IN DIJKSTRA
    #[n(34)]
    pub max_ref_script_size_per_block: Option<u32>,
    #[n(35)]
    pub max_ref_script_size_per_tx: Option<u32>,
    #[n(36)]
    pub ref_script_cost_stride: Option<std::num::NonZeroU32>,
    #[n(37)]
    pub ref_script_cost_multiplier: Option<PositiveInterval>,

    /// `max_pledge_leverage = nonnegative_interval/ nil` (`defs.cddl`), so an explicit nil differs from an absent key.
    #[n(38)]
    pub max_pledge_leverage: Option<Nullable<NonNegativeInterval>>,
    #[n(39)]
    pub min_pool_margin: Option<UnitInterval>,
    #[n(40)]
    pub leios_announcement_period_length: Option<u32>,
    #[n(41)]
    pub leios_vote_period_length: Option<u32>,
    #[n(42)]
    pub leios_diffusion_period_length: Option<u32>,
    #[n(43)]
    pub leios_committee_size: Option<u16>,
    #[n(44)]
    pub leios_quorum_stake_threshold: Option<UnitInterval>,
    #[n(45)]
    pub max_endorser_block_references_size: Option<u32>,
    #[n(46)]
    pub max_endorser_block_txs_size: Option<u32>,
    #[n(47)]
    pub max_endorser_block_execution_units: Option<ExUnits>,
    #[n(48)]
    pub max_ref_script_size_per_endorser_block: Option<u32>,
    #[n(49)]
    pub peras_min_candidate_block_age: Option<u32>,
    #[n(50)]
    pub peras_healing_factor: Option<PositiveInterval>,
    #[n(51)]
    pub peras_cert_boost: Option<u16>,
    #[n(52)]
    pub peras_target_committee_size: Option<u16>,

    /// `? 53 : nil/ uint .size 4` (`defs.cddl`), so an explicit nil differs from an absent key.
    #[n(53)]
    pub peras_bootstrap_round: Option<Nullable<u32>>,
    #[n(54)]
    pub peras_quorum_threshold_safety_margin: Option<UnitInterval>,
    #[n(55)]
    pub ref_inputs_cost_per_multi_asset_policy: Option<Coin>,
    #[n(56)]
    pub ref_inputs_cost_per_datum_byte: Option<Coin>,
}

crate::map_record::decode_map_record!(ProtocolParamUpdate,
    0 => minfee_a,
    1 => minfee_b,
    2 => max_block_body_size,
    3 => max_transaction_size,
    4 => max_block_header_size,
    5 => key_deposit,
    6 => pool_deposit,
    7 => maximum_epoch,
    8 => desired_number_of_stake_pools,
    9 => pool_pledge_influence,
    10 => expansion_rate,
    11 => treasury_growth_rate,
    16 => min_pool_cost,
    17 => ada_per_utxo_byte,
    18 => cost_models_for_script_languages,
    19 => execution_costs,
    20 => max_tx_ex_units,
    21 => max_block_ex_units,
    22 => max_value_size,
    23 => collateral_percentage,
    24 => max_collateral_inputs,
    25 => pool_voting_thresholds,
    26 => drep_voting_thresholds,
    27 => min_committee_size,
    28 => committee_term_limit,
    29 => governance_action_validity_period,
    30 => governance_action_deposit,
    31 => drep_deposit,
    32 => drep_inactivity_period,
    33 => minfee_refscript_cost_per_byte,
    34 => max_ref_script_size_per_block,
    35 => max_ref_script_size_per_tx,
    36 => ref_script_cost_stride,
    37 => ref_script_cost_multiplier,
    38 => max_pledge_leverage: decode_nullable_value,
    39 => min_pool_margin,
    40 => leios_announcement_period_length,
    41 => leios_vote_period_length,
    42 => leios_diffusion_period_length,
    43 => leios_committee_size,
    44 => leios_quorum_stake_threshold,
    45 => max_endorser_block_references_size,
    46 => max_endorser_block_txs_size,
    47 => max_endorser_block_execution_units,
    48 => max_ref_script_size_per_endorser_block,
    49 => peras_min_candidate_block_age,
    50 => peras_healing_factor,
    51 => peras_cert_boost,
    52 => peras_target_committee_size,
    53 => peras_bootstrap_round: decode_nullable_value,
    54 => peras_quorum_threshold_safety_margin,
    55 => ref_inputs_cost_per_multi_asset_policy,
    56 => ref_inputs_cost_per_datum_byte,
);

/// No CDDL rule answers to this type. It mirrors [`crate::conway::Update`] over this era's `protocol_param_update`.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct Update {
    #[n(0)]
    pub proposed_protocol_parameter_updates: BTreeMap<Genesishash, ProtocolParamUpdate>,

    #[n(1)]
    pub epoch: Epoch,
}

/// `proposal_procedure = [deposit : coin, reward_account, gov_action, anchor]` (`defs.cddl`).
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct ProposalProcedure {
    #[n(0)]
    pub deposit: Coin,

    #[n(1)]
    pub reward_account: RewardAccount,

    #[n(2)]
    pub gov_action: GovAction,

    #[n(3)]
    pub anchor: Anchor,
}

/// `gov_action` (`defs.cddl`). Its `parameter_change_action` arm reaches this era's `protocol_param_update`.
#[derive(Serialize, Deserialize, Encode, Debug, PartialEq, Eq, Clone)]
#[cbor(flat)]
pub enum GovAction {
    #[n(0)]
    ParameterChange(
        #[n(0)] Option<GovActionId>,
        #[n(1)] Box<ProtocolParamUpdate>,
        #[n(2)] Option<ScriptHash>,
    ),

    #[n(1)]
    HardForkInitiation(#[n(0)] Option<GovActionId>, #[n(1)] ProtocolVersion),

    #[n(2)]
    TreasuryWithdrawals(
        #[n(0)] BTreeMap<RewardAccount, Coin>,
        #[n(1)] Option<ScriptHash>,
    ),

    #[n(3)]
    NoConfidence(#[n(0)] Option<GovActionId>),

    #[n(4)]
    UpdateCommittee(
        #[n(0)] Option<GovActionId>,
        #[n(1)] Set<CommitteeColdCredential>,
        #[n(2)] BTreeMap<CommitteeColdCredential, Epoch>,
        #[n(3)] UnitInterval,
    ),

    #[n(5)]
    NewConstitution(#[n(0)] Option<GovActionId>, #[n(1)] Constitution),

    #[n(6)]
    Information,
}

crate::flat_enum::decode_flat_enum!(GovAction,
    0 => ParameterChange(previous, update, policy),
    1 => HardForkInitiation(previous, version),
    2 => TreasuryWithdrawals(withdrawals, policy),
    3 => NoConfidence(previous),
    4 => UpdateCommittee(previous, removed, added, threshold),
    5 => NewConstitution(previous, constitution),
    6 => Information,
);

/// `guards = nonempty_set<addr_keyhash>/ nonempty_oset<credential>`
/// (`defs.cddl`), Conway's `required_signers` widened. The arms are told
/// apart by element type: an `addr_keyhash` is a byte string, a `credential`
/// an array.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum Guards {
    AddrKeyhashes(NonEmptySet<AddrKeyhash>),
    Credentials(NonEmptySet<StakeCredential>),
}

fn empty_guards() -> minicbor::decode::Error {
    minicbor::decode::Error::message("guards must carry at least one element")
}

impl<'b, C> minicbor::Decode<'b, C> for Guards {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let mut probe = minicbor::Decoder::new(&d.input()[d.position()..]);
        if probe.datatype()? == minicbor::data::Type::Tag {
            probe.tag()?;
        }
        let len = probe.array()?;

        // Reading the element type of an empty array would read the byte after
        // the value, which belongs to whatever encloses it.
        if len == Some(0) {
            return Err(empty_guards());
        }

        match probe.datatype()? {
            minicbor::data::Type::Break => Err(empty_guards()),
            minicbor::data::Type::Array | minicbor::data::Type::ArrayIndef => {
                Ok(Guards::Credentials(d.decode_with(ctx)?))
            }
            minicbor::data::Type::Bytes | minicbor::data::Type::BytesIndef => {
                Ok(Guards::AddrKeyhashes(d.decode_with(ctx)?))
            }
            other => Err(minicbor::decode::Error::message(format!(
                "invalid guards element type {other} at position {}",
                d.position()
            ))),
        }
    }
}

impl<C> minicbor::Encode<C> for Guards {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Guards::AddrKeyhashes(x) => e.encode_with(x, ctx)?,
            Guards::Credentials(x) => e.encode_with(x, ctx)?,
        };

        Ok(())
    }
}

/// Decoders for a body's optional [`Guards`] field, where an empty set is no guards.
pub(crate) mod guards_field {
    use super::Guards;
    use pallas_codec::minicbor::{self, data::Type, decode::Error};

    /// Decodes a body's guards, reading null or an empty set as `None`.
    pub fn decode_option<Ctx>(
        d: &mut minicbor::Decoder<'_>,
        ctx: &mut Ctx,
    ) -> Result<Option<Guards>, Error> {
        let mut probe = minicbor::Decoder::new(&d.input()[d.position()..]);
        if probe.datatype()? == Type::Null {
            d.skip()?;
            return Ok(None);
        }
        if probe.datatype()? == Type::Tag {
            probe.tag()?;
        }
        let empty = match probe.array()? {
            Some(len) => len == 0,
            None => probe.datatype()? == Type::Break,
        };
        if empty {
            d.skip()?;
            return Ok(None);
        }
        d.decode_with(ctx).map(Some)
    }
}

pub type DirectDeposits = BTreeMap<RewardAccount, Coin>;

pub type RequiredTopLevelGuards = BTreeMap<StakeCredential, Nullable<PlutusData>>;

pub type AccountBalanceIntervals = BTreeMap<RewardAccount, AccountBalanceInterval>;

pub type StartingAccountBalanceIntervals = BTreeMap<RewardAccount, AccountBalanceInterval>;

/// `account_balance_interval` (`defs.cddl`), a two element array with at most
/// one bound missing, or a bare `coin`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum AccountBalanceInterval {
    /// `[coin, nil]`
    LowerBound(Coin),
    /// `[coin, coin]`
    Bounded(Coin, Coin),
    /// `[nil, coin]`
    UpperBound(Coin),
    /// A bare `coin`.
    Exact(Coin),
}

impl<'b, C> minicbor::Decode<'b, C> for AccountBalanceInterval {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        match d.datatype()? {
            minicbor::data::Type::Array | minicbor::data::Type::ArrayIndef => {}
            _ => return Ok(AccountBalanceInterval::Exact(d.decode_with(ctx)?)),
        }

        let len = d.array()?;
        match len {
            None | Some(2) => {}
            Some(found) => {
                return Err(minicbor::decode::Error::message(format!(
                    "account_balance_interval takes two elements, found {found}"
                )));
            }
        }

        let lower: Option<Coin> = match d.datatype()? {
            minicbor::data::Type::Null => {
                d.null()?;
                None
            }
            _ => Some(d.decode_with(ctx)?),
        };

        let upper: Option<Coin> = match d.datatype()? {
            minicbor::data::Type::Null => {
                d.null()?;
                None
            }
            _ => Some(d.decode_with(ctx)?),
        };

        if len.is_none() {
            if d.datatype()? != minicbor::data::Type::Break {
                return Err(minicbor::decode::Error::message(
                    "account_balance_interval takes two elements, found more",
                ));
            }
            d.skip()?;
        }

        match (lower, upper) {
            (Some(l), None) => Ok(AccountBalanceInterval::LowerBound(l)),
            (Some(l), Some(u)) => Ok(AccountBalanceInterval::Bounded(l, u)),
            (None, Some(u)) => Ok(AccountBalanceInterval::UpperBound(u)),
            (None, None) => Err(minicbor::decode::Error::message(
                "account_balance_interval with neither a lower nor an upper bound",
            )),
        }
    }
}

impl<C> minicbor::Encode<C> for AccountBalanceInterval {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            AccountBalanceInterval::LowerBound(l) => {
                e.array(2)?;
                e.encode_with(l, ctx)?;
                e.null()?;
            }
            AccountBalanceInterval::Bounded(l, u) => {
                e.array(2)?;
                e.encode_with(l, ctx)?;
                e.encode_with(u, ctx)?;
            }
            AccountBalanceInterval::UpperBound(u) => {
                e.array(2)?;
                e.null()?;
                e.encode_with(u, ctx)?;
            }
            AccountBalanceInterval::Exact(c) => {
                e.encode_with(c, ctx)?;
            }
        }

        Ok(())
    }
}

/// `sub_transaction_body` (`defs.cddl`), Conway's body minus the keys a sub
/// transaction cannot carry, such as the fee and the collateral.
#[derive(Serialize, Deserialize, Encode, Debug, PartialEq, Clone)]
#[cbor(map)]
pub struct SubTransactionBody<'a> {
    #[n(0)]
    pub inputs: Set<TransactionInput>,

    #[b(1)]
    pub outputs: MaybeIndefArray<TransactionOutput<'a>>,

    #[n(3)]
    pub ttl: Option<u64>,

    #[n(4)]
    pub certificates: Option<NonEmptySet<Certificate>>,

    #[n(5)]
    pub withdrawals: Option<Withdrawals>,

    #[n(7)]
    pub auxiliary_data_hash: Option<Hash<32>>,

    #[n(8)]
    pub validity_interval_start: Option<u64>,

    #[n(9)]
    pub mint: Option<Multiasset<NonZeroInt>>,

    #[n(11)]
    pub script_data_hash: Option<Hash<32>>,

    #[n(14)]
    pub guards: Option<Guards>,

    #[n(15)]
    pub network_id: Option<NetworkId>,

    #[n(18)]
    pub reference_inputs: Option<NonEmptySet<TransactionInput>>,

    #[n(19)]
    pub voting_procedures: Option<VotingProcedures>,

    #[n(20)]
    pub proposal_procedures: Option<NonEmptySet<ProposalProcedure>>,

    #[n(21)]
    pub treasury_value: Option<Coin>,

    #[n(22)]
    pub donation: Option<PositiveCoin>,

    #[n(24)]
    pub required_top_level_guards: Option<RequiredTopLevelGuards>,

    #[n(25)]
    pub direct_deposits: Option<DirectDeposits>,

    #[n(26)]
    pub account_balance_intervals: Option<AccountBalanceIntervals>,
}

crate::map_record::decode_map_record!(SubTransactionBody<'a>,
    0 => inputs,
    1 => outputs,
    3 => ttl,
    4 => certificates,
    5 => withdrawals,
    7 => auxiliary_data_hash,
    8 => validity_interval_start,
    9 => mint,
    11 => script_data_hash,
    14 => guards: guards_field::decode_option,
    15 => network_id,
    18 => reference_inputs,
    19 => voting_procedures,
    20 => proposal_procedures,
    21 => treasury_value,
    22 => donation,
    24 => required_top_level_guards,
    25 => direct_deposits,
    26 => account_balance_intervals,
);

/// `sub_transaction = [sub_transaction_body, transaction_witness_set, auxiliary_data/ nil]` (`defs.cddl`).
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Clone)]
pub struct SubTransaction<'b> {
    #[b(0)]
    pub sub_transaction_body: KeepRaw<'b, SubTransactionBody<'b>>,

    #[n(1)]
    pub transaction_witness_set: KeepRaw<'b, WitnessSet<'b>>,

    #[n(2)]
    pub auxiliary_data: Nullable<KeepRaw<'b, AuxiliaryData<'b>>>,
}

/// `sub_transactions = nonempty_oset<sub_transaction>` (`defs.cddl`).
pub type SubTransactions<'b> = NonEmptySet<SubTransaction<'b>>;

/// `transaction_body` (`defs.cddl`). Key 14 is `guards`, not Conway's `required_signers`.
#[derive(Serialize, Deserialize, Encode, Debug, PartialEq, Clone)]
#[cbor(map)]
pub struct TransactionBody<'a> {
    #[n(0)]
    pub inputs: Set<TransactionInput>,

    #[b(1)]
    pub outputs: MaybeIndefArray<TransactionOutput<'a>>,

    #[n(2)]
    pub fee: Coin,

    #[n(3)]
    pub ttl: Option<u64>,

    #[n(4)]
    pub certificates: Option<NonEmptySet<Certificate>>,

    #[n(5)]
    pub withdrawals: Option<Withdrawals>,

    #[n(7)]
    pub auxiliary_data_hash: Option<Hash<32>>,

    #[n(8)]
    pub validity_interval_start: Option<u64>,

    #[n(9)]
    pub mint: Option<Multiasset<NonZeroInt>>,

    #[n(11)]
    pub script_data_hash: Option<Hash<32>>,

    #[n(13)]
    pub collateral: Option<NonEmptySet<TransactionInput>>,

    #[n(14)]
    pub guards: Option<Guards>,

    #[n(15)]
    pub network_id: Option<NetworkId>,

    #[n(16)]
    pub collateral_return: Option<TransactionOutput<'a>>,

    #[n(17)]
    pub total_collateral: Option<Coin>,

    #[n(18)]
    pub reference_inputs: Option<NonEmptySet<TransactionInput>>,

    #[n(19)]
    pub voting_procedures: Option<VotingProcedures>,

    #[n(20)]
    pub proposal_procedures: Option<NonEmptySet<ProposalProcedure>>,

    #[n(21)]
    pub treasury_value: Option<Coin>,

    #[n(22)]
    pub donation: Option<PositiveCoin>,

    // -- NEW IN DIJKSTRA
    #[b(23)]
    pub sub_transactions: Option<SubTransactions<'a>>,

    #[n(24)]
    pub required_top_level_guards: Option<RequiredTopLevelGuards>,

    #[n(25)]
    pub direct_deposits: Option<DirectDeposits>,

    #[n(26)]
    pub account_balance_intervals: Option<AccountBalanceIntervals>,

    #[n(27)]
    pub starting_account_balance_intervals: Option<StartingAccountBalanceIntervals>,
}

crate::map_record::decode_map_record!(TransactionBody<'a>,
    0 => inputs,
    1 => outputs,
    2 => fee,
    3 => ttl,
    4 => certificates,
    5 => withdrawals,
    7 => auxiliary_data_hash,
    8 => validity_interval_start,
    9 => mint,
    11 => script_data_hash,
    13 => collateral,
    14 => guards: guards_field::decode_option,
    15 => network_id,
    16 => collateral_return,
    17 => total_collateral,
    18 => reference_inputs,
    19 => voting_procedures,
    20 => proposal_procedures,
    21 => treasury_value,
    22 => donation,
    23 => sub_transactions,
    24 => required_top_level_guards,
    25 => direct_deposits,
    26 => account_balance_intervals,
    27 => starting_account_balance_intervals,
);

/// `babbage_transaction_output` (`defs.cddl`), the map form of an output.
#[derive(Serialize, Deserialize, Encode, Debug, PartialEq, Eq, Clone)]
#[cbor(map)]
pub struct PostAlonzoTransactionOutput<'b> {
    #[n(0)]
    pub address: Bytes,

    #[n(1)]
    pub value: Value,

    #[b(2)]
    pub datum_option: Option<KeepRaw<'b, DatumOption<'b>>>,

    #[n(3)]
    pub script_ref: Option<CborWrap<ScriptRef<'b>>>,
}

crate::map_record::decode_map_record!(PostAlonzoTransactionOutput<'b>,
    0 => address,
    1 => value,
    2 => datum_option,
    3 => script_ref: babbage::decode_script_ref,
);

/// `transaction_output` (`defs.cddl`), in the form it was read from.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum TransactionOutput<'b> {
    Legacy(KeepRaw<'b, LegacyTransactionOutput>),
    PostAlonzo(KeepRaw<'b, PostAlonzoTransactionOutput<'b>>),
}

codec_by_datatype! {
    TransactionOutput<'b>,
    Array | ArrayIndef => Legacy,
    Map | MapIndef => PostAlonzo,
    ()
}

/// `native_script` gains `script_require_guard = (6, credential)` (`defs.cddl`).
///
/// A native script tree with stack-safe CBOR, clone, equality and drop
/// operations, like [`crate::alonzo::NativeScript`]. This type implements
/// `Drop` to dismantle deep trees iteratively. To consume a child list, match
/// by mutable reference and use [`std::mem::take`]. This stack-safety
/// guarantee does not cover Serde, debug formatting or downstream tree
/// visitors.
#[derive(Serialize, Deserialize, Debug, Eq)]
pub enum NativeScript {
    ScriptPubkey(AddrKeyhash),
    ScriptAll(Vec<NativeScript>),
    ScriptAny(Vec<NativeScript>),
    /// `script_n_of_k`'s threshold is `int64`, signed since Shelley (`defs.cddl`); do not narrow it back to unsigned.
    ScriptNOfK(i64, Vec<NativeScript>),
    InvalidBefore(u64),
    InvalidHereafter(u64),

    // -- NEW IN DIJKSTRA
    ScriptRequireGuard(StakeCredential),
}

/// `redeemer_tag` gains tag 6, `guarding` (`defs.cddl`).
#[derive(
    Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord,
)]
#[cbor(index_only)]
pub enum RedeemerTag {
    #[n(0)]
    Spend,
    #[n(1)]
    Mint,
    #[n(2)]
    Cert,
    #[n(3)]
    Reward,
    #[n(4)]
    Vote,
    #[n(5)]
    Propose,

    // -- NEW IN DIJKSTRA
    #[n(6)]
    Guarding,
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct RedeemersKey {
    #[n(0)]
    pub tag: RedeemerTag,
    #[n(1)]
    pub index: u32,
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct RedeemersValue {
    #[n(0)]
    pub data: PlutusData,
    #[n(1)]
    pub ex_units: ExUnits,
}

/// `redeemers` is map only in Dijkstra (`defs.cddl`). Conway's array arm and
/// the `redeemer` rule behind it were deleted.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone)]
#[cbor(transparent)]
pub struct Redeemers(pub BTreeMap<RedeemersKey, RedeemersValue>);

impl From<BTreeMap<RedeemersKey, RedeemersValue>> for Redeemers {
    fn from(value: BTreeMap<RedeemersKey, RedeemersValue>) -> Self {
        Redeemers(value)
    }
}

impl std::ops::Deref for Redeemers {
    type Target = BTreeMap<RedeemersKey, RedeemersValue>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// `transaction_witness_set` (`defs.cddl`) with cardano-ledger `9df9f98c`'s
/// `? 8 : nonempty_set<plutus_v4_script>`. Keys 0 to 7 are Conway's, but the
/// `native_script` and `redeemers` they reach both changed.
#[derive(Serialize, Deserialize, Encode, Debug, PartialEq, Clone)]
#[cbor(map)]
pub struct WitnessSet<'b> {
    #[n(0)]
    pub vkeywitness: Option<NonEmptySet<VKeyWitness>>,

    #[n(1)]
    pub native_script: Option<NonEmptySet<KeepRaw<'b, NativeScript>>>,

    /// Possibly empty, since cardano-ledger `9df9f98c` reads an empty set here although `defs.cddl` says `nonempty_set`.
    #[n(2)]
    pub bootstrap_witness: Option<Set<BootstrapWitness>>,

    #[n(3)]
    pub plutus_v1_script: Option<NonEmptySet<PlutusScript<1>>>,

    #[b(4)]
    pub plutus_data: Option<KeepRaw<'b, NonEmptySet<KeepRaw<'b, PlutusData>>>>,

    #[n(5)]
    pub redeemer: Option<KeepRaw<'b, Redeemers>>,

    #[n(6)]
    pub plutus_v2_script: Option<NonEmptySet<PlutusScript<2>>>,

    #[n(7)]
    pub plutus_v3_script: Option<NonEmptySet<PlutusScript<3>>>,

    #[n(8)]
    pub plutus_v4_script: Option<NonEmptySet<PlutusScript<4>>>,
}

crate::map_record::decode_map_record!(WitnessSet<'b>,
    0 => vkeywitness,
    1 => native_script,
    2 => bootstrap_witness,
    3 => plutus_v1_script,
    4 => plutus_data,
    5 => redeemer,
    6 => plutus_v2_script,
    7 => plutus_v3_script,
    8 => plutus_v4_script,
);

/// `auxiliary_data_map` gains `? 5 : [* plutus_v4_script]` (`defs.cddl`).
#[derive(Serialize, Deserialize, Encode, Debug, PartialEq, Clone, Eq)]
#[cbor(map, tag(259))]
pub struct PostAlonzoAuxiliaryData<'b> {
    #[n(0)]
    pub metadata: Option<Metadata>,

    #[b(1)]
    pub native_scripts: Option<Vec<KeepRaw<'b, NativeScript>>>,

    #[n(2)]
    pub plutus_v1_scripts: Option<Vec<PlutusScript<1>>>,

    #[n(3)]
    pub plutus_v2_scripts: Option<Vec<PlutusScript<2>>>,

    #[n(4)]
    pub plutus_v3_scripts: Option<Vec<PlutusScript<3>>>,

    // -- NEW IN DIJKSTRA
    #[n(5)]
    pub plutus_v4_scripts: Option<Vec<PlutusScript<4>>>,
}

crate::map_record::decode_map_record!(PostAlonzoAuxiliaryData<'b>, tag 259,
    0 => metadata,
    1 => native_scripts,
    2 => plutus_v1_scripts,
    3 => plutus_v2_scripts,
    4 => plutus_v3_scripts,
    5 => plutus_v4_scripts,
);

/// `auxiliary_data_array` (`defs.cddl`), whose second element is
/// `auxiliary_scripts = [* native_script]`, this era's.
#[derive(Serialize, Deserialize, Encode, Debug, PartialEq, Clone, Eq)]
pub struct ShelleyMaAuxiliaryData<'b> {
    #[n(0)]
    pub transaction_metadata: Metadata,

    #[b(1)]
    pub auxiliary_scripts: Option<Vec<KeepRaw<'b, NativeScript>>>,
}

impl<'b, C> minicbor::Decode<'b, C> for ShelleyMaAuxiliaryData<'b> {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        decode_array(d, |a| {
            Ok(ShelleyMaAuxiliaryData {
                transaction_metadata: a.decode_with(ctx)?,
                auxiliary_scripts: a.decode_with(ctx)?,
            })
        })
    }
}

/// `auxiliary_data` (`defs.cddl`).
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
pub enum AuxiliaryData<'b> {
    Shelley(Metadata),
    ShelleyMa(ShelleyMaAuxiliaryData<'b>),
    PostAlonzo(PostAlonzoAuxiliaryData<'b>),
}

codec_by_datatype! {
    AuxiliaryData<'b>,
    Map | MapIndef => Shelley,
    Array | ArrayIndef => ShelleyMa,
    Tag => PostAlonzo,
    ()
}

/// `script` gains `// 4, plutus_v4_script` (`defs.cddl`), reached through
/// `script_ref = #6.24(bytes .cbor script)`.
#[derive(Encode, Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[cbor(flat)]
pub enum ScriptRef<'b> {
    #[n(0)]
    NativeScript(#[b(0)] KeepRaw<'b, NativeScript>),
    #[n(1)]
    PlutusV1Script(#[n(0)] PlutusScript<1>),
    #[n(2)]
    PlutusV2Script(#[n(0)] PlutusScript<2>),
    #[n(3)]
    PlutusV3Script(#[n(0)] PlutusScript<3>),

    // -- NEW IN DIJKSTRA
    #[n(4)]
    PlutusV4Script(#[n(0)] PlutusScript<4>),
}

crate::flat_enum::decode_flat_enum!(ScriptRef<'b>,
    0 => NativeScript(script),
    1 => PlutusV1Script(script),
    2 => PlutusV2Script(script),
    3 => PlutusV3Script(script),
    4 => PlutusV4Script(script),
);

crate::babbage::decode_joined_script_ref!(
    ScriptRef,
    PlutusV1Script,
    PlutusV2Script,
    PlutusV3Script,
    PlutusV4Script
);

/// `block_body` (`defs.cddl`). Dijkstra replaces Conway's segregated witness
/// layout with complete inline transactions, and drops `invalid_transactions`
/// and `transaction_index` because each transaction carries its own flag.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Clone)]
pub struct BlockBody<'b> {
    #[b(0)]
    pub transactions: MaybeIndefArray<BlockTransaction<'b>>,

    #[n(1)]
    pub leios_certificate: Nullable<LeiosCertificate>,

    #[n(2)]
    pub peras_certificate: Nullable<PerasCertificate>,
}

/// `block = [header, block_body]` (`defs.cddl`).
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Clone)]
pub struct Block<'b> {
    #[n(0)]
    pub header: KeepRaw<'b, Header>,

    #[b(1)]
    pub block_body: BlockBody<'b>,
}

/// `block_transaction = [transaction_body, transaction_witness_set, auxiliary_data/ nil, bool]`
/// (`defs.cddl`), the four element form a ranking block carries. Conway puts
/// the flag at position 2, here it is last and is named `success` as in Conway.
#[derive(Clone, Serialize, Deserialize, Encode, Decode, Debug, PartialEq)]
pub struct BlockTransaction<'b> {
    #[b(0)]
    pub transaction_body: KeepRaw<'b, TransactionBody<'b>>,

    #[n(1)]
    pub transaction_witness_set: KeepRaw<'b, WitnessSet<'b>>,

    #[n(2)]
    pub auxiliary_data: Nullable<KeepRaw<'b, AuxiliaryData<'b>>>,

    /// Set by the block producer, not by the transaction author.
    #[n(3)]
    pub success: bool,
}

impl Eq for BlockTransaction<'_> {}

impl<'b> BlockTransaction<'b> {
    pub fn to_mempool_transaction(&self) -> MempoolTransaction<'b> {
        MempoolTransaction {
            transaction_body: self.transaction_body.clone(),
            transaction_witness_set: self.transaction_witness_set.clone(),
            is_valid_supplied: false,
            auxiliary_data: self.auxiliary_data.clone(),
        }
    }
}

/// `mempool_transaction` (`defs.cddl`) is three elements, and tolerates the
/// Conway four element shape with `is_valid` required to be `true`.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct MempoolTransaction<'b> {
    pub transaction_body: KeepRaw<'b, TransactionBody<'b>>,
    pub transaction_witness_set: KeepRaw<'b, WitnessSet<'b>>,
    pub is_valid_supplied: bool,
    pub auxiliary_data: Nullable<KeepRaw<'b, AuxiliaryData<'b>>>,
}

impl<'b> From<MempoolTransaction<'b>> for BlockTransaction<'b> {
    fn from(tx: MempoolTransaction<'b>) -> Self {
        BlockTransaction {
            transaction_body: tx.transaction_body,
            transaction_witness_set: tx.transaction_witness_set,
            auxiliary_data: tx.auxiliary_data,
            success: true,
        }
    }
}

impl<'b, C> minicbor::Decode<'b, C> for MempoolTransaction<'b> {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        decode_array(d, |a| {
            let transaction_body = a.decode_with(ctx)?;
            let transaction_witness_set = a.decode_with(ctx)?;

            let is_valid_supplied = match a.datatype()? {
                minicbor::data::Type::Bool => {
                    if a.decode_with(ctx)? {
                        true
                    } else {
                        return Err(minicbor::decode::Error::message(
                            "value `false` not allowed for `is_valid`",
                        ));
                    }
                }
                _ => false,
            };
            let auxiliary_data = a.decode_with(ctx)?;

            if a.datatype()? != minicbor::data::Type::Break {
                let expected = if is_valid_supplied { 4 } else { 3 };
                return Err(minicbor::decode::Error::message(format!(
                    "expected a {expected} element transaction, found more"
                )));
            }

            Ok(MempoolTransaction {
                transaction_body,
                transaction_witness_set,
                is_valid_supplied,
                auxiliary_data,
            })
        })
    }
}

impl<C> minicbor::Encode<C> for MempoolTransaction<'_> {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(if self.is_valid_supplied { 4 } else { 3 })?;
        e.encode_with(&self.transaction_body, ctx)?;
        e.encode_with(&self.transaction_witness_set, ctx)?;
        if self.is_valid_supplied {
            e.bool(true)?;
        }
        e.encode_with(&self.auxiliary_data, ctx)?;

        Ok(())
    }
}

impl Eq for MempoolTransaction<'_> {}
