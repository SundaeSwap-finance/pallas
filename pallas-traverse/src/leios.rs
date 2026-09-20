//! The Leios endorsement layer, from a follower's side of the wire.
//!
//! On a Leios network most transactions never appear in a ranking block. A
//! ranking block header announces an endorser block, a later ranking block
//! certifies that announcement, and the certified endorser block carries the
//! transactions. A follower that reads only the ranking chain builds a ledger
//! that is silently short.
//!
//! The endorser block body is a network object rather than a ledger one. Its
//! rule is
//!
//! ```cddl
//! endorser_block = { * hash => word32 }
//! ```
//!
//! from the node to node `leios-fetch` CDDL of cardano-blueprint on the
//! `leios-prototype` branch, `src/network/node-to-node/leios-fetch/messages.cddl`,
//! quoted verbatim in the conformance test in
//! `pallas-network2/src/protocol/leiosfetch.rs`. It is absent from the Dijkstra
//! ledger CDDL, which carries only `eb_announcement`, `leios_certificate` and
//! the two header fields.
//!
//! Three properties of that wire form each cost a follower its ledger if it
//! guesses, so every one of them is carried in a type here rather than left to
//! a caller.
//!
//! 1. The protocol has no not found reply. An endorser block the peer does not
//!    hold comes back as `a0`, a well formed empty body, indistinguishable from
//!    one that committed no transactions. The announcement commits the body
//!    length and the body hash before any fetch, so
//!    [`crate::leios::EndorserBlockBody::decode_announced`] is the constructor
//!    that pairs the two and refuses a body the announcement did not promise.
//!    Length alone does not identify one: a peer answering a `[slot, eb_hash]`
//!    point with a different endorser block of the same length passes every
//!    later check too, because each transaction is then checked against the
//!    entries of the body that arrived.
//! 2. The body keys a transaction by the blake2b-256 of the whole transaction,
//!    not by its transaction id, which is the blake2b-256 of the body alone. A
//!    follower that looks for transaction ids finds nothing, with no error.
//! 3. Each transaction arrives wrapped in a CBOR byte string, and the length in
//!    the body is the length of the unwrapped transaction.
//!
//! The certification rule needs nothing but ranking chain headers. Walk them in
//! order, carry the most recent announcement forward, and when a header sets
//! `block_body_contains_leios_cert` the carried announcement is the endorser
//! block to fetch and apply at that header's block. An announcement superseded
//! before any block certifies it is abandoned network wide.
//! [`crate::leios::CertificationTracker`] is that walk.
//!
//! The links above are written in full because this module carries an inner
//! doc block and `lib.rs` carries an outer one on its `mod` line. The two are
//! merged, and a bare item name in the merged text is looked for in the crate
//! root rather than here.

use pallas_codec::minicbor::{Decoder, Encoder, data::Type};
use pallas_codec::utils::MaybeIndefArray;
use pallas_crypto::hash::{Hash, Hasher};
use pallas_primitives::dijkstra;

use crate::{Era, MultiEraHeader, MultiEraTx};

/// Everything that can go wrong between an announcement and an applied
/// endorser block. Every variant names the evidence, so no caller has to infer
/// a failure from a value that merely came back empty.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("endorser block body is not a cbor map of hash to size: {0}")]
    InvalidBody(String),

    #[error(
        "endorser block body is {found} bytes, the announcement committed to {announced}; \
         leios-fetch has no not-found reply, so a short body is a missing endorser block"
    )]
    BodySize { announced: u32, found: usize },

    #[error(
        "endorser block body hashes to {found} and the announcement named {announced}, \
         so a body of the announced length arrived that is a different endorser block, \
         and every check inside it would have passed"
    )]
    BodyHash {
        announced: Hash<32>,
        found: Hash<32>,
    },

    #[error("endorser block names {named} transactions and {delivered} were delivered")]
    TxCount { named: usize, delivered: usize },

    #[error("transaction {index} is not wrapped in a cbor byte string: {reason}")]
    Envelope { index: usize, reason: String },

    #[error("transaction {index} is {found} bytes, the endorser block names {named}")]
    TxSize {
        index: usize,
        named: u32,
        found: usize,
    },

    #[error("transaction {index} hashes to {found}, the endorser block names {named}")]
    TxHash {
        index: usize,
        named: Hash<32>,
        found: Hash<32>,
    },

    #[error("transaction {index} does not decode as a Dijkstra transaction: {reason}")]
    TxDecode { index: usize, reason: String },

    #[error("the header at slot {slot} certifies an endorser block with no announcement pending")]
    CertifiesNothing { slot: u64 },

    #[error(
        "the header at slot {slot} certifies an endorser block and the walk cannot say which, \
         because it resumed from a stored position without establishing whether an announcement \
         was waiting"
    )]
    CertifiesUnknown { slot: u64 },

    #[error(
        "the block at slot {slot} certifies an endorser block and carries {count} transactions \
         of its own, which the chain inclusion rule forbids"
    )]
    CertifiesAndCarries { slot: u64, count: usize },

    #[error("the block at slot {slot} certifies no endorser block, so there is nothing to resolve")]
    NotCertifying { slot: u64 },

    #[error("a {era} block cannot certify an endorser block")]
    NotLeiosEra { era: Era },

    #[error("the block cbor is not a ranking block: {0}")]
    InvalidBlock(String),
}

/// One entry of an endorser block body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndorserBlockEntry {
    /// blake2b-256 of the whole transaction, which is not its transaction id.
    pub hash: Hash<32>,
    /// Byte length of the transaction with its byte string envelope removed.
    pub size: u32,
}

/// The body of an endorser block: the transactions it commits to, in the order
/// the wire delivered them, which is the order the ledger applies them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndorserBlockBody {
    entries: Vec<EndorserBlockEntry>,
}

impl EndorserBlockBody {
    /// Decodes a body with nothing to check it against.
    ///
    /// Prefer [`Self::decode_announced`]. This constructor cannot tell an
    /// endorser block that committed no transactions from one the peer does not
    /// hold, because the wire gives both answers as `a0`, and it cannot tell
    /// the endorser block that was asked for from any other one the peer chose
    /// to send.
    pub fn decode(cbor: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(cbor);
        let mut entries = Vec::new();

        let declared = d
            .map()
            .map_err(|e| Error::InvalidBody(format!("map header: {e}")))?;

        let read = |d: &mut Decoder| -> Result<EndorserBlockEntry, Error> {
            let key = d
                .bytes()
                .map_err(|e| Error::InvalidBody(format!("entry key: {e}")))?;
            let hash: [u8; 32] = key.try_into().map_err(|_| {
                Error::InvalidBody(format!("entry key is {} bytes, not 32", key.len()))
            })?;
            let size = d
                .u32()
                .map_err(|e| Error::InvalidBody(format!("entry size: {e}")))?;

            Ok(EndorserBlockEntry {
                hash: Hash::from(hash),
                size,
            })
        };

        match declared {
            Some(n) => {
                for _ in 0..n {
                    entries.push(read(&mut d)?);
                }
            }
            None => loop {
                match d.datatype() {
                    Ok(Type::Break) => {
                        d.skip()
                            .map_err(|e| Error::InvalidBody(format!("break: {e}")))?;
                        break;
                    }
                    Ok(_) => entries.push(read(&mut d)?),
                    Err(e) => return Err(Error::InvalidBody(format!("entry datatype: {e}"))),
                }
            },
        }

        if d.position() != cbor.len() {
            return Err(Error::InvalidBody(format!(
                "{} trailing bytes after the map",
                cbor.len() - d.position()
            )));
        }

        Ok(Self { entries })
    }

    /// Decodes a body fetched for a specific announcement, refusing any body
    /// the announcement did not commit to, on length and on hash.
    ///
    /// Both are checked before the body is read, because a body that is not the
    /// announced endorser block is the wrong object whatever its contents turn
    /// out to be, and saying so names what went wrong on the wire rather than
    /// what is wrong with bytes nobody asked for.
    ///
    /// The announced hash is read here as blake2b-256 of the endorser block
    /// bytes exactly as the wire delivered them. CIP-0164 says of the field
    /// that the hash referenced in ranking block headers is computed from the
    /// complete endorser block structure and serves as its unique identifier,
    /// and the complete structure a leios-fetch peer sends is the
    /// `endorser_block` map of that protocol's own CDDL, which is these bytes.
    /// The sibling field fixes the same reading of which bytes are meant:
    /// `eb_size` is the length of that map, and each fixture in this module is
    /// exactly the length its own announcement gave. Blake2b-256 is the digest
    /// every other 32 byte identity on this chain uses, the transaction keys
    /// inside this very body included.
    ///
    /// Every fixture here is decoded against the announcement a real ranking
    /// block header made of it, so that reading rests on captured pairs as
    /// well as on the two specifications.
    pub fn decode_announced(
        cbor: &[u8],
        announcement: &dijkstra::EbAnnouncement,
    ) -> Result<Self, Error> {
        if cbor.len() as u64 != announcement.eb_size as u64 {
            return Err(Error::BodySize {
                announced: announcement.eb_size,
                found: cbor.len(),
            });
        }

        let found = Hasher::<256>::hash(cbor);
        if found != announcement.eb_hash {
            return Err(Error::BodyHash {
                announced: announcement.eb_hash,
                found,
            });
        }

        Self::decode(cbor)
    }

    /// The entries in wire order. The announced hash commits to that order,
    /// because the same entries in any other order hash differently at exactly
    /// the announced length.
    pub fn entries(&self) -> &[EndorserBlockEntry] {
        &self.entries
    }

    /// How many transactions this endorser block commits to.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Re-encodes the body to the bytes the wire carried.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut e = Encoder::new(&mut out);

        e.map(self.entries.len() as u64).expect("write to a vec");
        for entry in &self.entries {
            e.bytes(entry.hash.as_ref()).expect("write to a vec");
            e.u32(entry.size).expect("write to a vec");
        }

        out
    }

    /// Pairs the delivered transactions with the entries that name them.
    ///
    /// `wire` is the leios-fetch values in body order, each still wrapped in its
    /// CBOR byte string. Every transaction is checked against the entry naming
    /// it, on count, length and hash, and then decoded as a Dijkstra
    /// transaction, so the returned list is either the whole endorser block or
    /// an error naming the transaction that failed.
    ///
    /// A closure transaction is the three element `mempool_transaction`, since
    /// nothing has put it in a block yet, and what comes back here is the four
    /// element `block_transaction` the certifying ranking block will carry.
    /// Only the validity flag is added, and only as `true`, because the mempool
    /// rule admits no other value for it. Reading a closure with the block form
    /// directly is what the era remodel made impossible: it fails at the
    /// missing fourth element rather than reading three fields and inventing a
    /// verdict for the fourth.
    pub fn transactions<'b>(&self, wire: &'b [Vec<u8>]) -> Result<Vec<MultiEraTx<'b>>, Error> {
        if wire.len() != self.entries.len() {
            return Err(Error::TxCount {
                named: self.entries.len(),
                delivered: wire.len(),
            });
        }

        let mut out = Vec::with_capacity(wire.len());

        for (index, (entry, delivered)) in self.entries.iter().zip(wire.iter()).enumerate() {
            let inner = unwrap_tx(delivered).map_err(|reason| Error::Envelope { index, reason })?;

            if inner.len() as u64 != entry.size as u64 {
                return Err(Error::TxSize {
                    index,
                    named: entry.size,
                    found: inner.len(),
                });
            }

            let found = Hasher::<256>::hash(inner);
            if found != entry.hash {
                return Err(Error::TxHash {
                    index,
                    named: entry.hash,
                    found,
                });
            }

            out.push(decode_closure_transaction(index, inner)?);
        }

        Ok(out)
    }
}

/// Removes the CBOR byte string envelope a leios-fetch transaction arrives in.
///
/// The length the endorser block body records is the length of the transaction
/// inside the envelope, so the envelope is invisible to the body's accounting
/// and a caller that forgets it fails every hash and every size check at once.
pub fn unwrap_tx(wire: &[u8]) -> Result<&[u8], String> {
    let mut d = Decoder::new(wire);

    let inner = d.bytes().map_err(|e| e.to_string())?;

    if d.position() != wire.len() {
        return Err(format!(
            "{} trailing bytes after the byte string",
            wire.len() - d.position()
        ));
    }

    Ok(inner)
}

/// Reads one unwrapped closure transaction and returns it in the form a block
/// carries.
///
/// The bytes are `mempool_transaction`, three elements. The value returned is
/// `block_transaction`, four, with the validity flag set to the only value the
/// mempool rule admits. The two rules are separate types in this era precisely
/// so that neither is read as the other, and this is the one place a follower
/// crosses between them, because certification is what puts a closure
/// transaction into a block.
///
/// A four element `mempool_transaction`, which the rule also allows on
/// submission with the deprecated flag present and `true`, is accepted here
/// too, and comes out with its fields in the block's order rather than the
/// mempool's. A byte level splice would get that pair the wrong way round,
/// which is why this decodes rather than editing an array header.
fn decode_closure_transaction(index: usize, inner: &[u8]) -> Result<MultiEraTx<'_>, Error> {
    let mempool: dijkstra::MempoolTransaction =
        pallas_codec::minicbor::decode(inner).map_err(|e| Error::TxDecode {
            index,
            reason: e.to_string(),
        })?;

    Ok(MultiEraTx::Dijkstra(Box::new(std::borrow::Cow::Owned(
        mempool.to_block_transaction(),
    ))))
}

/// An announcement carried forward by [`CertificationTracker`], and the point a
/// leios-fetch request needs.
///
/// The announcement itself has no slot in it. The slot a fetch point wants is
/// the slot of the ranking block that made the announcement, which is what the
/// node's own store keys the endorser block by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncedEndorserBlock {
    /// Slot of the ranking block that announced it.
    pub slot: u64,
    pub hash: Hash<32>,
    /// Byte length the announcement commits the body to.
    pub size: u32,
}

/// What one ranking block header says about the endorsement layer.
///
/// Both answers are held together because a header can certify the pending
/// announcement and make a new one of its own in the same block, and a caller
/// that reads only one of the two loses either the payload or the next
/// announcement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderOutcome {
    /// The endorser block this header certifies, to be fetched and applied at
    /// this header's block.
    pub certified: Option<AnnouncedEndorserBlock>,
    /// The announcement this header makes, which some later header may certify.
    pub announced: Option<AnnouncedEndorserBlock>,
}

/// What a certification walk knows about an announcement waiting to be
/// certified.
///
/// A follower walking from origin is only ever in the first two states. A
/// follower resuming from a stored position can be in a third: it has not read
/// the blocks that would tell it, so it does not know. Writing that third state
/// as `None` makes it indistinguishable from knowing that nothing is pending,
/// and the two demand opposite answers the moment a certificate arrives, so
/// they are held apart here rather than collapsed into an absence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum PendingAnnouncement {
    /// Nothing is waiting. Either the most recent Leios event on the chain was
    /// a certificate that consumed the announcement before it, or the chain has
    /// carried no Leios event at all.
    #[default]
    Nothing,

    /// This announcement is waiting for the certificate that will name it.
    Waiting(AnnouncedEndorserBlock),

    /// Whether an announcement is waiting could not be established, because the
    /// walk started from a stored position and has not yet read a Leios event.
    ///
    /// This is not a permanent state. The next announcement the walk sees
    /// settles it, because an announcement replaces whatever came before. Until
    /// then a certificate cannot be answered and is refused.
    Unknown,
}

impl PendingAnnouncement {
    /// The announcement waiting for a certificate, if the walk both knows and
    /// has one.
    ///
    /// A caller that needs to tell "nothing is waiting" from "cannot tell"
    /// should match on the value instead, which is the whole reason this is not
    /// an `Option`.
    pub fn waiting(&self) -> Option<&AnnouncedEndorserBlock> {
        match self {
            Self::Waiting(eb) => Some(eb),
            _ => None,
        }
    }
}

/// The walk over ranking chain headers that decides which endorser blocks a
/// follower must fetch, and when.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificationTracker {
    pending: PendingAnnouncement,
}

impl CertificationTracker {
    /// Starts a walk from a known state, for a follower resuming from a stored
    /// position rather than from origin.
    pub fn resume_from(pending: PendingAnnouncement) -> Self {
        Self { pending }
    }

    /// What the walk currently knows about a waiting announcement.
    pub fn pending(&self) -> &PendingAnnouncement {
        &self.pending
    }

    /// Observes the next header of the ranking chain.
    ///
    /// Certification is settled before the header's own announcement is
    /// recorded, because `block_body_contains_leios_cert` names the
    /// announcement that precedes this header, never the one this header makes.
    pub fn observe(&mut self, header: &MultiEraHeader) -> Result<HeaderOutcome, Error> {
        let mut outcome = HeaderOutcome::default();

        if header.block_body_contains_leios_cert() == Some(true) {
            // The state is only consumed when it can answer. A refusal leaves
            // the walk exactly as it was, so a caller that retries the same
            // header gets the same answer rather than a different one.
            match &self.pending {
                PendingAnnouncement::Nothing => {
                    return Err(Error::CertifiesNothing {
                        slot: header.slot(),
                    });
                }
                PendingAnnouncement::Unknown => {
                    return Err(Error::CertifiesUnknown {
                        slot: header.slot(),
                    });
                }
                PendingAnnouncement::Waiting(_) => {
                    let taken = std::mem::take(&mut self.pending);

                    let PendingAnnouncement::Waiting(pending) = taken else {
                        unreachable!("just matched as waiting")
                    };

                    outcome.certified = Some(pending);
                }
            }
        }

        if let Some(announcement) = header.eb_announcement() {
            let announced = AnnouncedEndorserBlock {
                slot: header.slot(),
                hash: announcement.eb_hash,
                size: announcement.eb_size,
            };

            self.pending = PendingAnnouncement::Waiting(announced.clone());
            outcome.announced = Some(announced);
        }

        Ok(outcome)
    }
}

/// Rewrites a certifying ranking block so its transaction list is the
/// transactions of the endorser block it certifies.
///
/// A Cardano node already serves this shape to its local clients: the node to
/// client chainsync server resolves the certificate and hands over a block
/// whose body carries the endorsed transactions inline, and CIP-0164 names
/// serving a modified block with inline endorser block transactions over
/// LocalChainSync as the recommended presentation. A follower reading node to
/// node gets the unresolved block and has to do the same resolution itself.
///
/// The transaction list is replaced rather than extended. A certifying ranking
/// block carries no transactions of its own, so there is no order to choose
/// between two sets, and a block that carried both is refused rather than
/// guessed at.
///
/// `txs` are the transactions of the certified endorser block in body order,
/// already unwrapped from their leios-fetch byte string envelopes. The header
/// is left byte identical, so the block keeps its hash and its slot.
pub fn resolve_certified_block(block_cbor: &[u8], txs: &[&[u8]]) -> Result<Vec<u8>, Error> {
    let block =
        crate::MultiEraBlock::decode(block_cbor).map_err(|e| Error::InvalidBlock(e.to_string()))?;

    if block.era() != Era::Dijkstra {
        return Err(Error::NotLeiosEra { era: block.era() });
    }

    if block.header().block_body_contains_leios_cert() != Some(true) {
        return Err(Error::NotCertifying { slot: block.slot() });
    }

    refuse_certifying_block_with_own_txs(block.slot(), true, block.tx_count())?;

    replace_transaction_list(block_cbor, txs)
}

/// Rewrites a Dijkstra block's transaction list and leaves every other byte of
/// the block alone.
///
/// This is the splice on its own, without the certification checks
/// [`resolve_certified_block`] makes before it, because a follower has a second
/// reason to rewrite a list: an ordinary ranking block can carry a transaction
/// the chain already applied, and applying it a second time spends an input
/// that is already spent.
///
/// The header keeps the bytes it arrived in, so the block keeps its hash and
/// its slot, and so the stored body no longer matches what the stored header
/// commits to. That is the same trade [`resolve_certified_block`] already
/// makes, and it is why a follower doing either of these must refuse to serve
/// blocks onward.
///
/// `txs` are `mempool_transaction` bytes, three elements, which is what an
/// endorser block closure and a client submission both carry. A ranking block
/// body carries `block_transaction`, four, so each one is decoded and written
/// back in the block's form rather than copied through. Copying them through
/// would build a block that no longer decodes as its own era.
///
/// Every element other than the transaction list reaches the output through
/// this crate's own encoder rather than as the bytes it arrived in, and
/// `block_isomorphic_decoding_encoding` is what holds those two the same.
pub fn replace_transaction_list(block_cbor: &[u8], txs: &[&[u8]]) -> Result<Vec<u8>, Error> {
    let (era, mut block): (u16, dijkstra::Block) = pallas_codec::minicbor::decode(block_cbor)
        .map_err(|e| Error::InvalidBlock(e.to_string()))?;

    let mut replacement = Vec::with_capacity(txs.len());
    for (index, tx) in txs.iter().enumerate() {
        let mempool: dijkstra::MempoolTransaction =
            pallas_codec::minicbor::decode(tx).map_err(|e| Error::TxDecode {
                index,
                reason: e.to_string(),
            })?;

        replacement.push(mempool.to_block_transaction());
    }

    block.block_body.transactions = MaybeIndefArray::Def(replacement);

    Ok(pallas_codec::minicbor::to_vec((era, block)).expect("write to a vec"))
}

/// Refuses a block that both certifies an endorser block and carries
/// transactions of its own.
///
/// CIP-0164 step 5 states that a ranking block contains either a certificate
/// for the endorser block announced by its predecessor or a list of
/// transactions forming a valid extension, and never both, on the ground that
/// allowing both would force a validator to build the ledger state from every
/// endorsed transaction before it could validate the block's own. So the two
/// sets have no defined order, and a follower that met a block carrying both
/// would have to guess one.
pub fn refuse_certifying_block_with_own_txs(
    slot: u64,
    certifies: bool,
    own_tx_count: usize,
) -> Result<(), Error> {
    if certifies && own_tx_count > 0 {
        return Err(Error::CertifiesAndCarries {
            slot,
            count: own_tx_count,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MultiEraBlock;

    /// Every fixture is a real endorser block of the Musashi testnet, pulled
    /// over leios-fetch from the public relay and written down exactly as the
    /// wire delivered it. The `.ebbody` file is the body, the `.ebtxs` file is
    /// one hex transaction per line in body order, each still carrying its byte
    /// string envelope, and the `.header` file is the ranking block header that
    /// announced that body, as the chain stored it.
    struct Fixture {
        name: &'static str,
        body: &'static str,
        txs: &'static str,
        /// Transactions the body names, counted off the wire bytes before any
        /// of this module ran.
        count: usize,
        /// The ranking block header whose `eb_announcement` names the body
        /// above, which is where every announced value under test comes from.
        header: &'static str,
        /// Slot of that header, which is the slot a leios-fetch point for this
        /// body carries.
        slot: u64,
        /// Hash the chain knows that header's block by, which is blake2b-256
        /// of the header bytes and what the node's own secondary index holds
        /// for it.
        header_hash: &'static str,
    }

    const FIXTURES: &[Fixture] = &[
        Fixture {
            name: "dijkstra-eb1",
            body: include_str!("../../test_data/dijkstra-eb1.ebbody"),
            txs: include_str!("../../test_data/dijkstra-eb1.ebtxs"),
            count: 1,
            header: include_str!("../../test_data/dijkstra-eb1.header"),
            slot: 429789,
            header_hash: "abba50f39b31ca7ed67ebe72f588668073a66090a33504a76d9abbc1d6a9d3b5",
        },
        Fixture {
            name: "dijkstra-eb2",
            body: include_str!("../../test_data/dijkstra-eb2.ebbody"),
            txs: include_str!("../../test_data/dijkstra-eb2.ebtxs"),
            count: 30,
            header: include_str!("../../test_data/dijkstra-eb2.header"),
            slot: 397855,
            header_hash: "779e95c2816db83f41528b1b8260034f68c8f817c4f32edadc05de0fc16f22fb",
        },
        Fixture {
            name: "dijkstra-eb3",
            body: include_str!("../../test_data/dijkstra-eb3.ebbody"),
            txs: include_str!("../../test_data/dijkstra-eb3.ebtxs"),
            count: 425,
            header: include_str!("../../test_data/dijkstra-eb3.header"),
            slot: 376369,
            header_hash: "a4c183c4234560ae182fd5e56a021f0f4b13d5019bab155a536db9e8bbebca90",
        },
    ];

    impl Fixture {
        fn body_bytes(&self) -> Vec<u8> {
            hex::decode(self.body.trim()).expect("fixture body is hex")
        }

        fn wire_txs(&self) -> Vec<Vec<u8>> {
            self.txs
                .split_whitespace()
                .map(|l| hex::decode(l).expect("fixture tx is hex"))
                .collect()
        }

        /// The announcement this body is checked against, read out of the
        /// ranking block header that made it rather than computed here, so no
        /// test in this module compares a body to a digest of itself.
        fn announcement(&self) -> dijkstra::EbAnnouncement {
            let raw = hex::decode(self.header.trim()).expect("fixture header is hex");
            let header = dijkstra_header(&raw);

            assert_eq!(header.slot(), self.slot, "{} announcing slot", self.name);

            header
                .eb_announcement()
                .unwrap_or_else(|| panic!("{} header announces nothing", self.name))
                .clone()
        }
    }

    /// The decoded body and the wire transactions of one fixture, for the tests
    /// in this module and the ones that resolve a block with them.
    pub(super) fn fixture(index: usize) -> (EndorserBlockBody, Vec<Vec<u8>>) {
        let f = &FIXTURES[index];
        let body = EndorserBlockBody::decode_announced(&f.body_bytes(), &f.announcement())
            .unwrap_or_else(|e| panic!("{}: {e}", f.name));

        (body, f.wire_txs())
    }

    /// MUST FIRE: each `.header` fixture is the ranking block header the chain
    /// stored, at the hash the chain knows that block by, and it announces the
    /// body beside it.
    ///
    /// Every announced value the tests below run against comes out of these
    /// three files, so without this a hand written header naming whatever a
    /// body happens to hash to would satisfy the whole module and the pairing
    /// would be worth nothing.
    #[test]
    fn each_fixture_header_is_the_ranking_block_the_chain_stored() {
        for f in FIXTURES {
            let raw = hex::decode(f.header.trim()).expect("fixture header is hex");

            assert_eq!(
                Hasher::<256>::hash(&raw).to_string(),
                f.header_hash,
                "{} announcing header is not the block the chain knows",
                f.name
            );

            let announcement = f.announcement();
            let body = f.body_bytes();

            assert_eq!(
                announcement.eb_size as usize,
                body.len(),
                "{} announces a length its body does not have",
                f.name
            );
            assert_eq!(
                announcement.eb_hash,
                Hasher::<256>::hash(&body),
                "{} announces a digest its body does not have",
                f.name
            );
        }
    }

    /// MUST FIRE: each body decodes to exactly the transactions the wire named,
    /// and re-encodes to the bytes the wire carried.
    #[test]
    fn bodies_decode_to_their_wire_transaction_count_and_re_encode_byte_for_byte() {
        for f in FIXTURES {
            let raw = f.body_bytes();
            let body = EndorserBlockBody::decode_announced(&raw, &f.announcement())
                .unwrap_or_else(|e| panic!("{}: {e}", f.name));

            assert_eq!(body.len(), f.count, "{} transaction count", f.name);
            assert_eq!(
                body.entries().len(),
                f.count,
                "{} entries and len disagree",
                f.name
            );
            assert_eq!(
                body.to_cbor(),
                raw,
                "{} does not re-encode to its wire bytes",
                f.name
            );
        }
    }

    /// MUST FIRE: leios-fetch answers "I do not have it" with a well formed
    /// empty body, so the only thing separating a missing endorser block from an
    /// empty one is the length the announcement committed to.
    ///
    /// MUST NOT FIRE: the real body of the same announcement is accepted.
    #[test]
    fn an_empty_reply_is_refused_against_the_announcement_that_named_it() {
        let f = &FIXTURES[2];
        let announcement = f.announcement();

        // 0xa0 is CBOR for the empty map, which is what the relay returns for an
        // endorser block it does not hold.
        let err = EndorserBlockBody::decode_announced(&[0xa0], &announcement)
            .expect_err("an empty body must not pass as this endorser block");

        match err {
            Error::BodySize { announced, found } => {
                assert_eq!(announced, 15303);
                assert_eq!(found, 1);
            }
            other => panic!("wrong refusal: {other}"),
        }

        // and the real one is not refused
        let body = EndorserBlockBody::decode_announced(&f.body_bytes(), &announcement)
            .expect("the announced body must be accepted");
        assert_eq!(body.len(), 425);
    }

    /// MUST FIRE: a body of exactly the announced length and the announced
    /// hash that is not a map of hash to size is refused as malformed rather
    /// than read as empty.
    ///
    /// The announcement here names this body's own length and digest, so the
    /// shape is the only thing left for the refusal to be about. A body that
    /// failed the length or the hash check would be refused before its shape
    /// was read, and this test would then pass without the shape check
    /// existing at all.
    #[test]
    fn a_body_of_the_right_length_but_the_wrong_shape_is_refused() {
        // a three byte cbor array, not a map
        let malformed = [0x83, 0x01, 0x02];

        let announcement = dijkstra::EbAnnouncement {
            eb_hash: Hash::from(
                <[u8; 32]>::try_from(
                    hex::decode("2f5cd8a253b845763f1d3bd7d75dbb43f20507eb4a69af58ef42ce0202082bcc")
                        .expect("hex")
                        .as_slice(),
                )
                .expect("32 bytes"),
            ),
            eb_size: 3,
        };

        let err = EndorserBlockBody::decode_announced(&malformed, &announcement)
            .expect_err("a non-map body must be refused");

        assert!(matches!(err, Error::InvalidBody(_)), "wrong refusal: {err}");
    }

    /// MUST FIRE: a body of exactly the announced length that is a different
    /// endorser block is refused, and the refusal names both hashes.
    ///
    /// A leios-fetch request names its endorser block by `[slot, eb_hash]` and
    /// the peer answers with bytes, so the only thing tying the answer to the
    /// request is the announcement. Length alone does not tie it: another
    /// endorser block of the same length passes every later check as well,
    /// because each transaction is checked against the entry of the body that
    /// arrived rather than against the announcement.
    ///
    /// MUST NOT FIRE: the body the announcement actually names is accepted.
    #[test]
    fn a_body_of_the_announced_length_that_is_a_different_endorser_block_is_refused() {
        let f = &FIXTURES[0];
        let announcement = f.announcement();
        let raw = f.body_bytes();

        // The first byte of the single entry's key, after the map header and
        // the byte string header. Flipping it leaves a well formed body of the
        // same length naming a different transaction, which is what another
        // endorser block looks like.
        let mut other = raw.clone();
        other[3] ^= 0xff;
        assert_eq!(other.len(), raw.len(), "the mutation changed the length");
        assert_ne!(other, raw, "the mutation changed nothing");

        let err = EndorserBlockBody::decode_announced(&other, &announcement)
            .expect_err("a body that is not the announced endorser block must be refused");

        let said = err.to_string();
        assert!(
            said.contains(&announcement.eb_hash.to_string()),
            "the refusal does not name the announced hash: {said}"
        );
        assert!(
            said.contains(&Hasher::<256>::hash(&other).to_string()),
            "the refusal does not name the hash of the body that arrived: {said}"
        );

        let body = EndorserBlockBody::decode_announced(&raw, &announcement)
            .expect("the announced body must be accepted");
        assert_eq!(body.len(), f.count);
    }

    /// MUST FIRE: a body carrying exactly the entries the announcement names,
    /// in another order, is refused on hash.
    ///
    /// MUST NOT FIRE: the length check ahead of it, and the body in wire order.
    /// Every key is 32 bytes and every value keeps its own encoding, so
    /// permuting the entries moves the same bytes about and changes no byte
    /// count at all. The reordered body is therefore exactly the announced
    /// length and reaches the hash, which is the only check left that can tell
    /// the two apart. That is what makes the entry order a value the chain
    /// commits to rather than a convenience of this decoder, and it is why the
    /// length check cannot stand in for the hash check.
    #[test]
    fn a_body_with_the_announced_entries_in_another_order_is_refused_on_hash() {
        let f = &FIXTURES[2];
        let announcement = f.announcement();
        let raw = f.body_bytes();

        let body = EndorserBlockBody::decode_announced(&raw, &announcement)
            .expect("the announced body must be accepted");

        let mut sorted = body.entries().to_vec();
        sorted.sort_by(|a, b| a.hash.as_ref().cmp(b.hash.as_ref()));

        let mut reordered = Vec::new();
        let mut e = Encoder::new(&mut reordered);
        e.map(sorted.len() as u64).expect("write to a vec");
        for entry in &sorted {
            e.bytes(entry.hash.as_ref()).expect("write to a vec");
            e.u32(entry.size).expect("write to a vec");
        }

        assert_ne!(
            reordered, raw,
            "the wire already carried this body in key sorted order"
        );
        assert_eq!(
            reordered.len(),
            announcement.eb_size as usize,
            "a reordering leaves the announced length intact"
        );

        let err = EndorserBlockBody::decode_announced(&reordered, &announcement)
            .expect_err("a reordered body must be refused");

        match err {
            Error::BodyHash { announced, found } => {
                assert_eq!(announced, announcement.eb_hash);
                assert_eq!(found, Hasher::<256>::hash(&reordered));
                assert_ne!(found, announced);
            }
            other => panic!("wrong refusal: {other}"),
        }

        // and the entries in the order the wire carried them are accepted
        let again = EndorserBlockBody::decode_announced(&raw, &announcement)
            .expect("the wire order body must be accepted");
        assert_eq!(again.entries(), body.entries());
    }

    /// MUST FIRE: the delivered transactions are the ones the body names, in
    /// body order, unwrapped from their envelopes and decoded as Dijkstra.
    #[test]
    fn transactions_are_the_named_ones_in_body_order() {
        for f in FIXTURES {
            let raw = f.body_bytes();
            let body = EndorserBlockBody::decode_announced(&raw, &f.announcement()).unwrap();
            let wire = f.wire_txs();

            let txs = body
                .transactions(&wire)
                .unwrap_or_else(|e| panic!("{}: {e}", f.name));

            assert_eq!(txs.len(), f.count, "{} assembled count", f.name);

            for tx in &txs {
                assert_eq!(tx.era(), Era::Dijkstra, "{} era", f.name);
            }
        }
    }

    /// MUST FIRE: the transaction an earlier investigation named, at the index
    /// it named, with the output the ranking chain at slot 382536 spends.
    ///
    /// The endorser block keys it by the blake2b-256 of the whole transaction,
    /// `9f3ce353...`, while its transaction id is `fffa4361...`. Both are
    /// asserted here, because a follower that confuses them finds nothing and
    /// gets no error.
    #[test]
    fn the_producing_transaction_of_the_block_that_stalled_is_at_index_391() {
        let f = &FIXTURES[2];
        let raw = f.body_bytes();
        let body = EndorserBlockBody::decode_announced(&raw, &f.announcement()).unwrap();

        assert_eq!(
            body.entries()[391].hash.to_string(),
            "9f3ce353a58a5ee42503cb22c0e3379894e32b7907b67f678894855577c8f7e6",
            "the body keys a transaction by its whole hash, not its id"
        );
        assert_eq!(body.entries()[391].size, 201);

        let wire = f.wire_txs();
        let txs = body.transactions(&wire).unwrap();
        let tx = &txs[391];

        assert_eq!(
            tx.hash().to_string(),
            "fffa4361c5251f57f4840c94dcbd05164cdce9b2bcf9bbf75e2fa4baaf30cf87",
            "the transaction id differs from the endorser block key"
        );
        assert_eq!(tx.outputs().len(), 1);
        assert_eq!(tx.inputs().len(), 1);
    }

    /// MUST FIRE: a delivery in the wrong order is refused, because the body
    /// names which transaction goes where.
    #[test]
    fn a_permuted_delivery_is_refused() {
        let f = &FIXTURES[1];
        let raw = f.body_bytes();
        let body = EndorserBlockBody::decode_announced(&raw, &f.announcement()).unwrap();

        let mut wire = f.wire_txs();
        wire.swap(0, 1);

        let err = body
            .transactions(&wire)
            .expect_err("a permuted delivery must be refused");

        assert!(matches!(err, Error::TxHash { index: 0, .. }), "{err}");
    }

    /// MUST FIRE: a short delivery is refused rather than yielding the prefix
    /// that did arrive.
    #[test]
    fn a_short_delivery_is_refused() {
        let f = &FIXTURES[1];
        let raw = f.body_bytes();
        let body = EndorserBlockBody::decode_announced(&raw, &f.announcement()).unwrap();

        let mut wire = f.wire_txs();
        wire.pop();

        let err = body
            .transactions(&wire)
            .expect_err("a short delivery must be refused");

        match err {
            Error::TxCount { named, delivered } => {
                assert_eq!(named, 30);
                assert_eq!(delivered, 29);
            }
            other => panic!("wrong refusal: {other}"),
        }
    }

    /// MUST FIRE: a transaction handed over without its byte string envelope is
    /// refused, which is the shape a caller that skipped the unwrap produces.
    #[test]
    fn a_transaction_delivered_without_its_envelope_is_refused() {
        let f = &FIXTURES[0];
        let raw = f.body_bytes();
        let body = EndorserBlockBody::decode_announced(&raw, &f.announcement()).unwrap();

        let wire = f.wire_txs();
        let inner = unwrap_tx(&wire[0])
            .expect("the fixture is enveloped")
            .to_vec();
        assert_eq!(inner.len(), 229);
        assert_ne!(inner.len(), wire[0].len(), "the envelope is real");

        let err = body
            .transactions(&[inner])
            .expect_err("an unwrapped transaction must be refused");

        assert!(matches!(err, Error::Envelope { index: 0, .. }), "{err}");
    }

    /// Three of the block fixtures set a Leios header field. Blocks 17403 and
    /// 17406 end their header body with a true certificate flag and an
    /// announcement, `f5 82 5820 ...`, and block 17512 ends it `f5 f6`, a
    /// certificate with nothing announced. Every other Dijkstra fixture ends
    /// `f4 f6`. The tests in `pallas-primitives` read all three and name the
    /// announced hash and size of the first.
    ///
    /// None of the three can stand in for what is built here. A resolve test
    /// needs a certifying block whose endorser block's transactions are in
    /// hand, and the two endorser blocks those fixtures announce were never
    /// fetched, so the block under test is built from one that certifies
    /// nothing.
    ///
    /// The build is a field set and a re-encode of a real header, so
    /// everything except the two fields under test is the chain's own bytes:
    /// the slot, the issuer, the vrf proof, the body hash and the block body
    /// are untouched. What the resulting block is not is a block a node would
    /// accept, because the header signature no longer covers the header body.
    /// Nothing here checks a signature, and the two callers that would care
    /// are named in the doc comment of [`resolve_certified_block`].
    pub(super) fn with_leios_header_fields(
        block_str: &str,
        certifies: bool,
        announcement: Option<dijkstra::EbAnnouncement>,
    ) -> Vec<u8> {
        let cbor = hex::decode(block_str.trim()).unwrap();

        let (start, end) = header_span(&cbor);

        let mut header: dijkstra::Header =
            pallas_codec::minicbor::decode(&cbor[start..end]).expect("fixture header decodes");

        assert!(
            !header.header_body.block_body_contains_leios_cert,
            "the fixture must not already certify, or this helper hides what it changed"
        );
        assert!(
            matches!(
                header.header_body.eb_announcement,
                pallas_codec::utils::Nullable::Null
            ),
            "the fixture must not already announce"
        );

        header.header_body.block_body_contains_leios_cert = certifies;
        header.header_body.eb_announcement = match announcement {
            Some(a) => pallas_codec::utils::Nullable::Some(a),
            None => pallas_codec::utils::Nullable::Null,
        };

        let rebuilt = pallas_codec::minicbor::to_vec(&header).expect("write to a vec");

        let mut out = Vec::with_capacity(cbor.len() + rebuilt.len());
        out.extend_from_slice(&cbor[..start]);
        out.extend_from_slice(&rebuilt);
        out.extend_from_slice(&cbor[end..]);

        out
    }

    /// The byte span of the header within a wire block, which is
    /// `[era_tag, [header, block_body]]`.
    fn header_span(block_cbor: &[u8]) -> (usize, usize) {
        let mut d = Decoder::new(block_cbor);

        d.array().expect("era envelope");
        d.u16().expect("era tag");
        d.array().expect("block array");

        let start = d.position();
        d.skip().expect("header");

        (start, d.position())
    }

    /// The byte span of the transaction list within a wire block, whose body is
    /// `[transactions, leios_certificate/ nil, peras_certificate/ nil]`.
    pub(super) fn transaction_list_span(block_cbor: &[u8]) -> (usize, usize) {
        let mut d = Decoder::new(block_cbor);

        d.array().expect("era envelope");
        d.u16().expect("era tag");
        d.array().expect("block array");
        d.skip().expect("header");
        d.array().expect("block body array");

        let start = d.position();
        d.skip().expect("transaction list");

        (start, d.position())
    }

    /// A synthetic announcement, since the chain carries none. The size is
    /// what a body fetched for it would have to weigh.
    pub(super) fn announcement_of(hash: [u8; 32], size: u32) -> dijkstra::EbAnnouncement {
        dijkstra::EbAnnouncement {
            eb_hash: Hash::new(hash),
            eb_size: size,
        }
    }

    /// Musashi block 14935 at slot 311025, which carries no transactions of
    /// its own, made to certify. A certifying ranking block carries none, so a
    /// fixture with none is the only honest one to build this from.
    pub(super) fn certifying_block() -> Vec<u8> {
        with_leios_header_fields(include_str!("../../test_data/dijkstra16.block"), true, None)
    }

    fn header_of(block_cbor: &[u8]) -> Vec<u8> {
        let block = MultiEraBlock::decode(block_cbor).unwrap();
        block.header().cbor().to_vec()
    }

    fn dijkstra_header(raw: &[u8]) -> MultiEraHeader<'_> {
        MultiEraHeader::decode(7, None, raw).unwrap()
    }

    /// MUST FIRE and MUST NOT FIRE: the helper above changes the two fields it
    /// says it changes and no other byte of the block.
    ///
    /// Without this the synthetic fixtures underneath every certification test
    /// are unexamined, and a helper that quietly rebuilt the whole header
    /// would make those tests pass against bytes no chain ever carried.
    #[test]
    fn the_synthetic_header_changes_two_fields_and_nothing_else() {
        let plain = hex::decode(include_str!("../../test_data/dijkstra16.block").trim()).unwrap();
        let built = with_leios_header_fields(
            include_str!("../../test_data/dijkstra16.block"),
            true,
            Some(announcement_of([7; 32], 4096)),
        );

        // the tail of the header body is the only run of bytes that moved
        let common = plain
            .iter()
            .zip(built.iter())
            .take_while(|(a, b)| a == b)
            .count();

        assert_eq!(
            &plain[common..common + 2],
            &[0xf4, 0xf6],
            "the fixture's own flag and null announcement are what changed"
        );
        assert_eq!(built[common], 0xf5, "the built block certifies");

        // and everything after the header is byte identical
        let (ps, pe) = header_span(&plain);
        let (bs, be) = header_span(&built);
        assert_eq!(ps, bs);
        assert_eq!(&plain[pe..], &built[be..], "the block body is untouched");

        // the accessors read what was set
        let raw = header_of(&built);
        let header = dijkstra_header(&raw);
        assert_eq!(header.block_body_contains_leios_cert(), Some(true));
        assert_eq!(header.eb_announcement().map(|a| a.eb_size), Some(4096));
        assert_eq!(header.slot(), 311025, "the chain's own slot survives");

        // MUST NOT FIRE: asking for neither field leaves a header that reads
        // exactly as the chain wrote it
        let neither = with_leios_header_fields(
            include_str!("../../test_data/dijkstra16.block"),
            false,
            None,
        );
        assert_eq!(neither, plain, "a no-op build re-encodes byte for byte");
    }

    /// MUST FIRE: a header that certifies with nothing pending is refused. A
    /// follower that answered this with "nothing to fetch" would skip a whole
    /// endorser block and never know.
    #[test]
    fn a_header_that_certifies_nothing_pending_is_refused() {
        let block = certifying_block();
        let raw = header_of(&block);
        let header = dijkstra_header(&raw);
        assert_eq!(
            header.block_body_contains_leios_cert(),
            Some(true),
            "fixture precondition"
        );

        let mut tracker = CertificationTracker::default();
        let err = tracker
            .observe(&header)
            .expect_err("certifying with nothing pending must be refused");

        match err {
            Error::CertifiesNothing { slot } => assert_eq!(slot, 311025),
            other => panic!("wrong refusal: {other}"),
        }
    }

    /// MUST FIRE and MUST NOT FIRE together: the walk carries the most recent
    /// announcement forward, yields it at the header that certifies it, holds
    /// certification and announcement together when one header does both, and
    /// abandons an announcement superseded before any block certified it.
    ///
    /// The headers are four real Musashi w36 blocks in chain order, each with
    /// its Leios fields set as this walk needs them, since the chain itself
    /// sets neither field on any block.
    #[test]
    fn certification_walks_the_headers_and_abandons_a_superseded_announcement() {
        let earlier = AnnouncedEndorserBlock {
            slot: 86000,
            hash: Hash::new([9; 32]),
            size: 1234,
        };

        let mut tracker =
            CertificationTracker::resume_from(PendingAnnouncement::Waiting(earlier.clone()));

        // block 4255, slot 86463: certifies the carried announcement and makes
        // one of its own in the same header.
        let block2 = with_leios_header_fields(
            include_str!("../../test_data/dijkstra1.block"),
            true,
            Some(announcement_of([0x2b; 32], 28519)),
        );
        let raw2 = header_of(&block2);
        let out = tracker.observe(&dijkstra_header(&raw2)).unwrap();
        assert_eq!(out.certified.as_ref(), Some(&earlier));
        let announced2 = out.announced.expect("4255 announces");
        assert_eq!(announced2.slot, 86463);
        assert_eq!(
            announced2.hash.to_string(),
            "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
        );
        assert_eq!(announced2.size, 28519);
        assert_eq!(tracker.pending().waiting(), Some(&announced2));

        // block 14212, slot 289441: neither certifies nor announces, and must
        // not disturb what is pending. This one is the chain's own header,
        // unmodified, so the walk is exercised against real bytes as well.
        let raw5 = header_of(
            &hex::decode(include_str!("../../test_data/dijkstra4.block").trim()).unwrap(),
        );
        let out = tracker.observe(&dijkstra_header(&raw5)).unwrap();
        assert_eq!(out, HeaderOutcome::default());
        assert_eq!(tracker.pending().waiting(), Some(&announced2));

        // block 14278, slot 291625: announces without certifying, so 4255's
        // announcement is abandoned and never fetched.
        let block7 = with_leios_header_fields(
            include_str!("../../test_data/dijkstra6.block"),
            false,
            Some(announcement_of([0x70; 32], 512)),
        );
        let raw7 = header_of(&block7);
        let out = tracker.observe(&dijkstra_header(&raw7)).unwrap();
        assert_eq!(out.certified, None, "14278 certifies nothing");
        let announced7 = out.announced.expect("14278 announces");
        assert_eq!(
            announced7.hash.to_string(),
            "7070707070707070707070707070707070707070707070707070707070707070"
        );
        assert_eq!(tracker.pending().waiting(), Some(&announced7));

        // block 14936, slot 311104: announces again, so 14278's announcement is
        // abandoned in turn.
        let block9 = with_leios_header_fields(
            include_str!("../../test_data/dijkstra7.block"),
            false,
            Some(announcement_of([0x17; 32], 74668)),
        );
        let raw9 = header_of(&block9);
        let out = tracker.observe(&dijkstra_header(&raw9)).unwrap();
        assert_eq!(out.certified, None);
        let announced9 = out.announced.expect("14936 announces");
        assert_eq!(announced9.slot, 311104);
        assert_eq!(announced9.size, 74668);
        assert_eq!(tracker.pending().waiting(), Some(&announced9));
    }

    /// MUST NOT FIRE: a pre-Leios header certifies nothing and announces
    /// nothing, and must not be read as certifying with nothing pending either.
    #[test]
    fn a_pre_leios_header_certifies_nothing() {
        let cbor = hex::decode(include_str!("../../test_data/conway1.block").trim()).unwrap();
        let block = MultiEraBlock::decode(&cbor).unwrap();
        let raw = block.header().cbor().to_vec();
        let header = MultiEraHeader::decode(6, None, &raw).unwrap();
        assert_eq!(
            header.block_body_contains_leios_cert(),
            None,
            "fixture precondition"
        );

        let mut tracker = CertificationTracker::resume_from(PendingAnnouncement::Waiting(
            AnnouncedEndorserBlock {
                slot: 1,
                hash: Hash::new([1; 32]),
                size: 5,
            },
        ));

        let out = tracker.observe(&header).unwrap();
        assert_eq!(out, HeaderOutcome::default());
        assert!(
            tracker.pending().waiting().is_some(),
            "pending is left alone"
        );
    }

    /// MUST FIRE: a walk that resumed without establishing whether an
    /// announcement was waiting refuses a certificate, and says that is why.
    ///
    /// MUST NOT FIRE: it must not be refused as certifying nothing. The two
    /// refusals mean opposite things. Certifying nothing is a chain that broke
    /// its own inclusion rule and the follower is right to stop for good.
    /// Certifying while the walk cannot tell is the follower's own cold start,
    /// which the next announcement repairs, and reporting it as the first would
    /// send an operator looking for a chain fault that is not there.
    #[test]
    fn a_walk_that_cannot_tell_refuses_a_certificate_as_its_own_ignorance() {
        let block = certifying_block();
        let raw = header_of(&block);
        let header = dijkstra_header(&raw);
        assert_eq!(
            header.block_body_contains_leios_cert(),
            Some(true),
            "fixture precondition"
        );

        let mut unknown = CertificationTracker::resume_from(PendingAnnouncement::Unknown);
        let err = unknown
            .observe(&header)
            .expect_err("a walk that cannot tell must refuse");

        match err {
            Error::CertifiesUnknown { slot } => assert_eq!(slot, 311025),
            other => panic!("wrong refusal: {other}"),
        }

        let mut nothing = CertificationTracker::resume_from(PendingAnnouncement::Nothing);
        let err = nothing
            .observe(&header)
            .expect_err("a walk that knows nothing is waiting must refuse");

        assert!(
            matches!(err, Error::CertifiesNothing { .. }),
            "knowing nothing is waiting is a different refusal: {err}"
        );
    }

    /// MUST FIRE: not knowing is temporary. An announcement settles the walk,
    /// and the certificate that follows resolves to that announcement rather
    /// than to a refusal.
    ///
    /// MUST NOT FIRE: the refusal must not survive the announcement, because a
    /// follower that stayed refused after learning the answer could never
    /// resume at all.
    #[test]
    fn an_announcement_settles_a_walk_that_could_not_tell() {
        let mut tracker = CertificationTracker::resume_from(PendingAnnouncement::Unknown);

        // block 14278, slot 291625: announces without certifying.
        let block7 = with_leios_header_fields(
            include_str!("../../test_data/dijkstra6.block"),
            false,
            Some(announcement_of([0x70; 32], 512)),
        );
        let raw7 = header_of(&block7);
        let out = tracker.observe(&dijkstra_header(&raw7)).unwrap();
        let announced = out.announced.expect("14278 announces");
        assert_eq!(
            tracker.pending(),
            &PendingAnnouncement::Waiting(announced.clone()),
            "the announcement replaces not knowing"
        );

        // block 14935, slot 311025: certifies. Out of chain order against the
        // one above only in that it announces nothing, which the tracker
        // neither knows nor needs to, because it is the announcement and not
        // the slot that decides what a certificate resolves to.
        let block8 = certifying_block();
        let raw8 = header_of(&block8);
        let out = tracker.observe(&dijkstra_header(&raw8)).unwrap();
        assert_eq!(out.certified, Some(announced));
    }

    /// MUST NOT FIRE: a refusal leaves the walk as it was, so the same header
    /// observed again gives the same answer rather than a different one.
    #[test]
    fn a_refused_certificate_does_not_change_the_walk() {
        let block = certifying_block();
        let raw = header_of(&block);
        let header = dijkstra_header(&raw);

        let mut tracker = CertificationTracker::resume_from(PendingAnnouncement::Unknown);

        assert!(tracker.observe(&header).is_err());
        assert_eq!(tracker.pending(), &PendingAnnouncement::Unknown);

        let err = tracker
            .observe(&header)
            .expect_err("the second look must refuse the same way");

        assert!(matches!(err, Error::CertifiesUnknown { .. }), "{err}");
    }

    /// MUST FIRE on the one illegal combination, MUST NOT FIRE on the other
    /// three. CIP-0164 forbids a ranking block that both certifies and carries
    /// its own transactions, and no such block exists on this chain, so the
    /// only way this refusal is ever exercised is here.
    #[test]
    fn a_certifying_block_with_its_own_transactions_is_refused() {
        assert!(refuse_certifying_block_with_own_txs(10, false, 0).is_ok());
        assert!(refuse_certifying_block_with_own_txs(10, false, 426).is_ok());
        assert!(refuse_certifying_block_with_own_txs(10, true, 0).is_ok());

        let err = refuse_certifying_block_with_own_txs(10, true, 426)
            .expect_err("certifying and carrying must be refused");

        match err {
            Error::CertifiesAndCarries { slot, count } => {
                assert_eq!(slot, 10);
                assert_eq!(count, 426);
            }
            other => panic!("wrong refusal: {other}"),
        }
    }
}

#[cfg(test)]
mod resolve_tests {
    use super::tests::{certifying_block, fixture, transaction_list_span};
    use super::*;
    use crate::MultiEraBlock;

    /// MUST FIRE: a certifying block resolves to a block carrying the endorser
    /// block's transactions, with its header and therefore its hash untouched.
    #[test]
    fn a_certifying_block_resolves_to_the_endorser_blocks_transactions() {
        let raw = certifying_block();
        let before = MultiEraBlock::decode(&raw).unwrap();
        assert_eq!(before.header().block_body_contains_leios_cert(), Some(true));
        assert_eq!(before.tx_count(), 0, "fixture precondition");

        let (body, wire) = fixture(2);
        let txs = body.transactions(&wire).unwrap();
        let inner: Vec<&[u8]> = wire.iter().map(|w| unwrap_tx(w).unwrap()).collect();

        let resolved_cbor = resolve_certified_block(&raw, &inner).expect("must resolve");
        let after = MultiEraBlock::decode(&resolved_cbor).expect("resolved block must decode");

        assert_eq!(after.tx_count(), 425);
        assert_eq!(after.era(), Era::Dijkstra);

        // the header, and so the block hash and slot, are untouched
        assert_eq!(after.header().cbor(), before.header().cbor());
        assert_eq!(after.hash(), before.hash());
        assert_eq!(after.slot(), before.slot());

        // and the transactions are the endorser block's, in its order
        let after_txs = after.txs();
        assert_eq!(after_txs.len(), txs.len());
        for (i, (a, b)) in after_txs.iter().zip(txs.iter()).enumerate() {
            assert_eq!(a.hash(), b.hash(), "transaction {i}");
        }
        assert_eq!(
            after_txs[391].hash().to_string(),
            "fffa4361c5251f57f4840c94dcbd05164cdce9b2bcf9bbf75e2fa4baaf30cf87"
        );
    }

    /// MUST FIRE: the one transaction case, so the array header width is not
    /// only ever exercised at one size.
    #[test]
    fn a_single_transaction_endorser_block_resolves() {
        let raw = certifying_block();
        let (_, wire) = fixture(0);
        let inner: Vec<&[u8]> = wire.iter().map(|w| unwrap_tx(w).unwrap()).collect();

        let resolved_cbor = resolve_certified_block(&raw, &inner).unwrap();
        let after = MultiEraBlock::decode(&resolved_cbor).unwrap();

        assert_eq!(after.tx_count(), 1);
        assert_eq!(after.txs()[0].inputs().len(), 1);
    }

    /// MUST NOT FIRE: a block that certifies nothing is refused rather than
    /// silently given somebody else's transactions.
    #[test]
    fn a_block_that_certifies_nothing_is_refused() {
        let raw = hex::decode(include_str!("../../test_data/dijkstra6.block").trim()).unwrap();
        let block = MultiEraBlock::decode(&raw).unwrap();
        assert_eq!(block.header().block_body_contains_leios_cert(), Some(false));
        assert_eq!(block.tx_count(), 4, "fixture precondition");

        let (_, wire) = fixture(0);
        let inner: Vec<&[u8]> = wire.iter().map(|w| unwrap_tx(w).unwrap()).collect();

        let err = resolve_certified_block(&raw, &inner)
            .expect_err("a non-certifying block must be refused");

        assert!(matches!(err, Error::NotCertifying { .. }), "{err}");
    }

    /// MUST FIRE: the splice replaces the transaction list.
    ///
    /// MUST NOT FIRE: it replaces nothing else. The two certificate slots that
    /// follow the list in a w36 block body have to come through byte for byte.
    ///
    /// This is the assertion the deleted `invalid_transactions` element costs.
    /// The body led with that element until the w36 ledger removed it, so a
    /// walk that still steps over one element before reading the list returns
    /// the span of the Leios certificate instead, and the splice writes a
    /// transaction list where a certificate belongs while leaving the real list
    /// untouched. The count assertion alone would not settle it, since a wrong
    /// span can still produce the count asked for, so the trailing bytes are
    /// pinned here separately.
    #[test]
    fn the_splice_replaces_the_transaction_list_and_not_a_certificate_slot() {
        let raw = hex::decode(include_str!("../../test_data/dijkstra6.block").trim()).unwrap();
        let before = MultiEraBlock::decode(&raw).unwrap();
        assert_eq!(before.tx_count(), 4, "fixture precondition");

        // this fixture's body ends with a nil Leios certificate and a nil Peras
        // certificate, which is what every block on this chain carries
        assert_eq!(&raw[raw.len() - 2..], &[0xf6, 0xf6], "fixture precondition");

        let spliced = replace_transaction_list(&raw, &[]).expect("the splice must succeed");
        let after = MultiEraBlock::decode(&spliced).expect("the spliced block must decode");

        assert_eq!(after.tx_count(), 0);
        assert_eq!(after.era(), Era::Dijkstra);
        assert_eq!(
            after.header().cbor(),
            before.header().cbor(),
            "the header is untouched"
        );

        // the empty list is one byte, so everything the certificate slots hold
        // sits at the same distance from the end as it did before
        assert_eq!(
            &spliced[spliced.len() - 2..],
            &[0xf6, 0xf6],
            "both certificate slots survive the splice"
        );

        // Both slots are nil on every block of this chain, so the assertion
        // above pins a value that a splice writing its own fresh nils would
        // satisfy by accident. Give the Peras slot a value nothing would
        // produce on its own and check it survives the same splice. The slot is
        // a byte string, so replacing the body's trailing `f6` with one is the
        // whole edit.
        let mut with_peras = raw[..raw.len() - 1].to_vec();
        with_peras.extend_from_slice(&[0x44, 0xde, 0xad, 0xbe, 0xef]);
        assert!(
            MultiEraBlock::decode(&with_peras).is_ok(),
            "a block carrying a Peras certificate must still decode"
        );

        let kept = replace_transaction_list(&with_peras, &[]).expect("the splice must succeed");
        MultiEraBlock::decode(&kept).expect("the spliced block must decode");
        assert_eq!(
            &kept[kept.len() - 5..],
            &[0x44, 0xde, 0xad, 0xbe, 0xef],
            "the Peras certificate comes through the splice byte for byte"
        );

        // and the whole prefix through the body array header is unchanged
        let (start, _) = transaction_list_span(&raw);
        assert_eq!(&spliced[..start], &raw[..start]);
        assert_eq!(
            spliced.len(),
            start + 3,
            "an empty list plus the two nil certificate slots is three bytes"
        );
    }

    /// MUST FIRE: what the splice writes is the block's four element
    /// transaction form, not the three element form the closure arrived in.
    ///
    /// MUST NOT FIRE: the transaction body is not rewritten, so the
    /// transaction keeps the hash the endorser block named it by.
    #[test]
    fn the_spliced_transactions_carry_the_blocks_validity_flag() {
        let raw = certifying_block();
        let (body, wire) = fixture(0);
        let inner: Vec<&[u8]> = wire.iter().map(|w| unwrap_tx(w).unwrap()).collect();

        let resolved = resolve_certified_block(&raw, &inner).unwrap();
        let after = MultiEraBlock::decode(&resolved).unwrap();

        let txs = after.txs();
        assert_eq!(txs.len(), 1);
        assert!(
            txs[0].is_valid(),
            "the mempool form admits no verdict but valid"
        );
        assert_eq!(
            txs[0].hash(),
            body.transactions(&wire).unwrap()[0].hash(),
            "the body the endorser block named it by is unchanged"
        );

        // the wire form was three elements and what the block carries is four
        assert_eq!(inner[0][0], 0x83, "the closure carries three elements");
        let (start, _) = transaction_list_span(&resolved);
        assert_eq!(
            resolved[start + 1],
            0x84,
            "the block carries four, the array header immediately after the list header"
        );
    }

    /// MUST NOT FIRE: a pre-Leios block is refused by era rather than having
    /// its body rewritten.
    #[test]
    fn a_pre_leios_block_is_refused() {
        let raw = hex::decode(include_str!("../../test_data/conway1.block").trim()).unwrap();

        let err =
            resolve_certified_block(&raw, &[]).expect_err("a Conway block must not be resolved");

        assert!(matches!(err, Error::NotLeiosEra { .. }), "{err}");
    }

    /// MUST FIRE: resolving with no transactions gives an empty block rather
    /// than an error, because an endorser block genuinely may commit to none,
    /// and the refusal that protects against a missing one is the announced
    /// size check at fetch time, not this.
    #[test]
    fn resolving_with_no_transactions_gives_an_empty_block() {
        let raw = certifying_block();
        let resolved_cbor = resolve_certified_block(&raw, &[]).unwrap();
        let after = MultiEraBlock::decode(&resolved_cbor).unwrap();
        assert_eq!(after.tx_count(), 0);
    }
}
