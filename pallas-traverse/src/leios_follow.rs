//! The certification walk over ranking block headers, and the rewrite of a
//! certified ranking block with its endorser block's transactions.

use pallas_codec::minicbor::Decoder;
use pallas_codec::utils::MaybeIndefArray;
use pallas_crypto::hash::Hash;
use pallas_primitives::dijkstra;

use crate::leios::{EndorserBlockBody, Error};
use crate::{Era, MultiEraHeader};

/// One entry of an endorser block body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndorserBlockEntry {
    /// blake2b-256 of the whole transaction, which is not its transaction id.
    pub hash: Hash<32>,
    /// Byte length of the transaction with its byte string envelope removed.
    pub size: u32,
}

impl EndorserBlockBody {
    /// The entries in body order.
    pub fn entries(&self) -> Vec<EndorserBlockEntry> {
        self.iter()
            .map(|(hash, size)| EndorserBlockEntry {
                hash: *hash,
                size: *size,
            })
            .collect()
    }
}

/// Removes the CBOR byte string envelope a leios-fetch transaction arrives in,
/// which the lengths in an endorser block body do not count.
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

/// An announcement carried forward by [`CertificationTracker`], and the point a
/// leios-fetch request needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncedEndorserBlock {
    /// Slot of the ranking block that announced it, which is the slot a
    /// leios-fetch point carries.
    pub slot: u64,
    /// Digest the announcement commits the body to.
    pub hash: Hash<32>,
    /// Byte length the announcement commits the body to.
    pub size: u32,
}

/// Both of the things one ranking block header says about the endorsement
/// layer, held together because a header can certify the pending announcement
/// and make a new one of its own in the same block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderOutcome {
    /// The endorser block this header certifies, to be fetched and applied at
    /// this header's block.
    pub certified: Option<AnnouncedEndorserBlock>,
    /// The announcement this header makes, which some later header may certify.
    pub announced: Option<AnnouncedEndorserBlock>,
}

/// What a certification walk knows about an announcement waiting to be
/// certified, where not knowing is a state of its own, because a walk that
/// resumed from a stored position must not be read as knowing that nothing is
/// pending.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum PendingAnnouncement {
    /// Nothing is waiting, either because a certificate consumed the last
    /// announcement or because the chain has carried no Leios event.
    #[default]
    Nothing,

    /// This announcement is waiting for the certificate that will name it.
    Waiting(AnnouncedEndorserBlock),

    /// The walk resumed from a stored position and has not yet read a Leios
    /// event, so a certificate cannot be answered and is refused until the next
    /// announcement settles it.
    Unknown,
}

impl PendingAnnouncement {
    /// The announcement waiting for a certificate, if the walk both knows and
    /// has one.
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

    /// Observes the next header of the ranking chain, settling certification
    /// before the header's own announcement is recorded, because
    /// `block_body_contains_leios_cert` names the announcement that precedes
    /// this header.
    pub fn observe(&mut self, header: &MultiEraHeader) -> Result<HeaderOutcome, Error> {
        let mut outcome = HeaderOutcome::default();

        if header.block_body_contains_leios_cert() == Some(true) {
            // A refusal leaves the walk as it was, so retrying the same header
            // gives the same answer.
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
/// transactions of the endorser block it certifies, given in body order and
/// already unwrapped from their leios-fetch envelopes.
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

/// Rewrites a Dijkstra block's transaction list from `mempool_transaction`
/// bytes, leaving the header in the bytes it arrived in, so the stored body no
/// longer matches what the stored header commits to.
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

        replacement.push(dijkstra::BlockTransaction::from(mempool));
    }

    block.block_body.transactions = MaybeIndefArray::Def(replacement);

    Ok(pallas_codec::minicbor::to_vec((era, block)).expect("write to a vec"))
}

/// Refuses a block that both certifies an endorser block and carries
/// transactions of its own, a combination the chain inclusion rule forbids and
/// for which the two sets have no defined order.
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
    use pallas_crypto::hash::Hasher;

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
            header: include_str!("../../test_data/dijkstra-eb1.header"),
            slot: 429789,
            header_hash: "abba50f39b31ca7ed67ebe72f588668073a66090a33504a76d9abbc1d6a9d3b5",
        },
        Fixture {
            name: "dijkstra-eb2",
            body: include_str!("../../test_data/dijkstra-eb2.ebbody"),
            txs: include_str!("../../test_data/dijkstra-eb2.ebtxs"),
            header: include_str!("../../test_data/dijkstra-eb2.header"),
            slot: 397855,
            header_hash: "779e95c2816db83f41528b1b8260034f68c8f817c4f32edadc05de0fc16f22fb",
        },
        Fixture {
            name: "dijkstra-eb3",
            body: include_str!("../../test_data/dijkstra-eb3.ebbody"),
            txs: include_str!("../../test_data/dijkstra-eb3.ebtxs"),
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

    /// Every announced value this module runs against comes out of the
    /// `.header` fixtures, so a hand written header naming whatever a body
    /// happens to hash to would otherwise satisfy all of it.
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

    /// Re-encodes a real header with the two Leios fields set, so the result
    /// is not a block a node would accept, because the header signature no
    /// longer covers the header body.
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

    /// Every certification test rests on `with_leios_header_fields`, and a
    /// version of it that quietly rebuilt the whole header would make those
    /// tests pass against bytes no chain ever carried.
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

        // asking for neither field leaves a header that reads exactly as the
        // chain wrote it
        let neither = with_leios_header_fields(
            include_str!("../../test_data/dijkstra16.block"),
            false,
            None,
        );
        assert_eq!(neither, plain, "a no-op build re-encodes byte for byte");
    }

    /// A follower that answered this with "nothing to fetch" would skip a whole
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

    /// The headers are four real Musashi blocks in chain order, each with its
    /// Leios fields set as this walk needs them, since the chain itself sets
    /// neither field on any block.
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

    /// The two refusals mean opposite things. Certifying with nothing pending
    /// is a chain that broke its own inclusion rule, and certifying while the
    /// walk cannot tell is the follower's own cold start.
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

    /// A follower whose refusal survived the announcement could never resume at
    /// all.
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

    /// No block on this chain both certifies and carries its own transactions,
    /// so the four combinations are built here rather than found.
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

    /// The one transaction case, so the array header width is not only ever
    /// exercised at one size.
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

    /// A splice that stepped over the wrong body element would write a
    /// transaction list where a certificate belongs and still produce the count
    /// asked for, so the trailing bytes are pinned separately.
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

    #[test]
    fn a_pre_leios_block_is_refused() {
        let raw = hex::decode(include_str!("../../test_data/conway1.block").trim()).unwrap();

        let err =
            resolve_certified_block(&raw, &[]).expect_err("a Conway block must not be resolved");

        assert!(matches!(err, Error::NotLeiosEra { .. }), "{err}");
    }

    /// An endorser block may commit to no transactions, and what refuses a
    /// missing one is the announced size check at fetch time rather than this.
    #[test]
    fn resolving_with_no_transactions_gives_an_empty_block() {
        let raw = certifying_block();
        let resolved_cbor = resolve_certified_block(&raw, &[]).unwrap();
        let after = MultiEraBlock::decode(&resolved_cbor).unwrap();
        assert_eq!(after.tx_count(), 0);
    }
}
