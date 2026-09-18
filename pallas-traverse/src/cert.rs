use pallas_primitives::{alonzo, conway};

#[cfg(feature = "unstable")]
use std::ops::Deref;

#[cfg(feature = "unstable")]
use pallas_primitives::dijkstra;

use crate::{Era, MultiEraCert, MultiEraCertKind, MultiEraPoolRegistration};

/// Reads the fifteen certificates Conway's type and every later era's both
/// name, under the era module given. The pool registration arm names every
/// field of its own era, taking the fields only a later era has as further
/// names, so a field new in an era reaches this match rather than passing
/// through it. An era that names more certificates passes them as further
/// arms, so each match stays exhaustive over its own type.
macro_rules! shared_certs {
    (
        $cert:expr, $era:ident,
        pool_registration { $($extra:ident),* $(,)? } => $bls:expr
        $(, $pattern:pat => $kind:expr)* $(,)?
    ) => {
        match $cert {
            $era::Certificate::StakeDelegation(credential, pool) => {
                MultiEraCertKind::StakeDelegation(credential, pool)
            }
            $era::Certificate::PoolRegistration {
                operator,
                vrf_keyhash,
                pledge,
                cost,
                margin,
                reward_account,
                pool_owners,
                relays,
                pool_metadata,
                $($extra,)*
            } => MultiEraCertKind::PoolRegistration(MultiEraPoolRegistration {
                operator,
                vrf_keyhash,
                pledge: *pledge,
                cost: *cost,
                margin,
                reward_account,
                pool_owners: &pool_owners[..],
                relays: &relays[..],
                pool_metadata: pool_metadata.as_ref(),
                #[cfg(feature = "unstable")]
                bls_key: $bls,
            }),
            $era::Certificate::PoolRetirement(pool, epoch) => {
                MultiEraCertKind::PoolRetirement(pool, *epoch)
            }
            $era::Certificate::Reg(credential, coin) => {
                MultiEraCertKind::Reg(credential, *coin)
            }
            $era::Certificate::UnReg(credential, coin) => {
                MultiEraCertKind::UnReg(credential, *coin)
            }
            $era::Certificate::VoteDeleg(credential, drep) => {
                MultiEraCertKind::VoteDeleg(credential, drep)
            }
            $era::Certificate::StakeVoteDeleg(credential, pool, drep) => {
                MultiEraCertKind::StakeVoteDeleg(credential, pool, drep)
            }
            $era::Certificate::StakeRegDeleg(credential, pool, coin) => {
                MultiEraCertKind::StakeRegDeleg(credential, pool, *coin)
            }
            $era::Certificate::VoteRegDeleg(credential, drep, coin) => {
                MultiEraCertKind::VoteRegDeleg(credential, drep, *coin)
            }
            $era::Certificate::StakeVoteRegDeleg(credential, pool, drep, coin) => {
                MultiEraCertKind::StakeVoteRegDeleg(credential, pool, drep, *coin)
            }
            $era::Certificate::AuthCommitteeHot(cold, hot) => {
                MultiEraCertKind::AuthCommitteeHot(cold, hot)
            }
            $era::Certificate::ResignCommitteeCold(cold, anchor) => {
                MultiEraCertKind::ResignCommitteeCold(cold, anchor.as_ref())
            }
            $era::Certificate::RegDRepCert(credential, coin, anchor) => {
                MultiEraCertKind::RegDRep(credential, *coin, anchor.as_ref())
            }
            $era::Certificate::UnRegDRepCert(credential, coin) => {
                MultiEraCertKind::UnRegDRep(credential, *coin)
            }
            $era::Certificate::UpdateDRepCert(credential, anchor) => {
                MultiEraCertKind::UpdateDRep(credential, anchor.as_ref())
            }
            $($pattern => $kind,)*
        }
    };
}

/// Reads the seven certificates the type serving Shelley through Babbage
/// names, two of which no later era's type has a name for.
fn alonzo_cert_kind(cert: &alonzo::Certificate) -> MultiEraCertKind<'_> {
    match cert {
        alonzo::Certificate::StakeRegistration(credential) => {
            MultiEraCertKind::StakeRegistration(credential)
        }
        alonzo::Certificate::StakeDeregistration(credential) => {
            MultiEraCertKind::StakeDeregistration(credential)
        }
        alonzo::Certificate::StakeDelegation(credential, pool) => {
            MultiEraCertKind::StakeDelegation(credential, pool)
        }
        alonzo::Certificate::PoolRegistration {
            operator,
            vrf_keyhash,
            pledge,
            cost,
            margin,
            reward_account,
            pool_owners,
            relays,
            pool_metadata,
        } => MultiEraCertKind::PoolRegistration(MultiEraPoolRegistration {
            operator,
            vrf_keyhash,
            pledge: *pledge,
            cost: *cost,
            margin,
            reward_account,
            pool_owners: &pool_owners[..],
            relays: &relays[..],
            pool_metadata: pool_metadata.as_ref(),
            #[cfg(feature = "unstable")]
            bls_key: BlsKeySlot::NoSlot,
        }),
        alonzo::Certificate::PoolRetirement(pool, epoch) => {
            MultiEraCertKind::PoolRetirement(pool, *epoch)
        }
        alonzo::Certificate::GenesisKeyDelegation(genesis, delegate, vrf) => {
            MultiEraCertKind::GenesisKeyDelegation(genesis, delegate, vrf)
        }
        alonzo::Certificate::MoveInstantaneousRewardsCert(rewards) => {
            MultiEraCertKind::MoveInstantaneousRewards(rewards)
        }
    }
}

/// Reads every certificate Conway's type names, the fifteen a later era's type
/// names too and the two it keeps from the era before.
fn conway_cert_kind(cert: &conway::Certificate) -> MultiEraCertKind<'_> {
    shared_certs!(
        cert,
        conway,
        pool_registration {} => BlsKeySlot::NoSlot,
        conway::Certificate::StakeRegistration(credential) =>
            MultiEraCertKind::StakeRegistration(credential),
        conway::Certificate::StakeDeregistration(credential) =>
            MultiEraCertKind::StakeDeregistration(credential),
    )
}

/// Reads every certificate the Dijkstra type names.
#[cfg(feature = "unstable")]
fn dijkstra_cert_kind(cert: &dijkstra::Certificate) -> MultiEraCertKind<'_> {
    shared_certs!(
        cert,
        dijkstra,
        pool_registration { bls_key } => dijkstra_bls_slot(bls_key),
    )
}

/// Reads the slot a Dijkstra pool registration writes its BLS key in, where
/// an omitted slot, a nil slot and a key are three results.
#[cfg(feature = "unstable")]
fn dijkstra_bls_slot(
    bls_key: &Option<pallas_primitives::Nullable<dijkstra::BlsKey>>,
) -> BlsKeySlot<'_> {
    match bls_key {
        None => BlsKeySlot::NoSlot,
        Some(pallas_primitives::Nullable::Some(k)) => BlsKeySlot::Key(k),
        Some(_) => BlsKeySlot::Null,
    }
}

impl MultiEraCert<'_> {
    pub fn as_alonzo(&self) -> Option<&alonzo::Certificate> {
        match self {
            MultiEraCert::AlonzoCompatible(x) => Some(x),
            _ => None,
        }
    }

    pub fn as_conway(&self) -> Option<&conway::Certificate> {
        match self {
            MultiEraCert::Conway(x) => Some(x),
            _ => None,
        }
    }

    #[cfg(feature = "unstable")]
    pub fn as_dijkstra(&self) -> Option<&dijkstra::Certificate> {
        match self {
            MultiEraCert::Dijkstra(x) => Some(x),
            _ => None,
        }
    }

    pub fn era(&self) -> Option<Era> {
        match self {
            MultiEraCert::NotApplicable => None,
            // The Alonzo type serves Shelley through Babbage, so this arm names the
            // first era of that group.
            MultiEraCert::AlonzoCompatible(_) => Some(Era::Alonzo),
            MultiEraCert::Conway(_) => Some(Era::Conway),
            #[cfg(feature = "unstable")]
            MultiEraCert::Dijkstra(_) => Some(Era::Dijkstra),
        }
    }

    #[cfg(feature = "unstable")]
    pub fn bls_key(&self) -> BlsKeySlot<'_> {
        match self {
            MultiEraCert::Dijkstra(x) => match x.deref().deref() {
                dijkstra::Certificate::PoolRegistration { bls_key, .. } => {
                    dijkstra_bls_slot(bls_key)
                }
                _ => BlsKeySlot::NotAPoolRegistration,
            },
            MultiEraCert::AlonzoCompatible(x) => match x.deref().deref() {
                alonzo::Certificate::PoolRegistration { .. } => BlsKeySlot::NoSlot,
                _ => BlsKeySlot::NotAPoolRegistration,
            },
            MultiEraCert::Conway(x) => match x.deref().deref() {
                conway::Certificate::PoolRegistration { .. } => BlsKeySlot::NoSlot,
                _ => BlsKeySlot::NotAPoolRegistration,
            },
            MultiEraCert::NotApplicable => BlsKeySlot::NotAPoolRegistration,
        }
    }

    /// Returns what this certificate certifies, with each payload in a type
    /// every era carrying that kind shares, or None for an era that carries
    /// no certificates at all.
    pub fn kind(&self) -> Option<MultiEraCertKind<'_>> {
        match self {
            MultiEraCert::NotApplicable => None,
            MultiEraCert::AlonzoCompatible(x) => Some(alonzo_cert_kind(x)),
            MultiEraCert::Conway(x) => Some(conway_cert_kind(x)),
            #[cfg(feature = "unstable")]
            MultiEraCert::Dijkstra(x) => Some(dijkstra_cert_kind(x)),
        }
    }
}

#[cfg(feature = "unstable")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlsKeySlot<'b> {
    NotAPoolRegistration,
    /// A pool registration with no BLS key slot, or one the transaction omitted.
    NoSlot,
    /// A pool registration that wrote the slot as nil.
    Null,
    Key(&'b dijkstra::BlsKey),
}

#[cfg(feature = "unstable")]
impl BlsKeySlot<'_> {
    pub fn key(&self) -> Option<&dijkstra::BlsKey> {
        match self {
            BlsKeySlot::Key(k) => Some(k),
            BlsKeySlot::NotAPoolRegistration | BlsKeySlot::NoSlot | BlsKeySlot::Null => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use pallas_primitives::{
        RationalNumber, Relay,
        conway::{Anchor, DRep, StakeCredential::AddrKeyhash},
    };

    use super::*;
    use crate::MultiEraBlock;

    /// Names the arm a certificate view reports, so a test says which kind it
    /// expects rather than that it got one.
    fn arm(kind: &MultiEraCertKind) -> &'static str {
        match kind {
            MultiEraCertKind::StakeRegistration(..) => "stake registration",
            MultiEraCertKind::StakeDeregistration(..) => "stake deregistration",
            MultiEraCertKind::StakeDelegation(..) => "stake delegation",
            MultiEraCertKind::PoolRegistration(..) => "pool registration",
            MultiEraCertKind::PoolRetirement(..) => "pool retirement",
            MultiEraCertKind::Reg(..) => "registration",
            MultiEraCertKind::UnReg(..) => "deregistration",
            MultiEraCertKind::VoteDeleg(..) => "vote delegation",
            MultiEraCertKind::StakeVoteDeleg(..) => "stake and vote delegation",
            MultiEraCertKind::StakeRegDeleg(..) => "stake registration and delegation",
            MultiEraCertKind::VoteRegDeleg(..) => "vote registration and delegation",
            MultiEraCertKind::StakeVoteRegDeleg(..) => "stake and vote registration and delegation",
            MultiEraCertKind::AuthCommitteeHot(..) => "committee hot key authorisation",
            MultiEraCertKind::ResignCommitteeCold(..) => "committee resignation",
            MultiEraCertKind::RegDRep(..) => "drep registration",
            MultiEraCertKind::UnRegDRep(..) => "drep deregistration",
            MultiEraCertKind::UpdateDRep(..) => "drep update",
            MultiEraCertKind::GenesisKeyDelegation(..) => "genesis key delegation",
            MultiEraCertKind::MoveInstantaneousRewards(..) => "move instantaneous rewards",
        }
    }

    fn credential() -> conway::StakeCredential {
        AddrKeyhash([0x01; 28].into())
    }

    fn anchor() -> Anchor {
        Anchor {
            url: "https://example.invalid/anchor".into(),
            content_hash: [0x22; 32].into(),
        }
    }

    fn margin() -> RationalNumber {
        RationalNumber {
            numerator: 1,
            denominator: 50,
        }
    }

    fn relays() -> Vec<Relay> {
        vec![Relay::MultiHostName("relay.example.invalid".into())]
    }

    fn metadata() -> conway::PoolMetadata {
        conway::PoolMetadata {
            url: "https://example.invalid/pool.json".into(),
            hash: vec![0x33; 32].into(),
        }
    }

    fn block(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str).expect("invalid hex")
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn every_dijkstra_fixture_certificate_is_readable() {
        let cases = [
            (
                include_str!("../../test_data/dijkstra2.block"),
                1usize,
                1usize,
            ),
            (include_str!("../../test_data/dijkstra3.block"), 0, 0),
            (include_str!("../../test_data/dijkstra4.block"), 2, 1),
            (include_str!("../../test_data/dijkstra5.block"), 2, 1),
            (include_str!("../../test_data/dijkstra6.block"), 5, 2),
            (include_str!("../../test_data/dijkstra7.block"), 1, 0),
            (include_str!("../../test_data/dijkstra10.block"), 2, 1),
            (include_str!("../../test_data/dijkstra13.block"), 2, 0),
        ];

        let mut total = 0usize;
        let mut with_key = 0usize;

        for (block_str, certs, registrations) in cases {
            let cbor = block(block_str);
            let decoded = MultiEraBlock::decode(&cbor).expect("invalid cbor");

            let txs = decoded.txs();
            let all: Vec<_> = txs.iter().flat_map(|tx| tx.certs()).collect();
            assert_eq!(all.len(), certs, "certificate count");

            let mut registrations_seen = 0usize;
            for cert in all.iter() {
                assert_eq!(cert.era(), Some(Era::Dijkstra));
                assert!(
                    cert.as_dijkstra().is_some(),
                    "a Dijkstra certificate must be readable as one"
                );
                assert!(cert.as_conway().is_none());
                assert!(cert.as_alonzo().is_none());

                if let Some(key) = cert.bls_key().key() {
                    assert_eq!(key.bls_pubkey.len(), 96, "bls_pubkey is 96 bytes");
                    assert_eq!(
                        key.bls_possession_proof.len(),
                        48,
                        "bls_possession_proof is 48 bytes"
                    );
                    registrations_seen += 1;
                    with_key += 1;
                }
            }

            assert_eq!(
                registrations_seen, registrations,
                "pool registrations carrying a populated bls_key"
            );
            total += all.len();
        }

        assert_eq!(
            total, 15,
            "certificates across the seven fixtures that have any"
        );
        assert_eq!(with_key, 6, "pool registrations carrying a BLS key");
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_vote_delegation_certificate_is_read_through_the_multi_era_cert() {
        let cbor = block(include_str!("../../test_data/dijkstra13.block"));
        let decoded = MultiEraBlock::decode(&cbor).expect("invalid cbor");

        let txs = decoded.txs();
        let all: Vec<_> = txs.iter().flat_map(|tx| tx.certs()).collect();
        assert_eq!(all.len(), 2, "a registration and a vote delegation");

        let delegation = all
            .iter()
            .find(|c| matches!(c.as_dijkstra(), Some(dijkstra::Certificate::VoteDeleg(..))))
            .expect("dijkstra13 carries a vote delegation certificate");

        assert_eq!(delegation.era(), Some(Era::Dijkstra));
        assert!(delegation.as_conway().is_none());
        assert!(delegation.as_alonzo().is_none());

        assert!(
            delegation.bls_key().key().is_none(),
            "a vote delegation carries no pool parameters"
        );

        let Some(dijkstra::Certificate::VoteDeleg(credential, drep)) = delegation.as_dijkstra()
        else {
            unreachable!()
        };
        assert!(matches!(
            credential,
            pallas_primitives::StakeCredential::AddrKeyhash(_)
        ));
        assert!(
            matches!(drep, dijkstra::DRep::Abstain),
            "this delegation is to the predefined abstain drep, found {drep:?}"
        );

        assert!(
            all.iter()
                .any(|c| matches!(c.as_dijkstra(), Some(dijkstra::Certificate::Reg(..)))),
            "the other certificate is a registration"
        );
    }

    #[test]
    fn every_conway_certificate_is_read_through_the_certificate_view() {
        let cases: Vec<(&str, conway::Certificate)> = vec![
            (
                "stake registration",
                conway::Certificate::StakeRegistration(credential()),
            ),
            (
                "stake deregistration",
                conway::Certificate::StakeDeregistration(credential()),
            ),
            (
                "stake delegation",
                conway::Certificate::StakeDelegation(credential(), [0x02; 28].into()),
            ),
            (
                "pool registration",
                conway::Certificate::PoolRegistration {
                    operator: [0x02; 28].into(),
                    vrf_keyhash: [0x06; 32].into(),
                    pledge: 500,
                    cost: 340,
                    margin: margin(),
                    reward_account: vec![0xe0; 29].into(),
                    pool_owners: vec![[0x04; 28].into()].into(),
                    relays: relays(),
                    pool_metadata: Some(metadata()),
                },
            ),
            (
                "pool retirement",
                conway::Certificate::PoolRetirement([0x02; 28].into(), 9),
            ),
            ("registration", conway::Certificate::Reg(credential(), 5)),
            (
                "deregistration",
                conway::Certificate::UnReg(credential(), 5),
            ),
            (
                "vote delegation",
                conway::Certificate::VoteDeleg(credential(), DRep::Abstain),
            ),
            (
                "stake and vote delegation",
                conway::Certificate::StakeVoteDeleg(
                    credential(),
                    [0x02; 28].into(),
                    DRep::NoConfidence,
                ),
            ),
            (
                "stake registration and delegation",
                conway::Certificate::StakeRegDeleg(credential(), [0x02; 28].into(), 5),
            ),
            (
                "vote registration and delegation",
                conway::Certificate::VoteRegDeleg(credential(), DRep::Abstain, 5),
            ),
            (
                "stake and vote registration and delegation",
                conway::Certificate::StakeVoteRegDeleg(
                    credential(),
                    [0x02; 28].into(),
                    DRep::Abstain,
                    5,
                ),
            ),
            (
                "committee hot key authorisation",
                conway::Certificate::AuthCommitteeHot(credential(), AddrKeyhash([0x07; 28].into())),
            ),
            (
                "committee resignation",
                conway::Certificate::ResignCommitteeCold(credential(), Some(anchor())),
            ),
            (
                "drep registration",
                conway::Certificate::RegDRepCert(credential(), 5, Some(anchor())),
            ),
            (
                "drep deregistration",
                conway::Certificate::UnRegDRepCert(credential(), 5),
            ),
            (
                "drep update",
                conway::Certificate::UpdateDRepCert(credential(), None),
            ),
        ];

        let read: Vec<&str> = cases
            .iter()
            .map(|(_, certificate)| {
                let cert = MultiEraCert::Conway(Box::new(Cow::Borrowed(certificate)));
                arm(&cert.kind().expect("a Conway certificate reads a kind"))
            })
            .collect();

        let expected: Vec<&str> = cases.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            read, expected,
            "each Conway certificate must reach the arm of the view that names it"
        );
        assert_eq!(read.len(), 17, "Conway's type names seventeen certificates");
    }

    #[test]
    fn every_alonzo_certificate_is_read_through_the_certificate_view() {
        let cases: Vec<(&str, alonzo::Certificate)> = vec![
            (
                "stake registration",
                alonzo::Certificate::StakeRegistration(credential()),
            ),
            (
                "stake deregistration",
                alonzo::Certificate::StakeDeregistration(credential()),
            ),
            (
                "stake delegation",
                alonzo::Certificate::StakeDelegation(credential(), [0x02; 28].into()),
            ),
            (
                "pool registration",
                alonzo::Certificate::PoolRegistration {
                    operator: [0x02; 28].into(),
                    vrf_keyhash: [0x06; 32].into(),
                    pledge: 500,
                    cost: 340,
                    margin: margin(),
                    reward_account: vec![0xe0; 29].into(),
                    pool_owners: vec![[0x04; 28].into()],
                    relays: relays(),
                    pool_metadata: Some(metadata()),
                },
            ),
            (
                "pool retirement",
                alonzo::Certificate::PoolRetirement([0x02; 28].into(), 9),
            ),
            (
                "genesis key delegation",
                alonzo::Certificate::GenesisKeyDelegation(
                    vec![0x08; 28].into(),
                    vec![0x09; 28].into(),
                    [0x06; 32].into(),
                ),
            ),
            (
                "move instantaneous rewards",
                alonzo::Certificate::MoveInstantaneousRewardsCert(
                    alonzo::MoveInstantaneousReward {
                        source: alonzo::InstantaneousRewardSource::Reserves,
                        target: alonzo::InstantaneousRewardTarget::OtherAccountingPot(7),
                    },
                ),
            ),
        ];

        let read: Vec<&str> = cases
            .iter()
            .map(|(_, certificate)| {
                let cert = MultiEraCert::AlonzoCompatible(Box::new(Cow::Borrowed(certificate)));
                arm(&cert.kind().expect("an Alonzo certificate reads a kind"))
            })
            .collect();

        let expected: Vec<&str> = cases.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            read, expected,
            "each Alonzo certificate must reach the arm of the view that names it"
        );
        assert_eq!(read.len(), 7, "the Alonzo type names seven certificates");
    }

    #[test]
    fn an_era_carrying_no_certificates_reads_no_kind() {
        assert!(
            MultiEraCert::NotApplicable.kind().is_none(),
            "an era with no certificate type has no kind to report"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn an_earlier_era_certificate_is_not_read_as_dijkstra() {
        let cbor = block(include_str!("../../test_data/babbage10.block"));
        let decoded = MultiEraBlock::decode(&cbor).expect("invalid cbor");

        let txs = decoded.txs();
        let all: Vec<_> = txs.iter().flat_map(|tx| tx.certs()).collect();
        assert!(!all.is_empty(), "this fixture carries body key 4");

        for cert in all.iter() {
            assert_eq!(cert.era(), Some(Era::Alonzo));
            assert!(cert.as_alonzo().is_some());
            assert!(cert.as_dijkstra().is_none());
            assert!(cert.as_conway().is_none());
            assert!(
                cert.bls_key().key().is_none(),
                "no era before Dijkstra has a BLS key slot"
            );
        }
    }

    #[test]
    fn an_alonzo_pool_registration_carries_its_parameters_through_the_view() {
        let cbor = block(include_str!("../../test_data/babbage10.block"));
        let decoded = MultiEraBlock::decode(&cbor).expect("invalid cbor");
        let txs = decoded.txs();
        let certs: Vec<_> = txs.iter().flat_map(|tx| tx.certs()).collect();
        assert_eq!(certs.len(), 1, "this fixture writes one certificate");

        let kind = certs[0].kind().expect("an Alonzo certificate reads a kind");
        let MultiEraCertKind::PoolRegistration(registration) = &kind else {
            panic!(
                "this fixture writes certificate tag 3, found {}",
                arm(&kind)
            )
        };

        assert_eq!(
            registration.operator.to_string(),
            "129a187287eb6c65e57af2a1ac5750113ecc1a1e658b960358fcaa59"
        );
        assert_eq!(
            registration.vrf_keyhash.to_string(),
            "cf027ebfbfec5c3f964b05341519180003e2ed092829a402f775efec666d78e1"
        );
        assert_eq!(registration.pledge, 9_223_372_036_854_775_809);
        assert_eq!(registration.cost, 340_000_000);
        assert_eq!(registration.margin.numerator, 9_223_372_036_854_775_809);
        assert_eq!(registration.margin.denominator, 10_000_000_000_000_000_000);
        assert_eq!(
            hex::encode(registration.reward_account.as_slice()),
            "e0b04dff59ee3b964a7d9f4fda04d98ef43de3abc832112cc37a35d138"
        );
        assert_eq!(
            registration
                .pool_owners
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>(),
            vec!["b04dff59ee3b964a7d9f4fda04d98ef43de3abc832112cc37a35d138"]
        );
        assert_eq!(registration.relays.len(), 3);
        assert_eq!(
            registration.pool_metadata.map(|x| x.url.as_str()),
            Some("https://raw.githubusercontent.com/stakelovelace/pub/main/s2.json")
        );

        #[cfg(feature = "unstable")]
        assert_eq!(
            registration.bls_key,
            BlsKeySlot::NoSlot,
            "no era before Dijkstra writes a BLS key slot"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn every_dijkstra_certificate_is_read_through_the_certificate_view() {
        let cases: Vec<(&str, dijkstra::Certificate)> = vec![
            (
                "stake delegation",
                dijkstra::Certificate::StakeDelegation(credential(), [0x02; 28].into()),
            ),
            (
                "pool registration",
                dijkstra::Certificate::PoolRegistration {
                    operator: [0x02; 28].into(),
                    vrf_keyhash: [0x06; 32].into(),
                    bls_key: None,
                    pledge: 500,
                    cost: 340,
                    margin: margin(),
                    reward_account: vec![0xe0; 29].into(),
                    pool_owners: vec![[0x04; 28].into()].into(),
                    relays: relays(),
                    pool_metadata: Some(metadata()),
                },
            ),
            (
                "pool retirement",
                dijkstra::Certificate::PoolRetirement([0x02; 28].into(), 9),
            ),
            ("registration", dijkstra::Certificate::Reg(credential(), 5)),
            (
                "deregistration",
                dijkstra::Certificate::UnReg(credential(), 5),
            ),
            (
                "vote delegation",
                dijkstra::Certificate::VoteDeleg(credential(), DRep::Abstain),
            ),
            (
                "stake and vote delegation",
                dijkstra::Certificate::StakeVoteDeleg(
                    credential(),
                    [0x02; 28].into(),
                    DRep::NoConfidence,
                ),
            ),
            (
                "stake registration and delegation",
                dijkstra::Certificate::StakeRegDeleg(credential(), [0x02; 28].into(), 5),
            ),
            (
                "vote registration and delegation",
                dijkstra::Certificate::VoteRegDeleg(credential(), DRep::Abstain, 5),
            ),
            (
                "stake and vote registration and delegation",
                dijkstra::Certificate::StakeVoteRegDeleg(
                    credential(),
                    [0x02; 28].into(),
                    DRep::Abstain,
                    5,
                ),
            ),
            (
                "committee hot key authorisation",
                dijkstra::Certificate::AuthCommitteeHot(
                    credential(),
                    AddrKeyhash([0x07; 28].into()),
                ),
            ),
            (
                "committee resignation",
                dijkstra::Certificate::ResignCommitteeCold(credential(), Some(anchor())),
            ),
            (
                "drep registration",
                dijkstra::Certificate::RegDRepCert(credential(), 5, Some(anchor())),
            ),
            (
                "drep deregistration",
                dijkstra::Certificate::UnRegDRepCert(credential(), 5),
            ),
            (
                "drep update",
                dijkstra::Certificate::UpdateDRepCert(credential(), None),
            ),
        ];

        let read: Vec<&str> = cases
            .iter()
            .map(|(_, certificate)| {
                let cert = MultiEraCert::Dijkstra(Box::new(Cow::Borrowed(certificate)));
                arm(&cert.kind().expect("a Dijkstra certificate reads a kind"))
            })
            .collect();

        let expected: Vec<&str> = cases.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            read, expected,
            "each Dijkstra certificate must reach the arm of the view that names it"
        );
        assert_eq!(
            read.len(),
            15,
            "this era's type names fifteen certificates, two fewer than Conway's"
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn every_dijkstra_fixture_certificate_reads_the_arm_its_tag_names() {
        let cases = [
            (
                "dijkstra2",
                include_str!("../../test_data/dijkstra2.block"),
                vec!["pool registration"],
            ),
            (
                "dijkstra6",
                include_str!("../../test_data/dijkstra6.block"),
                vec![
                    "stake delegation",
                    "registration",
                    "pool registration",
                    "registration",
                    "pool registration",
                ],
            ),
            (
                "dijkstra13",
                include_str!("../../test_data/dijkstra13.block"),
                vec!["registration", "vote delegation"],
            ),
        ];

        for (name, block_str, expected) in cases {
            let cbor = block(block_str);
            let decoded = MultiEraBlock::decode(&cbor).expect("invalid cbor");
            let txs = decoded.txs();
            let certs: Vec<_> = txs.iter().flat_map(|tx| tx.certs()).collect();

            let read: Vec<&str> = certs
                .iter()
                .map(|cert| arm(&cert.kind().expect("a Dijkstra certificate reads a kind")))
                .collect();

            assert_eq!(read, expected, "{name} writes another sequence of tags");
        }
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_dijkstra_pool_registration_carries_its_bls_key_through_the_view() {
        let cbor = block(include_str!("../../test_data/dijkstra2.block"));
        let decoded = MultiEraBlock::decode(&cbor).expect("invalid cbor");
        let txs = decoded.txs();
        let certs: Vec<_> = txs.iter().flat_map(|tx| tx.certs()).collect();
        assert_eq!(certs.len(), 1, "this fixture writes one certificate");

        let kind = certs[0]
            .kind()
            .expect("a Dijkstra certificate reads a kind");
        let MultiEraCertKind::PoolRegistration(registration) = &kind else {
            panic!(
                "this fixture writes certificate tag 3, found {}",
                arm(&kind)
            )
        };

        let key = registration
            .bls_key
            .key()
            .expect("this registration fills the BLS key slot");
        assert_eq!(key.bls_pubkey.len(), 96);
        assert_eq!(key.bls_possession_proof.len(), 48);
        assert_eq!(
            registration.bls_key,
            certs[0].bls_key(),
            "the view and the certificate must read the same slot"
        );
        assert_eq!(registration.pool_owners.len(), 1);
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn a_dijkstra_registration_that_fills_no_bls_key_slot_reads_no_key() {
        let certificate = dijkstra::Certificate::PoolRegistration {
            operator: [0x02; 28].into(),
            vrf_keyhash: [0x06; 32].into(),
            bls_key: None,
            pledge: 500,
            cost: 340,
            margin: margin(),
            reward_account: vec![0xe0; 29].into(),
            pool_owners: vec![[0x04; 28].into()].into(),
            relays: relays(),
            pool_metadata: None,
        };
        let cert = MultiEraCert::Dijkstra(Box::new(Cow::Borrowed(&certificate)));
        let kind = cert.kind().expect("a Dijkstra certificate reads a kind");
        let MultiEraCertKind::PoolRegistration(registration) = &kind else {
            panic!("a pool registration reached another arm of the view")
        };

        assert_eq!(
            registration.bls_key,
            BlsKeySlot::NoSlot,
            "a registration that wrote no slot must not read a key"
        );
        assert!(registration.bls_key.key().is_none());

        let null = dijkstra::Certificate::PoolRegistration {
            operator: [0x02; 28].into(),
            vrf_keyhash: [0x06; 32].into(),
            bls_key: Some(pallas_primitives::Nullable::Null),
            pledge: 500,
            cost: 340,
            margin: margin(),
            reward_account: vec![0xe0; 29].into(),
            pool_owners: vec![[0x04; 28].into()].into(),
            relays: relays(),
            pool_metadata: None,
        };
        let cert = MultiEraCert::Dijkstra(Box::new(Cow::Borrowed(&null)));
        let kind = cert.kind().expect("a Dijkstra certificate reads a kind");
        let MultiEraCertKind::PoolRegistration(registration) = &kind else {
            panic!("a pool registration reached another arm of the view")
        };
        assert_eq!(
            registration.bls_key,
            BlsKeySlot::Null,
            "a registration that wrote the slot as nil is not one that wrote no slot"
        );
    }

    fn show_credential(x: &conway::StakeCredential) -> String {
        match x {
            conway::StakeCredential::AddrKeyhash(hash) => format!("key {hash}"),
            conway::StakeCredential::ScriptHash(hash) => format!("script {hash}"),
        }
    }

    fn show_drep(x: &DRep) -> String {
        match x {
            DRep::Key(hash) => format!("key {hash}"),
            DRep::Script(hash) => format!("script {hash}"),
            DRep::Abstain => "abstain".to_string(),
            DRep::NoConfidence => "no confidence".to_string(),
        }
    }

    fn show_anchor(x: Option<&Anchor>) -> String {
        match x {
            Some(anchor) => format!("{} {}", anchor.url, anchor.content_hash),
            None => "none".to_string(),
        }
    }

    fn show_metadata(x: Option<&conway::PoolMetadata>) -> String {
        match x {
            Some(metadata) => format!("{} {}", metadata.url, hex::encode(metadata.hash.as_slice())),
            None => "none".to_string(),
        }
    }

    /// Renders every payload the view reports, so a test compares the values a
    /// certificate carries rather than the name of the arm they reached.
    fn payload(kind: &MultiEraCertKind) -> String {
        match kind {
            MultiEraCertKind::StakeRegistration(credential) => {
                format!("credential {}", show_credential(credential))
            }
            MultiEraCertKind::StakeDeregistration(credential) => {
                format!("credential {}", show_credential(credential))
            }
            MultiEraCertKind::StakeDelegation(credential, pool) => {
                format!("credential {} pool {pool}", show_credential(credential))
            }
            MultiEraCertKind::PoolRegistration(registration) => format!(
                "operator {} vrf {} pledge {} cost {} margin {}/{} reward account {} owners {} relays {:?} metadata {}",
                registration.operator,
                registration.vrf_keyhash,
                registration.pledge,
                registration.cost,
                registration.margin.numerator,
                registration.margin.denominator,
                hex::encode(registration.reward_account.as_slice()),
                registration
                    .pool_owners
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
                registration.relays,
                show_metadata(registration.pool_metadata),
            ),
            MultiEraCertKind::PoolRetirement(pool, epoch) => format!("pool {pool} epoch {epoch}"),
            MultiEraCertKind::Reg(credential, coin) => {
                format!("credential {} coin {coin}", show_credential(credential))
            }
            MultiEraCertKind::UnReg(credential, coin) => {
                format!("credential {} coin {coin}", show_credential(credential))
            }
            MultiEraCertKind::VoteDeleg(credential, drep) => format!(
                "credential {} drep {}",
                show_credential(credential),
                show_drep(drep)
            ),
            MultiEraCertKind::StakeVoteDeleg(credential, pool, drep) => format!(
                "credential {} pool {pool} drep {}",
                show_credential(credential),
                show_drep(drep)
            ),
            MultiEraCertKind::StakeRegDeleg(credential, pool, coin) => format!(
                "credential {} pool {pool} coin {coin}",
                show_credential(credential)
            ),
            MultiEraCertKind::VoteRegDeleg(credential, drep, coin) => format!(
                "credential {} drep {} coin {coin}",
                show_credential(credential),
                show_drep(drep)
            ),
            MultiEraCertKind::StakeVoteRegDeleg(credential, pool, drep, coin) => format!(
                "credential {} pool {pool} drep {} coin {coin}",
                show_credential(credential),
                show_drep(drep)
            ),
            MultiEraCertKind::AuthCommitteeHot(cold, hot) => format!(
                "cold {} hot {}",
                show_credential(cold),
                show_credential(hot)
            ),
            MultiEraCertKind::ResignCommitteeCold(cold, anchor) => format!(
                "cold {} anchor {}",
                show_credential(cold),
                show_anchor(*anchor)
            ),
            MultiEraCertKind::RegDRep(credential, coin, anchor) => format!(
                "credential {} coin {coin} anchor {}",
                show_credential(credential),
                show_anchor(*anchor)
            ),
            MultiEraCertKind::UnRegDRep(credential, coin) => {
                format!("credential {} coin {coin}", show_credential(credential))
            }
            MultiEraCertKind::UpdateDRep(credential, anchor) => format!(
                "credential {} anchor {}",
                show_credential(credential),
                show_anchor(*anchor)
            ),
            MultiEraCertKind::GenesisKeyDelegation(genesis, delegate, vrf) => format!(
                "genesis {} delegate {} vrf {vrf}",
                hex::encode(genesis.as_slice()),
                hex::encode(delegate.as_slice())
            ),
            MultiEraCertKind::MoveInstantaneousRewards(rewards) => {
                format!("source {:?} target {:?}", rewards.source, rewards.target)
            }
        }
    }

    fn key_credential(fill: u8) -> conway::StakeCredential {
        AddrKeyhash([fill; 28].into())
    }

    fn distinct_anchor(fill: u8) -> Anchor {
        Anchor {
            url: format!("https://example.invalid/anchor/{fill:02x}"),
            content_hash: [fill; 32].into(),
        }
    }

    fn distinct_metadata(fill: u8) -> conway::PoolMetadata {
        conway::PoolMetadata {
            url: format!("https://example.invalid/pool/{fill:02x}.json"),
            hash: vec![fill; 32].into(),
        }
    }

    fn conway_cert(certificate: conway::Certificate) -> MultiEraCert<'static> {
        MultiEraCert::Conway(Box::new(Cow::Owned(certificate)))
    }

    fn alonzo_cert(certificate: alonzo::Certificate) -> MultiEraCert<'static> {
        MultiEraCert::AlonzoCompatible(Box::new(Cow::Owned(certificate)))
    }

    #[cfg(feature = "unstable")]
    fn dijkstra_cert(certificate: dijkstra::Certificate) -> MultiEraCert<'static> {
        MultiEraCert::Dijkstra(Box::new(Cow::Owned(certificate)))
    }

    #[test]
    fn every_conway_certificate_payload_reads_back_by_value() {
        let cases: Vec<(conway::Certificate, &str)> = vec![
            (
                conway::Certificate::StakeRegistration(key_credential(0x11)),
                "credential key 11111111111111111111111111111111111111111111111111111111",
            ),
            (
                conway::Certificate::StakeDeregistration(key_credential(0x12)),
                "credential key 12121212121212121212121212121212121212121212121212121212",
            ),
            (
                conway::Certificate::StakeDelegation(key_credential(0x13), [0x14; 28].into()),
                "credential key 13131313131313131313131313131313131313131313131313131313 \
                 pool 14141414141414141414141414141414141414141414141414141414",
            ),
            (
                conway::Certificate::PoolRegistration {
                    operator: [0x15; 28].into(),
                    vrf_keyhash: [0x16; 32].into(),
                    pledge: 111,
                    cost: 222,
                    margin: RationalNumber {
                        numerator: 3,
                        denominator: 97,
                    },
                    reward_account: vec![0x17; 29].into(),
                    pool_owners: vec![[0x18; 28].into(), [0x19; 28].into()].into(),
                    relays: vec![Relay::MultiHostName("one.example.invalid".into())],
                    pool_metadata: Some(distinct_metadata(0x1a)),
                },
                "operator 15151515151515151515151515151515151515151515151515151515 \
                 vrf 1616161616161616161616161616161616161616161616161616161616161616 \
                 pledge 111 cost 222 margin 3/97 \
                 reward account 1717171717171717171717171717171717171717171717171717171717 \
                 owners 18181818181818181818181818181818181818181818181818181818 \
                 19191919191919191919191919191919191919191919191919191919 \
                 relays [MultiHostName(\"one.example.invalid\")] \
                 metadata https://example.invalid/pool/1a.json \
                 1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a",
            ),
            (
                conway::Certificate::PoolRetirement([0x1b; 28].into(), 303),
                "pool 1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b epoch 303",
            ),
            (
                conway::Certificate::Reg(key_credential(0x1c), 404),
                "credential key 1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c coin 404",
            ),
            (
                conway::Certificate::UnReg(key_credential(0x1d), 505),
                "credential key 1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d coin 505",
            ),
            (
                conway::Certificate::VoteDeleg(key_credential(0x1e), DRep::Key([0x1f; 28].into())),
                "credential key 1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e \
                 drep key 1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f",
            ),
            (
                conway::Certificate::StakeVoteDeleg(
                    key_credential(0x20),
                    [0x21; 28].into(),
                    DRep::Key([0x22; 28].into()),
                ),
                "credential key 20202020202020202020202020202020202020202020202020202020 \
                 pool 21212121212121212121212121212121212121212121212121212121 \
                 drep key 22222222222222222222222222222222222222222222222222222222",
            ),
            (
                conway::Certificate::StakeRegDeleg(key_credential(0x23), [0x24; 28].into(), 606),
                "credential key 23232323232323232323232323232323232323232323232323232323 \
                 pool 24242424242424242424242424242424242424242424242424242424 coin 606",
            ),
            (
                conway::Certificate::VoteRegDeleg(
                    key_credential(0x25),
                    DRep::Key([0x26; 28].into()),
                    707,
                ),
                "credential key 25252525252525252525252525252525252525252525252525252525 \
                 drep key 26262626262626262626262626262626262626262626262626262626 coin 707",
            ),
            (
                conway::Certificate::StakeVoteRegDeleg(
                    key_credential(0x27),
                    [0x28; 28].into(),
                    DRep::Key([0x29; 28].into()),
                    808,
                ),
                "credential key 27272727272727272727272727272727272727272727272727272727 \
                 pool 28282828282828282828282828282828282828282828282828282828 \
                 drep key 29292929292929292929292929292929292929292929292929292929 coin 808",
            ),
            (
                conway::Certificate::AuthCommitteeHot(key_credential(0x2a), key_credential(0x2b)),
                "cold key 2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a \
                 hot key 2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b",
            ),
            (
                conway::Certificate::ResignCommitteeCold(
                    key_credential(0x2c),
                    Some(distinct_anchor(0x2d)),
                ),
                "cold key 2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c \
                 anchor https://example.invalid/anchor/2d \
                 2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d",
            ),
            (
                conway::Certificate::RegDRepCert(
                    key_credential(0x2e),
                    909,
                    Some(distinct_anchor(0x2f)),
                ),
                "credential key 2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e coin 909 \
                 anchor https://example.invalid/anchor/2f \
                 2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f",
            ),
            (
                conway::Certificate::UnRegDRepCert(key_credential(0x30), 1010),
                "credential key 30303030303030303030303030303030303030303030303030303030 \
                 coin 1010",
            ),
            (
                conway::Certificate::UpdateDRepCert(
                    key_credential(0x31),
                    Some(distinct_anchor(0x32)),
                ),
                "credential key 31313131313131313131313131313131313131313131313131313131 \
                 anchor https://example.invalid/anchor/32 \
                 3232323232323232323232323232323232323232323232323232323232323232",
            ),
        ];

        assert_eq!(
            cases.len(),
            17,
            "every certificate Conway's type names carries its payloads here"
        );

        for (certificate, expected) in cases {
            let cert = conway_cert(certificate);
            let kind = cert.kind().expect("a Conway certificate reads a kind");
            assert_eq!(
                payload(&kind),
                expected,
                "the {} view must report the payloads its certificate carries",
                arm(&kind)
            );
        }
    }

    #[test]
    fn every_alonzo_certificate_payload_reads_back_by_value() {
        let cases: Vec<(alonzo::Certificate, &str)> = vec![
            (
                alonzo::Certificate::StakeRegistration(key_credential(0x41)),
                "credential key 41414141414141414141414141414141414141414141414141414141",
            ),
            (
                alonzo::Certificate::StakeDeregistration(key_credential(0x42)),
                "credential key 42424242424242424242424242424242424242424242424242424242",
            ),
            (
                alonzo::Certificate::StakeDelegation(key_credential(0x43), [0x44; 28].into()),
                "credential key 43434343434343434343434343434343434343434343434343434343 \
                 pool 44444444444444444444444444444444444444444444444444444444",
            ),
            (
                alonzo::Certificate::PoolRegistration {
                    operator: [0x45; 28].into(),
                    vrf_keyhash: [0x46; 32].into(),
                    pledge: 333,
                    cost: 444,
                    margin: RationalNumber {
                        numerator: 7,
                        denominator: 93,
                    },
                    reward_account: vec![0x47; 29].into(),
                    pool_owners: vec![[0x48; 28].into(), [0x49; 28].into()],
                    relays: vec![Relay::SingleHostName(
                        Some(3001),
                        "two.example.invalid".into(),
                    )],
                    pool_metadata: Some(distinct_metadata(0x4a)),
                },
                "operator 45454545454545454545454545454545454545454545454545454545 \
                 vrf 4646464646464646464646464646464646464646464646464646464646464646 \
                 pledge 333 cost 444 margin 7/93 \
                 reward account 4747474747474747474747474747474747474747474747474747474747 \
                 owners 48484848484848484848484848484848484848484848484848484848 \
                 49494949494949494949494949494949494949494949494949494949 \
                 relays [SingleHostName(Some(3001), \"two.example.invalid\")] \
                 metadata https://example.invalid/pool/4a.json \
                 4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a",
            ),
            (
                alonzo::Certificate::PoolRetirement([0x4b; 28].into(), 606),
                "pool 4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b epoch 606",
            ),
            (
                alonzo::Certificate::GenesisKeyDelegation(
                    vec![0x4c; 28].into(),
                    vec![0x4d; 28].into(),
                    [0x4e; 32].into(),
                ),
                "genesis 4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c \
                 delegate 4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d \
                 vrf 4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e",
            ),
            (
                alonzo::Certificate::MoveInstantaneousRewardsCert(
                    alonzo::MoveInstantaneousReward {
                        source: alonzo::InstantaneousRewardSource::Reserves,
                        target: alonzo::InstantaneousRewardTarget::OtherAccountingPot(777),
                    },
                ),
                "source Reserves target OtherAccountingPot(777)",
            ),
        ];

        assert_eq!(
            cases.len(),
            7,
            "every certificate the Alonzo type names carries its payloads here"
        );

        for (certificate, expected) in cases {
            let cert = alonzo_cert(certificate);
            let kind = cert.kind().expect("an Alonzo certificate reads a kind");
            assert_eq!(
                payload(&kind),
                expected,
                "the {} view must report the payloads its certificate carries",
                arm(&kind)
            );
        }
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn every_dijkstra_certificate_payload_reads_back_by_value() {
        let cases: Vec<(dijkstra::Certificate, &str)> = vec![
            (
                dijkstra::Certificate::StakeDelegation(key_credential(0x51), [0x52; 28].into()),
                "credential key 51515151515151515151515151515151515151515151515151515151 \
                 pool 52525252525252525252525252525252525252525252525252525252",
            ),
            (
                dijkstra::Certificate::PoolRegistration {
                    operator: [0x53; 28].into(),
                    vrf_keyhash: [0x54; 32].into(),
                    bls_key: None,
                    pledge: 555,
                    cost: 666,
                    margin: RationalNumber {
                        numerator: 5,
                        denominator: 91,
                    },
                    reward_account: vec![0x55; 29].into(),
                    pool_owners: vec![[0x56; 28].into(), [0x57; 28].into()].into(),
                    relays: vec![Relay::SingleHostName(
                        Some(3002),
                        "three.example.invalid".into(),
                    )],
                    pool_metadata: Some(distinct_metadata(0x58)),
                },
                "operator 53535353535353535353535353535353535353535353535353535353 \
                 vrf 5454545454545454545454545454545454545454545454545454545454545454 \
                 pledge 555 cost 666 margin 5/91 \
                 reward account 5555555555555555555555555555555555555555555555555555555555 \
                 owners 56565656565656565656565656565656565656565656565656565656 \
                 57575757575757575757575757575757575757575757575757575757 \
                 relays [SingleHostName(Some(3002), \"three.example.invalid\")] \
                 metadata https://example.invalid/pool/58.json \
                 5858585858585858585858585858585858585858585858585858585858585858",
            ),
            (
                dijkstra::Certificate::PoolRetirement([0x59; 28].into(), 707),
                "pool 59595959595959595959595959595959595959595959595959595959 epoch 707",
            ),
            (
                dijkstra::Certificate::Reg(key_credential(0x5a), 808),
                "credential key 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a coin 808",
            ),
            (
                dijkstra::Certificate::UnReg(key_credential(0x5b), 909),
                "credential key 5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b coin 909",
            ),
            (
                dijkstra::Certificate::VoteDeleg(
                    key_credential(0x5c),
                    DRep::Key([0x5d; 28].into()),
                ),
                "credential key 5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c \
                 drep key 5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d",
            ),
            (
                dijkstra::Certificate::StakeVoteDeleg(
                    key_credential(0x5e),
                    [0x5f; 28].into(),
                    DRep::Key([0x60; 28].into()),
                ),
                "credential key 5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e \
                 pool 5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f \
                 drep key 60606060606060606060606060606060606060606060606060606060",
            ),
            (
                dijkstra::Certificate::StakeRegDeleg(key_credential(0x61), [0x62; 28].into(), 1111),
                "credential key 61616161616161616161616161616161616161616161616161616161 \
                 pool 62626262626262626262626262626262626262626262626262626262 coin 1111",
            ),
            (
                dijkstra::Certificate::VoteRegDeleg(
                    key_credential(0x63),
                    DRep::Key([0x64; 28].into()),
                    1212,
                ),
                "credential key 63636363636363636363636363636363636363636363636363636363 \
                 drep key 64646464646464646464646464646464646464646464646464646464 coin 1212",
            ),
            (
                dijkstra::Certificate::StakeVoteRegDeleg(
                    key_credential(0x65),
                    [0x66; 28].into(),
                    DRep::Key([0x67; 28].into()),
                    1313,
                ),
                "credential key 65656565656565656565656565656565656565656565656565656565 \
                 pool 66666666666666666666666666666666666666666666666666666666 \
                 drep key 67676767676767676767676767676767676767676767676767676767 coin 1313",
            ),
            (
                dijkstra::Certificate::AuthCommitteeHot(key_credential(0x68), key_credential(0x69)),
                "cold key 68686868686868686868686868686868686868686868686868686868 \
                 hot key 69696969696969696969696969696969696969696969696969696969",
            ),
            (
                dijkstra::Certificate::ResignCommitteeCold(
                    key_credential(0x6a),
                    Some(distinct_anchor(0x6b)),
                ),
                "cold key 6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a \
                 anchor https://example.invalid/anchor/6b \
                 6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b",
            ),
            (
                dijkstra::Certificate::RegDRepCert(
                    key_credential(0x6c),
                    1414,
                    Some(distinct_anchor(0x6d)),
                ),
                "credential key 6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c coin 1414 \
                 anchor https://example.invalid/anchor/6d \
                 6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d",
            ),
            (
                dijkstra::Certificate::UnRegDRepCert(key_credential(0x6e), 1515),
                "credential key 6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e \
                 coin 1515",
            ),
            (
                dijkstra::Certificate::UpdateDRepCert(
                    key_credential(0x6f),
                    Some(distinct_anchor(0x70)),
                ),
                "credential key 6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f \
                 anchor https://example.invalid/anchor/70 \
                 7070707070707070707070707070707070707070707070707070707070707070",
            ),
        ];

        assert_eq!(
            cases.len(),
            15,
            "every certificate the Dijkstra type names carries its payloads here"
        );

        for (certificate, expected) in cases {
            let cert = dijkstra_cert(certificate);
            let kind = cert.kind().expect("a Dijkstra certificate reads a kind");
            assert_eq!(
                payload(&kind),
                expected,
                "the {} view must report the payloads its certificate carries",
                arm(&kind)
            );
        }
    }
}
