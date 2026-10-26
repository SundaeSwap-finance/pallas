use pallas_utxorpc::v1::spec::cardano as u5c;
use u5c_chain_oracle::coverage::{self, Held, Location, MappedTx};

fn agrees(location: Location, held: Held, tx: &u5c::Tx) -> Option<bool> {
    coverage::agrees(
        location,
        held,
        &u5c::Block::default(),
        Some(MappedTx::Top(tx)),
    )
}

fn top(common: u5c::TxCommon) -> u5c::Tx {
    u5c::Tx {
        common: Some(common),
        ..Default::default()
    }
}

fn redeemer(purpose: u5c::RedeemerPurpose) -> u5c::Redeemer {
    u5c::Redeemer {
        purpose: purpose as i32,
        ..Default::default()
    }
}

fn with_redeemers(redeemers: Vec<u5c::Redeemer>) -> u5c::Tx {
    top(u5c::TxCommon {
        witnesses: Some(u5c::WitnessSet {
            redeemers,
            ..Default::default()
        }),
        ..Default::default()
    })
}

#[test]
fn a_guarding_redeemer_holds_redeemer_tag_6() {
    let tx = with_redeemers(vec![redeemer(u5c::RedeemerPurpose::Guarding)]);
    assert_eq!(
        agrees(Location::RedeemerTag(6), Held::Count(1), &tx),
        Some(true)
    );
    let spend = with_redeemers(vec![redeemer(u5c::RedeemerPurpose::Spend)]);
    assert_eq!(
        agrees(Location::RedeemerTag(6), Held::Count(1), &spend),
        Some(false)
    );
}

fn native(x: u5c::native_script::NativeScript) -> u5c::NativeScript {
    u5c::NativeScript {
        native_script: Some(x),
    }
}

fn with_native(script: u5c::NativeScript) -> u5c::Tx {
    top(u5c::TxCommon {
        witnesses: Some(u5c::WitnessSet {
            script: vec![u5c::Script {
                script: Some(u5c::script::Script::Native(script)),
            }],
            ..Default::default()
        }),
        ..Default::default()
    })
}

#[test]
fn a_guard_clause_holds_native_clause_6() {
    use u5c::native_script::NativeScript as N;
    let guard = native(N::ScriptRequireGuard(u5c::StakeCredential::default()));
    let all = native(N::ScriptAll(u5c::NativeScriptList { items: vec![guard] }));
    assert_eq!(
        agrees(Location::NativeClause(6), Held::Count(1), &with_native(all)),
        Some(true)
    );
    let key = native(N::ScriptPubkeyHash(vec![1; 28].into()));
    assert_eq!(
        agrees(Location::NativeClause(6), Held::Count(1), &with_native(key)),
        Some(false)
    );
}

fn with_pool(bls_key: Option<u5c::PoolBlsKey>) -> u5c::Tx {
    top(u5c::TxCommon {
        certificates: vec![u5c::Certificate {
            certificate: Some(u5c::certificate::Certificate::PoolRegistration(
                u5c::PoolRegistrationCert {
                    bls_key,
                    ..Default::default()
                },
            )),
            ..Default::default()
        }],
        ..Default::default()
    })
}

#[test]
fn a_pool_registration_holds_its_bls_key_bytes() {
    let (pubkey, proof) = (vec![1; 96], vec![2; 48]);
    let key = |pubkey: &[u8], proof: &[u8]| u5c::PoolBlsKey {
        bls_pubkey: pubkey.to_vec().into(),
        bls_possession_proof: proof.to_vec().into(),
    };
    let held = coverage::pool_bls([Some((&pubkey[..], &proof[..]))]);
    let none = coverage::pool_bls([None]);
    assert_eq!(
        agrees(
            Location::PoolBls,
            held,
            &with_pool(Some(key(&pubkey, &proof)))
        ),
        Some(true)
    );
    assert_eq!(
        agrees(Location::PoolBls, none, &with_pool(None)),
        Some(true)
    );
    assert_eq!(
        agrees(
            Location::PoolBls,
            held,
            &with_pool(Some(key(&[0; 96], &proof)))
        ),
        Some(false)
    );
    assert_eq!(
        agrees(
            Location::PoolBls,
            held,
            &with_pool(Some(key(&pubkey, &[0; 48])))
        ),
        Some(false)
    );
    assert_eq!(
        agrees(Location::PoolBls, held, &with_pool(None)),
        Some(false)
    );
    assert_eq!(
        agrees(
            Location::PoolBls,
            none,
            &with_pool(Some(key(&pubkey, &proof)))
        ),
        Some(false)
    );
}

fn ratio(numerator: i32, denominator: u32) -> Option<u5c::RationalNumber> {
    Some(u5c::RationalNumber {
        numerator,
        denominator,
    })
}

/// A parameter update that sets every field of the keys 34 to 48.
fn every_dijkstra_key() -> u5c::PParamsUpdate {
    u5c::PParamsUpdate {
        max_ref_script_size_per_block: Some(34),
        max_ref_script_size_per_tx: Some(35),
        ref_script_cost_stride: Some(36),
        ref_script_cost_multiplier: ratio(37, 1),
        max_pledge_leverage: Some(u5c::MaxPledgeLeverageUpdate {
            update: ratio(38, 1).map(u5c::max_pledge_leverage_update::Update::Leverage),
        }),
        min_pool_margin: ratio(1, 39),
        leios_announcement_period_length: Some(40),
        leios_vote_period_length: Some(41),
        leios_diffusion_period_length: Some(42),
        leios_committee_size: Some(43),
        leios_quorum_stake_threshold: ratio(1, 44),
        max_endorser_block_references_size: Some(45),
        max_endorser_block_txs_size: Some(46),
        max_endorser_block_execution_units: Some(u5c::ExUnits {
            memory: 47,
            steps: 470,
        }),
        max_ref_script_size_per_endorser_block: Some(48),
        ..Default::default()
    }
}

fn with_update(p: u5c::PParamsUpdate) -> u5c::Tx {
    use u5c::governance_action::GovernanceAction as G;
    top(u5c::TxCommon {
        proposals: vec![u5c::GovernanceActionProposal {
            gov_action: Some(u5c::GovernanceAction {
                governance_action: Some(G::ParameterChangeAction(u5c::ParameterChangeAction {
                    protocol_param_update: Some(p),
                    ..Default::default()
                })),
            }),
            ..Default::default()
        }],
        ..Default::default()
    })
}

#[test]
fn an_update_holds_each_dijkstra_key_it_sets() {
    let set = with_update(every_dijkstra_key());
    let unset = with_update(u5c::PParamsUpdate::default());
    for k in 34..=48 {
        let at = Location::ParamUpdate(k);
        assert_eq!(agrees(at, Held::Count(1), &set), Some(true), "key {k}");
        assert_eq!(agrees(at, Held::Count(1), &unset), Some(false), "key {k}");
    }
}

#[test]
fn a_key_past_48_has_no_counterpart() {
    let set = with_update(every_dijkstra_key());
    assert_eq!(
        agrees(Location::ParamUpdate(49), Held::Count(1), &set),
        None
    );
}

fn coin(v: u64) -> Option<u5c::BigInt> {
    Some(u5c::BigInt {
        big_int: Some(u5c::big_int::BigInt::Int(v as i64)),
    })
}

#[test]
fn the_hashes_network_and_treasury_keys_hold_their_values() {
    let tx = top(u5c::TxCommon {
        auxiliary_data_hash: vec![7; 32].into(),
        script_data_hash: vec![11; 32].into(),
        network_id: Some(0),
        treasury_value: coin(21),
        treasury_donation: coin(22),
        ..Default::default()
    });
    let empty = top(u5c::TxCommon::default());
    for (key, held) in [
        (7, Held::Other),
        (11, Held::Other),
        (15, Held::Uint(0)),
        (21, Held::Uint(21)),
        (22, Held::Uint(22)),
    ] {
        let at = Location::Body(key);
        assert_eq!(agrees(at, held, &empty), Some(false), "key {key}");
        assert_eq!(agrees(at, held, &tx), Some(true), "key {key}");
    }
    assert_eq!(agrees(Location::Body(22), Held::Uint(21), &tx), Some(false));
}

fn block_agrees(location: Location, held: Held, block: &u5c::Block) -> Option<bool> {
    coverage::agrees(location, held, block, None)
}

#[test]
fn the_leios_header_and_body_fields_hold_their_presence() {
    let block = u5c::Block {
        header: Some(u5c::BlockHeader {
            body_contains_leios_certificate: true,
            endorser_block_announcement: Some(u5c::EndorserBlockAnnouncement::default()),
            ..Default::default()
        }),
        body: Some(u5c::BlockBody {
            leios_certificate: Some(u5c::LeiosCertificate::default()),
            peras_certificate: vec![2; 8].into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let empty = u5c::Block::default();
    for (at, held) in [
        (Location::HeaderBody(10), Held::Bool(true)),
        (Location::HeaderBody(11), Held::Count(2)),
        (Location::BlockBody(1), Held::Other),
        (Location::BlockBody(2), Held::Other),
    ] {
        assert_eq!(block_agrees(at, held, &empty), Some(false), "{at:?}");
        assert_eq!(block_agrees(at, held, &block), Some(true), "{at:?}");
    }
    assert_eq!(
        block_agrees(Location::HeaderBody(11), Held::Other, &empty),
        Some(true)
    );
    assert_eq!(
        block_agrees(Location::HeaderBody(10), Held::Bool(false), &empty),
        Some(true)
    );
}

#[test]
fn the_sub_transaction_and_account_fields_hold_their_counts() {
    let tx = u5c::Tx {
        common: Some(u5c::TxCommon {
            direct_deposits: vec![u5c::DirectDeposit::default(); 3],
            account_balance_intervals: vec![u5c::AccountBalanceInterval::default(); 4],
            ..Default::default()
        }),
        sub_transactions: vec![u5c::TxCommon::default(); 2],
        starting_account_balance_intervals: vec![u5c::AccountBalanceInterval::default(); 5],
        ..Default::default()
    };
    for (key, n) in [(23, 2), (25, 3), (26, 4), (27, 5)] {
        let at = Location::Body(key);
        assert_eq!(agrees(at, Held::Count(n), &tx), Some(true), "key {key}");
        assert_eq!(
            agrees(at, Held::Count(n), &top(u5c::TxCommon::default())),
            Some(false),
            "key {key}"
        );
    }
}
