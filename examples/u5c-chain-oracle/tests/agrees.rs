use pallas_utxorpc::v1beta::spec::cardano as u5c;
use u5c_chain_oracle::coverage::{self, Held, Location};

fn agrees(location: Location, held: Held, tx: &u5c::Tx) -> Option<bool> {
    coverage::agrees(location, held, &u5c::Block::default(), Some(tx))
}

fn redeemer(purpose: u5c::RedeemerPurpose) -> u5c::Redeemer {
    u5c::Redeemer {
        purpose: purpose as i32,
        ..Default::default()
    }
}

fn with_redeemers(redeemers: Vec<u5c::Redeemer>) -> u5c::Tx {
    u5c::Tx {
        witnesses: Some(u5c::WitnessSet {
            redeemers,
            ..Default::default()
        }),
        ..Default::default()
    }
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
    u5c::Tx {
        witnesses: Some(u5c::WitnessSet {
            script: vec![u5c::Script {
                script: Some(u5c::script::Script::Native(script)),
            }],
            ..Default::default()
        }),
        ..Default::default()
    }
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
    u5c::Tx {
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
    }
}

#[test]
fn a_pool_registration_with_a_bls_key_holds_the_bls_location() {
    let key = u5c::PoolBlsKey {
        bls_pubkey: vec![1; 96].into(),
        bls_possession_proof: vec![2; 48].into(),
    };
    assert_eq!(
        agrees(Location::PoolBls, Held::Count(1), &with_pool(Some(key))),
        Some(true)
    );
    assert_eq!(
        agrees(Location::PoolBls, Held::Count(1), &with_pool(None)),
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
fn every_dijkstra_key() -> u5c::PParams {
    u5c::PParams {
        max_ref_script_size_per_block: 34,
        max_ref_script_size_per_tx: 35,
        ref_script_cost_stride: 36,
        ref_script_cost_multiplier: ratio(37, 1),
        max_pledge_leverage: ratio(38, 1),
        min_pool_margin: ratio(1, 39),
        leios_announcement_period_length: 40,
        leios_vote_period_length: 41,
        leios_diffusion_period_length: 42,
        leios_committee_size: 43,
        leios_quorum_stake_threshold: ratio(1, 44),
        max_endorser_block_references_size: 45,
        max_endorser_block_txs_size: 46,
        max_endorser_block_execution_units: Some(u5c::ExUnits {
            memory: 47,
            steps: 470,
        }),
        max_ref_script_size_per_endorser_block: 48,
        ..Default::default()
    }
}

fn with_update(p: u5c::PParams) -> u5c::Tx {
    use u5c::governance_action::GovernanceAction as G;
    u5c::Tx {
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
    }
}

#[test]
fn an_update_holds_each_dijkstra_key_it_sets() {
    let set = with_update(every_dijkstra_key());
    let unset = with_update(u5c::PParams::default());
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

#[test]
fn the_sub_transaction_and_account_fields_hold_their_counts() {
    let tx = u5c::Tx {
        sub_transactions: vec![u5c::Tx::default(); 2],
        direct_deposits: vec![u5c::DirectDeposit::default(); 3],
        account_balance_intervals: vec![u5c::AccountBalanceInterval::default(); 4],
        starting_account_balance_intervals: vec![u5c::AccountBalanceInterval::default(); 5],
        ..Default::default()
    };
    for (key, n) in [(23, 2), (25, 3), (26, 4), (27, 5)] {
        let at = Location::Body(key);
        assert_eq!(agrees(at, Held::Count(n), &tx), Some(true), "key {key}");
        assert_eq!(
            agrees(at, Held::Count(n), &u5c::Tx::default()),
            Some(false),
            "key {key}"
        );
    }
}
