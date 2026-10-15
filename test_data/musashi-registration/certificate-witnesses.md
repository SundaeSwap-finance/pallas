# Certificate witnesses and phase-one redeemer pointers

Conway previously omitted certificates from both required scripts and redeemer
pointers, and did not require certificate author keys. The settings registration
was rejected with `UnneededRedeemer`; removing its redeemer made the witness
check accept it, even with its reference script removed. The fix derives required
scripts and keys from certificates, checks native certificate scripts, and builds
Plutus certificate pointers at their positions in the **entire certificate list**.
Required scripts are checked before classifying them as native or Plutus.

The implementation stays in Conway's existing witness checks. An exhaustive
certificate match selects author credentials; pool registration separately requires
operator and owner signatures, and retirement requires the operator. Native
certificate scripts reuse the Shelley/Mary evaluator. All remaining signatures
are verified (a valid unrelated witness previously hid later invalid signatures).
Reference scripts on spending and reference inputs are available; native references
satisfy script presence but do not create redeemers. Native reference evaluation
uses the original script hash, including noncanonical encodings.

## Ledger rules and era boundaries

Pinned cardano-ledger revision: `1587f21a7d1306dc590c2749a5c66232ef66aad0`.
The pinned source URLs and their SHA-256 hashes are in
[certificate-witnesses-provenance.json](certificate-witnesses-provenance.json).

- [Shelley certificate authors](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/shelley/impl/src/Cardano/Ledger/Shelley/TxCert.hs#L579):
  legacy registration has no author witness; deregistration/delegation require
  the credential's key or script. Pool and genesis-delegation authors are keys;
  MIR authorization uses separate rules. These earlier-era validators are unchanged.
- [Conway certificate authors](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/conway/impl/src/Cardano/Ledger/Conway/TxCert.hs#L809):
  legacy registration remains exempt; explicit-deposit registration, all other
  stake credential certificates, DRep certificates and committee cold credentials
  require authorization. A committee hot credential is not the author.
- [Dijkstra certificate authors](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/dijkstra/impl/src/Cardano/Ledger/Dijkstra/TxCert.hs#L323):
  the retained credential forms have the same witness requirements. Tags 0/1
  (legacy registration/deregistration) are removed; tag 2 delegation remains.
  This is rule comparison, not native Dijkstra validator coverage.
- [Conway script purposes](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/conway/impl/src/Cardano/Ledger/Conway/UTxO.hs#L59)
  enumerate the full certificate sequence. Only available Plutus scripts require
  redeemers; matching a script credential to an absent script must first fail.
- [Pool owner witnesses](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/shelley/impl/src/Cardano/Ledger/Shelley/UTxO.hs#L217)
  supplement the certificate operator author. Conway inherits these requirements.

## Coverage matrix

`K/N/P` means synthetic Conway witness-check tests for key, native script, and
Plutus credentials: acceptance plus missing/wrong key, invalid signature,
missing/incorrect script, and missing Plutus redeemer. Native credentials require
no redeemer and reject missing/wrong signing keys. These are authorization tests,
not successful ledger-state transitions. All rows below are implemented in Conway.

| Certificate (CBOR tag) | Author rule | Regression coverage | Dijkstra rule/type |
| --- | --- | --- | --- |
| StakeRegistration (0) | No credential witness | Key/script exemption; extra redeemer rejected | Removed |
| StakeDeregistration (1) | Stake credential | K/N/P | Removed |
| StakeDelegation (2) | Stake credential | K/N/P | Same |
| PoolRegistration (3) | Operator + all owners | Acceptance; each missing signer | Same key requirement; BLS out of scope |
| PoolRetirement (4) | Operator | Acceptance; missing signer | Same |
| Reg (7) | Stake credential | Real settings capture + K/N/P | Same; capture is native Dijkstra |
| UnReg (8) | Stake credential | K/N/P | Same |
| VoteDeleg (9) | Stake credential | K/N/P | Same |
| StakeVoteDeleg (10) | Stake credential | K/N/P | Same |
| StakeRegDeleg (11) | Stake credential | K/N/P | Same |
| VoteRegDeleg (12) | Stake credential | K/N/P | Same |
| StakeVoteRegDeleg (13) | Stake credential | K/N/P | Same |
| AuthCommitteeHot (14) | Cold credential | K/N/P; hot credential does not select author | Same |
| ResignCommitteeCold (15) | Cold credential | K/N/P | Same |
| RegDRep (16) | DRep credential | K/N/P | Same |
| UnRegDRep (17) | DRep credential | K/N/P | Same |
| UpdateDRep (18) | DRep credential | K/N/P | Same |

Additional cases cover list/map redeemers, multiple certificates sharing a script,
key/exempt certificates before Plutus certificates, wrong index, wrong purpose,
out-of-range index, unnecessary native/key redeemers, V1/V2/V3 witness scripts,
native reference scripts in both reference and spending inputs, native timelocks
and thresholds, and an invalid native signer following a valid unrelated witness.
A noncanonical native reference-script encoding checks original-byte hashing.
The captured Plutus V3 reference covers correct/missing/incorrect script,
missing/wrong-pointer redeemer, original payment signatures and deposit balance.
A synthetic `validate_txs` test catches omission of the Conway caller.

## Fixture and reproduction

Reuse the unchanged `settings` transaction and producer ranking blocks from
[provenance.json](provenance.json). See [README.md](README.md) for RealFi naming,
network/capture identity, successful inclusion, and historical parameter limits.
No new network capture, signing material, or deployment journal was imported.

The test first decodes Dijkstra and checks the original transaction ID, success,
producer identity, input indices, and recorded witness/reference-output byte hashes.
It then decodes the **same compatible CBOR** into Conway body/witness/output views
to call `check_witness_set`. It does not pass through era dispatch. The acceptance
path preserves original body/signatures, script, redeemer and UTxO amounts.
Reference output 0 and spending/collateral output 1 come from the same retained
producer. This test adapter is not a genuine Conway capture. Negative cases mutate
only witness data or script availability in memory; synthetic bodies are encoded
and then signed with deterministic test-only keys.

Baseline: `0394139c219920e9518e7efd97aa11bbc50078df`. Extract that tree into a
separate directory, copy the final `certificate_witnesses.rs`, `certificate-witnesses-provenance.json`
and integration `tests/conway.rs`, and add only its `#[cfg(test)]` module declaration
to `phase1/conway.rs`. No production behavior is changed in the baseline. Use its
own Cargo target directory. The baseline already contains the same captured blocks and dependencies.

```sh
cargo test --offline -p pallas-validate --features unstable --lib certificate_witnesses
cargo test --offline -p pallas-validate --test conway certificate_script_is_required_through_dispatch
cargo test --offline -p pallas-traverse --features unstable --test musashi_registration
```

The final baseline/fixed outcomes and repository gates are recorded in
[certificate-witnesses-verification.json](certificate-witnesses-verification.json). Baseline failures are assertions,
not build errors. The valid capture fails specifically at `UnneededRedeemer`;
removing its redeemer, or both redeemer and reference script, incorrectly returns
`Ok(())`. The fixed expectations are success, `RedeemerMissing`, and
`ScriptWitnessMissing`, respectively. The dispatch baseline reaches
`VKWrongSignature`, whereas the fix rejects at `ScriptWitnessMissing` before the
intentionally stale signature. Baseline and fixed builds use separate directories.

## Remaining gaps and next step

- No native Dijkstra phase-one dispatch, complete native transaction validation,
  or submission is established. These require native era dispatch and end-to-end
  submission tests.
- No genuine Conway network registration is claimed. Other certificate kinds
  have synthetic authorization coverage, not captured successful state transitions.
- Earlier-era validators, genesis delegation and MIR are unchanged. Dijkstra pool
  BLS validity and certificate state/deposits/refunds beyond the
  [stake-registration accounting tests](README.md) remain untested.
- Plutus execution, redeemer data semantics, script context/language restrictions
  and integrity hashes are outside these focused witness tests. The next missing
  behavior is resolving `Reg` certificate purposes in phase two, including the
  reference script in the retained capture.
- Governance voting/proposal and withdrawal authorization, general native scripts
  unrelated to certificates, duplicate redeemer-list validation, cross-era UTxO
  accessors, and canonical hashing of witness-carried native scripts remain outside
  this fix. Reference-output access here still uses Conway views; native
  Dijkstra input consumers need separate implementation and tests. This is not
  a claim of complete phase-one validation.
- Historical node/evaluator version and independent historical parameter comparison
  remain unavailable as documented in [the capture provenance](provenance.json).

Downstream consumers must verify complete registration validation, script execution
and submission before removing compatibility workarounds. These focused tests
do not establish that integration result.
