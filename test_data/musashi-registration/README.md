# Stake-registration deposit accounting

Conway's value-preservation check omitted stake-registration deposits from
produced value. A shared accounting helper now adds the fee and one protocol
key deposit for each stake registration, including registration with delegation.
It uses existing `MultiEraCert::kind()` accessors and checked arithmetic;
original input values are unchanged.

These two successfully included Musashi registrations exercise that production
helper through native Dijkstra decoding. They are evidence for the shared
accounting rule; Conway caller coverage uses separate synthetic cases.

The fixture names come from the RealFi V1.1 application deployment on Musashi.
`settings` registers the stake credential of RealFi's settings validator;
`protocol` registers the stake credentials of four RealFi protocol validators.
They correspond to the deployment steps `registerSettingsStake` and
`registerProtocolStakes`, respectively. These application names identify the
captured transactions; the deposit-accounting rule applies to stake registrations
from any application.

| Case | Transaction ID | Slot | Registrations | Deposit |
| --- | --- | ---: | ---: | ---: |
| settings | `da910a9bfbe657724d64b505099010dd47f86fb573aa1d20b4da0367163e94c6` | 1401365 | 1 | 2,000,000 lovelace |
| protocol | `4918868794546ff4c10121a7caef9b74a208e59e191945a3bd48d21dc7fe2b2e` | 1401321 | 4 | 8,000,000 lovelace |

The eight payload files contain lowercase hex without a trailing newline, matching
the existing Pallas fixtures. `blocks/*.block` holds four original ranking blocks:
the two registration blocks and their input producers. `*.body.hex` and
`*.input.hex` hold the two transaction bodies and their spending outputs.
Hex decoding recovers the exact original CBOR bytes; no CBOR was re-encoded.
No input value or captured transaction was changed to make a test pass.

`provenance.json` records checksums of the decoded CBOR bytes (not the hex text),
separately indexed header hashes, transaction positions, network identity and
capture sources. It retains only the
relevant fields from the historical Dolos epoch-64 parameter response, including
the 2,000,000-lovelace key deposit and the complete response's SHA-256. This
excerpt is not independent node parameter verification. The exact historical
node/evaluator build was not established. A full certificate-state reconstruction
is unnecessary for this value rule and is outside this reduced fixture.

The specification is cardano-ledger revision
`1587f21a7d1306dc590c2749a5c66232ef66aad0`:
[Shelley's deposit calculation](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/shelley/impl/src/Cardano/Ledger/Shelley/TxCert.hs#L613)
counts stake registrations and charges the protocol key deposit.
[Conway's registration lookup](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/conway/impl/src/Cardano/Ledger/Conway/TxCert.hs#L138)
includes legacy, explicit and combined registrations;
[Dijkstra uses the same deposit calculation](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/dijkstra/impl/src/Cardano/Ledger/Dijkstra/TxCert.hs#L311).
[Conway DELEG](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/conway/impl/src/Cardano/Ledger/Conway/Rules/Deleg.hs#L205)
separately checks the supplied amount and prior registration state. The pinned
source files were verified during capture.

## Regression and limits

Run offline from the Pallas root:

```sh
cargo test --offline -p pallas-validate --features unstable --lib registration_deposits
cargo test --offline -p pallas-validate --test conway registration_deposit_is_required_through_dispatch
cargo test --offline -p pallas-traverse --features unstable --test musashi_registration
```

The native accounting tests decode the original registration blocks, identify
the transactions and inputs, and verify that these cases have no mint, withdrawals
or other balance terms. They supply the actual certificates, output values, fee
and historical key deposit to `add_fee_and_stake_deposits`, then assert that its
result equals the original spending input. They do not convert the transaction
or its input output to another era. Dijkstra already shares Conway's value type.

On baseline `385599890cda4c6384dbfc102849709f7adc9d97`, the unchanged native
assertions fail because produced value lacks exactly 2,000,000 lovelace (settings)
and 8,000,000 lovelace (protocol). The focused suite reports 4 passed / 7 failed;
with the fix it reports 11 passed. The Conway dispatch regression fails on the
baseline because it reaches `VKWrongSignature`, skipping the deposit imbalance;
with the fix it correctly reports `PreservationOfValue` before signature checks.
The original, unmodified Conway control passes on the prepared baseline.

Baseline replay uses a behavior-preserving extraction of the original fee-only
addition into the new helper interface. Copy the final tests, fixture files,
feature/dev-dependency declarations and typed Conway caller to the baseline;
keep the helper's body as the original operation:

```rust
conway_add_values(
    outputs,
    &ConwayValue::Coin(fee),
    &ValidationError::PostAlonzo(PostAlonzoError::NegativeValue),
)
```

Its certificate and key-deposit arguments are unused there. The rest of the old
accounting is unchanged. Run identical tests/payloads on both versions, with
separate Cargo target directories. An interface or compilation failure does not
count as reproducing the omission.

Synthetic Conway tests cover all five stake-registration forms (Dijkstra retains
four), both output encodings, changing protocol deposits, absent/delegation-only
certificates, missing registrations, surplus/deficit and wrong declared amounts
with compensating fees. Shared-helper tests cover overflow and native-asset
preservation. The dispatch test deliberately mutates a native Conway fixture;
it isolates balance before signatures and does not claim valid witnesses.

The integrity test checks all eight payload hashes, header and block-body
commitments, successful inclusion, certificate deposits, transaction body IDs,
the spending input reference, and its exact original output bytes. Both input
producers are successful ranking transactions, so no endorser payload is needed.

Scope is the stake-registration component: `StakeRegistration`, `Reg`,
`StakeRegDeleg`, `VoteRegDeleg` and `StakeVoteRegDeleg`. Refunds, pool/DRep/proposal
deposits, withdrawals and full certificate validation remain separate work.
The current validator does not necessarily reject every omitted case. These tests
do not establish genuine Conway network-registration coverage or full native
Dijkstra validation/submission. Keep the Dolos deposit shim until S07 integration
verification passes.
