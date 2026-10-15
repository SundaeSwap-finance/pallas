# Native Dijkstra input UTxOs

The Conway input consumers now inspect native Dijkstra outputs without changing
an output's era or CBOR. The captured payment witness previously failed with
`InputDecoding`; its reference script was also invisible, producing
`ScriptWitnessMissing`. Address, value and datum inspection use the existing
`MultiEraOutput` accessors. Only reference scripts cross a checked representation
boundary into the script types this validator can handle.

This is a scoped input-consumer regression using a Conway transaction view.
It does **not** establish native Dijkstra transaction dispatch, phase-two contexts,
evaluation, historical replay or submission. The existing
[registration script execution proof](registration-scripts.md) still uses an
explicitly derived Conway **protocol-9** context. Native Dijkstra evaluation and
protocol-aware post-bootstrap V3 deposit/refund translation remain outstanding.
No phase-two production code changes here.

## Captured evidence

The smallest retained suitable case is the settings registration
`da910a9bfbe657724d64b505099010dd47f86fb573aa1d20b4da0367163e94c6`, at slot
1401365, and its producer
`3171608e4d1b0812131e64e40f670ab7cdeef7f8e0cbad096b0d15dc62b76ba9`, at slot
1401345. Settings identifies the RealFi application settings validator, as
explained in [README.md](README.md). Producer output 1 is both spending and
collateral input; output 0 carries the captured Plutus V3 reference script.
The tests need only the two existing blocks and the existing extracted spending
output; no new payload, private journal or signing material is imported.

Both blocks decode natively as Dijkstra, and both transactions have successful
ledger outcomes. Tests check transaction/producer identities, input positions,
original witness and reference-output hashes, and the spending output against
`settings.input.hex` and its decoded-byte checksum. The unchanged body and
witness CBOR are decoded into the existing Conway transaction view. **Every
resolved output remains `MultiEraOutput::Dijkstra`; `as_conway()` is `None`.**
There is no input-output Conway wrapper or Dolos era relabeling.

Capture identity, network magic 164, genesis identity, capture revision, original
payload checksums and historical protocol-12/key-deposit excerpt are recorded in
[provenance.json](provenance.json). Reference-output and witness identities are in
[certificate-witnesses-provenance.json](certificate-witnesses-provenance.json).
[native-inputs-provenance.json](native-inputs-provenance.json) records the scope,
source hashes and synthetic derivations. Historical node/evaluator versions and
independent historical parameter verification remain unavailable.

## Applicable rules and supported scope

Ledger comparison uses cardano-ledger revision
`1587f21a7d1306dc590c2749a5c66232ef66aad0`; this is a pinned specification comparison,
not identification of the unknown historical node binary.

- [Dijkstra TxOut](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/dijkstra/impl/src/Cardano/Ledger/Dijkstra/TxOut.hs#L28)
  uses the Babbage output representation and address/value/datum/reference lenses.
  Pallas likewise shares legacy outputs, datum options and Conway values.
- [Dijkstra scripts](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/dijkstra/impl/src/Cardano/Ledger/Dijkstra/Scripts.hs#L420)
  upgrade the six existing timelock constructors and add guard requirements.
  The compatibility boundary accepts the existing constructors and Plutus V1–V3.
  V4 returns `UnsupportedPlutusLanguage`; a native guard, including a nested guard,
  returns `UnsupportedNativeScript`. It does not treat an unsupported script as absent.
- [Reference availability and datums](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/babbage/impl/src/Cardano/Ledger/Babbage/UTxO.hs#L75)
  distinguish spending, reference and collateral inputs. Scripts are available
  from spending and reference inputs, not collateral-only or unrelated outputs.
  Reference datum hashes can justify supplementary datum witnesses.
- [Babbage collateral](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/babbage/impl/src/Cardano/Ledger/Babbage/Rules/Utxo.hs#L193)
  is triggered by redeemers, including when scripts come only from references;
  the input-minus-return balance must be ADA-only, sufficient and agree with
  an annotated total. [Key locking](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/alonzo/impl/src/Cardano/Ledger/Alonzo/Rules/Utxo.hs#L263)
  accepts key and bootstrap addresses, not script addresses.
  [Dijkstra's batch collateral rule](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/dijkstra/impl/src/Cardano/Ledger/Dijkstra/Rules/Utxo.hs#L395)
  includes subtransactions; that transaction-level rule is not implemented here.

| Consumer | Behavior and boundary |
| --- | --- |
| Payment witnesses and spending script hashes | Shared address accessor; Shelley payment key/script credentials work for legacy and map outputs. Malformed/reward input addresses reject. Bootstrap witness validation in this Conway consumer remains unsupported (`InputDecoding`). |
| Value and collateral assets | Existing `value().into_conway()` already reads Dijkstra correctly. No value adjustment or production arithmetic change. Native assets are preserved; zero entries follow the existing earlier-era normalization. |
| Collateral addresses and trigger | Inspect every supplied collateral output; script addresses reject. Nonempty redeemers trigger the existing checks even with reference-only scripts. |
| Input and reference datums | Existing input datum accessor retained; supplementary reference-datum lookup now uses it too. Hash/inline/absent cases covered. |
| Script discovery, mint policies, certificate scripts and redeemer classification | Checked reference boundary; both spending and reference inputs supply scripts. Native hashes retain original CBOR, including noncanonical encodings. Existing certificate native evaluator is reused. |
| Language and script-integrity input discovery | Include native outputs' inline datums/reference scripts and languages. Missing integrity hash rejects when a native input supplies V1–V3. |
| Phase-two input resolution | Audited but unchanged: `phase2/tx.rs` decodes `EraCbor` bytes into Conway `ResolvedInput`, without using the era tag. Replacing that boundary and building native contexts belongs to native evaluation work. |

Supported input inspection covers legacy arrays and post-Alonzo maps, coin and
multiasset values, absent/hash/inline datums, no script or V1–V3/guard-free native
reference scripts. Outputs retain their native identities. The checked projection
copies supported script fields only; native scripts decode through the existing
codec and retain their original bytes in `KeepRaw`. Unsupported references fail
conservatively even if their script is not needed. Collateral-only scripts are
not discovered or evaluated. No new traversal API or validation framework is added.

## Regression coverage

The unchanged capture checks original payment signatures, complete witness-set
checks, registration balance, collateral key locking and collateral accounting.
Synthetic boundary parameters use collateral percentage 150; they are not a
historical parameter replay. Mutations are in memory and explicitly synthetic:

- Missing/corrupt payment witnesses, missing/incorrect/unavailable reference scripts.
- Script, malformed and reward collateral addresses; absent collateral with the
  captured reference-only script; insufficient collateral, wrong total and native
  assets with/without their matching collateral return.
- Input hash datums, reference hash datums, inline datums and unneeded datums.
- V1–V3 references in spending/reference roles for minting and integrity discovery;
  inline/reference input features restrict the V1-compatible output set.
- V4, direct guards and nested guards reject explicitly. Noncanonical native
  all/any scripts retain the committed hash; native certificate references need
  no redeemer and authorization denial is checked.
- Synthetic Shelley through Conway inputs retain era-appropriate values/datums;
  legacy/map representations cover script credentials, collateral and asset
  extraction. Earlier-era payment signatures remain checked. Byron address/value
  inspection and the existing bootstrap witness rejection are explicit.

Two older Conway tests supplied collateral equal to the transaction's collateral
**return**, leaving zero paid collateral. The new reference-only trigger exposes
that invalid test context. `conway4.tx` supplies/returns 2,554,439,518 lovelace
with fee 180,403; `conway5.tx` supplies/returns 49,731,771 with fee 178,819.
Their assertions now require `CollateralMinLovelace` and their names describe it.
Transaction bytes, supplied output values and phase-two test calls are unchanged.
These are corrected assertions for manually supplied UTxOs, not newly verified
historical producer outputs or altered captures.

## Reproduction and verification

```sh
cargo test --offline -p pallas-validate --features unstable --lib native_inputs -- --nocapture
cargo test --offline -p pallas-validate --test conway reference_script_rejects_underfunded_collateral -- --nocapture
cargo test --offline -p pallas-validate --features unstable,phase2
cargo test --offline -p pallas-traverse --features unstable --test musashi_registration
```

Baseline is `9a298f8d8fdf5ed21582d4c8e3836a8e0fde9d15`. Extract that tree to a
separate directory, copy the final `phase1/conway/native_inputs.rs` and
`tests/conway.rs`, and append only
`#[cfg(all(test, feature = "unstable"))] mod native_inputs;` to its
`phase1/conway.rs`. Use a separate `CARGO_TARGET_DIR`; the replay uses
`CARGO_PROFILE_DEV_DEBUG=0` for the baseline, default dev profile for the fix.
No baseline production behavior, captured payload or assertion is changed.

The identical final native-input suite gives **5 passed / 12 failed** before the
fix and **17 passed** afterward. The original payment signature assertion reaches
`Err(PostAlonzo(InputDecoding))` on baseline. The two revised older Conway
collateral assertions both fail on baseline (false acceptance) and pass afterward.
Compilation succeeds on both sides. Detailed outcomes, source checksums and
repository checks are in [native-inputs-verification.json](native-inputs-verification.json).

## Remaining work

Native Dijkstra dispatch, subtransaction rules, certificate/governance state,
native phase-two input resolution and contexts, post-bootstrap V3 deposit/refund
translation, historical cost models/budget enforcement and complete submission
remain separate work. The existing language-availability predicate and general
native script validation beyond certificates were not redesigned. Input inspection
does not prove those rules complete; earlier-era validators are unchanged.
No genuine earlier-era network capture is added. Downstream Pallas pins and all
workarounds must remain until complete integration verifies their replacements.
