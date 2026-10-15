# Native guard reference scripts in legacy contexts

A native reference script containing `RequireGuard` can be **carried** by a
Dijkstra output while Plutus V3 runs. Its presence does not request execution of
a guard. The script's original hash is the only reference-script information
exposed in the V3 output context. This also applies to nested constructors and to
`RequireGuard` naming a script credential. Do not translate constructor 6 into
Conway or replace the native script to obtain that hash.

## Pinned expectations

The offline reference is `cardano-cli 11.2.2.0`, binary SHA-256
`9bf4a2576754ff76533c387687cfb8fbe0713fac6952a0db973356b00a376e9d`.
Its reported revision `afa091b4af2795d1d9c46e59145ed16127760f7b` belongs to
[cardano-node; its build manifest](https://github.com/IntersectMBO/cardano-node/blob/afa091b4af2795d1d9c46e59145ed16127760f7b/cabal.project)
pins ledger `1587f21a7d1306dc590c2749a5c66232ef66aad0`, API
`e32d8c07035283233fbdca4beeafbd78abc66512`, and CLI source
`517ffe9ed02bba2b9ed644454a74c280ad62c2fa`. This identifies the inspected local
reference build, not the historical accepting or currently deployed Musashi
node. Those node build identities remain unknown. The ledger's Plutus package
constraint is `plutus-ledger-api >=1.68`; the binary's exact resolved Plutus
version is unknown.

The reference ledger's
[Dijkstra TxInfo](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/dijkstra/impl/src/Cardano/Ledger/Dijkstra/TxInfo.hs)
uses `Babbage.transTxOutV2` for V3 outputs and the same translation through
`Conway.transTxInInfoV3` for spending/reference inputs.
[Babbage TxInfo](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/babbage/impl/src/Cardano/Ledger/Babbage/TxInfo.hs)
`transReferenceScript` hashes any era-native script; it does not inspect its
constructors. V2 follows that same hash projection. V1 rejects reference scripts
altogether. This increment does not add V1/V2 execution to Pallas's Dijkstra path.

By contrast, `guardDijkstraFeaturesForPlutusV1toV3` rejects script credentials in
field 14 and nonempty field 24. The current ledger comparison revision
[`af08d7b551a31a3e87cf9b46dfa65bf99588294b`](https://github.com/IntersectMBO/cardano-ledger/blob/af08d7b551a31a3e87cf9b46dfa65bf99588294b/eras/dijkstra/impl/src/Cardano/Ledger/Dijkstra/TxInfo.hs)
retains these distinctions. Neither a missing key guard nor an incorrect native
witness is made valid by allowing a script's hash into a context. Native execution
still checks current-body guard membership in
[`evalDijkstraNativeScript`](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/dijkstra/impl/src/Cardano/Ledger/Dijkstra/Scripts.hs).

CIP comparison is pinned to `cc548aa2e5b24a8c5309abcd43fa911418f92896`:
[CIP-0112](https://github.com/cardano-foundation/CIPs/blob/cc548aa2e5b24a8c5309abcd43fa911418f92896/CIP-0112/README.md)
still uses observer terminology and proposed context changes;
[CIP-0118](https://github.com/cardano-foundation/CIPs/blob/cc548aa2e5b24a8c5309abcd43fa911418f92896/CIP-0118/README.md)
requires V4 for new features and discusses legacy isolation. Its root field-24
prose differs from ledger code. Public prose is not the deployed implementation.

## Minimal fixtures and results

The three `.hex` files are **synthetic**, not captured scripts:

- `direct`: `RequireGuard(KeyHash(02…02))`.
- `nested`: `All([Any([NOfK(1, [RequireGuard(KeyHash(02…02))])])])`.
- `script-credential`: `RequireGuard(ScriptHash(03…03))`.

`provenance.json` hashes decoded CBOR, including the native-script hash with its
zero language prefix. Existing captures remain in `musashi-registration` and
`musashi-phase1`; no original native bytes are duplicated here. The captured
transaction `da910a9b…3e94c6` registers RealFi's settings validator (an
application-specific protocol configuration script). Its original body, witnesses,
V3 validator, inputs and historical protocol-12 350-entry model are the control.

The offline probe adds only a native reference script to its single output,
retaining raw original address/value fields and all other body/witness bytes.
The output's legacy CBOR shape becomes the Dijkstra map shape to carry field 3.
All three mutations and the original control execute the original V3 validator
successfully: **18,485 memory / 4,805,428 steps**. They prove context translation
acceptance, not that this validator checks reference-script hashes. Pallas tests
separately assert exact context hash encoding. A synthetic V3 validator reads
the output reference hash: the original nonminimal-CBOR hash succeeds and the
semantic re-encoding hash fails. This projection also corrects nonminimal
guard-free native reference hashes in Dijkstra; the earlier-era serializer is
unchanged.

A separate synthetic field-24 control fails specifically with
`RequiredTopLevelGuardsNotSupported`. This historical ledger encodes field 24 as
a **map**; the control does not pretend to test the current array representation.
The mutations invalidate original signatures and are phase-two evidence only.
No guard was funded, signed, submitted or confirmed on-chain.

Two reference-tool limitations are explicit:

- Native guard reference scripts in an input's UTxO JSON cannot be evaluated by
  this CLI: its `SimpleScript` decoder uses Allegra `Timelock` and rejects native
  constructor 6. Input behavior is supported by the pinned shared ledger
  translation and Pallas caller tests, not an independent CLI input replay.
- Field-14 script-guard probing reaches an API panic,
  `toScriptIndexDijkstra: unexpected DijkstraGuarding at index 0`. That is
  unavailable runtime evidence, not a ledger rejection. Keep the source-backed
  legacy exclusion.

## Offline reproduction

Run from the Pallas root with the pinned CLI available:

```sh
MUSASHI_EVAL_EXPORT=/tmp/musashi-guard-replay \
  cargo test --offline -p pallas-validate --features phase2,unstable \
  export_registration_cli_comparison -- --ignored
python3 test_data/musashi-guard-reference/reproduce.py \
  --cli /home/rodrigo/leios-testnet/bin/cardano-cli \
  --export-dir /tmp/musashi-guard-replay
```

The exporter asserts absent validity bounds. The synthetic era-history interpreter
therefore cannot affect these contexts. The script renames captured parameter
fields without changing the cost vector, preserves all native script bytes, and
asserts the four successful budgets plus the intended required-guard rejection.
Generated envelopes, verbose CLI diagnostics and downloaded source copies stay
outside Git. Durable local archive location is recorded in `MUSASHI_FIX_PLAN.md`.

The Dolos caller replay uses its published `7bab64ec…` source in an isolated
directory, with local Pallas path overrides and no canonical dependency changes:

```sh
CARGO_TARGET_DIR=/path/to/dolos-build-cache \
  test_data/musashi-guard-reference/reproduce-callers.sh \
  /path/to/pallas /path/to/dolos
```

`caller-regression.rs` is appended to the existing TTL integration suite. It adds
each synthetic native reference script to the spending UTxO of the captured
confirmed-TTL transaction `9b354b0f…212f56f`. The in-memory UTxO is synthetic;
the signed transaction, historical parameters and reference-script fees are
unchanged. All three variants pass admission, evaluation, estimation and
builtin-call estimation, preserving the original submitted bytes and script
CBOR/hash. This is offline caller evidence, not a new on-chain confirmation.
The existing confirmed-TTL, cross-epoch and exclusive-expiry tests also pass.
The replay additionally runs unsupported-error mapping and existing estimation
RPC/mapping tests, including legacy Conway behavior. Results: **4 integration,
2 error-mapping and 39 RPC/mapping tests pass**, with no failures. Canonical
Dolos's published Pallas dependency pin remains unchanged.

V4 execution, its verified cost model/language view, `Guarding` dispatch/results,
field-24 data validation, exact V4 context encoding and original-credential
redeemer indexing remain separate prerequisites; batches and child execution
remain later increments. Current Plutus context comparison is pinned to
[`cf3c0feff7034c73c1fa840a9f0b51a2f2354272`](https://github.com/IntersectMBO/plutus/blob/cf3c0feff7034c73c1fa840a9f0b51a2f2354272/plutus-ledger-api/src/PlutusLedgerApi/V4/Contexts.hs),
not the unknown Plutus dependency of the historical node.

For the identical before/after Pallas assertions, export published baseline
`4d4bb129957ac24e9388821c9cd01094673b204b` with `git archive` into a temporary
checkout, copy only `pallas-validate/src/phase2/dijkstra_evaluation_tests.rs`
from this increment into it, and run:

```sh
CARGO_TARGET_DIR=/tmp/guard-baseline-build cargo test --offline \
  --manifest-path /tmp/guard-baseline-source/Cargo.toml \
  -p pallas-validate --features phase2,unstable guard_reference
cargo test --offline -p pallas-validate --features phase2,unstable guard_reference
```

Use separate build directories. Both assertions fail on the baseline with
`DijkstraUnsupported("native script guards")`; the fixed assertions pass.
Compilation failures and development attempts are not regression evidence.
Existing phase-one native tests cover missing guard membership, missing/incorrect
witnesses and short-circuit combinators; the full validation suite retains legacy
exclusions, TTL/cross-epoch and incorrect-context coverage.

## In-memory reference scripts (2026-11-02 review correction)

`KeepRaw::from` creates a script without retained CBOR; mutation also clears its
raw bytes. The projection uses `MultiEraNativeScript::hash()` so such scripts
hash their current encoding, while decoded scripts retain their original hash.
This applies to both the Dijkstra and Conway carrier branches. The general
`MultiEraScriptRef::hash()` helper is unchanged and is not used for this fallback.

`reference_without_raw` tests construct and mutate scripts in both eras, compare
the projected hash with the encoded script hash, and compare complete output
context data before/after a CBOR roundtrip. Both tests fail on the unamended
`38ee58d` with the prefix-only hash; the roundtrip controls pass. Existing
nonminimal-CBOR and context-sensitive validator tests protect byte preservation.
These are synthetic in-memory boundary tests, not new network captures. The
prior independent CLI evidence and its limitations remain unchanged.
