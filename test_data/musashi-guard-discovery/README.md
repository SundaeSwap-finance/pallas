# Phase-two guard discovery regressions

These tests use unchanged native Musashi blocks at slots 1401365 and 1401345
from `../musashi-registration/blocks/`, with explicitly synthetic mutations.
[provenance.json](provenance.json) records decoded-byte checksums, transaction
and block identities, capture tool revision, historical parameters and limits.
The original transaction registers RealFi's settings validator: an application
configuration validator, not a Cardano protocol setting. The producer supplies
the spending and reference outputs through the existing native fixture helper.
Original captures are never rewritten; no signing keys are used.

## Rebase onto current V4 support

The original local fix `0d4bfc58bf21bfc1b0aacd7e094d5df9da31b23b` was written
against `b7a9d8661c225b2df04dfa94770f58a049211fcd`, where phase two omitted guard
purposes and refused all V4 execution. Both missing-guard cases could return
`Ok([])` from evaluation and estimation.

Upstream `924e3f2d80d4e454e8226324fdd71decc8221f04` now supplies V4/Guarding and
subtransaction evaluation. Its shared `redeemer_scripts` collector already adds
guards before native filtering, witness checks and the empty-report shortcut.
The rebased change retains upstream production code and adds regression coverage.
The redundant local collector is removed; its boundary tests now exercise the
shared production collector through a synthetic `Level`.

A V4 witness without a redeemer must now report the missing `Guarding[0]`
redeemer. Supplying the matching redeemer can execute V4, so the former blanket
refusal control is now a positive execution control. The upstream legacy feature
case supplies a real witness and still expects `script guards`; the separate
missing-witness regression expects `MissingRequiredScript`.

## Current coverage

| Case | Expected behavior in both APIs |
| --- | --- |
| Guard without witness or redeemer | `MissingRequiredScript` |
| V4 guard with witness but no redeemer | `RequiredRedeemersMismatch`, missing `Guarding[0]`, no extras |
| No guards or other script purposes | Empty successful report |
| Native guard supplied directly or by reference | Empty successful report; no phase-two redeemer required |
| Supplied V1, V2 or V3 guard script | Legacy context rejects `script guards` |
| V4 guard with matching witness and redeemer | One successful `Guarding[0]` result |

Synthetic collector tests cover absent guards, both key-only representations,
and `[key, script A, key, script B]` retaining indices **1 and 3**, tags and hashes.
They decode the synthetic body `a3008001800200` (empty inputs/outputs, zero fee)
solely to construct a `Level`; this is not a valid admission fixture.

The omission cases retain the archived epoch-64 V3/V4 vectors supplied by
`guard_params`; they fail before machine execution. The positive V4 control uses
upstream's `v4_params` and its existing 369-entry model from
`../dijkstra-plutus-v4/1896.json`. This distinction is explicit in provenance;
the historical 251-entry vector is not silently changed to make execution pass.

Run using the repository's pinned toolchain and normal ignored target directory:

```sh
cargo test --locked --offline -p pallas-validate --features phase2,unstable native_guard_ -- --nocapture
```

## Historical proof and limits

Before the rebase, the same original assertions failed at runtime on `b7a9d866`
after both APIs printed `Ok([])`, then passed on `0d4bfc58`. The no-guard control
passed in both. The original tests, checksums and expectations remain available
at the immutable local tag `musashi-guard-discovery-pallas-20261106` and in
`historical_pre_rebase_verification` / `historical_pre_rebase_regressions`.
Those results are historical evidence, not a claim that the rebased test source
is identical. The Musashi work plan records separate rebased results and logs.

Mutated signatures and integrity commitments are not recomputed. These cases
establish discovery, indexing, errors and one synthetic V4 execution control;
they do not establish phase-one admission, current spendability, complete native
Dijkstra validation, Dolos integration or on-chain acceptance. Upstream V4/batch
behavior is retained and must be covered by its existing tests as well. Historical
parameter provenance comes from the archived Dolos response, with its stated
limits; capture-time node version and current state remain unknown.
