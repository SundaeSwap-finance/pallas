# Native registration phase-one checkpoint

This is the first half of the split of combined checkpoint
`76003a3054ef7aa4a694bd9b0c47868fa17b92c5`. It follows transfer checkpoint
`1af163ecfa94515477c24f97180dc1aaf849023c` and adds native top-level registration.
It deliberately still rejects all subtransactions and guards; their support is a
separate commit. The combined checkpoint remains preserved by its original tag.
No transaction semantics are being redesigned during this history split.

## Scope and evidence

Native protocol-12.0 `Reg` certificates use explicit known credential prestate:
Unregistered permits registration, Registered rejects it, and an absent entry
rejects as unknown. Check the protocol deposit, credential author, native
certificate redeemer pointers, script-integrity hash, execution budgets,
execution/reference fees and collateral. Registration state changes are staged
until phase one succeeds and remain provisional until phase two succeeds.
Shared input, output, signature and arithmetic helpers land with this first user
of them. No phase-two execution or context translation occurs.

Key credentials and Plutus V3 credentials whose scripts come from original
reference UTxOs are supported. Other certificates, script spending, mint,
withdrawals, datums, witness-carried Plutus, account/governance features, and
Plutus upper validity bounds requiring unavailable forecast state reject
explicitly. Existing key/ADA transfer restrictions remain: no bootstrap,
pointer or script outputs and no multiasset values. Missing parameters or
historical state never imply default historical values.

The unchanged native settings registration
`da910a9bfbe657724d64b505099010dd47f86fb573aa1d20b4da0367163e94c6`
at slot 1401365 uses original Dijkstra spending/collateral output
`3171608e4d1b0812131e64e40f670ab7cdeef7f8e0cbad096b0d15dc62b76ba9#1`
and reference output 0 of the same producer. Settings is RealFi's application
settings validator. Transaction/output CBOR remains in `../musashi-registration`
and is unchanged; there is no Conway wrapper or output-era relabeling.
The original control transfer remains covered by `dijkstra_tests.rs`.

The original 427-byte mempool serialization and 350-entry epoch-64 V3 cost model
produce the original integrity hash. Historical parameter response, certificate
prestate/history and genesis files are byte-identical extractions from S00 backup
`472c235eca7597c96cb95e77fe1b7b0080fce791`. `registration-provenance.json` records
source paths and checksums. Its parameter scan found only the early cost-model and
hard-fork proposals, supporting the captured genesis reference-fee fields within
Dolos's expanded archive trust boundary. This is not consensus replay, proof of
all endorser commitments or independent node parameter verification.

Rules are pinned to cardano-ledger
`1587f21a7d1306dc590c2749a5c66232ef66aad0`. The historical node binary is unknown;
that specification revision does not identify it. The `protocol` registration
fixture still has scoped deposit evidence; only settings has its complete native
phase-one prerequisites packaged for acceptance here. Mutated rejection cases
and key-author cases are explicitly synthetic.

## Independent verification

The registration regression module is unchanged from the combined checkpoint:

```sh
cargo test --offline -p pallas-validate --features unstable --lib dijkstra_registration_tests -- --nocapture
cargo test --offline -p pallas-validate --features unstable,phase2
```

`registration-only-verification.json` and `registration-only-{baseline,fixed}.txt`
record the new replay for this split. The baseline uses `1af163e`, with
`registration-only-baseline-preparation.patch` applied using `git apply
--unidiff-zero`. Copy the new registration test module and the `registration-*.json`
fixtures to the extracted baseline. The patch adds parameter/state/error vocabulary,
module/test wiring and an unused state argument, preserving the old validator's
behavior. It does not add the registration implementation. Baseline and fixed
Cargo targets are separate; compilation errors are not reproduction.

The full native+phase2 validation suite exercises earlier-era regressions too.
Native Clippy, Rust 1.88 and workspace all-feature checks are rerun for this
intermediate tree. Formatting retains the known seven unrelated differences in
`examples/leios-testnet/src/bin/harvest.rs`; changed Rust files are formatted.
Full logs are local at `.git/musashi-s05-split-evidence/`; portable runtime logs,
checksums and summaries are tracked here.

S04 remains scoped input handling; S03 script execution remains derived Conway
protocol 9. Native Dijkstra evaluation and post-bootstrap V3 deposit/refund
translation remain S06. Submission, dependency pins and workaround removal remain
S07. Neither step is part of this split.
