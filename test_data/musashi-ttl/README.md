# Musashi TTL regression fixtures

Two **constructed test transactions captured from Musashi**, preserved as native
Dijkstra bytes:

| Fixture | Purpose |
| --- | --- |
| `confirmed-ttl` | Successful final-pair live spend; default regression input |
| `cross-epoch-ttl` | Signed cross-epoch bounds regression using its original historical local parameters; no network success claimed |

The tiny Plutus V3 validator requires the owner's signature and a finite,
exclusive upper bound equal to the redeemer's POSIX-millisecond value. It has no
fixed expiry. Both cases retain complete replay inputs, parameters and historical
time context; shared genesis initializes the caller domain. No captured CBOR was
rewritten or relabelled. The confirmed spend has no mint, certificates,
withdrawals, script guards, reference inputs or subtransactions.

Confirmed transaction:
`9b354b0f9b042c677ffdb15665a914499d2bdcef093cd834d5ce0538b212f56f`,
slot `1109288`, block
`5db7f685a86823f403496907ffa503265b49aa7db392bd2b4cbd3bbf8f5afd79`.
We observed 32 subsequent blocks, a 1,818,528-lovelace wallet return and unchanged
1,000,000-lovelace collateral. No rollback was observed in periodic checks.
The peer ranking block has no inline transactions: the original endorser map and
selected block transaction preserve the native success flag and exact signed
body/witnesses. `confirmed_native_proof_matches_signed_transaction` checks the
announcement, parent link, certificate presence and payload commitment. It does
not independently verify BLS signatures or full consensus.

`provenance.json` records identities, tools, decoded-byte checksums and limitations.
The reference CLI costs are retained. The three small text logs are the original
post-inclusion baseline/fixed/caller results. Broader build logs, builders, setup
transactions, unsuccessful retries and the first successful capture are archived
outside these commits, with checksums and original Git backup refs.

The confirmed capture uses the observed 350-entry V3 model. The cross-epoch case
keeps its original 251-entry local model; it is not evidence of network validity.
Parameters came from Dolos, without an independent reference-node parameter RPC.
The CLI era interpreter derives the observed one-second mapping, not an LSQ era
history dump. Upstream node build is unknown. Full consensus forecast enforcement
is separate. No keys or private deployment journals are included.

Run from Pallas (Rust 1.97.0, dependencies cached for `--offline`):

```sh
python3 test_data/musashi-ttl/verify.py
cargo +1.97.0 test --offline -p pallas-validate --features phase2,unstable --test dijkstra_ttl
```

All bounds, historical mapping, overflow and native-proof cases run together.
`PALLAS_TTL_FIXTURE`, when set, points to this collection directory.
To reproduce the original TTL rejection with separate build outputs:

```sh
work=$(mktemp -d /tmp/pallas-ttl-baseline.XXXXXX)
git archive f3419a3a1e3e7c33d0b9027343089b5030ec8ef3 | tar -x -C "$work"
patch --batch -d "$work" -p1 -i "$PWD/test_data/musashi-ttl/baseline-api-adapter.patch"
cp pallas-validate/tests/dijkstra_ttl.rs "$work/pallas-validate/tests/"
cp -R test_data/musashi-ttl "$work/test_data/"
CARGO_TARGET_DIR="$work/build" cargo +1.97.0 test --offline \
  --manifest-path "$work/Cargo.toml" -p pallas-validate --features phase2,unstable \
  --test dijkstra_ttl captured_ttl
# Expected runtime exit 101: signatures pass; phase one/two/estimation reject TTL.
```

The adapter supplies only the newer test-facing API/parameter fields; the original
phase-one, phase-two and native evaluator files remain byte-identical to baseline.
The same success assertions pass on the fix, independent of current expiry or
spendability. Do not resubmit these captured transactions.
