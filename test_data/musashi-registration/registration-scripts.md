# Registration-certificate scripts in phase two

The phase-two resolver rejected explicit-deposit `Reg` certificates with
`UnsupportedCertificateType`. It now selects the certificate's author credential
and resolves its hash through the existing script table, including reference
scripts and witness-carried scripts. Key credentials still fail with
`NonScriptStakeCredential`; legacy witness-free registration and pool certificates
remain unsupported as phase-two targets. No new resolver or validation framework
is introduced.

The existing purpose builder already selects from the **full certificate list**
and constructs `Certifying(index, certificate)`. The fix also translates `Reg`
into V1/V2 `DCertDelegRegKey (StakingHash credential)`, avoiding the previous
unreachable-code panic. Other certificate encodings are unchanged.

## Ledger rules and supported context

Primary source: cardano-ledger revision
`1587f21a7d1306dc590c2749a5c66232ef66aad0`. Source URLs and SHA-256 checksums are
in [registration-scripts-provenance.json](registration-scripts-provenance.json).

- [Conway certificate authors](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/conway/impl/src/Cardano/Ledger/Conway/TxCert.hs#L809):
  explicit registration requires its credential's witness; legacy registration
  does not. A script credential selects its own hash.
- [Script purposes](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/conway/impl/src/Cardano/Ledger/Conway/UTxO.hs#L70)
  enumerate all certificates, including certificates without a Plutus witness.
- [V1/V2 translation](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/conway/impl/src/Cardano/Ledger/Conway/TxInfo.hs#L400)
  maps explicit registration to legacy registration, omitting the deposit and
  wrapping the credential in `StakingHash`.
- [V3 translation](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/conway/impl/src/Cardano/Ledger/Conway/TxInfo.hs#L570)
  intentionally omits registration deposits at protocol version 9; later versions
  include them. The [V3 purpose](https://github.com/IntersectMBO/cardano-ledger/blob/1587f21a7d1306dc590c2749a5c66232ef66aad0/eras/conway/impl/src/Cardano/Ledger/Conway/TxInfo.hs#L638)
  includes both the certificate index and translated certificate.

**The successful replay is an explicitly derived Conway bootstrap (protocol 9)
view, not historical protocol-12 replay or native Dijkstra evaluation.** Pallas's
existing V3 context encoder always omits the registration deposit. This regression
uses protocol 9, where that encoding agrees with the ledger, and asserts the
actual encoded purpose. Protocol-aware V3 context translation after version 9
remains a separate gap; successful execution must not conceal it.

## Captured evidence and replay

Reuse the original settings registration
`da910a9bfbe657724d64b505099010dd47f86fb573aa1d20b4da0367163e94c6`,
its block at slot 1401365, and the producer block at slot 1401345.
“Settings” identifies a RealFi application settings validator, not a ledger
configuration setting. [README.md](README.md), [provenance.json](provenance.json)
and [certificate-witnesses.md](certificate-witnesses.md) describe its capture,
network identity, successful inclusion, and original phase-one evidence.
All eight existing captured CBOR payloads remain byte-for-byte unchanged.

The tests decode the blocks natively as Dijkstra, check transaction/producer
identity and successful inclusion, and hash the original witness and reference
output bytes. They decode compatible original body/witness/output CBOR into
Conway views. The reference script is the captured Plutus V3 script with hash
`9eb9018892f84064087cfb1559cab8956d6300c47b6f325a7262c3db`, on producer output 0;
output 1 supplies the original spending input. The acceptance path preserves
body, redeemer, script and input values. No private deployment files or signing
keys are needed.

`eval_redeemer` follows production script lookup, transaction-info construction,
context encoding and the `amaru-uplc` evaluator. The result is checked for actual
`success == true`, absent failure message and positive execution units, rather
than merely successful lookup or an `Ok` containing a failed evaluation.
Observed result: `Cert[0]`, memory 18485, CPU 4805428, no logs or failure.
These units use the evaluator's built-in cost model; they are **not** an exact
historical budget comparison or proof that the transaction meets its ledger budget.
The historical node/evaluator build remains unknown.

The test slot configuration uses the captured genesis start, slot zero and
one-second slots. Protocol 9 is a synthetic context choice; the historical
parameter excerpt records protocol 12. Full historical cost models are not fed
into the current evaluator. This is a focused certificate rule test, not full
transaction validation or a submission test.

## Regression and negative cases

All mutations are synthetic, in memory; none replaces captured CBOR on disk.
Body mutations invalidate signatures and are tested only at phase two.

| Case | Required result |
| --- | --- |
| Unchanged captured script/reference/redeemer, Conway view | Successful V3 execution |
| Remove reference script | `MissingRequiredScript` with the certificate's exact hash |
| Replace reference script with unrelated bytes | Same exact missing-script error, before decoding/executing unrelated bytes |
| Certificate indices 1 and `u32::MAX` | `MissingScriptForRedeemer` |
| Change purpose to mint with no mint entry | `MissingScriptForRedeemer` |
| Point to a key `Reg` | `NonScriptStakeCredential` |
| Point to legacy exempt registration | `UnsupportedCertificateType` |
| Insert key certificate before script registration, list redeemer at index 1 | Resolve captured V3 script, build `Certifying(1, original Reg)`; index 0 rejects key target |
| Relocate captured V3 script from reference output to witness set | Successful execution of the same script |
| Derived V1/V2 contexts without reference inputs | Exact registration encoding in both purpose and certificate list, including `StakingHash` |

Reproduce using only tracked files:

```sh
cargo test --offline -p pallas-validate --features unstable,phase2 --lib registration_scripts -- --nocapture
```

For the baseline, extract `fd67e8ff1fa75c2057d500f5eafb252c089c0d71` into a
separate directory, copy the final
`pallas-validate/src/phase2/script_context/registration_scripts.rs`, and append
only `#[cfg(all(test, feature = "unstable"))] mod registration_scripts;` to
`phase2/script_context.rs`. Preserve baseline production code and captured files.
Use a separate `CARGO_TARGET_DIR`. The identical assertions yield **2 passed,
6 failed** before the fix and **8 passed** afterward. The actual captured-script
assertion fails specifically with `UnsupportedCertificateType`, not a compiler
failure. V1/V2 translation independently reproduces the baseline panic.
[registration-scripts-verification.json](registration-scripts-verification.json)
records commands, source hashes, outcomes and repository checks.

## Remaining work

Native Dijkstra phase-two dispatch and contexts, protocol-aware post-bootstrap
V3 deposit/refund translation, historical cost-model/budget enforcement, complete
transaction validation and submission remain unverified. V1/V2 tests here verify
context encoding, not captured V1/V2 network execution. Other certificate kinds'
context encodings and language restrictions are not audited by this fix; in
particular existing legacy certificate encodings remain unchanged. The generic
script table's input filtering is unchanged and callers must supply transaction
inputs. No genuine Conway network capture is claimed.

Downstream's local `Reg` resolver workaround now has a tested replacement for
this scoped rule, but must remain until native validation/evaluation and complete
submission integration pass. No downstream pin or workaround is changed here.
