# S06 integration with the published Pallas history

The integration combines the tested S06 checkpoint
`fee0fac2cf7ad3fde2e19eae96d618ec1d4f52ca` with published Pallas
`a5f93ea58900020058ae22f5108f97b7d69f9373`. The remote history was restacked;
its phase-one fixes are patch-equivalent to the earlier checkpoint, while its
networking implementation and removal of the old follow layer must be retained.

A local merge preserves both histories. Before adding this report, the resulting
index was verified byte-for-byte as the published tree plus the exact S06 diff
from `4be4fb2171a73bdb04994c8472e76f601d41318f` to `fee0fac...`.
The diff contains only validation phase-two code, its evidence, dependency/compiler
configuration, CI, README and changelog. Its SHA-256 is
`52074f2fa04dddccbf1acdabc956ebde07cabfd8d342df0bca6eded62c40a030`.
No networking implementation was ported from the old branch, no commits were
rebased, and no historical tag was moved. Existing captures remain unchanged.

The Amaru candidate is `e122ffb2018196ba9c57f42b70b94ada603d3fbc`, branch
`experiment/rust197-compat`. Its full workspace passed after libclang installation;
see the adjacent `dual-evaluator/` report for runtime baselines and independent
CLI comparisons. The initial integration checks use the already-tested local Git
URI. Publication of this candidate is still required before changing to the exact
GitHub fork pin and verifying that portable dependency. No push is authorized for
the assistant; the user will publish the branch.

All supported/unsupported evaluation boundaries from `dual-evaluator/README.md`
remain in force. This is scoped S06 work, not S07, Dolos integration or submission.
No provisional registration state is committed. The canonical Dolos checkout
remains `c431ca8dbaa40af31a715fda498505d9a9415105` with its original Pallas pin;
read-only inspection found remote `abe2642391006e7e5439a00493d41db5da280a02`
already pins Pallas `a5f93ea...`. That remote Dolos history was not applied here.

Verification commands, exact dependency lock and results are retained alongside
this report. The Pallas integration remains on its isolated branch until the
published dependency has been verified; canonical branches are not yet advanced.

At this preparation checkpoint, all 241 native/earlier-era validation tests and
the workspace build pass on Rust 1.97. The remaining workspace/feature/lint/docs
checks are still running (session 29563); no complete check-suite pass is claimed.
The seven known harvest.rs formatting differences are pre-existing.
