# Published Musashi cost-model regression

This commit contains **tests and evidence only**. The production Alonzo parser
is unchanged from upstream de8177d. Upstream already preserves complete ordered
cost arrays, PlutusV3/V4 and numbered Unknown models with their intended precedence.
Dolos's upstream era translation carries the injected models into bootstrap.

The test compares every V1/V2/V3 coefficient from the published Musashi Alonzo
genesis through the existing merged-model conversion to conway::CostModels.
The arrays have 332/332/350 entries. No duplicate explicit-override API or parser
wrapper remains, and no local stricter malformed-input policy is imposed.

The fixture was downloaded on 2026-10-29, matched the configured local bytes,
and matched the advertised genesis hash. Public URLs/hashes are in
public-source.json; complete bootstrap fixtures are in the paired Dolos repository.
The isolated cleanup candidate passed 78 unit tests and the doc test. Current
verification is also recorded with the final paired cleanup results.

## Historical investigation

The earlier local parser truncated V1/V2 and skipped V3. We initially added
extra_cost_models and a strict wrapper while investigating the TTL spend. After
rebasing, upstream had independently fixed the parser and Dolos propagation, so
our extra production code became unnecessary and was removed. Original source
hashes, test logs and rebase records in provenance.json describe those historical
checkpoints; they are retained rather than rewritten as current results.

This fixture establishes published initial parameters, not an independent query
of every active parameter. The user subsequently replayed the corrected node
state and TTL attempt 005 executed successfully; its native evidence is retained
separately under ../musashi-ttl/confirmed-ttl. No keys or private journals are included.
