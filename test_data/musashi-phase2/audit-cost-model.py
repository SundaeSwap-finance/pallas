"""Audit the scoped evaluator's coefficient names against retained historical data.

Run: python3 test_data/musashi-phase2/audit-cost-model.py /path/to/amaru-uplc-0.1.0
Uses only Python's standard library. Does not establish node/evaluator equivalence.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

here = Path(__file__).resolve().parent
crate = Path(sys.argv[1])
params = json.loads((here / '../musashi-phase1/registration-epoch64-parameters.json').read_text())
raw = params['cost_models_raw']['PlutusV3']
source = crate / 'src/machine/cost_model/cost_map.rs'
text = source.read_text().split('PlutusVersion::V3 => {')[1].split('if values.len()')[0]
keys = re.findall(r'"([^"]+)"', text)
# Audit the rejected candidate, not the final production implementation.
evaluator = here / 'native-candidate.patch'
allow = sorted(set(re.findall(r'F::(\w+)', evaluator.read_text())))


def normalize(name):
    return re.sub('[^a-z0-9]', '', name.lower().replace('memory', 'mem').replace('model-arguments-', ''))


named = {normalize(k): (k, v) for k, v in params['cost_models']['PlutusV3'].items()}
assert len(allow) == 35
allowed = {normalize(x) for x in allow}
entries = []
for index, key in enumerate(keys):
    if normalize(key.split('-')[0]) not in allowed and not key.startswith('cek_'):
        continue
    lookup = normalize(key)
    # Evaluator's historical spelling names this constant "slope" on both sides.
    if key == 'blake2b_224-mem-arguments-slope':
        lookup = normalize('blake2b_224-memory-arguments')
    name, value = named[lookup]
    assert value == raw[index], (index, key, name, value, raw[index])
    entries.append({'index': index, 'evaluator_name': key, 'historical_name': name, 'value': value})
assert len(raw) == 350
print(json.dumps({
    'evaluator': 'amaru-uplc 0.1.0',
    'crate_checksum': 'b565727e99c072b9d29f7ddf9eafffd51ec69a653dad6589c36d4d1ca053603c',
    'cost_map_source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
    'historical_vector_length': len(raw),
    'evaluator_base_mapping_length': len(keys),
    'candidate_builtins': allow,
    'status': 'candidate rejected: protocol-12 argument bounds are not implemented',
    'checked_coefficients': entries,
    'limitations': [
        'Parameter response is captured Dolos data, not independent node parameters.',
        'Evaluator maps the first 251 entries for a 350-entry vector; complete vector is passed unchanged.',
        'Candidate enumerates these builtins and CEK costs; coefficient agreement does not prove their protocol-12 semantics.',
        'Quotient/remainder naming discrepancies outside this subset are not resolved or supported.',
        'This is a coefficient-position audit, not an independent implementation of builtin semantics.',
        'Historical node/evaluator identity and independent execution-unit comparison are unavailable.'
    ]
}, indent=2))
