#!/usr/bin/env python3
"""Offline reference probes; no keys, node socket, signing or submission.

First export the original registration with the command in README.md. The small
CBOR reader retains raw children, so changing one output does not re-encode any
other body field, witness or native script. It is fixture tooling, not validation.
"""
import argparse
import json
from pathlib import Path
import subprocess


class Raw:
    def __init__(self, raw, value=None):
        self.raw, self.value = raw, value


class Tag:
    def __init__(self, number, value):
        self.number, self.value = number, value


def decode(data, at=0):
    start = at
    major, additional = data[at] >> 5, data[at] & 31
    at += 1
    if additional < 24:
        number = additional
    elif additional == 31:
        number = None
    else:
        size = 1 << (additional - 24)
        number = int.from_bytes(data[at:at + size], "big")
        at += size
    if major < 2:
        value = number if major == 0 else -1 - number
    elif major in (2, 3):
        assert number is not None, "this capture has definite strings"
        value = data[at:at + number]
        at += number
    elif major in (4, 5):
        value = []
        count = 0
        while ((number is None and data[at] != 255)
               or (number is not None and count < number * (2 if major == 5 else 1))):
            child, at = decode(data, at)
            value.append(child)
            count += 1
        if number is None:
            at += 1
        if major == 5:
            value = {(key.value if isinstance(key.value, (int, bytes)) else key): child
                     for key, child in zip(value[::2], value[1::2])}
    elif major == 6:
        child, at = decode(data, at)
        value = Tag(number, child)
    else:
        assert major == 7 and number in (20, 21, 22)
        value = {20: False, 21: True, 22: None}[number]
    return Raw(data[start:at], value), at


def head(major, number):
    if number < 24:
        return bytes([major * 32 + number])
    for additional, size in [(24, 1), (25, 2), (26, 4), (27, 8)]:
        if number < 2 ** (size * 8):
            return bytes([major * 32 + additional]) + number.to_bytes(size, "big")
    raise ValueError(number)


def encode(value):
    if isinstance(value, Raw):
        return value.raw
    if isinstance(value, Tag):
        return head(6, value.number) + encode(value.value)
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(map(encode, value))
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(encode(k) + encode(v) for k, v in value.items())
    raise ValueError(type(value))


def parameters(repo):
    """Rename captured HTTP fields; preserve every historical cost coefficient."""
    root = repo / "test_data/musashi-phase1"
    p = json.loads((root / "registration-epoch64-parameters.json").read_text())
    g = json.loads((root / "registration-dijkstra-genesis.json").read_text())
    q = {k: v for k, v in g.items() if k != "plutusV4CostModel"}
    aliases = {
        "collateralPercentage": "collateral_percent", "committeeMaxTermLength": "committee_max_term_length",
        "committeeMinSize": "committee_min_size", "dRepActivity": "drep_activity", "dRepDeposit": "drep_deposit",
        "govActionDeposit": "gov_action_deposit", "govActionLifetime": "gov_action_lifetime",
        "maxBlockBodySize": "max_block_size", "maxBlockHeaderSize": "max_block_header_size",
        "maxCollateralInputs": "max_collateral_inputs", "maxTxSize": "max_tx_size", "maxValueSize": "max_val_size",
        "minFeeRefScriptCostPerByte": "min_fee_ref_script_cost_per_byte", "minPoolCost": "min_pool_cost",
        "monetaryExpansion": "rho", "poolPledgeInfluence": "a0", "poolRetireMaxEpoch": "e_max",
        "stakeAddressDeposit": "key_deposit", "stakePoolDeposit": "pool_deposit", "stakePoolTargetNum": "n_opt",
        "treasuryCut": "tau", "txFeeFixed": "min_fee_b", "txFeePerByte": "min_fee_a", "utxoCostPerByte": "coins_per_utxo_size",
    }
    for target, source in aliases.items():
        q[target] = int(p[source]) if isinstance(p[source], str) else p[source]
    q["executionUnitPrices"] = {"priceMemory": p["price_mem"], "priceSteps": p["price_step"]}
    q["protocolVersion"] = {"major": p["protocol_major_ver"], "minor": p["protocol_minor_ver"]}
    q["costModels"] = p["cost_models_raw"]
    for target, key in [("maxTxExecutionUnits", "tx"), ("maxBlockExecutionUnits", "block")]:
        q[target] = {"memory": int(p["max_" + key + "_ex_mem"]), "steps": int(p["max_" + key + "_ex_steps"])}
    groups = [
        ("poolVotingThresholds", "pvt_", {"committeeNoConfidence": "committee_no_confidence", "committeeNormal": "committee_normal", "hardForkInitiation": "hard_fork_initiation", "motionNoConfidence": "motion_no_confidence", "ppSecurityGroup": "p_p_security_group"}),
        ("dRepVotingThresholds", "dvt_", {"committeeNoConfidence": "committee_no_confidence", "committeeNormal": "committee_normal", "hardForkInitiation": "hard_fork_initiation", "motionNoConfidence": "motion_no_confidence", "ppEconomicGroup": "p_p_economic_group", "ppGovGroup": "p_p_gov_group", "ppNetworkGroup": "p_p_network_group", "ppTechnicalGroup": "p_p_technical_group", "treasuryWithdrawal": "treasury_withdrawal", "updateToConstitution": "update_to_constitution"}),
    ]
    for target, prefix, fields in groups:
        q[target] = {k: p[prefix + v] for k, v in fields.items()}
    return q


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True)
    parser.add_argument("--export-dir", required=True, type=Path)
    args = parser.parse_args()
    fixtures = Path(__file__).resolve().parent
    repo = fixtures.parent.parent
    out = args.export_dir.resolve()
    save = lambda name, value: (out / name).write_text(json.dumps(value, indent=2) + "\n")
    original = json.loads((out / "settings.tx.json").read_text())
    raw = bytes.fromhex(original["cborHex"])
    tx, end = decode(raw)
    assert end == len(raw) and encode(tx) == raw
    body = tx.value[0].value
    captured_body = bytes.fromhex((fixtures.parent / "musashi-registration/settings.body.hex").read_text())
    assert tx.value[0].raw == captured_body
    assert 3 not in body and 8 not in body, "synthetic era history requires no time bounds"
    save("parameters.json", parameters(repo))
    history = [[[0, 0, 0], [0, 0, 0], [21600, 10**12, [0, 432, [0]], 432]] for _ in range(7)]
    history.append([[0, 0, 0], None, [21600, 10**12, [1], 432]])
    save("synthetic-era-history.json", {"type": "EraHistory", "description": "Synthetic unbounded-transaction interpreter; not historical evidence", "cborHex": encode(history).hex()})
    for name in ("direct", "nested", "script-credential", "required-guard"):
        changed = body.copy()
        if name == "required-guard":
            # The pinned historical ledger uses a MAP, not current field-24 CDDL.
            changed[24] = {Raw(encode([0, bytes([2]) * 28])): None}
        else:
            native = bytes.fromhex((fixtures / (name + ".hex")).read_text())
            outputs = list(body[1].value)
            assert len(outputs) == 1 and len(outputs[0].value) == 2
            old = outputs[0].value
            outputs[0] = {0: old[0], 1: old[1], 3: Tag(24, encode([0, Raw(native)]))}
            changed[1] = outputs
        save(name + ".tx.json", {"type": "Tx DijkstraEra", "description": "Synthetic offline mutation; original signatures are invalid; never submitted", "cborHex": encode([changed, *tx.value[1:]]).hex()})
    results = {}
    for name in ("settings", "direct", "nested", "script-credential", "required-guard"):
        command = [args.cli, "dijkstra", "transaction", "calculate-plutus-script-cost", "offline",
                   "--start-time-utc", "2026-09-07T00:00:00Z", "--era-history-file", str(out / "synthetic-era-history.json"),
                   "--protocol-params-file", str(out / "parameters.json"), "--utxo-file", str(out / "settings.utxos.json"),
                   "--tx-file", str(out / (name + ".tx.json"))]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        results[name] = {"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        if name == "required-guard":
            assert result.returncode != 0 and "RequiredTopLevelGuardsNotSupported" in result.stderr, results[name]
        else:
            assert result.returncode == 0, results[name]
            assert json.loads(result.stdout)[0]["executionUnits"] == {"memory": 18485, "steps": 4805428}
        print(name + ": expected reference result")
    save("reference-results.json", results)


if __name__ == "__main__":
    main()
