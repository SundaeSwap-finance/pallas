#!/usr/bin/env python3
"""Verify retained capture bytes and replay identities; no network or signing."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def verify():
    manifest = json.loads((ROOT / "provenance.json").read_text())
    for name, expected in manifest["file_sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, name
    for item in manifest["decoded_cbor_sha256"]:
        raw = bytes.fromhex((ROOT / item["path"]).read_text())
        assert len(raw) == item["bytes"], item["path"]
        assert hashlib.sha256(raw).hexdigest() == item["sha256"], item["path"]
    for case in ["confirmed-ttl", "cross-epoch-ttl"]:
        root = ROOT / case
        replay = json.loads((root / "replay.json").read_text())
        genesis = json.loads((root / "genesis.json").read_text())
        assert replay["txid"] == manifest["cases"][case]["transaction"]
        assert genesis["network_magic"] == 164
        assert replay["expected_upper_posix_ms"] == (
            genesis["system_start"] + replay["ttl"] * genesis["slot_length"]) * 1000
        if case == "cross-epoch-ttl":
            assert replay["validation_slot"] // genesis["epoch_length"] < replay["ttl"] // genesis["epoch_length"]
        for expected in manifest["cases"][case]["input_output_sha256"]:
            inputs = json.loads((root / "inputs.json").read_text())
            item = next(x for x in inputs if x["hash"] == expected["hash"] and x["index"] == expected["index"])
            assert hashlib.sha256(bytes.fromhex(item["output_cbor_hex"])).hexdigest() == expected["sha256"]
    print("Both native fixtures, historical mappings and input CBOR checksums verified.")


if __name__ == "__main__":
    verify()
