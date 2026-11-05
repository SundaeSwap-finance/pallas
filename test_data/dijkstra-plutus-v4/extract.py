#!/usr/bin/env python3
"""Write one fixture per record from a ledger conformance corpus and the ledger's script arguments.

Usage: extract.py CORPUS.jsonl.gz CASES.json OUT_DIR
"""
import gzip
import json
import sys
from pathlib import Path

RECORDS = [900, 1896, 2109, 2113, 2165, 2302, 9846]


def main():
    corpus, cases, out = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    contexts = {c["name"]: c for c in json.load(open(cases))}
    utxo = {}
    previous = None
    for line in gzip.open(corpus, "rt"):
        record = json.loads(line)
        if record["pre"] == "follows_prev":
            accepted = previous["outcome"].get("accepted") if previous else None
            if accepted:
                for spent in accepted["consumed"]:
                    utxo.pop(spent, None)
                utxo.update(dict(accepted["produced"]))
        else:
            utxo = dict(record["pre"]["fresh"])
        previous = record
        if record["n"] not in RECORDS:
            continue
        tx = record["tx"]
        redeemers = []
        scripts = [
            case
            for name, case in contexts.items()
            if name.startswith(f"record {record['n']}, top, script ")
        ]
        assert len(scripts) == len(record["ex_units"]), record["n"]
        for row in record["ex_units"]:
            (case,) = [c for c in scripts if c["haskell"]["ran"] == row["evaluation"]["ran"]]
            mem, steps = row["evaluation"]["ran"]
            redeemers.append(
                {
                    "purpose": row["purpose"],
                    "mem": mem,
                    "steps": steps,
                    "context": case["args"][0],
                }
            )
        fixture = {
            "record": record["n"],
            "tx": tx,
            "utxos": sorted([i, o] for i, o in utxo.items() if i[6:] in tx),
            "plutus_v4": record["pparams"]["costModels"]["PlutusV4"],
            "redeemers": redeemers,
        }
        path = out / f"{record['n']}.json"
        path.write_text(json.dumps(fixture, indent=1) + "\n")


if __name__ == "__main__":
    main()
