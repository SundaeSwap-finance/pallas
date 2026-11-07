#!/usr/bin/env python3
"""Write one fixture per record from a ledger supplement corpus whose records carry the ledger's script arguments.

Usage: extract.py CORPUS.jsonl.gz OUT_DIR
"""
import gzip
import json
import sys
from pathlib import Path

RECORDS = [211, 214, 217]


def main():
    corpus, out = sys.argv[1], Path(sys.argv[2])
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
        for row in record["ex_units"]:
            mem, steps = row["evaluation"]["ran"]
            redeemers.append(
                {
                    "purpose": row["purpose"],
                    "mem": mem,
                    "steps": steps,
                    "context": row["args"][0],
                }
            )
        fixture = {
            "record": record["n"],
            "tx": tx,
            "utxos": sorted([i, o] for i, o in utxo.items() if i[6:] in tx),
            "plutus_v3": record["pparams"]["costModels"]["PlutusV3"],
            "redeemers": redeemers,
        }
        path = out / f"{record['n']}.json"
        path.write_text(json.dumps(fixture, indent=1) + "\n")


if __name__ == "__main__":
    main()
