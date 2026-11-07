# Dijkstra PlutusV3 builtin redeemers

Three records of a Dijkstra ledger supplement corpus written by Imp tests at protocol
12, each spending an output locked at a PlutusV3 script. 211 calls `sha2_256`, 214
calls `mkNilData`, and 217 compares two to the 262144 with `lessThanInteger`. Each
fixture holds the transaction, the UTxO entries it reads, the PlutusV3 cost model, and
per redeemer the ex units the Haskell ledger spent and the script context it built. The
ledger accepts all three.

Source: `supp.jsonl.gz`, sha256
`9c182714af5fea7299b2add8e7ca90660d8c8e1749a64b1d19d10cc73fe21e7c`, the ledger
supplement corpus.

Regenerate with:

```
python3 -I extract.py supp.jsonl.gz .
```

| File | sha256 |
|---|---|
| 211.json | 76abcd5c0026694d53271426e6495a814b46930974c6da20b71feabafd97361e |
| 214.json | 7a66800833483611e8569d0bfbb805695a38e67990188c9f5f22fa0f56f2a613 |
| 217.json | a8e8b55f54c8bffac88a191e1a4c8184fa7081e248ea1cfa55508a8513ee027a |
