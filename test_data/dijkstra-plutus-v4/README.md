# Dijkstra PlutusV4 redeemers

Ten records of a Dijkstra ledger conformance corpus whose redeemers run PlutusV4
scripts. At the top level: guarding (900, and 1344 beside a sub transaction), spend
(1896, 2165), certificate (2109, 2165, 2302), reward (2113) and proposal (9846). In a
sub transaction: spend (890, 9820). Each fixture holds the transaction, the UTxO entries
it reads, the PlutusV4 cost model, and per redeemer the ex units the Haskell
ledger spent and the script context it built, with `sub` naming the sub transaction
of a sub transaction redeemer.

Sources:

- `ic.jsonl.gz`, sha256 `86cd9446e7d42d0a0eda1b1e5e26eb77af616d82592dd6cc09526f4be5781c6a`,
  the ledger conformance corpus.
- `all-cases.json`, sha256 `432a1254823ab771e79a4c44465c85e228e40c86da49541214616247c85316be`,
  the script arguments the Haskell ledger passed for each corpus redeemer.

Regenerate with:

```
python3 -I extract.py ic.jsonl.gz all-cases.json .
```

| File | sha256 |
|---|---|
| 890.json | 7ac5ff3e1697138a91f2b31246626e8f8d512e5a21aa667707e83ecab4756988 |
| 900.json | 9388374ee77cf9625d85abd124e16854df4a74648067d97d86d0bf3dc8cd9ece |
| 1344.json | 0c85dd22b039fbafe8f9e98c5959d8f43b75d8adf73dcbc24b766240769ca105 |
| 1896.json | acb8eaa6b99e403476e175329c2db27ba06d05ad89fb9eeede89e10b1771b25b |
| 2109.json | 8eeec7b4042f1696f351e28f6e3d977a1de339c0080abcd1740eb5d571863318 |
| 2113.json | cbba6897fa27b3bff1fa64d3fb746ceb87a3ffaff57ef9e9686bb3d71403266a |
| 2165.json | 4aec2abdee26f407a62e294ef4f9c060a5a26ac88365ddaeca3af5dd67efd8c5 |
| 2302.json | 122f395cda30ef9f4fe0aeece0f8761691651cd047ddce2bee5a3b750ef43189 |
| 9820.json | 080ef0edec7a24f8a21da5cccb59caf0c9c69fb801312c5e8fa13f0adff2efb7 |
| 9846.json | 5eb77c2f977b7f33cc51947831250503679d5531136d4ded91bfb38125df2e67 |
