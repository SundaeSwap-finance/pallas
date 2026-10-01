"""Verify portable capture checksums; hex checksums cover decoded CBOR bytes."""
import hashlib
import json
from pathlib import Path

base = Path(__file__).resolve().parent
manifest = json.loads((base / "provenance.json").read_text())
for name, entry in manifest["files"].items():
    path = base / name
    raw = bytes.fromhex(path.read_text()) if path.suffix == ".hex" else path.read_bytes()
    assert len(raw) == entry["bytes"], name
    assert hashlib.sha256(raw).hexdigest() == entry["sha256"], name
for entry in json.loads((base / "replay-context.json").read_text())["parameters"]:
    assert hashlib.sha256((base / entry["file"]).read_bytes()).hexdigest() == entry["sha256"], entry["file"]
print("All captured fixture and parameter checksums match.")
