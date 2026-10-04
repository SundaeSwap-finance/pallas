#!/usr/bin/env python3
"""Copy every block from origin to the node's tip into a fixture directory.

Usage: capture_blocks.py <socket> <network magic> <out dir>

Reads node to client ChainSync, read only. Blocks go into gzip chunk files of
length prefixed records, and index.jsonl names each block's chunk and record
ordinal in chain order. A second run resumes from the last indexed point.
"""
import gzip, hashlib, json, os, socket, struct, sys, time

CHUNK_BLOCKS = 1000
# A rollback deeper than this many blocks stops the capture.
HOLD = 256


def head(b, i):
    ib = b[i]; mt = ib >> 5; ai = ib & 31; i += 1
    if ai < 24: return mt, ai, i
    if ai == 31: return mt, None, i
    n = {24: 1, 25: 2, 26: 4, 27: 8}[ai]
    return mt, int.from_bytes(b[i:i + n], "big"), i + n


def skip(b, i):
    mt, v, i = head(b, i)
    if mt in (0, 1, 7): return i
    if mt in (2, 3):
        if v is None:
            while b[i] != 0xff: i = skip(b, i)
            return i + 1
        return i + v
    if mt in (4, 5):
        k = 1 if mt == 4 else 2
        if v is None:
            while b[i] != 0xff: i = skip(b, i)
            return i + 1
        for _ in range(k * v): i = skip(b, i)
        return i
    if mt == 6: return skip(b, i)
    raise ValueError(mt)


def items(b, i):
    mt, v, j = head(b, i)
    assert mt == 4, (mt, i)
    out = []
    if v is None:
        while b[j] != 0xff:
            e = skip(b, j); out.append((j, e)); j = e
        return out, j + 1
    for _ in range(v):
        e = skip(b, j); out.append((j, e)); j = e
    return out, j


def uint(mt, v):
    if v < 24: return bytes([(mt << 5) | v])
    for ai, n in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if v < 256 ** n: return bytes([(mt << 5) | ai]) + v.to_bytes(n, "big")


def enc(x):
    if isinstance(x, bool): return b"\xf5" if x else b"\xf4"
    if isinstance(x, int): return uint(0, x)
    if isinstance(x, bytes): return uint(2, len(x)) + x
    if isinstance(x, list): return uint(4, len(x)) + b"".join(enc(e) for e in x)
    if isinstance(x, dict): return uint(5, len(x)) + b"".join(enc(k) + enc(v) for k, v in x.items())
    raise TypeError(type(x))


class Conn:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(path); self.s.settimeout(60)
        self.buf = {}

    def recvn(self, n):
        d = b""
        while len(d) < n:
            c = self.s.recv(n - len(d))
            if not c: raise EOFError
            d += c
        return d

    def read(self, want):
        acc = self.buf.pop(want, b"")
        while True:
            if acc:
                try:
                    e = skip(acc, 0)
                except IndexError:
                    e = None
                # A byte string whose length runs past the bytes read so far is not yet whole.
                if e is not None and e <= len(acc):
                    if e < len(acc): self.buf[want] = acc[e:]
                    return acc[:e]
            _, proto, ln = struct.unpack(">IHH", self.recvn(8))
            p = self.recvn(ln)
            if proto & 0x7fff == want: acc += p
            else: self.buf[proto & 0x7fff] = self.buf.get(proto & 0x7fff, b"") + p

    def send(self, proto, msg):
        ts = int(time.time() * 1e6) & 0xffffffff
        self.s.sendall(struct.pack(">IHH", ts, proto, len(msg)) + msg)


def unwrap(raw):
    """Return the `[era, block]` bytes a roll forward carries."""
    mt, v, j = head(raw, 0)
    if mt == 6 and v == 24:
        _, ln, k = head(raw, j)
        raw = raw[k:k + ln]
    (era_s, era_e), (blk_s, blk_e) = items(raw, 0)[0]
    mt, v, k = head(raw, blk_s)
    if mt == 6 and v == 24:
        _, ln, k2 = head(raw, k)
        inner = raw[k2:k2 + ln]
        return raw[:blk_s] + inner + raw[blk_e:]
    return raw


def point_of(wrapped):
    (era_s, _), (blk_s, blk_e) = items(wrapped, 0)[0]
    era = head(wrapped, era_s)[1]
    blk = wrapped[blk_s:blk_e]
    els, _ = items(blk, 0)
    hdr = blk[els[0][0]:els[0][1]]
    hb, _ = items(hdr, 0)
    hbe, _ = items(hdr, hb[0][0])
    blockno = head(hdr, hbe[0][0])[1]
    slot = head(hdr, hbe[1][0])[1]
    return era, slot, blockno, hashlib.blake2b(hdr, digest_size=32).hexdigest()


class Store:
    def __init__(self, out):
        self.out = out
        os.makedirs(os.path.join(out, "chunks"), exist_ok=True)
        self.index_path = os.path.join(out, "index.jsonl")
        self.index = []
        if os.path.exists(self.index_path):
            self.index = [json.loads(l) for l in open(self.index_path)]
        names = sorted(os.listdir(os.path.join(out, "chunks")))
        self.next_chunk = int(names[-1].split(".")[0]) + 1 if names else 0
        self.pending = []

    def last_points(self):
        return [[r["slot"], bytes.fromhex(r["hash"])] for r in reversed(self.index[-50:])]

    def rollback(self, slot, hh):
        if slot is None:
            if self.index or self.pending:
                raise SystemExit("rollback to origin over a nonempty capture")
            return
        while self.pending and (self.pending[-1][1], self.pending[-1][3]) != (slot, hh):
            self.pending.pop()
        if self.pending:
            return
        while self.index and (self.index[-1]["slot"], self.index[-1]["hash"]) != (slot, hh):
            self.index.pop()
        if not self.index:
            raise SystemExit("rollback point %s %s is not in the capture" % (slot, hh))
        with open(self.index_path, "w") as f:
            for r in self.index: f.write(json.dumps(r) + "\n")

    def push(self, rec):
        self.pending.append(rec)
        if len(self.pending) >= HOLD + CHUNK_BLOCKS:
            self.flush(CHUNK_BLOCKS)

    def flush(self, n):
        batch, self.pending = self.pending[:n], self.pending[n:]
        if not batch: return
        name = "%06d.blk.gz" % self.next_chunk
        self.next_chunk += 1
        with gzip.open(os.path.join(self.out, "chunks", name), "wb", compresslevel=6) as g:
            for (_, _, _, _, raw) in batch:
                g.write(struct.pack(">I", len(raw))); g.write(raw)
        with open(self.index_path, "a") as f:
            for ordinal, (era, slot, blockno, hh, _) in enumerate(batch):
                r = {"era": era, "slot": slot, "blockno": blockno, "hash": hh,
                     "chunk": name, "ordinal": ordinal}
                self.index.append(r)
                f.write(json.dumps(r) + "\n")


def main():
    sock, magic, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    store = Store(out)
    c = Conn(sock)
    c.send(0, enc([0, {v: [magic, False] for v in range(32784, 32800)}]))
    print("handshake", c.read(0).hex()[:40], flush=True)
    c.send(5, enc([4, store.last_points() or [[]]]))
    r = c.read(5)
    print("intersect", r.hex()[:120], flush=True)
    n = 0; t0 = time.time()
    while True:
        c.send(5, enc([0]))
        r = c.read(5)
        tag = r[1]
        if tag == 1:
            break
        if tag == 3:
            (_, _), (ps, pe), _ = items(r, 0)[0]
            pts, _ = items(r, ps)
            if not pts:
                store.rollback(None, None)
            else:
                store.rollback(head(r, pts[0][0])[1], r[pts[1][0]:pts[1][1]][-32:].hex())
            continue
        assert tag == 2, r[:10].hex()
        (_, _), (bs, be), _ = items(r, 0)[0]
        raw = unwrap(r[bs:be])
        era, slot, blockno, hh = point_of(raw)
        store.push((era, slot, blockno, hh, raw))
        n += 1
        if n % 5000 == 0:
            print(n, slot, round(time.time() - t0), "s", flush=True)
    store.flush(len(store.pending))
    last = store.index[-1]
    print("at tip after", n, "blocks, last", last["slot"], last["blockno"], last["hash"], flush=True)
    c.send(5, enc([7]))


if __name__ == "__main__":
    main()
