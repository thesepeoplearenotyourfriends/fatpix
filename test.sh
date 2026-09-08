#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

tmp=${TMPDIR:-/tmp}/garble-clarity-test.$$
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp"
python3 - <<'PY' > "$tmp/plain.bin"
import sys
sys.stdout.buffer.write((b"The quick brown fox jumps over the lazy dog.\n" * 10000) + bytes(range(256)) * 20)
PY
: > "$tmp/empty.bin"
printf '\000\377\020\200key\000tail' > "$tmp/key.bin"

# --- Garble mechanics: every transform family must obey the same container contract. ---

./garble -k 'BlueVelvet' "$tmp/plain.bin" "$tmp/xor.grb"
./garble -d -k 'BlueVelvet' "$tmp/xor.grb" "$tmp/xor.out"
cmp "$tmp/plain.bin" "$tmp/xor.out"

./garble -t subst -k 'BlueVelvet' "$tmp/plain.bin" "$tmp/subst.grb"
./garble -d -k 'BlueVelvet' "$tmp/subst.grb" "$tmp/subst.out"
cmp "$tmp/plain.bin" "$tmp/subst.out"

./garble -t shuffle -k 'BlueVelvet' "$tmp/plain.bin" "$tmp/shuffle.grb"
./garble -d -k 'BlueVelvet' "$tmp/shuffle.grb" "$tmp/shuffle.out"
cmp "$tmp/plain.bin" "$tmp/shuffle.out"

# Empty input still produces a valid container and decodes to empty for both transforms.
for t in xor subst shuffle; do
    ./garble -t "$t" -k x "$tmp/empty.bin" "$tmp/empty-$t.grb"
    ./garble -d -k x "$tmp/empty-$t.grb" "$tmp/empty-$t.out"
    cmp "$tmp/empty.bin" "$tmp/empty-$t.out"
    [ "$(wc -c < "$tmp/empty-$t.grb")" -eq 32 ]
done

# Binary key file, including NUL and high bytes.
for t in xor subst shuffle; do
    ./garble -t "$t" -K "$tmp/key.bin" "$tmp/plain.bin" "$tmp/binary-$t.grb"
    ./garble -d -K "$tmp/key.bin" "$tmp/binary-$t.grb" "$tmp/binary-$t.out"
    cmp "$tmp/plain.bin" "$tmp/binary-$t.out"
done

# Pure stdin/stdout operation in both directions.
for t in xor subst shuffle; do
    cat "$tmp/plain.bin" | ./garble -t "$t" -k PipeKey - - | ./garble -d -k PipeKey - - > "$tmp/pipe-$t.out"
    cmp "$tmp/plain.bin" "$tmp/pipe-$t.out"
done

# Refuse destructive same-file output, including hard-link aliases.
cp "$tmp/plain.bin" "$tmp/same.bin"
if ./garble -k x "$tmp/same.bin" "$tmp/same.bin" >/dev/null 2>&1; then
    echo "FAIL: identical input/output path accepted" >&2
    exit 1
fi
cmp "$tmp/plain.bin" "$tmp/same.bin"
ln "$tmp/same.bin" "$tmp/same-link.bin"
if ./garble -t subst -k x "$tmp/same.bin" "$tmp/same-link.bin" >/dev/null 2>&1; then
    echo "FAIL: hard-link input/output alias accepted" >&2
    exit 1
fi
cmp "$tmp/plain.bin" "$tmp/same.bin"

# Wrong keys and modified payloads must fail integrity for both transforms.
for t in xor subst shuffle; do
    src="$tmp/$t.grb"
    if ./garble -d -k WrongKey "$src" "$tmp/wrong-$t.bin" >/dev/null 2>&1; then
        echo "FAIL: $t accepted wrong key" >&2
        exit 1
    fi
    cp "$src" "$tmp/tampered-$t.grb"
    python3 - "$tmp/tampered-$t.grb" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
b = bytearray(p.read_bytes())
b[32] ^= 0x80
p.write_bytes(b)
PY
    if ./garble -d -k BlueVelvet "$tmp/tampered-$t.grb" "$tmp/tampered-$t.out" >/dev/null 2>&1; then
        echo "FAIL: $t accepted tampered payload" >&2
        exit 1
    fi
done

# Header remains byte-exact; only transform ID differs.
python3 - "$tmp/xor.grb" "$tmp/subst.grb" "$tmp/shuffle.grb" <<'PY'
from pathlib import Path
import sys
for path, transform_id in ((sys.argv[1], 1), (sys.argv[2], 2), (sys.argv[3], 3)):
    b = Path(path).read_bytes()[:16]
    assert b[:8] == b'GRBLv1\r\n'
    assert b[8] == 1 and b[9] == transform_id and b[10:12] == b'\0\0'
    assert int.from_bytes(b[12:16], 'little') == 16
PY
if ./garble -d -t xor -k BlueVelvet "$tmp/xor.grb" "$tmp/nope" >/dev/null 2>&1; then
    echo "FAIL: decode accepted encode-only -t" >&2
    exit 1
fi
if ./garble -t nope -k x "$tmp/plain.bin" "$tmp/nope" >/dev/null 2>&1; then
    echo "FAIL: unknown transform accepted" >&2
    exit 1
fi

# Small analysis specimens keep Clarity CLI tests dense without making each statistical
# pass chew through the larger streaming fixture above.
python3 - <<'PY2' > "$tmp/probe-plain.bin"
import sys
sys.stdout.buffer.write((b"The quick brown fox jumps over the lazy dog.\n" * 200) + bytes(4096) + bytes(range(256)) * 4)
PY2
./garble -k BlueVelvet "$tmp/probe-plain.bin" "$tmp/probe-xor.grb"
./garble -t subst -k BlueVelvet "$tmp/probe-plain.bin" "$tmp/probe-subst.grb"
./garble -t shuffle -k BlueVelvet "$tmp/probe-plain.bin" "$tmp/probe-shuffle.grb"

# --- Clarity's instruments: prove the measuring sticks before using them. ---

python3 - <<'PY'
import binascii
import math
import struct
import zlib
import clarity

checks = []
def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append(name)

check("empty entropy", clarity.entropy(b"") == 0.0)
check("uniform entropy", math.isclose(clarity.entropy(bytes(range(256)) * 4), 8.0, abs_tol=1e-12))
check("exact lag coincidence", clarity.coincidence(b"abcabcabc", 3) == 1.0)
check("nonmatching lag coincidence", clarity.coincidence(b"abcdef", 1) == 0.0)
check("full hamming distance", clarity.hamming_ratio(b"\x00", b"\xff") == 1.0)
check("zero hamming distance", clarity.hamming_ratio(b"same", b"same") == 0.0)
check("exact period", clarity.smallest_period_exact(b"abcabcab", 8) == 3)
check("no exact period", clarity.smallest_period_exact(b"abcdef", 3) is None)
check("constant serial correlation", clarity.serial_correlation(b"\x07" * 100) == 0.0)
check("printable annotation", clarity.byte_annotation(0x45) == "ASCII 'E'")
check("control annotation", clarity.byte_annotation(0x0a) == "LF")
check("unnamed byte annotation", clarity.byte_annotation(0x80) is None)
periodic = (b"abcdefg" * 700)[:4096]
claim = clarity.periodicity_claim(periodic, 128)
check("period claim", claim is not None and claim["period"] == 7)
check("fill structural character", clarity.structural_character(b"\xaa" * 1024)["kind"] == "fill")
check("ASCII structural character", clarity.structural_character((b"hello world\n" * 100))["kind"] == "ascii_compatible")
check("nontext structural character", clarity.structural_character(bytes(range(32)) * 32)["kind"] == "other")


print(f"Clarity metrology: {len(checks)}/{len(checks)} exact checks")
PY

# Raw statistics remain available without interpretation; --stats is explicit STFU mode.
python3 clarity.py "$tmp/probe-xor.grb" > "$tmp/default-stats.txt"
python3 clarity.py --stats "$tmp/probe-xor.grb" > "$tmp/explicit-stats.txt"
cmp "$tmp/default-stats.txt" "$tmp/explicit-stats.txt"
if grep -q '^CLAIM:' "$tmp/explicit-stats.txt"; then
    echo "FAIL: --stats emitted interpretation" >&2
    exit 1
fi
# Human-readable byte aliases are notation, not interpretation.
printf 'EEEEKKK\n\n' > "$tmp/ascii-stats.bin"
python3 clarity.py --stats "$tmp/ascii-stats.bin" > "$tmp/ascii-stats.txt"
grep -q "45: .*ASCII 'E'" "$tmp/ascii-stats.txt"
grep -q "0a: .*LF" "$tmp/ascii-stats.txt"

# --analyze may claim observed periodicity but must abstain from naming a transform family.
python3 - <<'PY' > "$tmp/periodic.bin"
import sys
sys.stdout.buffer.write((b"abc" * 4096))
PY
python3 clarity.py --analyze "$tmp/periodic.bin" > "$tmp/analyze.txt"
grep -q '^CLAIM: strong byte-coincidence periodicity' "$tmp/analyze.txt"
grep -q 'fundamental lag: 3 bytes' "$tmp/analyze.txt"
grep -q '^ABSTAIN: transform family' "$tmp/analyze.txt"

# Structure map is first-class in --analyze and stays byte-character evidence, not
# an invented format identity. Four exact 1024-byte regions exercise merge/boundary logic.
python3 - <<'PY' > "$tmp/mixed-structure.bin"
import random, sys
rng = random.Random(0x57A7)
text = (b"int main(void) { return 0; }\n" * 40)[:1024].ljust(1024, b" ")
fill = b"\xff" * 1024
high = bytes(rng.randrange(256) for _ in range(1024))
other = (bytes(range(32)) * 32)[:1024]
sys.stdout.buffer.write(text + fill + high + other)
PY
python3 clarity.py --json "$tmp/mixed-structure.bin" > "$tmp/mixed-structure.json"
python3 - "$tmp/mixed-structure.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
regions = obj["structure"]["regions"]
assert [(r["start"], r["end"], r["kind"]) for r in regions] == [
    (0, 1024, "ascii_compatible"),
    (1024, 2048, "fill"),
    (2048, 3072, "high_entropy"),
    (3072, 4096, "other"),
]
assert regions[1]["fill_byte"] == 0xff
PY

# MBR is the first structured "view": exact field ranges remain available in JSON,
# while a damaged signature keeps the useful shape but loses the identity claim.
python3 - <<'PY' > "$tmp/mbr.bin"
import sys
b = bytearray(512)
b[:4] = b"\xfa\x31\xc0\x8e"
p = 0x1be
b[p] = 0x80
b[p + 4] = 0x83
b[p + 8:p + 12] = (2048).to_bytes(4, "little")
b[p + 12:p + 16] = (409600).to_bytes(4, "little")
b[510:512] = b"\x55\xaa"
sys.stdout.buffer.write(b)
PY
python3 clarity.py --json --base-offset 0x2000 "$tmp/mbr.bin" > "$tmp/mbr.json"
python3 - "$tmp/mbr.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
claims = [c for c in obj["claims"] if c["kind"] == "mbr_partition_table"]
assert len(claims) == 1 and claims[0]["offset"] == 0x2000
assert obj["base_offset"] == 0x2000
view = obj["views"][0]
assert view["strong_identity"] is True
assert view["shape_source"] == "kaitai/filesystem/mbr_partition_table.ksy"
by_path = {a["path"]: a for a in view["annotations"]}
assert (by_path["mbr.bootstrap_code"]["start"], by_path["mbr.bootstrap_code"]["end"]) == (0x2000, 0x21be)
assert (by_path["mbr.partitions[0].lba_start"]["start"], by_path["mbr.partitions[0].lba_start"]["end"]) == (0x21c6, 0x21ca)
assert by_path["mbr.partitions[0].lba_start"]["value"] == 2048
PY
cp "$tmp/mbr.bin" "$tmp/mbr-damaged.bin"
printf '\0\0' | dd of="$tmp/mbr-damaged.bin" bs=1 seek=510 conv=notrunc status=none
python3 clarity.py --json "$tmp/mbr-damaged.bin" > "$tmp/mbr-damaged.json"
python3 - "$tmp/mbr-damaged.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
assert not [c for c in obj["claims"] if c["kind"] == "mbr_partition_table"]
assert len(obj["views"]) == 1
view = obj["views"][0]
assert view["checks_passed"] == 9 and not view["strong_identity"]
assert "boot signature 55 aa absent" in view["hard_contradictions"]
PY

# A structurally consistent ELF hidden behind unrelated bytes should earn identity;
# a magic string alone is never enough.
python3 - <<'PY' > "$tmp/embedded-elf.bin"
import sys
prefix = b"wrapper-not-elf:" + bytes(range(16))
eh = bytearray(64)
eh[:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
eh[16:18] = (2).to_bytes(2, "little")
eh[18:20] = (62).to_bytes(2, "little")
eh[20:24] = (1).to_bytes(4, "little")
eh[32:40] = (64).to_bytes(8, "little")
eh[52:54] = (64).to_bytes(2, "little")
eh[54:56] = (56).to_bytes(2, "little")
eh[56:58] = (1).to_bytes(2, "little")
eh[58:60] = (64).to_bytes(2, "little")
ph = bytearray(56)
ph[0:4] = (1).to_bytes(4, "little")
ph[4:8] = (5).to_bytes(4, "little")
ph[8:16] = (120).to_bytes(8, "little")
ph[32:40] = (32).to_bytes(8, "little")
ph[40:48] = (32).to_bytes(8, "little")
ph[48:56] = (4096).to_bytes(8, "little")
payload = bytes(range(32))
sys.stdout.buffer.write(prefix + eh + ph + payload + b"tail")
PY
python3 clarity.py --analyze "$tmp/embedded-elf.bin" > "$tmp/embedded-elf.txt"
grep -q '^CLAIM: structurally validated embedded ELF object' "$tmp/embedded-elf.txt"
grep -q 'class/endian: ELF64 little-endian' "$tmp/embedded-elf.txt"
grep -q 'minimum structurally referenced extent: 152 bytes' "$tmp/embedded-elf.txt"

# Known-plaintext relation discovery remains generic: no Garble parser is involved.
python3 clarity.py --known "$tmp/probe-plain.bin" "$tmp/probe-xor.grb" > "$tmp/xor-known.txt"
grep -q 'exact repeating XOR-mask period: 10 bytes' "$tmp/xor-known.txt"
grep -q 'candidate payload offset: 16' "$tmp/xor-known.txt"
grep -q 'PR:\[hex=426c756556656c766574' "$tmp/xor-known.txt"

python3 clarity.py --known "$tmp/probe-plain.bin" "$tmp/probe-subst.grb" > "$tmp/subst-known.txt"
grep -q 'exact position-independent one-byte substitution relation' "$tmp/subst-known.txt"
grep -q 'candidate payload offset: 16' "$tmp/subst-known.txt"
grep -q 'observed plaintext symbols mapped consistently: 256/256' "$tmp/subst-known.txt"
grep -q 'recovered mapping: PR:\[' "$tmp/subst-known.txt"

python3 clarity.py --known "$tmp/probe-plain.bin" "$tmp/probe-shuffle.grb" > "$tmp/shuffle-known.txt"
grep -q 'exact fixed within-block position-permutation relation across complete blocks' "$tmp/shuffle-known.txt"
grep -q 'candidate payload offset: 16' "$tmp/shuffle-known.txt"
grep -q 'smallest supported block size: 16 bytes' "$tmp/shuffle-known.txt"
grep -q 'trailing bytes outside this claim: 8' "$tmp/shuffle-known.txt"
grep -q 'recovered position mapping: PR:\[out->in ' "$tmp/shuffle-known.txt"

# --private suppresses all recovered key/mapping material while retaining diagnosis.
python3 clarity.py --private --known "$tmp/probe-plain.bin" "$tmp/probe-xor.grb" > "$tmp/xor-private.txt"
grep -q 'PR:\[redacted by --private\]' "$tmp/xor-private.txt"
if grep -q '426c756556656c766574' "$tmp/xor-private.txt"; then
    echo "FAIL: --private leaked recovered XOR mask" >&2
    exit 1
fi
python3 clarity.py --private --known "$tmp/probe-plain.bin" "$tmp/probe-subst.grb" > "$tmp/subst-private.txt"
grep -q 'recovered mapping: PR:\[redacted by --private\]' "$tmp/subst-private.txt"
python3 clarity.py --private --known "$tmp/probe-plain.bin" "$tmp/probe-shuffle.grb" > "$tmp/shuffle-private.txt"
grep -q 'recovered position mapping: PR:\[redacted by --private\]' "$tmp/shuffle-private.txt"

# JSON is the scoring contract: tests inspect claims, never English phrasing.
python3 clarity.py --json --known "$tmp/probe-plain.bin" "$tmp/probe-subst.grb" > "$tmp/result.json"
python3 - "$tmp/result.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
assert obj["stats"]["bytes"] > 0
assert isinstance(obj["claims"], list)
assert isinstance(obj["abstentions"], list)
assert isinstance(obj["views"], list)
assert obj["base_offset"] == 0
assert obj["known_plaintext"]["kind"] == "fixed_byte_substitution"
assert obj["known_plaintext"]["offset"] == 16
assert obj["known_plaintext"]["observed_symbols"] == 256
assert obj["known_plaintext"]["mapping_pr"].startswith("PR:[")
PY
python3 clarity.py --json --private --known "$tmp/probe-plain.bin" "$tmp/probe-subst.grb" > "$tmp/private.json"
python3 - "$tmp/private.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
assert obj["known_plaintext"]["mapping_pr"] == "PR:[redacted by --private]"
PY
python3 clarity.py --json --known "$tmp/probe-plain.bin" "$tmp/probe-shuffle.grb" > "$tmp/shuffle.json"
python3 - "$tmp/shuffle.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
assert obj["known_plaintext"]["kind"] == "fixed_block_position_permutation"
assert obj["known_plaintext"]["offset"] == 16
assert obj["known_plaintext"]["block_size"] == 16
assert obj["known_plaintext"]["verified_bytes"] % 16 == 0
assert obj["known_plaintext"]["trailing_bytes"] == 8
assert obj["known_plaintext"]["mapping_pr"].startswith("PR:[out->in ")
PY

# --- Bullshit-fuzzer 1: ciphertext-only periodicity claim vs hostile near-misses. ---
# Exactly 300 deterministic specimens. A wrong period is a false claim, not a near miss.
python3 - <<'PY'
import random
import clarity

rng = random.Random(0xC1A17A)
tp = fp = fn = tn = wrong = 0

# 100 true periodic specimens, fundamental periods 2..64.
for _ in range(100):
    p = rng.randint(2, 64)
    while True:
        unit = bytes(rng.randrange(256) for _ in range(p))
        if clarity.smallest_period_exact(unit * 3, p) == p:
            break
    data = (unit * ((4096 // p) + 2))[:4096]
    claim = clarity.periodicity_claim(data, 128)
    if claim is None:
        fn += 1
    elif claim["period"] == p:
        tp += 1
    else:
        wrong += 1
        fn += 1

# 75 uniform-random negatives.
for _ in range(75):
    data = bytes(rng.randrange(256) for _ in range(4096))
    if clarity.periodicity_claim(data, 128) is None:
        tn += 1
    else:
        fp += 1

# 75 heavily biased but independent negatives: low entropy alone must not become "periodic".
for _ in range(75):
    alphabet = bytes(range(rng.randint(2, 24)))
    data = bytes(rng.choice(alphabet) for _ in range(4096))
    if clarity.periodicity_claim(data, 128) is None:
        tn += 1
    else:
        fp += 1

# 50 run-heavy/Markov-ish negatives: strong serial correlation is not periodicity.
for _ in range(50):
    b = bytearray()
    while len(b) < 4096:
        b.extend([rng.randrange(256)] * rng.randint(1, 24))
    if clarity.periodicity_claim(bytes(b[:4096]), 128) is None:
        tn += 1
    else:
        fp += 1

assert tp + fn == 100
assert fp + tn == 200
precision = tp / (tp + fp + wrong) if (tp + fp + wrong) else 1.0
recall = tp / (tp + fn) if (tp + fn) else 1.0
print(
    "Ciphertext-only periodicity corpus: "
    f"TP={tp} FP={fp} WRONG={wrong} FN={fn} TN={tn} "
    f"precision={precision:.2%} recall={recall:.2%}"
)
if precision < 0.99 or recall < 0.90:
    raise SystemExit("FAIL: periodicity claim has not earned its threshold")
PY

# --- Bullshit-fuzzer 2: known-plaintext relation families, independent of Garble. ---
# 300 more deterministic specimens: XOR, arbitrary substitution, modular ADD, unrelated random.
python3 - <<'PY'
import random
import clarity

rng = random.Random(0x51A7E)
correct = wrong = abstain = 0


def fundamental_key(n):
    while True:
        key = bytes(rng.randrange(256) for _ in range(n))
        if clarity.smallest_period_exact(key * 2, n) == n:
            return key


def wrap(payload):
    pre = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 33)))
    post = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 33)))
    return pre + payload + post, len(pre)


def plain_bytes():
    # Repeated values across many positions make one-byte relation claims falsifiable.
    b = bytearray(bytes(range(256)) * 3)
    b.extend(rng.randrange(256) for _ in range(256))
    return bytes(b)

# 100 exact repeating XOR relationships.
for _ in range(100):
    plain = plain_bytes()
    klen = rng.randint(2, 31)
    key = fundamental_key(klen)
    payload = bytes(b ^ key[i % klen] for i, b in enumerate(plain))
    cipher, off = wrap(payload)
    found = clarity.known_plaintext_probe(cipher, plain, 64)
    if found is None:
        abstain += 1
    elif found["kind"] == "repeating_xor" and found["offset"] == off and found["period"] == klen:
        correct += 1
    else:
        wrong += 1

# 100 arbitrary fixed substitutions. These do not use Garble's permutation generator.
for _ in range(100):
    plain = plain_bytes()
    table = list(range(256))
    rng.shuffle(table)
    payload = bytes(table[b] for b in plain)
    cipher, off = wrap(payload)
    found = clarity.known_plaintext_probe(cipher, plain, 64)
    if found is None:
        abstain += 1
    elif found["kind"] == "fixed_byte_substitution" and found["offset"] == off:
        correct += 1
    else:
        wrong += 1

# 50 position-dependent modular ADD near-misses: neither exact XOR nor fixed substitution.
for _ in range(50):
    plain = plain_bytes()
    klen = rng.randint(2, 31)
    key = fundamental_key(klen)
    payload = bytes((b + key[i % klen]) & 0xff for i, b in enumerate(plain))
    cipher, _ = wrap(payload)
    found = clarity.known_plaintext_probe(cipher, plain, 64)
    if found is None:
        correct += 1
    else:
        wrong += 1

# 50 unrelated random near-misses.
for _ in range(50):
    plain = plain_bytes()
    payload = bytes(rng.randrange(256) for _ in range(len(plain)))
    cipher, _ = wrap(payload)
    found = clarity.known_plaintext_probe(cipher, plain, 64)
    if found is None:
        correct += 1
    else:
        wrong += 1

claims = correct + wrong
precision = correct / claims if claims else 1.0
coverage = claims / 300
print(
    "Known-plaintext relation corpus: "
    f"correct={correct} wrong={wrong} abstain={abstain} "
    f"precision={precision:.2%} answered={coverage:.2%}"
)
if wrong != 0:
    raise SystemExit("FAIL: known-plaintext relation detector made a false claim")
if correct < 295:
    raise SystemExit("FAIL: known-plaintext relation detector abstains too often on known-truth corpus")
PY

# --- Bullshit-fuzzer 3: fixed within-block position permutation vs near-miss families. ---
# Another 300 deterministic specimens. The detector gets known plaintext but no transform metadata.
python3 - <<'PY'
import random
import clarity

rng = random.Random(0xB10C5)
tp = fp = fn = tn = wrong = 0

def wrap(payload):
    pre = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 33)))
    post = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 33)))
    return pre + payload + post, len(pre)

def plain_for(block_size, trailing=0):
    return bytes(rng.randrange(256) for _ in range(block_size * 40 + trailing))

def shuffled_full_blocks(plain, block_size, perm, hostile_tail=False):
    full = (len(plain) // block_size) * block_size
    out = bytearray()
    for off in range(0, full, block_size):
        block = plain[off:off + block_size]
        out.extend(block[i] for i in perm)
    tail = plain[full:]
    if hostile_tail:
        # Deliberately do something unrelated to the tail. The detector's claim is
        # scoped to complete blocks and must report, not silently absorb, this gap.
        out.extend(((b + 73) & 0xff) for b in tail)
    else:
        out.extend(tail)
    return bytes(out)

# 100 true block permutations, varying block sizes and arbitrary maps independent of Garble.
# Half include an adversarial short tail to verify that Clarity scopes the claim honestly.
for case in range(100):
    block_size = rng.randint(3, 32)
    trailing = 0 if case < 50 else rng.randint(1, block_size - 1)
    plain = plain_for(block_size, trailing)
    while True:
        perm = list(range(block_size))
        rng.shuffle(perm)
        if perm != list(range(block_size)):
            break
    cipher, off = wrap(shuffled_full_blocks(plain, block_size, perm, hostile_tail=bool(trailing)))
    found = clarity.best_known_plaintext_block_permutation(cipher, plain, 64)
    if found is None:
        fn += 1
    elif (
        found["offset"] == off
        and found["block_size"] == block_size
        and found["mapping"] == perm
        and found["trailing_bytes"] == trailing
        and found["verified_bytes"] == len(plain) - trailing
    ):
        tp += 1
    else:
        wrong += 1
        fn += 1

# 60 fixed byte substitutions: values change, positions do not.
for _ in range(60):
    block_size = rng.randint(3, 32)
    plain = plain_for(block_size)
    table = list(range(256))
    rng.shuffle(table)
    cipher, _ = wrap(bytes(table[b] for b in plain))
    if clarity.best_known_plaintext_block_permutation(cipher, plain, 64) is None:
        tn += 1
    else:
        fp += 1

# 60 repeating XOR near-misses.
for _ in range(60):
    block_size = rng.randint(3, 32)
    plain = plain_for(block_size)
    key = bytes(rng.randrange(256) for _ in range(rng.randint(2, 17)))
    cipher, _ = wrap(bytes(b ^ key[i % len(key)] for i, b in enumerate(plain)))
    if clarity.best_known_plaintext_block_permutation(cipher, plain, 64) is None:
        tn += 1
    else:
        fp += 1

# 40 modular-ADD near-misses.
for _ in range(40):
    block_size = rng.randint(3, 32)
    plain = plain_for(block_size)
    key = bytes(rng.randrange(256) for _ in range(rng.randint(2, 17)))
    cipher, _ = wrap(bytes((b + key[i % len(key)]) & 0xff for i, b in enumerate(plain)))
    if clarity.best_known_plaintext_block_permutation(cipher, plain, 64) is None:
        tn += 1
    else:
        fp += 1

# 40 unrelated random payloads.
for _ in range(40):
    block_size = rng.randint(3, 32)
    plain = plain_for(block_size)
    payload = bytes(rng.randrange(256) for _ in range(len(plain)))
    cipher, _ = wrap(payload)
    if clarity.best_known_plaintext_block_permutation(cipher, plain, 64) is None:
        tn += 1
    else:
        fp += 1

assert tp + fn == 100
assert fp + tn == 200
precision = tp / (tp + fp + wrong) if (tp + fp + wrong) else 1.0
recall = tp / (tp + fn) if (tp + fn) else 1.0
print(
    "Known-plaintext block-permutation corpus: "
    f"TP={tp} FP={fp} WRONG={wrong} FN={fn} TN={tn} "
    f"precision={precision:.2%} recall={recall:.2%}"
)
if precision < 0.99 or recall < 0.90:
    raise SystemExit("FAIL: block-permutation relation has not earned its threshold")
PY

# --- Bullshit-fuzzer 4: coarse structure character, including an explicit OTHER lane. ---
# 300 deterministic windows. These labels describe measured byte character only; they
# intentionally do not pretend that printable bytes are prose or high entropy is encryption.
python3 - <<'PY'
import random
import clarity

rng = random.Random(0x5712C7)
correct = wrong = 0

def judge(data, expected):
    global correct, wrong
    got = clarity.structural_character(data)["kind"]
    if got == expected:
        correct += 1
    else:
        wrong += 1

for _ in range(75):
    value = rng.randrange(256)
    data = bytearray([value] * 1024)
    for _ in range(rng.randrange(0, 10)):
        data[rng.randrange(len(data))] = rng.randrange(256)
    judge(bytes(data), "fill")

alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-:;,.(){}[]/\\\n\t"
for _ in range(75):
    data = bytes(rng.choice(alphabet) for _ in range(1024))
    judge(data, "ascii_compatible")

for _ in range(75):
    data = bytes(rng.randrange(256) for _ in range(1024))
    judge(data, "high_entropy")

for _ in range(75):
    alphabet2 = bytes([0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23])
    data = bytes(rng.choice(alphabet2) for _ in range(1024))
    judge(data, "other")

print(f"Structure-character corpus: correct={correct} wrong={wrong} precision={correct/(correct+wrong):.2%}")
if wrong:
    raise SystemExit("FAIL: coarse structure character mislabeled generated ground truth")
PY

# --- Bullshit-fuzzer 5: ELF identity must be structural, never magic-number enthusiasm. ---
# 300 deterministic specimens: valid embedded ELF32/ELF64, malformed magic-bearing decoys,
# and unrelated random data. The positive generator uses only the public ELF layout.
python3 - <<'PY'
import random
import clarity

rng = random.Random(0xE1F1D)
tp = fp = fn = tn = wrong = 0

def noise(n):
    while True:
        b = bytes(rng.randrange(256) for _ in range(n))
        if b"\x7fELF" not in b:
            return b

def put(buf, off, size, value, order):
    buf[off:off+size] = value.to_bytes(size, order)

def make_elf(bits, order):
    if bits == 32:
        ehsize, phentsize, payload_off, machine = 52, 32, 84, 3
    else:
        ehsize, phentsize, payload_off, machine = 64, 56, 120, 62
    payload_len = rng.randrange(16, 97)
    eh = bytearray(ehsize)
    eh[:16] = b"\x7fELF" + bytes([1 if bits == 32 else 2, 1 if order == "little" else 2, 1, 0]) + bytes(8)
    put(eh, 16, 2, rng.choice((1, 2, 3)), order)
    put(eh, 18, 2, machine, order)
    put(eh, 20, 4, 1, order)
    if bits == 32:
        put(eh, 28, 4, ehsize, order)
        put(eh, 40, 2, ehsize, order)
        put(eh, 42, 2, phentsize, order)
        put(eh, 44, 2, 1, order)
        put(eh, 46, 2, 40, order)
        ph = bytearray(phentsize)
        put(ph, 0, 4, 1, order)
        put(ph, 4, 4, payload_off, order)
        put(ph, 16, 4, payload_len, order)
        put(ph, 20, 4, payload_len, order)
        put(ph, 24, 4, 5, order)
        put(ph, 28, 4, 4096, order)
    else:
        put(eh, 32, 8, ehsize, order)
        put(eh, 52, 2, ehsize, order)
        put(eh, 54, 2, phentsize, order)
        put(eh, 56, 2, 1, order)
        put(eh, 58, 2, 64, order)
        ph = bytearray(phentsize)
        put(ph, 0, 4, 1, order)
        put(ph, 4, 4, 5, order)
        put(ph, 8, 8, payload_off, order)
        put(ph, 32, 8, payload_len, order)
        put(ph, 40, 8, payload_len, order)
        put(ph, 48, 8, 4096, order)
    payload = noise(payload_len)
    return bytes(eh + ph + payload), payload_off + payload_len

for _ in range(100):
    bits = rng.choice((32, 64))
    order = rng.choice(("little", "big"))
    elf, extent = make_elf(bits, order)
    pre = noise(rng.randrange(0, 65))
    blob = pre + elf + noise(rng.randrange(0, 65))
    claims = clarity.elf_identity_claims(blob)
    if not claims:
        fn += 1
    elif len(claims) == 1 and claims[0]["offset"] == len(pre) and claims[0]["class_bits"] == bits and claims[0]["endian"] == order and claims[0]["minimum_referenced_extent"] == extent:
        tp += 1
    else:
        wrong += 1
        fn += 1

for case in range(100):
    bits = rng.choice((32, 64))
    order = rng.choice(("little", "big"))
    elf, _ = make_elf(bits, order)
    bad = bytearray(elf)
    mode = case % 5
    if mode == 0:
        bad[4] = 0
    elif mode == 1:
        bad[6] = 2
    elif mode == 2:
        bad[18:20] = b"\0\0"
    elif mode == 3:
        off = 40 if bits == 32 else 52
        bad[off:off+2] = (1).to_bytes(2, order)
    else:
        if bits == 32:
            ph = 52
            bad[ph+16:ph+20] = (0x7fffffff).to_bytes(4, order)
        else:
            ph = 64
            bad[ph+32:ph+40] = (0x7fffffffffffffff).to_bytes(8, order)
    blob = noise(rng.randrange(0, 65)) + bytes(bad) + noise(rng.randrange(0, 65))
    if clarity.elf_identity_claims(blob):
        fp += 1
    else:
        tn += 1

for _ in range(100):
    blob = noise(rng.randrange(128, 4097))
    if clarity.elf_identity_claims(blob):
        fp += 1
    else:
        tn += 1

assert tp + fn == 100
assert fp + tn == 200
precision = tp / (tp + fp + wrong) if (tp + fp + wrong) else 1.0
recall = tp / (tp + fn) if (tp + fn) else 1.0
print(
    "ELF identity corpus: "
    f"TP={tp} FP={fp} WRONG={wrong} FN={fn} TN={tn} "
    f"precision={precision:.2%} recall={recall:.2%}"
)
if precision < 0.99 or recall < 0.95:
    raise SystemExit("FAIL: ELF identity claim has not earned its threshold")
PY

# --- Bullshit-fuzzer 6: MBR strong identity vs partial surviving form vs noise. ---
# 300 deterministic sectors. Missing-signature specimens must retain a useful view
# but may not be promoted to identity; random aligned sectors must do neither.
python3 - <<'PY'
import random
import clarity

rng = random.Random(0x4D4252)
tp = fp = fn = tn = wrong = 0
partial_ok = partial_wrong = 0

def make_mbr():
    b = bytearray(rng.randrange(256) for _ in range(446))
    b.extend(bytes(66))
    count = rng.randint(1, 4)
    used = sorted(rng.sample(range(4), count))
    next_lba = rng.randint(1, 4096)
    for i in used:
        p = 0x1be + 16 * i
        b[p] = 0x80 if i == used[0] and rng.randrange(2) else 0
        # CHS is intentionally arbitrary legacy metadata; Clarity does not use it.
        b[p+1:p+4] = bytes(rng.randrange(256) for _ in range(3))
        b[p+4] = rng.choice((0x01, 0x04, 0x06, 0x07, 0x0b, 0x0c, 0x0e, 0x82, 0x83, 0xee))
        b[p+5:p+8] = bytes(rng.randrange(256) for _ in range(3))
        sectors = rng.randint(1, 2_000_000)
        b[p+8:p+12] = next_lba.to_bytes(4, "little")
        b[p+12:p+16] = sectors.to_bytes(4, "little")
        next_lba = min(0xffffffff, next_lba + sectors)
    b[510:512] = b"\x55\xaa"
    return bytes(b)

for _ in range(100):
    sector = make_mbr()
    prefix_sectors = rng.randrange(0, 9)
    pre = b"".join(bytes(rng.randrange(256) for _ in range(512)) for _ in range(prefix_sectors))
    blob = pre + sector
    claims = clarity.mbr_identity_claims(blob)
    expected = prefix_sectors * 512
    if not claims:
        fn += 1
    elif len(claims) == 1 and claims[0]["offset"] == expected and claims[0]["checks_passed"] == 10:
        tp += 1
    else:
        wrong += 1
        fn += 1

for _ in range(100):
    sector = bytearray(make_mbr())
    sector[510:512] = b"\0\0"
    views = clarity.mbr_views(bytes(sector))
    claims = clarity.mbr_identity_claims(bytes(sector))
    if len(views) == 1 and views[0]["checks_passed"] == 9 and not views[0]["strong_identity"] and not claims:
        partial_ok += 1
    else:
        partial_wrong += 1
        if claims:
            fp += 1

for _ in range(100):
    while True:
        sector = bytearray(rng.randrange(256) for _ in range(512))
        sector[510:512] = b"\0\0"
        if clarity.mbr_view_at(bytes(sector), 0) is None:
            break
    if clarity.mbr_identity_claims(bytes(sector)) or clarity.mbr_views(bytes(sector)):
        fp += 1
    else:
        tn += 1

assert tp + fn == 100
assert partial_ok + partial_wrong == 100
assert fp + tn == 100
precision = tp / (tp + fp + wrong) if (tp + fp + wrong) else 1.0
recall = tp / (tp + fn) if (tp + fn) else 1.0
print(
    "MBR structure/identity corpus: "
    f"TP={tp} FP={fp} WRONG={wrong} FN={fn} TN={tn} "
    f"partial={partial_ok}/100 precision={precision:.2%} recall={recall:.2%}"
)
if precision < 0.99 or recall < 0.95 or partial_wrong:
    raise SystemExit("FAIL: MBR structure/identity behavior has not earned its threshold")
PY

# --- Real Kaitai acceptance: public anonymous-file path, never generated KSY. ---
check_real_ksy() {
    specimen=$1
    expected=$2
    ./clarity.py --analyze --json "$specimen" > "$tmp/real-ksy.json"
    python3 - "$tmp/real-ksy.json" "$expected" "$specimen" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
expected, specimen = sys.argv[2:]
views = obj.get("views", [])
matches = [v for v in views if v.get("ksy_id") == expected and v.get("strong_identity")]
if not matches:
    detail = [(v.get("ksy_id", v.get("kind")), v.get("issues", [])[:1]) for v in views]
    raise SystemExit(f"FAIL: {specimen} did not earn {expected} identity; views={detail}")
for view in matches:
    evidence = view.get("evidence", {})
    assert evidence.get("anchor") == 1
    assert any(value for key, value in evidence.items() if key != "anchor"), evidence
PY
}

check_real_ksy test/gpt.img gpt_partition_table
check_real_ksy test/sample.png png
check_real_ksy test/x86_64.elf elf
check_real_ksy test/george.zip zip
check_real_ksy test/george.gz gzip
check_real_ksy test/george.tar.gz gzip
check_real_ksy test/sample.iso iso9660
check_real_ksy test/sample.sqlite sqlite3
check_real_ksy test/sample.avi avi
check_real_ksy test/sample.mp3 id3v2_3
# This specimen's suffix is misleading; its bytes are an ordinary gzip stream.
check_real_ksy test/george.jpg gzip
check_real_ksy test/george2.jpg jpeg
check_real_ksy test/sample.wav wav
check_real_ksy test/fat.img vfat
check_real_ksy test/ext2.img ext2
if [ -f test/cmd.exe ]; then
    check_real_ksy test/cmd.exe microsoft_pe
else
    echo "PE acceptance BLOCKED: test/cmd.exe is not present" >&2
fi

# The real FAT and ext2 definitions currently prove useful structure before
# reaching an out-of-line extent / malformed directory tail in these images.
# Keep those concrete unresolved KSY relationships visible rather than silently
# treating a prefix parse as complete.
for specimen in test/fat.img test/ext2.img; do
    ./clarity.py --analyze --json "$specimen" > "$tmp/partial-real-ksy.json"
    python3 - "$tmp/partial-real-ksy.json" "$specimen" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
views = [v for v in obj["views"] if v.get("strong_identity")]
assert views and any(v.get("partial") and v.get("issues") for v in views), sys.argv[2]
PY
done

# Strong anchors remain root-relative during structural scanning. Two complete
# PNGs at nonzero offsets must yield two hypotheses, while common PK bytes in the
# surrounding payload must not nominate embedded ZIP identities.
python3 - <<'PY' > "$tmp/two-embedded-pngs"
import sys
png = open("test/sample.png", "rb").read()
sys.stdout.buffer.write(b"prefix-PK-noise" + png + b"middle-PK-noise" + png + b"tail")
PY
./clarity.py --analyze --json --windowed "$tmp/two-embedded-pngs" > "$tmp/two-embedded.json"
python3 - "$tmp/two-embedded.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
pngs = [v for v in obj["views"] if v.get("ksy_id") == "png"]
assert len({v["offset"] for v in pngs}) == 2
assert all(not v.get("strong_identity") for v in pngs)
assert not any(v.get("ksy_id") == "zip" for v in obj["views"])
PY

# Real MBR follows its dedicated structural-coherence path backed by the real KSY.
./clarity.py --analyze --json test/mbr.img > "$tmp/real-mbr.json"
python3 - "$tmp/real-mbr.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
assert any(c.get("kind") == "mbr_partition_table" for c in obj.get("claims", []))
PY

dd if=/dev/zero of="$tmp/blank-real-negative" bs=65536 count=1 2>/dev/null
python3 - "$tmp/random-real-negative" <<'PY'
import os, sys
open(sys.argv[1], "wb").write(os.urandom(65536))
PY
for specimen in "$tmp/blank-real-negative" "$tmp/random-real-negative"; do
    ./clarity.py --analyze --json "$specimen" > "$tmp/real-negative.json"
    python3 - "$tmp/real-negative.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
assert not any(v.get("strong_identity") for v in obj.get("views", []))
PY
done

echo "PASS: mechanics + metrology + stats/analyze/JSON contracts + 1800-case truth universe + real KSY acceptance"
