#!/usr/bin/env python3
"""Generic byte-stream analysis. Deliberately contains no Garble parser or transform registry."""

from __future__ import annotations

import argparse
import ast
import json
import math
import os
import re
import struct
import sys
from collections import Counter
from pathlib import Path

SAMPLE_LIMIT = 2 * 1024 * 1024
LAG_SAMPLE_LIMIT = 64 * 1024
BLOCK_PERMUTE_MAX = 64
STRUCTURE_WINDOW = 1024
STRUCTURE_SAMPLE_LIMIT = 8 * 1024 * 1024
MAX_IDENTITY_CLAIMS = 16
MBR_KSY_RELATIVE = "filesystem/mbr_partition_table.ksy"
MBR_SHAPE_SOURCE = "kaitai/" + MBR_KSY_RELATIVE
MAX_MBR_VIEWS = 16
MAX_AUTO_KSY_VIEWS = 16
AUTO_KSY_MIN_ANCHOR = 2

_KSY_ROOT_OVERRIDE: Path | None = None
_KSY_DOC_CACHE: dict[str, tuple[int, int, dict]] = {}

BYTE_NAMES = {
    0x00: "NUL",
    0x09: "TAB",
    0x0a: "LF",
    0x0d: "CR",
    0x1b: "ESC",
    0x7f: "DEL",
}


def read_bytes(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    return Path(path).read_bytes()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def serial_correlation(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    a = data[:-1]
    b = data[1:]
    ma = sum(a) / len(a)
    mb = sum(b) / len(b)
    num = sum((x - ma) * (y - mb) for x, y in zip(a, b))
    da = sum((x - ma) ** 2 for x in a)
    db = sum((y - mb) ** 2 for y in b)
    if da == 0 or db == 0:
        return 0.0
    return num / math.sqrt(da * db)


def coincidence(data: bytes, lag: int) -> float:
    if lag <= 0 or len(data) <= lag:
        return 0.0
    n = len(data) - lag
    return sum(x == y for x, y in zip(data[:-lag], data[lag:])) / n


def hamming_ratio(a: bytes, b: bytes) -> float:
    n = min(len(a), len(b))
    if not n:
        return 0.0
    flips = sum((x ^ y).bit_count() for x, y in zip(a[:n], b[:n]))
    return flips / (8 * n)


def smallest_period_exact(data: bytes, max_period: int) -> int | None:
    """Return the smallest exact period <= max_period, allowing a partial final repetition."""
    n = len(data)
    if n < 2:
        return None
    limit = min(max_period, n // 2)
    for p in range(1, limit + 1):
        if data[p] != data[0]:
            continue
        probe_end = min(n, p + 4096)
        if data[p:probe_end] != data[:probe_end - p]:
            continue
        # Bytes slicing/comparison does the exact confirmation in C.
        if data[p:] == data[:-p]:
            return p
    return None


def lag_scores(data: bytes, max_lag: int) -> tuple[float, list[dict]]:
    """Return independent-byte coincidence baseline and observed lag scores."""
    sample = data[:LAG_SAMPLE_LIMIT]
    n = len(sample)
    if n < 4:
        return 0.0, []
    counts = Counter(sample)
    baseline = sum((c / n) ** 2 for c in counts.values())
    rows = []
    for lag in range(1, min(max_lag, n - 1) + 1):
        obs = coincidence(sample, lag)
        pairs = n - lag
        var = baseline * (1.0 - baseline) / pairs if 0.0 < baseline < 1.0 else 0.0
        z = (obs - baseline) / math.sqrt(var) if var > 0.0 else 0.0
        rows.append({"lag": lag, "coincidence": obs, "z": z})
    return baseline, rows


def periodicity_claim(data: bytes, max_lag: int) -> dict | None:
    """Conservative ciphertext-only claim about equality periodicity, not its cause."""
    sample = data[:SAMPLE_LIMIT]
    if len(sample) < 256:
        return None
    baseline, rows = lag_scores(sample, max_lag)
    by_lag = {row["lag"]: row for row in rows}

    # Lag 1 is intentionally excluded: local runs/Markov structure are not by
    # themselves evidence of a repeating period.
    def local_peak(row: dict) -> bool:
        lag = row["lag"]
        left = by_lag.get(lag - 1)
        right = by_lag.get(lag + 1)
        neighbors = [x["coincidence"] for x in (left, right) if x is not None]
        return not neighbors or row["coincidence"] >= max(neighbors) + 0.002

    strong = [
        row for row in rows if row["lag"] >= 2
        and row["z"] >= 8.0
        and row["coincidence"] >= baseline + 0.005
        and row["coincidence"] >= baseline * 1.25
        and local_peak(row)
    ]
    if len(strong) < 2:
        return None

    strongest = sorted(strong, key=lambda r: (r["z"], r["coincidence"]), reverse=True)[:16]
    candidates = []
    max_seen = rows[-1]["lag"] if rows else 0
    for p in range(2, min(256, max_seen) + 1):
        root = by_lag.get(p)
        if root not in strong:
            continue
        supporters = [row for row in strongest if row["lag"] % p == 0]
        needed = 3 if max_seen >= 3 * p else 2
        if len(supporters) < needed:
            continue
        fraction = len(supporters) / len(strongest)
        if fraction < 0.50:
            continue
        candidates.append((p, supporters, fraction, root))

    if not candidates:
        return None

    # Prefer the smallest supported fundamental lag. Requiring the root lag
    # itself to be strong prevents divisors such as 2 from stealing period 32.
    p, supporters, fraction, root = min(candidates, key=lambda item: item[0])
    support_lags = sorted(row["lag"] for row in supporters)
    return {
        "kind": "byte_coincidence_periodicity",
        "period": p,
        "baseline": baseline,
        "coincidence": root["coincidence"],
        "z": root["z"],
        "supporting_lags": support_lags,
        "support_fraction": fraction,
    }


def basic_stats(data: bytes, max_lag: int) -> dict:
    sample = data[:SAMPLE_LIMIT]
    counts = Counter(sample)
    n = len(sample)
    denom = max(1, n)
    baseline, rows = lag_scores(sample, max_lag)
    strongest = sorted(rows, key=lambda r: (r["coincidence"], -r["lag"]), reverse=True)[:8]
    return {
        "bytes": len(data),
        "sample_bytes": n,
        "entropy_bits_per_byte": entropy(sample),
        "distinct_byte_values": len(counts),
        "printable_ascii_ratio": sum(32 <= b <= 126 for b in sample) / denom,
        "zero_ratio": counts.get(0, 0) / denom,
        "ff_ratio": counts.get(255, 0) / denom,
        "serial_correlation": serial_correlation(sample),
        "independent_coincidence_baseline": baseline,
        "strongest_lags": strongest,
        "most_common": [
            {"byte": value, "ratio": count / denom}
            for value, count in counts.most_common(8)
        ],
    }


def structural_character(data: bytes) -> dict:
    """Describe byte-level character only; do not infer semantic identity."""
    n = len(data)
    if not n:
        return {"kind": "empty", "bytes": 0}
    counts = Counter(data)
    value, count = counts.most_common(1)[0]
    dominant = count / n
    if dominant >= 0.98:
        return {
            "kind": "fill",
            "bytes": n,
            "fill_byte": value,
            "dominant_ratio": dominant,
        }

    text_compatible = sum((32 <= b <= 126) or b in (9, 10, 13) for b in data) / n
    if text_compatible >= 0.98 and counts.get(0, 0) == 0:
        return {
            "kind": "ascii_compatible",
            "bytes": n,
            "compatible_ratio": text_compatible,
        }

    ent = entropy(data)
    distinct = len(counts)
    if n >= 256 and ent >= 7.50 and distinct >= min(180, n // 2):
        return {
            "kind": "high_entropy",
            "bytes": n,
            "entropy_bits_per_byte": ent,
            "distinct_byte_values": distinct,
        }

    return {
        "kind": "other",
        "bytes": n,
        "entropy_bits_per_byte": ent,
        "distinct_byte_values": distinct,
        "ascii_compatible_ratio": text_compatible,
    }


def structure_regions(data: bytes, window: int = STRUCTURE_WINDOW) -> dict:
    """Coarse first-pass structure map over a bounded prefix of the input."""
    if window < 64:
        raise ValueError("structure window must be at least 64 bytes")
    scan = data[:STRUCTURE_SAMPLE_LIMIT]
    raw = []
    for start in range(0, len(scan), window):
        end = min(len(scan), start + window)
        char = structural_character(scan[start:end])
        key = (char["kind"], char.get("fill_byte"))
        if raw and raw[-1]["_key"] == key and raw[-1]["end"] == start:
            raw[-1]["end"] = end
            raw[-1]["windows"] += 1
        else:
            row = {
                "start": start,
                "end": end,
                "windows": 1,
                "kind": char["kind"],
                "_key": key,
            }
            if char["kind"] == "fill":
                row["fill_byte"] = char["fill_byte"]
            raw.append(row)
    for row in raw:
        row.pop("_key", None)
    return {
        "window_bytes": window,
        "scanned_bytes": len(scan),
        "total_bytes": len(data),
        "truncated": len(scan) != len(data),
        "regions": raw,
    }


def _uint(data: bytes, start: int, size: int, byteorder: str) -> int:
    return int.from_bytes(data[start:start + size], byteorder)



class KsyError(ValueError):
    pass


class KsyUnsupported(KsyError):
    pass


def configure_ksy_root(path: str | os.PathLike[str] | None) -> None:
    """Override where Clarity looks for the external Kaitai format corpus."""
    global _KSY_ROOT_OVERRIDE
    _KSY_ROOT_OVERRIDE = Path(path).expanduser().resolve() if path else None


def _ksy_roots() -> list[Path]:
    roots: list[Path] = []
    if _KSY_ROOT_OVERRIDE is not None:
        roots.append(_KSY_ROOT_OVERRIDE)
    env = os.environ.get("CLARITY_KSY_ROOT")
    if env:
        roots.append(Path(env).expanduser())
    script_dir = Path(__file__).resolve().parent
    roots.extend((script_dir / "kaitai", Path.cwd() / "kaitai"))
    out: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = str(root)
        if key not in seen:
            seen.add(key)
            out.append(root)
    return out


def resolve_ksy_path(relative: str) -> Path | None:
    for root in _ksy_roots():
        candidate = root / relative
        if candidate.is_file():
            return candidate
    return None


def _normalize_ksy_relative(relative: str, importer: str | None = None) -> str:
    """Normalize Kaitai import names to corpus-relative ``*.ksy`` paths."""
    if not isinstance(relative, str) or not relative.strip():
        raise KsyUnsupported(f"invalid KSY path/import: {relative!r}")
    text = relative.strip().replace("\\", "/")
    if text.startswith("/"):
        text = text[1:]
    elif importer is not None:
        text = str((Path(importer).parent / text).as_posix())
    if not text.endswith(".ksy"):
        text += ".ksy"
    parts: list[str] = []
    for part in text.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                raise KsyUnsupported(f"KSY import escapes corpus root: {relative!r}")
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


def _split_inline(text: str, delimiter: str = ",") -> list[str]:
    parts: list[str] = []
    start = 0
    quote: str | None = None
    depth = 0
    escaped = False
    for i, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if quote:
            if ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch in "[({":
            depth += 1
        elif ch in "])}":
            depth -= 1
        elif ch == delimiter and depth == 0:
            parts.append(text[start:i].strip())
            start = i + 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _split_mapping_pair(text: str) -> tuple[str, str]:
    quote: str | None = None
    depth = 0
    escaped = False
    for i, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if quote:
            if ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch in "[({":
            depth += 1
        elif ch in "])}":
            depth -= 1
        elif ch == ":" and depth == 0:
            return text[:i].strip(), text[i + 1:].strip()
    raise KsyError(f"expected mapping pair: {text!r}")


def _yaml_scalar(text: str):
    text = text.strip()
    if not text:
        return None
    low = text.lower()
    if low in {"null", "~"}:
        return None
    if low == "true":
        return True
    if low == "false":
        return False
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        return [] if not inner else [_yaml_scalar(part) for part in _split_inline(inner)]
    if text.startswith("{") and text.endswith("}"):
        inner = text[1:-1].strip()
        out = {}
        if inner:
            for part in _split_inline(inner):
                key, value = _split_mapping_pair(part)
                out[key] = _yaml_scalar(value)
        return out
    if text[:1] in {"'", '"'} and text[-1:] == text[:1]:
        try:
            return ast.literal_eval(text)
        except (SyntaxError, ValueError):
            return text[1:-1]
    try:
        return int(text, 0)
    except ValueError:
        return text


def parse_ksy_yaml(text: str) -> dict:
    """Tiny dependency-free YAML reader for the conservative KSY subset we consume.

    This is intentionally not a general YAML implementation.  Unsupported syntax
    raises KsyUnsupported instead of being guessed at.  Growing this reader is one
    of the knobs that can unlock more of the external Kaitai corpus.
    """
    raw = text.splitlines()
    lines: list[tuple[int, str]] = []
    for line in raw:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "\t" in line[: len(line) - len(line.lstrip("\t "))]:
            raise KsyUnsupported("tabs in YAML indentation are unsupported")
        indent = len(line) - len(line.lstrip(" "))
        lines.append((indent, line[indent:]))

    def parse_block(i: int, indent: int):
        if i >= len(lines) or lines[i][0] < indent:
            return {}, i
        is_list = lines[i][0] == indent and lines[i][1].startswith("- ")
        if is_list:
            out: list = []
            while i < len(lines) and lines[i][0] == indent and lines[i][1].startswith("- "):
                body = lines[i][1][2:].strip()
                i += 1
                if not body:
                    if i >= len(lines) or lines[i][0] <= indent:
                        out.append(None)
                        continue
                    item, i = parse_block(i, lines[i][0])
                    out.append(item)
                    continue
                if ":" in body and body[:1] not in {"'", '"'}:
                    key, value = _split_mapping_pair(body)
                    item: dict = {key: _yaml_scalar(value) if value else None}
                    if not value and i < len(lines) and lines[i][0] > indent:
                        child_indent = lines[i][0]
                        child, i = parse_block(i, child_indent)
                        item[key] = child
                    if i < len(lines) and lines[i][0] > indent:
                        child_indent = lines[i][0]
                        extra, i = parse_block(i, child_indent)
                        if not isinstance(extra, dict):
                            raise KsyUnsupported("list-item mapping continuation must be a mapping")
                        item.update(extra)
                    out.append(item)
                else:
                    out.append(_yaml_scalar(body))
            return out, i

        out: dict = {}
        while i < len(lines) and lines[i][0] == indent and not lines[i][1].startswith("- "):
            key, value = _split_mapping_pair(lines[i][1])
            i += 1
            if value in {"|", ">", "|-", ">-", "|+", ">+"}:
                chunks: list[str] = []
                while i < len(lines) and lines[i][0] > indent:
                    chunks.append(lines[i][1])
                    i += 1
                out[key] = "\n".join(chunks)
            elif value:
                out[key] = _yaml_scalar(value)
            elif i < len(lines) and lines[i][0] > indent:
                child_indent = lines[i][0]
                out[key], i = parse_block(i, child_indent)
            else:
                out[key] = {}
        return out, i

    if not lines:
        return {}
    result, end = parse_block(0, lines[0][0])
    if end != len(lines) or not isinstance(result, dict):
        raise KsyUnsupported("unsupported YAML shape")
    return result


def _load_ksy_raw(relative: str) -> tuple[dict, Path] | None:
    relative = _normalize_ksy_relative(relative)
    path = resolve_ksy_path(relative)
    if path is None:
        return None
    st = path.stat()
    key = str(path.resolve())
    cached = _KSY_DOC_CACHE.get(key)
    if cached and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
        return cached[2], path
    doc = parse_ksy_yaml(path.read_text(encoding="utf-8"))
    if not isinstance(doc.get("meta"), dict):
        raise KsyUnsupported(f"{relative}: expected meta mapping")
    # Kaitai permits instance-only roots.  Filesystem definitions such as ext2
    # and ISO9660 use the file itself as an address space and expose their first
    # structures exclusively through ``instances`` rather than a root ``seq``.
    if "seq" in doc and not isinstance(doc.get("seq"), list):
        raise KsyUnsupported(f"{relative}: root seq must be a list when present")
    if not isinstance(doc.get("seq", []), list):
        raise KsyUnsupported(f"{relative}: unsupported root seq")
    _KSY_DOC_CACHE[key] = (st.st_mtime_ns, st.st_size, doc)
    return doc, path


def _load_ksy_with_imports(relative: str, stack: tuple[str, ...]) -> tuple[dict, Path] | None:
    relative = _normalize_ksy_relative(relative)
    if relative in stack:
        chain = " -> ".join(stack + (relative,))
        raise KsyUnsupported(f"cyclic KSY imports are unsupported: {chain}")
    loaded = _load_ksy_raw(relative)
    if loaded is None:
        return None
    raw_doc, path = loaded
    doc = dict(raw_doc)
    doc["__ksy_relative__"] = relative
    imported_types: dict[str, dict] = {}
    imports = raw_doc.get("meta", {}).get("imports", [])
    if imports:
        if not isinstance(imports, list):
            raise KsyUnsupported(f"{relative}: meta.imports must be a list")
        for import_name in imports:
            if not isinstance(import_name, str):
                raise KsyUnsupported(f"{relative}: unsupported import name {import_name!r}")
            import_relative = _normalize_ksy_relative(import_name, relative)
            child_loaded = _load_ksy_with_imports(import_relative, stack + (relative,))
            if child_loaded is None:
                raise KsyError(f"{relative}: imported KSY definition not found: {import_name}")
            child_doc, _ = child_loaded
            child_id = child_doc.get("meta", {}).get("id")
            if not isinstance(child_id, str) or not child_id:
                raise KsyUnsupported(f"{import_relative}: imported KSY needs meta.id")
            # Imported KSY roots behave as named types in the importing grammar.
            # Keep their own document attached so endian/bit-endian/enums/imports
            # remain those of the imported definition rather than the caller.
            child_root = dict(child_doc)
            child_root["__ksy_doc__"] = child_doc
            imported_types[child_id] = child_root
    doc["__ksy_import_types__"] = imported_types
    return doc, path


def load_ksy(relative: str) -> tuple[dict, Path] | None:
    return _load_ksy_with_imports(relative, ())


def _primitive_type_size(type_name: str) -> tuple[int, bool] | None:
    """Return byte width + signedness for integer primitives we can project."""
    if not isinstance(type_name, str):
        return None
    base = type_name
    if base.endswith("le") or base.endswith("be"):
        base = base[:-2]
    signed = False
    if base.startswith("u"):
        digits = base[1:]
    elif base.startswith("s"):
        signed = True
        digits = base[1:]
    else:
        return None
    if digits not in {"1", "2", "4", "8"}:
        return None
    return int(digits), signed


def _primitive_byteorder(type_name: str, default: str) -> str:
    if type_name.endswith("le"):
        return "little"
    if type_name.endswith("be"):
        return "big"
    return default


def _float_type_size(type_name: str) -> int | None:
    if not isinstance(type_name, str):
        return None
    base = type_name
    if base.endswith("le") or base.endswith("be"):
        base = base[:-2]
    if base == "f4":
        return 4
    if base == "f8":
        return 8
    return None

def _bit_type_width(type_name: str) -> int | None:
    if not isinstance(type_name, str) or not type_name.startswith("b"):
        return None
    digits = type_name[1:]
    if not digits.isdigit() or int(digits) < 1:
        return None
    return int(digits)


def _ksy_enum_value(enums: dict, enum_name: str, member: str):
    enum = enums.get(enum_name)
    if not isinstance(enum, dict):
        raise KsyError(f"unknown KSY enum {enum_name!r}")
    for raw_value, spec in enum.items():
        try:
            value = int(str(raw_value), 0)
        except ValueError:
            continue
        if isinstance(spec, str) and spec == member:
            return value
        if isinstance(spec, dict) and spec.get("id") == member:
            return value
    raise KsyError(f"unknown KSY enum member {enum_name}::{member}")


def _ksy_case_value(text, doc: dict, enums: dict | None = None):
    if isinstance(text, (int, bool)):
        return text
    if not isinstance(text, str):
        raise KsyUnsupported(f"unsupported switch case key: {text!r}")
    key = text.strip()
    if key[:1] in {"'", '"'} and key[-1:] == key[:1]:
        key = _yaml_scalar(key)
        if not isinstance(key, str):
            return key
    if "::" in key:
        enum_name, member = key.split("::", 1)
        return _ksy_enum_value(enums if enums is not None else doc.get("enums", {}), enum_name, member)
    return _yaml_scalar(key)


def _contents_bytes(value) -> bytes | None:
    """Flatten the KSY contents forms useful for magic/constants.

    Kaitai allows convenient string literals as well as byte arrays, and some
    definitions mix both (e.g. ["SQLite format 3", 0]).
    """
    out = bytearray()

    def add(item) -> bool:
        if isinstance(item, int) and 0 <= item <= 255:
            out.append(item)
            return True
        if isinstance(item, str):
            try:
                out.extend(item.encode("latin-1"))
            except UnicodeEncodeError:
                return False
            return True
        if isinstance(item, list):
            return all(add(part) for part in item)
        return False

    return bytes(out) if add(value) else None


def _ksy_seq_static_size(doc: dict, seq: list, stack: tuple[str, ...] = ()) -> int | None:
    total = 0
    types = doc.get("types", {})
    for field in seq:
        if not isinstance(field, dict):
            return None
        if field.get("if") is not None:
            return None
        repeat = field.get("repeat")
        if repeat is None:
            count = 1
        elif repeat == "expr" and isinstance(field.get("repeat-expr"), int):
            count = field["repeat-expr"]
        else:
            return None

        if "contents" in field:
            expected = _contents_bytes(field["contents"])
            if expected is None:
                return None
            one = len(expected)
        elif isinstance(field.get("size"), int):
            one = field["size"]
        else:
            type_name = field.get("type")
            if type_name == "str" and isinstance(field.get("size"), int):
                one = field["size"]
            elif not isinstance(type_name, str):
                return None
            else:
                primitive = _primitive_type_size(type_name)
                if primitive is not None:
                    one = primitive[0]
                else:
                    if type_name in stack or type_name not in types:
                        return None
                    type_def = types[type_name]
                    if not isinstance(type_def, dict) or not isinstance(type_def.get("seq"), list):
                        return None
                    nested = _ksy_seq_static_size(doc, type_def["seq"], stack + (type_name,))
                    if nested is None:
                        return None
                    one = nested
        total += one * count
    return total


def ksy_static_size(doc: dict) -> int | None:
    return _ksy_seq_static_size(doc, doc.get("seq", []))


def _ksy_endian(doc: dict, type_def: dict | None = None) -> str:
    value = None
    if type_def:
        value = type_def.get("endian")
    if value is None:
        value = doc.get("meta", {}).get("endian", "be")
    if value == "le":
        return "little"
    if value == "be":
        return "big"
    raise KsyUnsupported(f"dynamic/unknown endian is not supported yet: {value!r}")


class _KsyIO:
    __slots__ = ("start", "end", "size", "pos")

    def __init__(self, start: int, end: int, absolute_pos: int | None = None) -> None:
        self.start = start
        self.end = end
        self.size = end - start
        self.pos = (start if absolute_pos is None else absolute_pos) - start

    @property
    def eof(self) -> bool:
        return self.pos >= self.size


class _KsyStruct(dict):
    """Mapping-shaped parsed value that also remembers its Kaitai substream.

    Keep a live reference to the originating scope.  Kaitai instances are lazy:
    a child object can legally expose an instance that cannot resolve until an
    ancestor instance has itself been installed.  Copying only the child's
    current value mapping made those later resolutions invisible to callers.
    """

    __slots__ = ("stream_start", "stream_end", "scope")

    def __init__(
        self, values: dict[str, object], stream_start: int, stream_end: int,
        scope: "_KsyScope | None" = None,
    ) -> None:
        super().__init__(values)
        self.stream_start = stream_start
        self.stream_end = stream_end
        self.scope = scope


class _KsyScope:
    __slots__ = (
        "path", "values", "parent", "root", "stream_start", "stream_end", "doc", "types", "enums",
        "instance_specs", "lazy_resolver", "cursor", "resolving_instances",
    )

    def __init__(
        self,
        path: str,
        parent: "_KsyScope | None",
        stream_start: int,
        stream_end: int,
        doc: dict | None = None,
        local_types: dict | None = None,
        local_enums: dict | None = None,
    ) -> None:
        self.path = path
        self.values: dict[str, object] = {}
        self.parent = parent
        self.root = self if parent is None else parent.root
        self.stream_start = stream_start
        self.stream_end = stream_end
        self.doc = doc if doc is not None else (parent.doc if parent is not None else None)
        inherited = parent.types if parent is not None else {}
        self.types = dict(inherited)
        if local_types:
            self.types.update(local_types)
        inherited_enums = parent.enums if parent is not None else {}
        self.enums = dict(inherited_enums)
        if local_enums:
            self.enums.update(local_enums)
        self.instance_specs: dict[str, dict] = {}
        self.lazy_resolver = None
        self.cursor = stream_start
        self.resolving_instances: set[str] = set()


def _ksy_div(a, b):
    # Kaitai integer expressions use integer division.  Avoid Python's ``//``
    # negative-flooring difference by truncating toward zero explicitly.
    if isinstance(a, int) and not isinstance(a, bool) and isinstance(b, int) and not isinstance(b, bool):
        if b == 0:
            raise ZeroDivisionError
        q = abs(a) // abs(b)
        return -q if (a < 0) ^ (b < 0) else q
    return a / b


_BIN_OPS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: _ksy_div,
    ast.FloorDiv: lambda a, b: a // b,
    ast.Mod: lambda a, b: a % b,
    ast.LShift: lambda a, b: a << b,
    ast.RShift: lambda a, b: a >> b,
    ast.BitAnd: lambda a, b: a & b,
    ast.BitOr: lambda a, b: a | b,
    ast.BitXor: lambda a, b: a ^ b,
}


def _ksy_equal(a, b) -> bool:
    if isinstance(a, (bytes, bytearray)) and isinstance(b, list) and all(isinstance(x, int) for x in b):
        return list(a) == b
    if isinstance(b, (bytes, bytearray)) and isinstance(a, list) and all(isinstance(x, int) for x in a):
        return a == list(b)
    return a == b

_CMP_OPS = {
    ast.Eq: _ksy_equal,
    ast.NotEq: lambda a, b: not _ksy_equal(a, b),
    ast.Lt: lambda a, b: a < b,
    ast.LtE: lambda a, b: a <= b,
    ast.Gt: lambda a, b: a > b,
    ast.GtE: lambda a, b: a >= b,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}


def _ksy_attr(value, name: str):
    if isinstance(value, _KsyScope):
        if name == "_io":
            return _KsyIO(value.stream_start, value.stream_end)
        if name in value.values:
            return value.values[name]
        if name in value.instance_specs and value.lazy_resolver is not None:
            value.lazy_resolver(name)
            if name in value.values:
                return value.values[name]
        raise KsyError(f"unknown KSY field {name!r} in {value.path}")
    if isinstance(value, _KsyStruct):
        if name == "_io":
            return _KsyIO(value.stream_start, value.stream_end)
        if name in value:
            return value[name]
        if value.scope is not None:
            if name in value.scope.values:
                resolved = value.scope.values[name]
                value[name] = resolved
                return resolved
            if name in value.scope.instance_specs and value.scope.lazy_resolver is not None:
                value.scope.lazy_resolver(name)
                if name in value.scope.values:
                    resolved = value.scope.values[name]
                    value[name] = resolved
                    return resolved
        raise KsyError(f"unknown KSY mapping field {name!r}")
    if isinstance(value, dict):
        if name in value:
            return value[name]
        raise KsyError(f"unknown KSY mapping field {name!r}")
    if name == "size" and isinstance(value, (bytes, bytearray, str, list, tuple)):
        return len(value)
    if name == "to_s" and isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, _KsyIO) and name in {"size", "pos", "eof", "start", "end"}:
        return getattr(value, name)
    raise KsyUnsupported(f"unsupported attribute .{name} on {type(value).__name__}")


def _matching_delimiter(text: str, start: int) -> int:
    pairs = {"(": ")", "[": "]", "{": "}"}
    opening = text[start]
    closing = pairs[opening]
    depth = 1
    quote: str | None = None
    escaped = False
    for i in range(start + 1, len(text)):
        ch = text[i]
        if escaped:
            escaped = False
            continue
        if quote:
            if ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch == opening:
            depth += 1
        elif ch == closing:
            depth -= 1
            if depth == 0:
                return i
    raise KsyUnsupported(f"unbalanced delimiter in KSY expression: {text!r}")


def _translate_ksy_ternary(text: str) -> str:
    """Translate Kaitai's ``cond ? a : b`` recursively into Python syntax."""
    text = text.strip()

    # First translate nested delimiter contents, so a ternary wrapped in
    # parentheses becomes ordinary Python before we inspect this level.
    rebuilt: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch in "([{":
            end = _matching_delimiter(text, i)
            rebuilt.append(ch)
            rebuilt.append(_translate_ksy_ternary(text[i + 1:end]))
            rebuilt.append(text[end])
            i = end + 1
            continue
        if ch in {"'", '"'}:
            quote = ch
            j = i + 1
            escaped = False
            while j < len(text):
                cj = text[j]
                if escaped:
                    escaped = False
                elif cj == "\\":
                    escaped = True
                elif cj == quote:
                    j += 1
                    break
                j += 1
            rebuilt.append(text[i:j])
            i = j
            continue
        rebuilt.append(ch)
        i += 1
    text = "".join(rebuilt)

    quote = None
    depth = 0
    qmark = None
    nested_q = 0
    colon = None
    escaped = False
    for i, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if quote:
            if ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in {"'", '"'}:
            quote = ch
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0 and ch == "?":
            if qmark is None:
                qmark = i
            else:
                nested_q += 1
        elif depth == 0 and ch == ":" and qmark is not None:
            # Do not mistake Kaitai enum ``::`` for a ternary separator.
            if (i > 0 and text[i - 1] == ":") or (i + 1 < len(text) and text[i + 1] == ":"):
                continue
            if nested_q:
                nested_q -= 1
            else:
                colon = i
                break
    if qmark is None:
        return text
    if colon is None:
        raise KsyUnsupported(f"unterminated KSY ternary: {text!r}")
    cond = _translate_ksy_ternary(text[:qmark])
    yes = _translate_ksy_ternary(text[qmark + 1:colon])
    no = _translate_ksy_ternary(text[colon + 1:])
    return f"({yes} if {cond} else {no})"


def _ksy_eval(expr, scope: _KsyScope, cursor: int, index: int | None = None, current=None):
    """Evaluate a deliberately small, side-effect-free Kaitai expression subset."""
    if isinstance(expr, (int, bool)):
        return expr
    if not isinstance(expr, str):
        raise KsyUnsupported(f"unsupported KSY expression value: {expr!r}")
    text = " ".join(part.strip() for part in expr.strip().splitlines())
    if not text:
        raise KsyUnsupported("empty KSY expression")

    # Casts in corpus expressions are used to pin generated-language types;
    # Python's arbitrary precision integers already preserve the value here.
    text = re.sub(r"\.as<[A-Za-z_][A-Za-z0-9_]*>", "", text)
    text = _translate_ksy_ternary(text)

    enum_refs: dict[str, tuple[str, str]] = {}
    def repl_enum(match):
        token = f"__ksy_enum_{len(enum_refs)}"
        enum_refs[token] = (match.group(1), match.group(2))
        return token
    text = re.sub(r"\b([A-Za-z_]\w*)::([A-Za-z_]\w*)\b", repl_enum, text)
    try:
        tree = ast.parse(text, mode="eval")
    except SyntaxError as exc:
        raise KsyUnsupported(f"unsupported KSY expression syntax: {expr!r}") from exc

    def ev(node):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id == "_root":
                return scope.root
            if node.id == "_parent":
                if scope.parent is None:
                    raise KsyError("_parent used at KSY root")
                return scope.parent
            if node.id == "_io":
                return _KsyIO(scope.stream_start, scope.stream_end, cursor)
            if node.id == "_index":
                if index is None:
                    raise KsyError("_index used outside a repeat")
                return index
            if node.id == "_":
                return current
            if node.id == "true":
                return True
            if node.id == "false":
                return False
            if node.id in scope.values:
                return scope.values[node.id]
            if node.id in scope.instance_specs and scope.lazy_resolver is not None:
                scope.lazy_resolver(node.id)
                if node.id in scope.values:
                    return scope.values[node.id]
            if node.id in enum_refs:
                enum_name, member = enum_refs[node.id]
                return _ksy_enum_value(scope.enums, enum_name, member)
            raise KsyError(f"unknown KSY name {node.id!r} in {scope.path}")
        if isinstance(node, ast.Attribute):
            return _ksy_attr(ev(node.value), node.attr)
        if isinstance(node, ast.Subscript):
            value = ev(node.value)
            # Python 3.9+ uses the expression node directly in .slice.
            return value[ev(node.slice)]
        if isinstance(node, ast.List):
            return [ev(x) for x in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(ev(x) for x in node.elts)
        if isinstance(node, ast.Call):
            if node.keywords:
                raise KsyUnsupported(f"keyword arguments are unsupported in {expr!r}")
            if isinstance(node.func, ast.Attribute) and node.func.attr == "to_s":
                target = ev(node.func.value)
                if len(node.args) == 0:
                    if isinstance(target, (int, float)) and not isinstance(target, bool):
                        return str(target)
                    raise KsyUnsupported(f"zero-argument to_s() unsupported for {type(target).__name__}")
                if len(node.args) != 1:
                    raise KsyUnsupported(f"to_s() needs zero args or one encoding in {expr!r}")
                encoding = ev(node.args[0])
                if not isinstance(encoding, str):
                    raise KsyUnsupported(f"to_s() encoding must be a string in {expr!r}")
                if isinstance(target, str):
                    return target
                if isinstance(target, list) and all(isinstance(x, int) and 0 <= x <= 255 for x in target):
                    target = bytes(target)
                if isinstance(target, (bytes, bytearray)):
                    try:
                        return bytes(target).decode(encoding, errors="strict")
                    except (LookupError, UnicodeDecodeError) as exc:
                        raise KsyError(f"to_s() decode failed for encoding {encoding!r}") from exc
                raise KsyUnsupported(f"to_s() unsupported for {type(target).__name__} in {expr!r}")
            raise KsyUnsupported(f"unsupported KSY call in {expr!r}")
        if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
            return _BIN_OPS[type(node.op)](ev(node.left), ev(node.right))
        if isinstance(node, ast.UnaryOp):
            value = ev(node.operand)
            if isinstance(node.op, ast.Not):
                return not value
            if isinstance(node.op, ast.USub):
                return -value
            if isinstance(node.op, ast.UAdd):
                return +value
            if isinstance(node.op, ast.Invert):
                return ~value
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                result = True
                for item in node.values:
                    result = ev(item)
                    if not result:
                        return result
                return result
            if isinstance(node.op, ast.Or):
                result = False
                for item in node.values:
                    result = ev(item)
                    if result:
                        return result
                return result
        if isinstance(node, ast.Compare):
            left = ev(node.left)
            for op, right_node in zip(node.ops, node.comparators):
                right = ev(right_node)
                fn = _CMP_OPS.get(type(op))
                if fn is None:
                    raise KsyUnsupported(f"unsupported comparison in {expr!r}")
                if not fn(left, right):
                    return False
                left = right
            return True
        if isinstance(node, ast.IfExp):
            return ev(node.body) if bool(ev(node.test)) else ev(node.orelse)
        raise KsyUnsupported(f"unsupported KSY expression node {type(node).__name__}: {expr!r}")

    return ev(tree)


def _ksy_int(expr, scope: _KsyScope, cursor: int, *, index: int | None = None) -> int:
    value = _ksy_eval(expr, scope, cursor, index=index)
    if not isinstance(value, int) or isinstance(value, bool):
        raise KsyError(f"KSY expression did not produce an integer: {expr!r} -> {value!r}")
    if value < 0:
        raise KsyError(f"KSY expression produced a negative size/count/offset: {expr!r} -> {value}")
    return value


def _decode_ksy_string(raw: bytes, encoding: str, terminator, pad_right) -> str:
    data = raw
    if terminator is not None:
        term = int(terminator)
        try:
            cut = data.index(term)
            data = data[:cut]
        except ValueError:
            pass
    if pad_right is not None:
        data = data.rstrip(bytes([int(pad_right)]))
    try:
        return data.decode(encoding or "UTF-8", errors="strict")
    except (LookupError, UnicodeDecodeError) as exc:
        raise KsyError(f"string decode failed for encoding {encoding!r}") from exc


def parse_ksy_structure(
    data: bytes,
    doc: dict,
    offset: int = 0,
    base_offset: int = 0,
    root_path: str | None = None,
    root_instance_filter: set[str] | None = None,
    partial: bool = False,
) -> dict:
    """Project the supported KSY structure onto bytes without promoting identity.

    This is a structure projector, not a Kaitai compiler.  It deliberately grows
    by language feature.  Literal/validity failures are evidence rows rather than
    fatal parser assertions whenever we can preserve a useful partial shape.
    """
    meta = doc.get("meta", {})
    root = root_path or str(meta.get("id") or "root")
    types = doc.get("types", {})
    annotations: list[dict] = []
    values: dict[str, object] = {}
    constraints: list[dict] = []
    pending_instances: list[tuple[str, dict, _KsyScope, int, int]] = []
    issues: list[str] = []

    if offset < 0 or offset > len(data):
        raise KsyError("KSY start offset outside supplied data")

    def ann(start: int, end: int, path: str, label: str, depth: int, kind: str, **extra) -> dict:
        row = {
            "start": base_offset + start,
            "end": base_offset + end,
            "path": path,
            "label": label,
            "depth": depth,
            "kind": kind,
        }
        row.update(extra)
        annotations.append(row)
        return row

    def field_size(field: dict, scope: _KsyScope, cursor: int, index: int | None = None) -> int | None:
        if "size" in field:
            return _ksy_int(field["size"], scope, cursor, index=index)
        if field.get("size-eos") is True:
            return scope.stream_end - cursor
        return None

    def validate_field(
        field: dict,
        value,
        scope: _KsyScope,
        cursor: int,
        path: str,
        start: int,
        end: int,
        index: int | None = None,
    ) -> None:
        if "valid" not in field:
            return
        spec = field["valid"]
        passed = True
        expected = None
        detail: dict[str, object] = {}
        if isinstance(spec, dict):
            if "expr" in spec:
                passed = bool(_ksy_eval(spec["expr"], scope, cursor, index=index, current=value))
                expected = "expr"
            if "min" in spec:
                minimum = _ksy_eval(spec["min"], scope, cursor, index=index, current=value)
                detail["min"] = minimum
                passed = passed and value >= minimum
            if "max" in spec:
                maximum = _ksy_eval(spec["max"], scope, cursor, index=index, current=value)
                detail["max"] = maximum
                passed = passed and value <= maximum
            if "any-of" in spec:
                allowed = spec["any-of"]
                if not isinstance(allowed, list):
                    raise KsyUnsupported(f"valid any-of must be a list on {path}")
                detail["any_of"] = allowed
                passed = passed and any(_ksy_equal(value, candidate) for candidate in allowed)
            if spec.get("in-enum") is True:
                enum_name = field.get("enum")
                enum = scope.enums.get(enum_name) if isinstance(enum_name, str) else None
                if not isinstance(enum, dict):
                    raise KsyUnsupported(f"valid in-enum needs a known enum on {path}")
                enum_values = set()
                for raw in enum:
                    try:
                        enum_values.add(int(str(raw), 0))
                    except ValueError:
                        pass
                detail["enum"] = enum_name
                passed = passed and value in enum_values
            if not any(key in spec for key in {"expr", "min", "max", "any-of", "in-enum"}):
                raise KsyUnsupported(f"unsupported valid mapping on {path}: {spec!r}")
        else:
            expected = spec
            candidate = _ksy_eval(spec, scope, cursor, index=index, current=value) if isinstance(spec, str) else spec
            passed = _ksy_equal(value, candidate)
            detail["expected"] = candidate
        row = {
            "kind": "valid",
            "path": path,
            "start": base_offset + start,
            "end": base_offset + end,
            "passed": bool(passed),
        }
        if expected is not None:
            row["rule"] = expected
        row.update(detail)
        constraints.append(row)

    def _deferable_instance_error(exc: KsyError) -> bool:
        text = str(exc)
        return (
            text.startswith("unknown KSY field ")
            or text.startswith("unknown KSY name ")
            or text.startswith("cyclic KSY instance dependency ")
        )

    def process_one_instance(
        instance_id: str,
        spec: dict,
        scope: _KsyScope,
        depth: int,
        cursor: int,
    ) -> None:
        if spec.get("if") is not None and not bool(_ksy_eval(spec["if"], scope, cursor)):
            return
        instance_path = f"{scope.path}.{instance_id}"
        if "value" in spec:
            value = _ksy_eval(spec["value"], scope, cursor)
            scope.values[instance_id] = value
            values[instance_path] = value
            return
        if "pos" not in spec:
            raise KsyUnsupported(f"instance {instance_path} needs value or pos")

        io_spec = spec.get("io")
        if io_spec is None:
            io_start, io_end = scope.stream_start, scope.stream_end
        else:
            selected_io = _ksy_eval(io_spec, scope, cursor)
            if not isinstance(selected_io, _KsyIO):
                raise KsyUnsupported(
                    f"io selector on {instance_path} did not resolve to a KSY stream: {io_spec!r}"
                )
            io_start, io_end = selected_io.start, selected_io.end

        pos = _ksy_int(spec["pos"], scope, cursor)
        start = io_start + pos
        if start < io_start or start > io_end:
            raise KsyError(f"instance {instance_path} offset outside selected stream")
        size = None
        if "size" in spec:
            size = _ksy_int(spec["size"], scope, cursor)
        elif spec.get("size-eos") is True:
            size = io_end - start
        limit = io_end if size is None else start + size
        if limit > io_end:
            raise KsyError(f"instance {instance_path} exceeds selected stream")

        repeat = spec.get("repeat")
        if repeat is None:
            count = 1
            repeat_mode = None
        elif repeat == "expr":
            count = _ksy_int(spec.get("repeat-expr"), scope, cursor)
            repeat_mode = "expr"
        elif repeat == "eos":
            count = None
            repeat_mode = "eos"
        elif repeat == "until":
            count = None
            repeat_mode = "until"
            if spec.get("repeat-until") is None:
                raise KsyUnsupported(f"repeat-until missing on {instance_path}")
        else:
            raise KsyUnsupported(f"unsupported repeat mode on {instance_path}: {repeat!r}")

        # For repeated instances, Kaitai's ``size`` bounds each item, not the
        # entire repeated table.  GPT partition entries are the canonical case:
        # entries_size=128 with entries_count commonly 128.
        if repeat_mode and size is not None:
            if count is None:
                limit = io_end
            else:
                limit = start + size * count
                if limit > io_end:
                    raise KsyError(f"repeated instance {instance_path} exceeds selected stream")

        item_cursor = start
        collected = []
        index = 0
        while count is None or index < count:
            if count is None and item_cursor >= limit:
                break
            item_path = f"{instance_path}[{index}]" if repeat_mode else instance_path
            item_label = f"{instance_id}[{index}]" if repeat_mode else str(instance_id)
            before = item_cursor
            value, item_cursor = parse_field_value(
                spec,
                item_cursor,
                scope,
                item_path,
                item_label,
                depth + (1 if repeat_mode else 0),
                "record" if repeat_mode else "instance",
                limit,
                None,
                repeat_index=index if repeat_mode else None,
                force_size=size,
            )
            if repeat_mode:
                collected.append(value)
            else:
                scope.values[instance_id] = value
                values[instance_path] = value
            if repeat_mode in {"eos", "until"} and item_cursor <= before:
                raise KsyError(f"repeated instance {item_path} made no progress")
            stop_repeat = False
            if repeat_mode == "until":
                stop_repeat = bool(_ksy_eval(
                    spec["repeat-until"], scope, item_cursor, index=index, current=value
                ))
            index += 1
            if stop_repeat:
                break

        if repeat_mode:
            scope.values[instance_id] = collected
            values[instance_path] = collected
            ann(start, item_cursor, instance_path, str(instance_id), depth, "table", count=len(collected))
        elif item_cursor == start and size == 0:
            ann(start, start, instance_path, str(instance_id), depth, "instance")

    def process_instances(type_def: dict, scope: _KsyScope, depth: int, cursor: int) -> None:
        # scope.instance_specs is the authoritative lazy-instance set.  Normally
        # it is identical to type_def.instances; windowed auto-projection may
        # narrow only the root set to the address-space branch containing the
        # anchor that actually matched.
        instances = scope.instance_specs
        for instance_id, spec in instances.items():
            if not isinstance(spec, dict):
                raise KsyUnsupported(f"instance {instance_id!r} must be a mapping")
            if str(instance_id) in scope.values:
                continue
            # An instance that explicitly switches streams is often an alternate
            # interpretation rather than unconditional structure (ext2's
            # ``inode.as_dir`` is the canonical example).  Kaitai itself keeps
            # instances lazy; eagerly parsing every such view causes nonsense
            # interpretations of objects that nobody referenced.  Root instances
            # remain eager so instance-only address-space grammars still project.
            # Nested instances are lazy in Kaitai, including ones selecting the
            # root stream. Parse them only when an expression actually refers to
            # them; eagerly walking directory extents can recurse through `.`
            # indefinitely and invents views no caller requested.
            if scope.parent is not None:
                continue
            try:
                process_one_instance(str(instance_id), spec, scope, depth, cursor)
            except KsyError as exc:
                # Kaitai instances are lazy and may legally reference fields later
                # in a parent structure.  Preserve that semantics cheaply: defer
                # only unresolved-name failures, then replay them after root parse.
                if _deferable_instance_error(exc):
                    pending_instances.append((str(instance_id), spec, scope, depth, cursor))
                else:
                    raise

    def flush_pending_instances() -> None:
        while pending_instances:
            batch = list(pending_instances)
            pending_instances.clear()
            deferred: list[tuple[str, dict, _KsyScope, int, int, KsyError]] = []
            progress = 0
            for instance_id, spec, scope, depth, cursor in batch:
                if instance_id in scope.values:
                    progress += 1
                    continue
                try:
                    process_one_instance(instance_id, spec, scope, depth, cursor)
                    progress += 1
                except KsyError as exc:
                    if _deferable_instance_error(exc):
                        deferred.append((instance_id, spec, scope, depth, cursor, exc))
                    else:
                        raise
            # New pending work may have been discovered while successfully
            # parsing an out-of-line typed instance.  Keep it for the next pass.
            pending_instances.extend((a, b, c, d, e) for a, b, c, d, e, _ in deferred)
            if progress == 0 and deferred:
                raise deferred[0][5]

    def parse_type(
        type_def: dict,
        cursor: int,
        path: str,
        depth: int,
        parent_scope: _KsyScope | None,
        stream_start: int,
        stream_end: int,
        child_field_kind: str = "field",
        param_values: list[object] | None = None,
        source_doc: dict | None = None,
    ) -> tuple[int, _KsyScope]:
        if depth > 64:
            raise KsyUnsupported(f"nested KSY structure exceeds depth limit at {path}")
        seq = type_def.get("seq", [])
        if not isinstance(seq, list):
            raise KsyUnsupported(f"type {path} has no supported seq")
        effective_doc = source_doc or (parent_scope.doc if parent_scope is not None else doc)
        local_types = dict(effective_doc.get("__ksy_import_types__", {}))
        if isinstance(type_def.get("types"), dict):
            local_types.update(type_def.get("types", {}))
        local_enums = dict(effective_doc.get("enums", {}))
        if isinstance(type_def.get("enums"), dict):
            local_enums.update(type_def.get("enums", {}))
        scope = _KsyScope(
            path, parent_scope, stream_start, stream_end, effective_doc,
            local_types, local_enums
        )
        instance_specs = type_def.get("instances", {})
        if instance_specs and not isinstance(instance_specs, dict):
            raise KsyUnsupported(f"instances in {path} must be a mapping")
        scope.instance_specs = {
            str(name): spec for name, spec in (instance_specs.items() if isinstance(instance_specs, dict) else [])
            if isinstance(spec, dict)
        }
        if parent_scope is None and root_instance_filter is not None:
            # A windowed projection may intentionally select one address-space
            # instance (GPT.primary, ISO9660.primary_vol_desc, ...).  Constant
            # value instances remain available because position/size expressions
            # often depend on them.  This keeps unrelated far-away instances from
            # being hallucinated at the edge of a viewport whose _io is only a
            # slice of the real source.
            scope.instance_specs = {
                name: spec for name, spec in scope.instance_specs.items()
                if name in root_instance_filter or "value" in spec
            }
        scope.cursor = cursor

        def resolve_lazy_instance(name: str) -> None:
            if name in scope.values:
                return
            spec = scope.instance_specs.get(name)
            if spec is None:
                raise KsyError(f"unknown KSY instance {name!r} in {scope.path}")
            if name in scope.resolving_instances:
                raise KsyError(f"cyclic KSY instance dependency {scope.path}.{name}")
            scope.resolving_instances.add(name)
            try:
                process_one_instance(name, spec, scope, depth, scope.cursor)
            finally:
                scope.resolving_instances.discard(name)

        scope.lazy_resolver = resolve_lazy_instance
        if parent_scope is None:
            scope.root = scope
        params = type_def.get("params", [])
        if param_values is not None:
            if not isinstance(params, list) or len(params) != len(param_values):
                raise KsyError(f"parameter count mismatch for {path}")
            for param, value in zip(params, param_values):
                if not isinstance(param, dict) or not isinstance(param.get("id"), str):
                    raise KsyUnsupported(f"unsupported parameter declaration in {path}")
                scope.values[param["id"]] = value
                values[f"{path}.{param['id']}"] = value
        elif params:
            raise KsyError(f"type {path} requires parameters")
        endian = _ksy_endian(effective_doc, type_def if type_def is not effective_doc else None)
        bit_endian = type_def.get("bit-endian", effective_doc.get("meta", {}).get("bit-endian", "be"))
        if bit_endian not in {"be", "le"}:
            raise KsyUnsupported(f"unsupported bit-endian {bit_endian!r}")

        field_index = 0
        while field_index < len(seq):
            field = seq[field_index]
            scope.cursor = cursor
            if not isinstance(field, dict) or not isinstance(field.get("id"), str):
                raise KsyUnsupported("every supported seq item needs an id")

            # Kaitai keeps a bit cursor across adjacent bit fields, then aligns
            # back to the next byte when ordinary byte fields resume.  Handling
            # contiguous runs here covers pure flag structures and mixed forms
            # such as FAT32's u4 + b1/b3/b4 + byte fields.
            first_width = _bit_type_width(field.get("type"))
            if first_width is not None:
                run: list[tuple[dict, int]] = []
                j = field_index
                while j < len(seq):
                    candidate = seq[j]
                    if not isinstance(candidate, dict):
                        break
                    width = _bit_type_width(candidate.get("type"))
                    if width is None:
                        break
                    if candidate.get("repeat") is not None or candidate.get("if") is not None:
                        raise KsyUnsupported(f"conditional/repeated bit fields are not supported yet in {path}")
                    if not isinstance(candidate.get("id"), str):
                        raise KsyUnsupported("every supported bit field needs an id")
                    run.append((candidate, width))
                    j += 1
                total_bits = sum(width for _, width in run)
                byte_count = (total_bits + 7) // 8
                if cursor + byte_count > stream_end:
                    raise KsyError(f"truncated bit-field run in {path}")
                bit_pos = 0
                for bit_field, width in run:
                    value = 0
                    for k in range(width):
                        absolute_bit = bit_pos + k
                        byte_value = data[cursor + absolute_bit // 8]
                        within = absolute_bit % 8
                        bit = (byte_value >> (7 - within if bit_endian == "be" else within)) & 1
                        if bit_endian == "be":
                            value = (value << 1) | bit
                        else:
                            value |= bit << k
                    field_id = bit_field["id"]
                    field_path = f"{path}.{field_id}"
                    start_byte = cursor + bit_pos // 8
                    end_byte = cursor + (bit_pos + width + 7) // 8
                    ann(start_byte, end_byte, field_path, field_id, depth, "bitfield", value=value, bits=width)
                    validate_field(bit_field, value, scope, end_byte, field_path, start_byte, end_byte)
                    scope.values[field_id] = value
                    values[field_path] = value
                    bit_pos += width
                cursor += byte_count
                scope.cursor = cursor
                field_index = j
                continue

            if field.get("if") is not None and not bool(_ksy_eval(field["if"], scope, cursor)):
                field_index += 1
                continue
            field_id = field["id"]
            field_path = f"{path}.{field_id}"
            repeat = field.get("repeat")
            if repeat is None:
                count = 1
                repeat_mode = None
            elif repeat == "expr":
                count = _ksy_int(field.get("repeat-expr"), scope, cursor)
                repeat_mode = "expr"
            elif repeat == "eos":
                count = None
                repeat_mode = "eos"
            elif repeat == "until":
                count = None
                repeat_mode = "until"
                if field.get("repeat-until") is None:
                    raise KsyUnsupported(f"repeat-until missing on {field_path}")
            else:
                raise KsyUnsupported(f"unsupported repeat mode on {field_path}: {repeat!r}")

            field_start = cursor
            collected = []
            index = 0
            while count is None or index < count:
                if count is None and cursor >= stream_end:
                    break
                item_path = f"{field_path}[{index}]" if repeat_mode else field_path
                item_label = f"{field_id}[{index}]" if repeat_mode else field_id
                before = cursor
                value, cursor = parse_field_value(
                    field,
                    cursor,
                    scope,
                    item_path,
                    item_label,
                    depth + (1 if repeat_mode else 0),
                    "record" if repeat_mode else child_field_kind,
                    stream_end,
                    endian,
                    repeat_index=index if repeat_mode else None,
                )
                scope.cursor = cursor
                if repeat_mode:
                    collected.append(value)
                else:
                    scope.values[field_id] = value
                    values[field_path] = value
                if repeat_mode in {"eos", "until"} and cursor <= before:
                    raise KsyError(f"repeated field {item_path} made no progress")
                stop_repeat = False
                if repeat_mode == "until":
                    stop_repeat = bool(_ksy_eval(
                        field["repeat-until"], scope, cursor, index=index, current=value
                    ))
                index += 1
                if stop_repeat:
                    break

            if repeat_mode:
                scope.values[field_id] = collected
                values[field_path] = collected
                ann(field_start, cursor, field_path, field_id, depth, "table", count=len(collected))
            field_index += 1

        process_instances(type_def, scope, depth, cursor)
        scope.cursor = cursor
        return cursor, scope

    def parse_field_value(
        field: dict,
        cursor: int,
        scope: _KsyScope,
        path: str,
        label: str,
        depth: int,
        semantic_kind: str,
        limit_end: int,
        default_endian: str | None,
        repeat_index: int | None = None,
        force_size: int | None = None,
    ) -> tuple[object, int]:
        if cursor < 0 or cursor > limit_end or limit_end > len(data):
            raise KsyError(f"field {path} outside supplied data")
        endian = default_endian or _ksy_endian(scope.doc or doc)

        if "contents" in field:
            expected = _contents_bytes(field["contents"])
            if expected is None:
                raise KsyUnsupported(f"unsupported contents form on {path}")
            end = cursor + len(expected)
            if end > limit_end:
                raise KsyError(f"truncated field {path}")
            actual = data[cursor:end]
            matches = actual == expected
            ann(cursor, end, path, label, depth, semantic_kind,
                expected_hex=expected.hex(), actual_hex=actual.hex(), matches_contents=matches)
            constraints.append({
                "kind": "contents",
                "path": path,
                "start": base_offset + cursor,
                "end": base_offset + end,
                "passed": matches,
                "expected_hex": expected.hex(),
                "actual_hex": actual.hex(),
            })
            values[path] = actual
            return actual, end

        type_name = field.get("type")
        if isinstance(type_name, dict) and "switch-on" in type_name:
            switch_value = _ksy_eval(type_name["switch-on"], scope, cursor, index=repeat_index)
            cases = type_name.get("cases", {})
            if not isinstance(cases, dict):
                raise KsyUnsupported(f"switch cases on {path} must be a mapping")
            chosen = None
            default_case = None
            for case_key, case_type in cases.items():
                if str(case_key).strip() == "_":
                    default_case = case_type
                    continue
                if switch_value == _ksy_case_value(case_key, doc, scope.enums):
                    chosen = case_type
                    break
            type_name = chosen if chosen is not None else default_case
        primitive = _primitive_type_size(type_name) if isinstance(type_name, str) else None
        float_width = _float_type_size(type_name) if isinstance(type_name, str) else None
        size = force_size if force_size is not None else field_size(field, scope, cursor, repeat_index)

        if primitive is not None:
            width, signed = primitive
            if size is not None and size != width:
                raise KsyUnsupported(f"primitive {path} cannot be constrained to size {size}")
            end = cursor + width
            if end > limit_end:
                raise KsyError(f"truncated field {path}")
            byteorder = _primitive_byteorder(type_name, endian)
            value = int.from_bytes(data[cursor:end], byteorder, signed=signed)
            ann(cursor, end, path, label, depth, semantic_kind, value=value)
            validate_field(field, value, scope, end, path, cursor, end, repeat_index)
            values[path] = value
            return value, end

        if float_width is not None:
            if size is not None and size != float_width:
                raise KsyUnsupported(f"float {path} cannot be constrained to size {size}")
            end = cursor + float_width
            if end > limit_end:
                raise KsyError(f"truncated field {path}")
            byteorder = _primitive_byteorder(type_name, endian)
            fmt = ("<" if byteorder == "little" else ">") + ("f" if float_width == 4 else "d")
            value = struct.unpack(fmt, data[cursor:end])[0]
            ann(cursor, end, path, label, depth, semantic_kind, value=value)
            validate_field(field, value, scope, end, path, cursor, end, repeat_index)
            values[path] = value
            return value, end

        if type_name in {"str", "strz"}:
            terminator = field.get("terminator")
            if type_name == "strz" and terminator is None:
                terminator = 0
            if size is None:
                if terminator is None:
                    raise KsyUnsupported(f"string {path} needs size/size-eos/terminator")
                try:
                    term_at = data.index(int(terminator), cursor, limit_end)
                except ValueError as exc:
                    raise KsyError(f"unterminated string {path}") from exc
                end = term_at + 1
            else:
                end = cursor + size
            if end > limit_end:
                raise KsyError(f"truncated string {path}")
            raw = data[cursor:end]
            value = _decode_ksy_string(raw, str(field.get("encoding") or meta.get("encoding") or "UTF-8"), terminator, field.get("pad-right"))
            ann(cursor, end, path, label, depth, semantic_kind, value=value)
            validate_field(field, value, scope, end, path, cursor, end, repeat_index)
            values[path] = value
            return value, end

        if type_name is None and size is None and field.get("terminator") is not None:
            term = int(field["terminator"])
            try:
                term_at = data.index(term, cursor, limit_end)
            except ValueError as exc:
                raise KsyError(f"unterminated byte field {path}") from exc
            end = term_at + 1
            value = data[cursor:term_at]
            ann(cursor, end, path, label, depth, semantic_kind, terminator=term)
            validate_field(field, value, scope, end, path, cursor, end, repeat_index)
            values[path] = value
            return value, end

        type_args = None
        nested_type_name = type_name
        if isinstance(type_name, str):
            match = re.fullmatch(r"([A-Za-z_]\w*)\((.*)\)", type_name.strip())
            if match:
                nested_type_name = match.group(1)
                arg_text = match.group(2).strip()
                arg_exprs = [] if not arg_text else _split_inline(arg_text)
                type_args = [_ksy_eval(arg, scope, cursor, index=repeat_index) for arg in arg_exprs]

        if isinstance(nested_type_name, str) and nested_type_name in scope.types:
            nested = scope.types[nested_type_name]
            if not isinstance(nested, dict):
                raise KsyUnsupported(f"type {nested_type_name!r} is not a mapping")
            nested_doc = nested.get("__ksy_doc__") if isinstance(nested.get("__ksy_doc__"), dict) else scope.doc
            child_end_limit = limit_end if size is None else cursor + size
            if child_end_limit > limit_end:
                raise KsyError(f"bounded type {path} exceeds parent stream")
            child_end, child_scope = parse_type(
                nested,
                cursor,
                path,
                depth + 1,
                scope,
                cursor if size is not None else scope.stream_start,
                child_end_limit if size is not None else scope.stream_end,
                "subfield",
                param_values=type_args,
                source_doc=nested_doc,
            )
            visible_end = child_end_limit if size is not None else child_end
            ann(cursor, visible_end, path, label, depth, semantic_kind, type=nested_type_name)
            child_value = _KsyStruct(
                child_scope.values, child_scope.stream_start, child_scope.stream_end, child_scope
            )
            values[path] = child_value
            return child_value, visible_end

        if size is not None:
            end = cursor + size
            if end > limit_end:
                raise KsyError(f"truncated field {path}")
            value = data[cursor:end]
            ann(cursor, end, path, label, depth, "payload" if semantic_kind == "instance" else semantic_kind)
            validate_field(field, value, scope, end, path, cursor, end, repeat_index)
            values[path] = value
            return value, end

        raise KsyUnsupported(f"unsupported field form on {path}: {field!r}")

    root_def = dict(doc)
    root_def.setdefault("seq", doc.get("seq", []))
    try:
        seq_end, root_scope = parse_type(root_def, offset, root, 1, None, offset, len(data))
        flush_pending_instances()
    except (KsyError, KsyUnsupported) as exc:
        if not partial or not annotations:
            raise
        # Preserve proven prefix geometry when a later field is truncated or
        # uses vocabulary this deliberately small projector cannot yet consume.
        issues.append(str(exc))
        seq_end = max(
            offset,
            max((row["end"] - base_offset for row in annotations), default=offset),
        )
    max_end = seq_end
    if annotations:
        max_end = max(max_end, max(row["end"] - base_offset for row in annotations))
    annotations.insert(0, {
        "start": base_offset + offset,
        "end": base_offset + max_end,
        "path": root,
        "label": str(meta.get("title") or meta.get("id") or root),
        "depth": 0,
        "kind": "container",
    })
    return {
        "root": root,
        "start": base_offset + offset,
        "end": base_offset + max_end,
        "extent": max_end - offset,
        "annotations": annotations,
        "values": values,
        "constraints": constraints,
        "partial": bool(issues),
        "issues": issues,
    }



def project_ksy(data: bytes, relative: str, base_offset: int = 0) -> dict:
    """Project one explicitly named corpus definition at the start of *data*.

    This does not promote an object-identity claim.  It is the generic bridge
    used to prove that new KSY vocabulary can produce byte geometry without a
    format-specific parser in Clarity.
    """
    loaded = load_ksy(relative)
    if loaded is None:
        raise KsyError(f"KSY definition not found: {relative}")
    doc, path = loaded
    parsed = parse_ksy_structure(data, doc, offset=0, base_offset=base_offset)
    parsed["ksy"] = relative
    parsed["ksy_id"] = doc.get("meta", {}).get("id")
    parsed["definition_path"] = str(path)
    return parsed


def ksy_projection_for_json(projection: dict) -> dict:
    # Keep machine output bounded: raw payload bytes and duplicated nested
    # dictionaries stay in the in-process projection, while JSON exposes
    # scalar field values plus all byte geometry/constraints.
    out = {
        key: value for key, value in projection.items()
        if key not in {"values", "definition_path"}
    }
    out["values"] = {
        key: value for key, value in projection.get("values", {}).items()
        if isinstance(value, (int, float, str, bool)) or value is None
    }
    return out


def _print_ksy_projection(projection: dict) -> None:
    constraints = projection.get("constraints", [])
    passed = sum(bool(row.get("passed")) for row in constraints)
    print(f"KSY structure: {projection.get('ksy_id') or projection.get('root')} ({projection.get('ksy')})")
    print(
        f"  projected extent: 0x{projection['start']:x}..0x{projection['end']:x} "
        f"({projection['extent']} bytes)"
    )
    print(f"  structural annotations: {len(projection.get('annotations', []))}")
    if constraints:
        print(f"  literal constraints: {passed}/{len(constraints)} passed")
    print()



def _auto_const_eval(expr, env: dict[str, int]) -> int | None:
    """Evaluate the tiny constant-expression subset needed for static KSY anchors."""
    if isinstance(expr, int) and not isinstance(expr, bool):
        return expr
    if not isinstance(expr, str) or not expr.strip():
        return None
    try:
        node = ast.parse(expr.strip(), mode="eval").body
    except SyntaxError:
        return None

    def ev(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, int) and not isinstance(n.value, bool):
            return n.value
        if isinstance(n, ast.Name):
            return env.get(n.id)
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "_root":
            return env.get(n.attr)
        if isinstance(n, ast.UnaryOp):
            value = ev(n.operand)
            if value is None:
                return None
            if isinstance(n.op, ast.UAdd):
                return +value
            if isinstance(n.op, ast.USub):
                return -value
            if isinstance(n.op, ast.Invert):
                return ~value
            return None
        if isinstance(n, ast.BinOp) and type(n.op) in _BIN_OPS:
            left = ev(n.left)
            right = ev(n.right)
            if left is None or right is None:
                return None
            try:
                value = _BIN_OPS[type(n.op)](left, right)
            except (ArithmeticError, TypeError, ValueError):
                return None
            return value if isinstance(value, int) and not isinstance(value, bool) else None
        return None

    value = ev(node)
    return value if isinstance(value, int) and value >= 0 else None


def _auto_root_constants(doc: dict) -> dict[str, int]:
    """Resolve root value-instances that are pure integer constants."""
    specs = doc.get("instances", {})
    if not isinstance(specs, dict):
        return {}
    env: dict[str, int] = {}
    pending = {
        str(name): spec.get("value")
        for name, spec in specs.items()
        if isinstance(spec, dict) and "value" in spec
    }
    for _ in range(len(pending) + 1):
        progress = False
        for name, expr in list(pending.items()):
            value = _auto_const_eval(expr, env)
            if value is not None:
                env[name] = value
                del pending[name]
                progress = True
        if not progress:
            break
    return env


def _auto_type_name(value) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    match = re.fullmatch(r"([A-Za-z_]\w*)\(.*\)", text)
    return match.group(1) if match else text


def _auto_seq_anchors(
    doc: dict,
    seq: list,
    base: int,
    types: dict,
    constants: dict[str, int],
    stack: tuple[str, ...] = (),
) -> tuple[list[tuple[int, bytes]], int | None]:
    """Return statically positioned literal byte anchors and, when known, size.

    This deliberately stops at the first layout ambiguity.  It is not another
    parser; it only discovers literals whose offset from an object root follows
    mechanically from fixed-width KSY structure.
    """
    anchors: list[tuple[int, bytes]] = []
    cursor = base
    i = 0
    while i < len(seq):
        field = seq[i]
        if not isinstance(field, dict):
            return anchors, None
        if field.get("if") is not None:
            return anchors, None

        repeat = field.get("repeat")
        if repeat is None:
            count = 1
            repeat_fixed = True
        elif repeat == "expr":
            raw_count = field.get("repeat-expr")
            count = _auto_const_eval(raw_count, constants)
            repeat_fixed = count is not None
            if count is None:
                count = 1  # first record can still provide an anchor at cursor
        else:
            count = 1
            repeat_fixed = False

        one_anchors: list[tuple[int, bytes]] = []
        one_size: int | None = None
        if "contents" in field:
            expected = _contents_bytes(field["contents"])
            if expected is not None:
                one_anchors.append((cursor, expected))
                one_size = len(expected)
        else:
            size = field.get("size")
            static_size = _auto_const_eval(size, constants) if size is not None else None
            type_name = _auto_type_name(field.get("type"))
            primitive = _primitive_type_size(type_name) if type_name else None
            float_width = _float_type_size(type_name) if type_name else None
            if static_size is not None:
                one_size = static_size
            elif primitive is not None:
                one_size = primitive[0]
            elif float_width is not None:
                one_size = float_width
            elif type_name in {"str", "strz"}:
                one_size = None
            elif type_name and type_name in types and type_name not in stack:
                type_def = types[type_name]
                if isinstance(type_def, dict) and isinstance(type_def.get("seq", []), list):
                    local_types = dict(types)
                    nested_doc = type_def.get("__ksy_doc__")
                    if isinstance(nested_doc, dict):
                        local_types.update(nested_doc.get("__ksy_import_types__", {}))
                        local_types.update(nested_doc.get("types", {}))
                    if isinstance(type_def.get("types"), dict):
                        local_types.update(type_def["types"])
                    nested_anchors, nested_size = _auto_seq_anchors(
                        nested_doc if isinstance(nested_doc, dict) else doc,
                        type_def.get("seq", []),
                        cursor,
                        local_types,
                        constants,
                        stack + (type_name,),
                    )
                    one_anchors.extend(nested_anchors)
                    if one_size is None:
                        one_size = nested_size

        anchors.extend(one_anchors)
        if one_size is None or not repeat_fixed:
            return anchors, None
        cursor += one_size * count
        i += 1
    return anchors, cursor - base


def _auto_anchor_is_discriminating(magic: bytes) -> bool:
    """Return whether a literal is useful for automatic object nomination.

    Kaitai ``contents`` is a parse constraint, not necessarily a file magic.
    Real definitions use it for long runs of reserved zeroes, 0xff padding, and
    spaces just as readily as for signatures.  Treating every such literal as a
    discovery anchor makes blank media look richly structured, which is exactly
    backwards for Clarity.

    Generic auto-discovery rejects filler-dominated literals. Short signatures
    may nominate only at their exact statically derived position; the subsequent
    parse and contradiction checks decide whether identity is justified.
    """
    if not isinstance(magic, bytes) or len(magic) < AUTO_KSY_MIN_ANCHOR:
        return False
    if len(set(magic)) < 2:
        return False
    # NUL, erased-flash 0xff, and ASCII padding spaces are structural filler,
    # not identity.  A literal dominated by any one of them is too cheap to
    # nominate an object from an arbitrary viewport.
    filler_peak = max(magic.count(0x00), magic.count(0xff), magic.count(0x20))
    if filler_peak * 4 >= len(magic) * 3:
        return False
    return True


def _auto_ksy_anchors(doc: dict) -> list[dict]:
    constants = _auto_root_constants(doc)
    types = dict(doc.get("__ksy_import_types__", {}))
    if isinstance(doc.get("types"), dict):
        types.update(doc["types"])
    out: list[dict] = []

    root_anchors, _ = _auto_seq_anchors(doc, doc.get("seq", []), 0, types, constants)
    for offset, magic in root_anchors:
        out.append({"offset": offset, "bytes": magic, "root_instance": None})

    instances = doc.get("instances", {})
    if isinstance(instances, dict):
        for name, spec in instances.items():
            if not isinstance(spec, dict) or "value" in spec or "pos" not in spec:
                continue
            pos = _auto_const_eval(spec.get("pos"), constants)
            if pos is None:
                continue
            type_name = _auto_type_name(spec.get("type"))
            if not type_name or type_name not in types:
                continue
            type_def = types[type_name]
            if not isinstance(type_def, dict):
                continue
            local_types = dict(types)
            nested_doc = type_def.get("__ksy_doc__")
            if isinstance(nested_doc, dict):
                local_types.update(nested_doc.get("__ksy_import_types__", {}))
                local_types.update(nested_doc.get("types", {}))
            if isinstance(type_def.get("types"), dict):
                local_types.update(type_def["types"])
            anchors, _ = _auto_seq_anchors(
                nested_doc if isinstance(nested_doc, dict) else doc,
                type_def.get("seq", []),
                pos,
                local_types,
                constants,
                (type_name,),
            )
            for offset, magic in anchors:
                out.append({"offset": offset, "bytes": magic, "root_instance": str(name)})

    # Prefer the longest, most discriminating literal at each structural branch.
    best: dict[tuple[int, str | None], dict] = {}
    for row in out:
        magic = row["bytes"]
        if not _auto_anchor_is_discriminating(magic):
            continue
        key = (int(row["offset"]), row.get("root_instance"))
        old = best.get(key)
        if old is None or len(magic) > len(old["bytes"]):
            best[key] = row
    return sorted(best.values(), key=lambda row: (-len(row["bytes"]), int(row["offset"])))


def _iter_ksy_relatives() -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for root in _ksy_roots():
        if not root.is_dir():
            continue
        try:
            paths = root.rglob("*.ksy")
            for path in paths:
                try:
                    relative = path.relative_to(root).as_posix()
                except ValueError:
                    continue
                if relative not in seen:
                    seen.add(relative)
                    out.append(relative)
        except OSError:
            continue
    return sorted(out)


def auto_ksy_views(
    data: bytes,
    base_offset: int = 0,
    limit: int = MAX_AUTO_KSY_VIEWS,
) -> list[dict]:
    """Discover KSY structures from strong, statically positioned literals.

    A definition joins this search without a Clarity code branch: if its corpus
    file contains a sufficiently discriminating literal at a mechanically
    derivable root-relative offset, that literal can nominate a candidate root.  The full supported KSY
    projector must still parse the candidate before any structural view is emitted.
    Filler-like literals are excluded. Short literals are position-bound and
    require additional parsed structure rather than becoming identity by magic.
    """
    if not data or limit <= 0:
        return []
    out: list[dict] = []
    seen_candidates: set[tuple[str, int, str | None]] = set()

    for relative in _iter_ksy_relatives():
        if len(out) >= limit:
            break
        # MBR has deliberately stricter coherence checks below; its ubiquitous
        # 55 aa trailer is also present on FAT boot sectors and must not enter
        # the generic literal-only identity path.
        if relative == MBR_KSY_RELATIVE:
            continue
        path = resolve_ksy_path(relative)
        if path is None:
            continue
        try:
            # Cheaply avoid parsing the large portion of the corpus that has no
            # defining literal at all.
            if "contents:" not in path.read_text(encoding="utf-8"):
                continue
            loaded = load_ksy(relative)
        except Exception:
            # The KSY corpus is external vocabulary.  One definition that uses
            # syntax we do not yet understand (or trips an expression edge case)
            # must be an abstention for that definition, never a process-wide
            # analyzer failure.  Explicit --ksy remains strict and reports errors.
            continue
        if loaded is None:
            continue
        doc, _ = loaded
        try:
            anchors = _auto_ksy_anchors(doc)
        except Exception:
            # Auto-discovery is opportunistic over a heterogeneous corpus.
            continue
        if not anchors:
            continue
        ksy_id = str(doc.get("meta", {}).get("id") or Path(relative).stem)
        title = str(doc.get("meta", {}).get("title") or ksy_id)

        # Two independent static anchors are plenty for nomination; searching
        # every tiny literal in a definition only burns time and raises the
        # accidental-hit surface.
        for anchor in anchors[:2]:
            magic = anchor["bytes"]
            anchor_offset = int(anchor["offset"])
            search_from = 0
            matches = 0
            while len(out) < limit:
                # Two- and four-byte signatures may nominate an object only at
                # their statically expected position.  Do not hunt arbitrary
                # payloads for cheap short-magic coincidences.
                if len(magic) < 5:
                    # Common short clues are local corroborators: they can
                    # nominate the supplied root, but are never scanned across
                    # arbitrary payload bytes.
                    match = anchor_offset if data[anchor_offset:anchor_offset + len(magic)] == magic else -1
                else:
                    # A distinctive global clue implies a candidate root in the
                    # clue's own coordinate system, not at absolute offset zero.
                    match = data.find(magic, search_from)
                if match < 0:
                    break
                search_from = match + 1
                matches += 1
                if matches > 8:
                    break
                root_local = match - anchor_offset
                if root_local < 0 or root_local >= len(data):
                    continue
                root_instance = anchor.get("root_instance")
                key = (relative, root_local, root_instance)
                if key in seen_candidates:
                    continue
                seen_candidates.add(key)
                try:
                    parsed = parse_ksy_structure(
                        data,
                        doc,
                        offset=root_local,
                        base_offset=base_offset,
                        root_path=ksy_id,
                        root_instance_filter={root_instance} if root_instance else None,
                        partial=True,
                    )
                except Exception:
                    # A literal hit only nominates a candidate.  If this KSY's
                    # remaining grammar cannot be evaluated safely on the bytes,
                    # reject that candidate and keep scanning other definitions.
                    continue

                annotations = list(parsed.get("annotations", []))
                constraints = list(parsed.get("constraints", []))
                if root_instance:
                    prefix = f"{ksy_id}.{root_instance}"
                    body = [row for row in annotations if str(row.get("path", "")).startswith(prefix)]
                    constraints = [row for row in constraints if str(row.get("path", "")).startswith(prefix)]
                    if not body:
                        continue
                    absolute_start = base_offset + root_local
                    absolute_end = max(int(row.get("end", absolute_start)) for row in body)
                    annotations = [{
                        "start": absolute_start,
                        "end": absolute_end,
                        "path": ksy_id,
                        "label": title,
                        "depth": 0,
                        "kind": "container",
                    }] + body
                if len(annotations) < 2:
                    continue

                absolute_start = base_offset + root_local
                absolute_end = max(int(row.get("end", absolute_start)) for row in annotations)
                failed = [row for row in constraints if not bool(row.get("passed"))]
                passed = len(constraints) - len(failed)
                field_rows = [row for row in annotations if int(row.get("depth", 0)) > 0]
                strong = not failed and len(field_rows) >= 3 and root_local == 0
                out.append({
                    "kind": "ksy_structure",
                    "ksy_id": ksy_id,
                    "offset": absolute_start,
                    "local_offset": root_local,
                    "extent": max(0, absolute_end - absolute_start),
                    "shape_source": "kaitai/" + relative,
                    "anchor_offset": anchor_offset,
                    "anchor_hex": magic.hex(),
                    "anchor_bytes": len(magic),
                    "checks_passed": passed,
                    "checks_total": len(constraints),
                    "hard_contradictions": [str(row.get("path", "constraint")) for row in failed],
                    "strong_identity": strong,
                    "partial": bool(parsed.get("partial")),
                    "issues": list(parsed.get("issues", [])),
                    "annotations": annotations,
                    "constraints": constraints,
                })
                # Keep looking: one source range can contain several objects of
                # the same format. seen_candidates merges secondary clues that
                # imply an already-investigated (format, root) hypothesis.
    return out

def _mbr_ksy() -> tuple[dict, Path] | None:
    return load_ksy(MBR_KSY_RELATIVE)


def _mbr_value(parsed: dict, path: str) -> int:
    value = parsed["values"].get(path)
    if not isinstance(value, int):
        raise KsyError(f"MBR KSY did not produce integer field {path}")
    return value


def _mbr_entries_from_ksy(parsed: dict) -> list[dict]:
    entries = []
    for index in range(4):
        base = f"mbr.partitions[{index}]"
        status = _mbr_value(parsed, base + ".status")
        partition_type = _mbr_value(parsed, base + ".partition_type")
        lba_start = _mbr_value(parsed, base + ".lba_start")
        num_sectors = _mbr_value(parsed, base + ".num_sectors")
        empty = partition_type == 0
        coherent = (
            status in (0x00, 0x80)
            and (
                (empty and lba_start == 0 and num_sectors == 0)
                or (not empty and lba_start > 0 and num_sectors > 0)
            )
        )
        entries.append({
            "index": index,
            "status": status,
            "partition_type": partition_type,
            "lba_start": lba_start,
            "num_sectors": num_sectors,
            "empty": empty,
            "coherent": coherent,
        })
    return entries


def mbr_view_at(data: bytes, offset: int, base_offset: int = 0) -> dict | None:
    """Test an MBR hypothesis whose byte geometry comes from the external KSY.

    Kaitai supplies shape; Clarity supplies conservative evidence/contradiction
    rules and is willing to retain a useful partial view after a defining literal
    is damaged.
    """
    loaded = _mbr_ksy()
    if loaded is None:
        return None
    doc, _path = loaded
    extent = ksy_static_size(doc)
    if extent is None:
        raise KsyUnsupported("MBR KSY no longer has a statically derivable extent")
    if offset < 0 or offset + extent > len(data):
        return None
    try:
        parsed = parse_ksy_structure(data, doc, offset=offset, base_offset=base_offset, root_path="mbr")
        entries = _mbr_entries_from_ksy(parsed)
    except (KsyError, KsyUnsupported):
        return None

    signature_constraint = next(
        (row for row in parsed["constraints"] if row["path"] == "mbr.boot_signature"),
        None,
    )
    signature = bool(signature_constraint and signature_constraint["passed"])
    valid_statuses = sum(entry["status"] in (0x00, 0x80) for entry in entries)
    coherent_entries = sum(entry["coherent"] for entry in entries)
    nonempty_entries = sum(not entry["empty"] for entry in entries)

    passed = int(signature) + valid_statuses + coherent_entries + int(nonempty_entries > 0)
    total = 10
    hard_contradictions = []
    if not signature:
        hard_contradictions.append("boot signature 55 aa absent")
    for entry in entries:
        if entry["status"] not in (0x00, 0x80):
            hard_contradictions.append(f"partition[{entry['index']}].status is 0x{entry['status']:02x}")
        elif not entry["coherent"]:
            hard_contradictions.append(f"partition[{entry['index']}] type/LBA/size relationship is incoherent")
    if nonempty_entries == 0:
        hard_contradictions.append("no non-empty partition entries")

    if passed < 8 or nonempty_entries == 0:
        return None

    absolute = base_offset + offset
    return {
        "kind": "mbr_partition_table",
        "offset": absolute,
        "local_offset": offset,
        "extent": parsed["extent"],
        "shape_source": MBR_SHAPE_SOURCE,
        "ksy_id": doc.get("meta", {}).get("id"),
        "checks_passed": passed,
        "checks_total": total,
        "signature_55aa": signature,
        "valid_statuses": valid_statuses,
        "coherent_entries": coherent_entries,
        "nonempty_entries": nonempty_entries,
        "hard_contradictions": hard_contradictions,
        "strong_identity": (
            signature
            and valid_statuses == 4
            and coherent_entries == 4
            and nonempty_entries > 0
        ),
        "partitions": entries,
        "annotations": parsed["annotations"],
        "constraints": parsed["constraints"],
    }


def mbr_views(
    data: bytes,
    base_offset: int = 0,
    limit: int = MAX_MBR_VIEWS,
    *,
    windowed: bool = False,
) -> list[dict]:
    """Find MBR structure, with stricter location semantics for source windows.

    A free-standing blob may legitimately contain an embedded sector image, so
    historical whole-blob analysis still scans sector boundaries.  A FatPix
    viewport is different: its base offset is authoritative source geometry.
    Calling an arbitrary 512-byte-aligned sector at 0x99c... an MBR merely because
    it resembles one is exactly the sort of context error Clarity should reject.
    In windowed mode, automatic MBR interpretation is therefore confined to
    absolute source offset zero.
    """
    loaded = _mbr_ksy()
    if loaded is None:
        return []
    extent = ksy_static_size(loaded[0])
    if not extent:
        return []
    if windowed:
        off = -base_offset
        if off < 0 or off + extent > len(data):
            return []
        view = mbr_view_at(data, off, base_offset)
        return [view] if view is not None and limit > 0 else []

    out = []
    first = (-base_offset) % extent
    stop = len(data) - extent
    for off in range(first, stop + 1, extent):
        # The missing-signature partial case is meaningful at a caller-proposed
        # root, not at every sector of a large arbitrary source. Avoid parsing
        # hundreds of obviously ineligible sectors through the full KSY.
        if off != first and data[off + 510:off + 512] != b"\x55\xaa":
            continue
        view = mbr_view_at(data, off, base_offset)
        if view is not None:
            out.append(view)
            if len(out) >= limit:
                break
    return out

def mbr_identity_claim_from_view(view: dict) -> dict | None:
    # Structural views are heterogeneous now: generic KSY discoveries share the
    # same list with MBR views.  Identity helpers must therefore be total over
    # that list instead of assuming every view has MBR-only bookkeeping fields.
    if view.get("kind") != "mbr_partition_table":
        return None
    if not view.get("strong_identity"):
        return None
    return {
        "kind": "mbr_partition_table",
        "offset": view["offset"],
        "extent": view["extent"],
        "shape_source": view["shape_source"],
        "checks_passed": view["checks_passed"],
        "checks_total": view["checks_total"],
        "nonempty_entries": view["nonempty_entries"],
        "partitions": view["partitions"],
    }


def mbr_identity_claims(data: bytes, base_offset: int = 0, limit: int = MAX_IDENTITY_CLAIMS) -> list[dict]:
    claims = []
    for view in mbr_views(data, base_offset, limit=limit):
        claim = mbr_identity_claim_from_view(view)
        if claim is not None:
            claims.append(claim)
    return claims


def validate_elf_at(data: bytes, offset: int) -> dict | None:
    """Validate enough ELF structure to make an identity claim, not just a magic hit."""
    remaining = len(data) - offset
    if remaining < 52 or data[offset:offset + 4] != b"\x7fELF":
        return None
    elf_class = data[offset + 4]
    encoding = data[offset + 5]
    ident_version = data[offset + 6]
    if elf_class not in (1, 2) or encoding not in (1, 2) or ident_version != 1:
        return None
    byteorder = "little" if encoding == 1 else "big"

    if elf_class == 1:
        ehsize_expected, phentsize_expected, shentsize_expected = 52, 32, 40
        if remaining < ehsize_expected:
            return None
        e_type = _uint(data, offset + 16, 2, byteorder)
        e_machine = _uint(data, offset + 18, 2, byteorder)
        e_version = _uint(data, offset + 20, 4, byteorder)
        e_phoff = _uint(data, offset + 28, 4, byteorder)
        e_shoff = _uint(data, offset + 32, 4, byteorder)
        e_ehsize = _uint(data, offset + 40, 2, byteorder)
        e_phentsize = _uint(data, offset + 42, 2, byteorder)
        e_phnum = _uint(data, offset + 44, 2, byteorder)
        e_shentsize = _uint(data, offset + 46, 2, byteorder)
        e_shnum = _uint(data, offset + 48, 2, byteorder)
    else:
        ehsize_expected, phentsize_expected, shentsize_expected = 64, 56, 64
        if remaining < ehsize_expected:
            return None
        e_type = _uint(data, offset + 16, 2, byteorder)
        e_machine = _uint(data, offset + 18, 2, byteorder)
        e_version = _uint(data, offset + 20, 4, byteorder)
        e_phoff = _uint(data, offset + 32, 8, byteorder)
        e_shoff = _uint(data, offset + 40, 8, byteorder)
        e_ehsize = _uint(data, offset + 52, 2, byteorder)
        e_phentsize = _uint(data, offset + 54, 2, byteorder)
        e_phnum = _uint(data, offset + 56, 2, byteorder)
        e_shentsize = _uint(data, offset + 58, 2, byteorder)
        e_shnum = _uint(data, offset + 60, 2, byteorder)

    if e_version != 1 or e_ehsize != ehsize_expected:
        return None
    if e_type not in (0, 1, 2, 3, 4) or e_machine == 0:
        return None
    # Extended-count ELF variants deliberately abstain for now rather than being
    # half-parsed and promoted to identity claims.
    if e_phnum == 0xffff:
        return None
    if e_phnum:
        if e_phentsize != phentsize_expected or e_phoff < ehsize_expected:
            return None
        ph_end = e_phoff + e_phentsize * e_phnum
        if ph_end > remaining:
            return None
    else:
        ph_end = ehsize_expected
    if e_shnum:
        if e_shentsize != shentsize_expected or e_shoff < ehsize_expected:
            return None
        sh_end = e_shoff + e_shentsize * e_shnum
        if sh_end > remaining:
            return None
    else:
        sh_end = ehsize_expected

    referenced_end = max(ehsize_expected, ph_end, sh_end)

    # Program headers: include every file-backed segment's end in the minimum
    # extent and reject references that escape the supplied byte stream.
    for i in range(e_phnum):
        pos = offset + e_phoff + i * e_phentsize
        if elf_class == 1:
            p_offset = _uint(data, pos + 4, 4, byteorder)
            p_filesz = _uint(data, pos + 16, 4, byteorder)
        else:
            p_offset = _uint(data, pos + 8, 8, byteorder)
            p_filesz = _uint(data, pos + 32, 8, byteorder)
        end = p_offset + p_filesz
        if end > remaining:
            return None
        referenced_end = max(referenced_end, end)

    # Section headers add file-backed section extents. SHT_NOBITS (8) occupies
    # memory but no bytes in the file, so it is intentionally excluded.
    for i in range(e_shnum):
        pos = offset + e_shoff + i * e_shentsize
        sh_type = _uint(data, pos + 4, 4, byteorder)
        if elf_class == 1:
            sh_offset = _uint(data, pos + 16, 4, byteorder)
            sh_size = _uint(data, pos + 20, 4, byteorder)
        else:
            sh_offset = _uint(data, pos + 24, 8, byteorder)
            sh_size = _uint(data, pos + 32, 8, byteorder)
        if sh_type == 8:
            continue
        end = sh_offset + sh_size
        if end > remaining:
            return None
        referenced_end = max(referenced_end, end)

    return {
        "kind": "elf",
        "offset": offset,
        "class_bits": 32 if elf_class == 1 else 64,
        "endian": byteorder,
        "type": e_type,
        "machine": e_machine,
        "program_headers": e_phnum,
        "section_headers": e_shnum,
        "minimum_referenced_extent": referenced_end,
    }


def elf_identity_claims(data: bytes, limit: int = MAX_IDENTITY_CLAIMS) -> list[dict]:
    claims = []
    start = 0
    while len(claims) < limit:
        off = data.find(b"\x7fELF", start)
        if off < 0:
            break
        found = validate_elf_at(data, off)
        if found is not None:
            claims.append(found)
        start = off + 1
    return claims


def best_known_plaintext_xor(cipher: bytes, plain: bytes, max_period: int):
    if not plain or len(cipher) < len(plain):
        return None
    extra = len(cipher) - len(plain)
    max_offset = min(extra, 65536)
    sample_n = min(len(plain), SAMPLE_LIMIT)
    ps = plain[:sample_n]
    for off in range(max_offset + 1):
        cs = cipher[off:off + sample_n]
        if len(cs) != sample_n:
            break
        mask = bytes(x ^ y for x, y in zip(cs, ps))
        period = smallest_period_exact(mask, max_period)
        if period is not None:
            return {
                "kind": "repeating_xor",
                "offset": off,
                "period": period,
                "mask": mask[:period],
            }
    return None


def exact_substitution_mapping(cipher: bytes, plain: bytes, off: int, sample_n: int):
    p_to_c = [-1] * 256
    c_to_p = [-1] * 256
    repeats = 0
    for p, c in zip(plain[:sample_n], cipher[off:off + sample_n]):
        old_c = p_to_c[p]
        old_p = c_to_p[c]
        if old_c == -1 and old_p == -1:
            p_to_c[p] = c
            c_to_p[c] = p
        elif old_c != c or old_p != p:
            return None
        else:
            repeats += 1
    observed = [(p, c) for p, c in enumerate(p_to_c) if c != -1]
    if len(observed) < 16 or repeats < 32:
        return None
    return observed


def best_known_plaintext_substitution(cipher: bytes, plain: bytes):
    if not plain or len(cipher) < len(plain):
        return None
    extra = len(cipher) - len(plain)
    max_offset = min(extra, 65536)
    sample_n = min(len(plain), SAMPLE_LIMIT)
    if sample_n < 64:
        return None
    for off in range(max_offset + 1):
        mapping = exact_substitution_mapping(cipher, plain, off, sample_n)
        if mapping is not None:
            return {
                "kind": "fixed_byte_substitution",
                "offset": off,
                "observed_symbols": len(mapping),
                "mapping": mapping,
            }
    return None


def recover_block_permutation(cipher: bytes, plain: bytes, off: int, block_size: int, blocks: int):
    """Recover output-position -> input-position mapping across aligned full blocks."""
    candidates = [set(range(block_size)) for _ in range(block_size)]
    for block in range(blocks):
        po = block * block_size
        co = off + po
        pb = plain[po:po + block_size]
        cb = cipher[co:co + block_size]
        for out_pos, value in enumerate(cb):
            keep = {in_pos for in_pos in candidates[out_pos] if pb[in_pos] == value}
            if not keep:
                return None
            candidates[out_pos] = keep

    if any(len(options) != 1 for options in candidates):
        return None
    mapping = [next(iter(options)) for options in candidates]
    if len(set(mapping)) != block_size:
        return None

    # Exact confirmation over every complete block in the sampled plaintext.
    full_blocks = min(len(plain), SAMPLE_LIMIT) // block_size
    for block in range(full_blocks):
        po = block * block_size
        co = off + po
        pb = plain[po:po + block_size]
        cb = cipher[co:co + block_size]
        if any(cb[out_pos] != pb[in_pos] for out_pos, in_pos in enumerate(mapping)):
            return None
    return mapping


def best_known_plaintext_block_permutation(cipher: bytes, plain: bytes, max_block: int = BLOCK_PERMUTE_MAX):
    """Find an exact fixed within-block position permutation, without knowing its format."""
    if not plain or len(cipher) < len(plain):
        return None
    sample_n = min(len(plain), SAMPLE_LIMIT)
    max_offset = min(len(cipher) - len(plain), 65536)
    max_block = min(max_block, sample_n // 8)
    if max_block < 2:
        return None

    # A commutative rolling fingerprint cheaply finds windows whose byte multiset
    # matches the first plaintext block. Use nonlinear per-byte weights so equal
    # byte sums do not masquerade as equal multisets; exact recovery still rejects
    # the vanishingly rare hash collision.
    mask64 = 0xffffffffffffffff

    def mix64(x: int) -> int:
        x = (x + 0x9E3779B97F4A7C15) & mask64
        x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & mask64
        x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & mask64
        return (x ^ (x >> 31)) & mask64

    weights = [mix64(b) for b in range(256)]

    for block_size in range(2, max_block + 1):
        blocks = min(sample_n // block_size, 64)
        if blocks < 8:
            continue
        target = sum(weights[b] for b in plain[:block_size]) & mask64
        window = sum(weights[b] for b in cipher[:block_size]) & mask64
        for off in range(max_offset + 1):
            if off:
                window = (
                    window
                    - weights[cipher[off - 1]]
                    + weights[cipher[off + block_size - 1]]
                ) & mask64
            if window != target:
                continue
            if Counter(cipher[off:off + block_size]) != Counter(plain[:block_size]):
                continue
            mapping = recover_block_permutation(cipher, plain, off, block_size, blocks)
            if mapping is not None:
                verified_bytes = (sample_n // block_size) * block_size
                return {
                    "kind": "fixed_block_position_permutation",
                    "offset": off,
                    "block_size": block_size,
                    "mapping": mapping,
                    "verified_blocks": verified_bytes // block_size,
                    "verified_bytes": verified_bytes,
                    "trailing_bytes": sample_n - verified_bytes,
                }
    return None


def known_plaintext_probe(cipher: bytes, plain: bytes, max_period: int):
    found = best_known_plaintext_xor(cipher, plain, max_period)
    if found is not None:
        return found
    found = best_known_plaintext_substitution(cipher, plain)
    if found is not None:
        return found
    return best_known_plaintext_block_permutation(cipher, plain)


def comparison_result(data: bytes, other: bytes) -> dict:
    n = min(len(data), len(other))
    changed = sum(x != y for x, y in zip(data[:n], other[:n]))
    return {
        "compared_bytes": n,
        "changed_bytes": changed,
        "changed_ratio": changed / n if n else 0.0,
        "changed_bits_ratio": hamming_ratio(data, other),
        "length_delta": len(data) - len(other),
    }


def analysis_result(
    data: bytes, max_lag: int, base_offset: int = 0, *, windowed: bool = False
) -> tuple[list[dict], list[dict], dict, list[dict]]:
    claims = []
    abstentions = []
    structure = structure_regions(data)

    views = mbr_views(data, base_offset, windowed=windowed)
    views.extend(auto_ksy_views(data, base_offset, max(0, MAX_AUTO_KSY_VIEWS - len(views))))
    identity = [
        claim
        for view in views
        if (claim := mbr_identity_claim_from_view(view)) is not None
    ]
    for view in views:
        if view.get("kind") == "ksy_structure" and view.get("strong_identity"):
            identity.append({
                "kind": "ksy_identity",
                "ksy_id": view["ksy_id"],
                "offset": view["offset"],
                "extent": view["extent"],
                "shape_source": view["shape_source"],
                "checks_passed": view["checks_passed"],
                "checks_total": view["checks_total"],
                "partial": view.get("partial", False),
                "issues": view.get("issues", []),
            })
    # ELF offsets are local to the supplied byte stream; translate them into the
    # same global coordinate space used by structural views.
    elf_claims = elf_identity_claims(data)
    for claim in elf_claims:
        claim = dict(claim)
        claim["offset"] += base_offset
        identity.append(claim)
    claims.extend(identity)
    if not identity:
        abstentions.append({
            "kind": "object_identity",
            "reason": "no object identity in the currently validated detector set crossed its claim threshold",
        })

    period = periodicity_claim(data, max_lag)
    if period is not None:
        claims.append(period)
    else:
        abstentions.append({
            "kind": "byte_coincidence_periodicity",
            "reason": "no periodic equality structure crossed the validated claim threshold",
        })
    # Deliberately no ciphertext-only transform-family detector yet. Periodicity
    # describes an observed relationship; naming its cause requires more evidence.
    abstentions.append({
        "kind": "transform_family",
        "reason": "ciphertext-only evidence does not justify a transform-family claim",
    })
    return claims, abstentions, structure, views


def byte_annotation(value: int) -> str | None:
    if value in BYTE_NAMES:
        return BYTE_NAMES[value]
    if 32 <= value <= 126:
        return f"ASCII {chr(value)!r}"
    return None


def print_basic(stats: dict) -> None:
    print(f"bytes: {stats['bytes']}")
    if stats["sample_bytes"] != stats["bytes"]:
        print(f"analysis sample: first {stats['sample_bytes']} bytes")
    print(f"entropy: {stats['entropy_bits_per_byte']:.5f} bits/byte")
    print(f"distinct byte values: {stats['distinct_byte_values']}/256")
    print(f"printable ASCII: {stats['printable_ascii_ratio']:.2%}")
    print(f"00 bytes: {stats['zero_ratio']:.2%}")
    print(f"ff bytes: {stats['ff_ratio']:.2%}")
    print(f"serial correlation: {stats['serial_correlation']:+.6f}")
    if stats["strongest_lags"]:
        print("strongest byte-coincidence lags:")
        for row in stats["strongest_lags"]:
            print(f"  lag {row['lag']:4d}: {row['coincidence']:.4%}")
    if stats["most_common"]:
        print("most common bytes:")
        for row in stats["most_common"]:
            annotation = byte_annotation(row["byte"])
            suffix = f"  {annotation}" if annotation else ""
            print(f"  {row['byte']:02x}: {row['ratio']:.3%}{suffix}")


def print_structure(structure: dict) -> None:
    print(f"Structure ({structure['window_bytes']}-byte windows):")
    regions = structure["regions"]
    shown = regions[:24]
    for row in shown:
        start = row["start"]
        end = row["end"]
        if row["kind"] == "fill":
            label = f"fill byte {row['fill_byte']:02x}"
        elif row["kind"] == "ascii_compatible":
            label = "ASCII-compatible bytes"
        elif row["kind"] == "high_entropy":
            label = "high-entropy bytes"
        else:
            label = row["kind"]
        print(f"  0x{start:08x}-0x{end:08x}  {label}")
    if len(regions) > len(shown):
        print(f"  ... {len(regions) - len(shown)} more regions")
    if structure["truncated"]:
        print(f"  scan limited to first {structure['scanned_bytes']} of {structure['total_bytes']} bytes")
    print()


def print_views(views: list[dict]) -> None:
    for view in views:
        if view["kind"] == "ksy_structure":
            verdict = "recognized, partial" if view.get("partial") else "recognized"
            print(f"View: {view['ksy_id']} structure at 0x{view['offset']:x} ({verdict})")
            print(
                f"  structural checks: {view['checks_passed']}/{view['checks_total']}  "
                f"annotations: {len(view.get('annotations', []))}"
            )
            print(f"  shape source: {view['shape_source']}")
            for issue in view.get("issues", [])[:1]:
                print(f"  unresolved: {issue}")
            print()
            continue
        if view["kind"] != "mbr_partition_table":
            continue
        verdict = "strong" if view["strong_identity"] else "partial"
        print(f"View: MBR-shaped sector at 0x{view['offset']:x} ({verdict} fit)")
        print(
            f"  structural checks: {view['checks_passed']}/{view['checks_total']}  "
            f"contradictions: {len(view['hard_contradictions'])}"
        )
        # Show the useful first two levels; field-level annotations remain in JSON
        # for FatPix cursor inspection without turning --analyze into a phone book.
        for row in view["annotations"]:
            if row["depth"] > 2:
                continue
            print(f"  0x{row['start']:08x}-0x{row['end']:08x}  {row['path']}")
        if view["hard_contradictions"]:
            for text in view["hard_contradictions"]:
                print(f"  conflict: {text}")
        print()


def print_analysis(
    claims: list[dict], abstentions: list[dict], structure: dict, views: list[dict]
) -> None:
    print("Clarity analysis")
    print()
    print_structure(structure)
    print_views(views)
    if claims:
        for claim in claims:
            if claim["kind"] == "mbr_partition_table":
                where = "MBR partition table" if claim["offset"] == 0 else "embedded MBR partition table"
                print(f"CLAIM: structurally consistent {where}")
                print(f"  offset: 0x{claim['offset']:x}  extent: {claim['extent']} bytes")
                print(
                    f"  structural checks: {claim['checks_passed']}/{claim['checks_total']}  "
                    f"non-empty partitions: {claim['nonempty_entries']}"
                )
                for entry in claim["partitions"]:
                    if entry["empty"]:
                        continue
                    boot = " bootable" if entry["status"] == 0x80 else ""
                    print(
                        f"  partition[{entry['index']}]: type=0x{entry['partition_type']:02x}"
                        f" lba={entry['lba_start']} sectors={entry['num_sectors']}{boot}"
                    )
                print(f"  shape source: {claim['shape_source']}")
                print()
            elif claim["kind"] == "elf":
                where = "ELF object" if claim["offset"] == 0 else "embedded ELF object"
                print(f"CLAIM: structurally validated {where}")
                print(f"  offset: 0x{claim['offset']:x}")
                print(f"  class/endian: ELF{claim['class_bits']} {claim['endian']}-endian")
                print(f"  type: {claim['type']}  machine: 0x{claim['machine']:04x}")
                print(
                    f"  program headers: {claim['program_headers']}  "
                    f"section headers: {claim['section_headers']}"
                )
                print(
                    "  minimum structurally referenced extent: "
                    f"{claim['minimum_referenced_extent']} bytes"
                )
                print()
            elif claim["kind"] == "ksy_identity":
                suffix = " (partial)" if claim.get("partial") else ""
                print(f"CLAIM: structurally validated {claim['ksy_id']} object{suffix}")
                print(f"  offset: 0x{claim['offset']:x}  projected extent: {claim['extent']} bytes")
                print(f"  shape source: {claim['shape_source']}")
                print()
            elif claim["kind"] == "byte_coincidence_periodicity":
                print("CLAIM: strong byte-coincidence periodicity")
                print(f"  fundamental lag: {claim['period']} bytes")
                print(
                    f"  coincidence at lag {claim['period']}: {claim['coincidence']:.4%} "
                    f"(independent-byte baseline {claim['baseline']:.4%})"
                )
                joined = ", ".join(str(x) for x in claim["supporting_lags"])
                print(f"  supporting strong lags divisible by {claim['period']}: {joined}")
                print()
    else:
        print("CLAIM: none")
        print()
    for item in abstentions:
        if item["kind"] == "object_identity":
            print("ABSTAIN: object identity")
            print(f"  {item['reason']}")
            print()
        elif item["kind"] == "transform_family":
            print("ABSTAIN: transform family")
            print(f"  {item['reason']}")
            print()
        elif item["kind"] == "byte_coincidence_periodicity":
            print("ABSTAIN: repeating byte-coincidence structure")
            print(f"  {item['reason']}")
            print()


def printable_mapping_preview(mapping: list[tuple[int, int]], limit: int = 16) -> str:
    parts = []
    for p, c in mapping[:limit]:
        parts.append(f"{p:02x}->{c:02x}")
    if len(mapping) > limit:
        parts.append("...")
    return " ".join(parts)


def known_probe_for_json(found: dict | None, private: bool) -> dict | None:
    if found is None:
        return None
    out = {k: v for k, v in found.items() if k not in {"mask", "mapping"}}
    if found["kind"] == "repeating_xor":
        key = found["mask"]
        if private:
            out["mask_pr"] = "PR:[redacted by --private]"
        else:
            ascii_view = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in key)
            out["mask_pr"] = f"PR:[hex={key.hex()} ascii={ascii_view!r}]"
    elif found["kind"] in {"fixed_byte_substitution", "fixed_block_position_permutation"}:
        # Recovered transform material stays behind the same privacy boundary.
        if private:
            out["mapping_pr"] = "PR:[redacted by --private]"
        elif found["kind"] == "fixed_byte_substitution":
            out["mapping_pr"] = "PR:[" + printable_mapping_preview(found["mapping"], 256) + "]"
        else:
            out["mapping_pr"] = "PR:[out->in " + " ".join(
                f"{out_pos:02x}->{in_pos:02x}" for out_pos, in_pos in enumerate(found["mapping"])
            ) + "]"
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Generic binary-stream analyzer; no Garble-specific parser or transform registry.")
    ap.add_argument("file", help="cipher/unknown file, or - for stdin")
    ap.add_argument("--known", metavar="PLAINTEXT", help="known/chosen plaintext aligned somewhere inside FILE")
    ap.add_argument("--compare", metavar="OTHER", help="compare FILE against another same-role specimen")
    ap.add_argument("--max-lag", type=int, default=256, help="largest byte lag to score (default: 256)")
    ap.add_argument("--max-period", type=int, default=4096, help="largest exact known-plaintext XOR-mask period to test")
    ap.add_argument("--analyze", action="store_true", help="interpret only claim types that have crossed test thresholds")
    ap.add_argument("--stats", action="store_true", help="raw statistical report only (also the default without --analyze)")
    ap.add_argument("--json", action="store_true", help="machine-readable result for test/scoring tools")
    ap.add_argument("--private", action="store_true", help="redact recovered key/mapping bytes while preserving findings")
    ap.add_argument(
        "--ksy-root",
        metavar="DIR",
        help="Kaitai .ksy corpus root (default: CLARITY_KSY_ROOT or ./kaitai beside clarity.py)",
    )
    ap.add_argument(
        "--ksy",
        action="append",
        default=[],
        metavar="RELATIVE.ksy",
        help="project an explicit Kaitai definition at the start of FILE (repeatable; no identity claim)",
    )
    ap.add_argument(
        "--windowed",
        action="store_true",
        help="treat FILE as a positioned window of a larger source; use source-aware structural discovery",
    )
    ap.add_argument(
        "--base-offset",
        type=lambda text: int(text, 0),
        default=0,
        help="global byte offset corresponding to the first supplied byte (default: 0)",
    )
    args = ap.parse_args()

    if args.ksy_root:
        configure_ksy_root(args.ksy_root)

    if args.max_lag < 1 or args.max_period < 1:
        ap.error("--max-lag and --max-period must be positive")
    if args.base_offset < 0:
        ap.error("--base-offset must be non-negative")
    if args.analyze and args.stats:
        ap.error("use only one of --analyze and --stats")

    data = read_bytes(args.file)
    try:
        ksy_projections = [project_ksy(data, relative, args.base_offset) for relative in args.ksy]
    except (KsyError, KsyUnsupported) as exc:
        ap.error(str(exc))
    stats = basic_stats(data, args.max_lag)
    if args.analyze or args.json:
        claims, abstentions, structure, views = analysis_result(
            data, args.max_lag, args.base_offset, windowed=args.windowed
        )
    else:
        claims, abstentions, structure, views = [], [], None, []
    comp = comparison_result(data, read_bytes(args.compare)) if args.compare else None
    known = known_plaintext_probe(data, read_bytes(args.known), args.max_period) if args.known else None

    if args.json:
        obj = {
            "stats": stats,
            "claims": claims,
            "abstentions": abstentions,
            "structure": structure,
            "views": views,
            "base_offset": args.base_offset,
            "comparison": comp,
            "known_plaintext": known_probe_for_json(known, args.private),
            "ksy_projections": [ksy_projection_for_json(p) for p in ksy_projections],
        }
        print(json.dumps(obj, sort_keys=True, separators=(",", ":")))
        return 0

    if args.analyze:
        assert structure is not None
        print_analysis(claims, abstentions, structure, views)
        print("Statistics:")
    print_basic(stats)

    for projection in ksy_projections:
        _print_ksy_projection(projection)

    if comp is not None:
        print("comparison:")
        print(f"  compared bytes: {comp['compared_bytes']}")
        print(f"  changed bytes: {comp['changed_bytes']}/{comp['compared_bytes']} ({comp['changed_ratio']:.2%})")
        print(f"  changed bits: {comp['changed_bits_ratio']:.2%}")
        print(f"  length delta: {comp['length_delta']:+d}")

    if args.known:
        print("known-plaintext probe:")
        if known is None:
            print("  no exact repeating-XOR, fixed byte-substitution, or fixed block-permutation relationship found in scanned alignments")
        elif known["kind"] == "repeating_xor":
            key = known["mask"]
            print(f"  candidate payload offset: {known['offset']}")
            print(f"  exact repeating XOR-mask period: {known['period']} bytes")
            if args.private:
                print("  recovered mask: PR:[redacted by --private]")
            else:
                ascii_view = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in key)
                print(f"  recovered mask: PR:[hex={key.hex()} ascii={ascii_view!r}]")
        elif known["kind"] == "fixed_byte_substitution":
            print(f"  candidate payload offset: {known['offset']}")
            print("  exact position-independent one-byte substitution relation")
            print(f"  observed plaintext symbols mapped consistently: {known['observed_symbols']}/256")
            if args.private:
                print("  recovered mapping: PR:[redacted by --private]")
            else:
                print(f"  recovered mapping: PR:[{printable_mapping_preview(known['mapping'])}]")
        else:
            print(f"  candidate payload offset: {known['offset']}")
            print("  exact fixed within-block position-permutation relation across complete blocks")
            print(f"  smallest supported block size: {known['block_size']} bytes")
            print(
                f"  verified complete-block coverage: {known['verified_bytes']} bytes "
                f"({known['verified_blocks']} blocks)"
            )
            if known["trailing_bytes"]:
                print(f"  trailing bytes outside this claim: {known['trailing_bytes']}")
            if args.private:
                print("  recovered position mapping: PR:[redacted by --private]")
            else:
                preview = " ".join(
                    f"{out_pos:02x}->{in_pos:02x}"
                    for out_pos, in_pos in enumerate(known["mapping"])
                )
                print(f"  recovered position mapping: PR:[out->in {preview}]")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
