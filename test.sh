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
def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

for path, transform_id in ((sys.argv[1], 1), (sys.argv[2], 2), (sys.argv[3], 3)):
    b = Path(path).read_bytes()[:16]
    require(b[:8] == b'GRBLv1\r\n', "assertion failed: b[:8] == b'GRBLv1\\r\\n'")
    require(b[8] == 1 and b[9] == transform_id and (b[10:12] == b'\x00\x00'), "assertion failed: b[8] == 1 and b[9] == transform_id and (b[10:12] == b'\\x00\\x00')")
    require(int.from_bytes(b[12:16], 'little') == 16, "assertion failed: int.from_bytes(b[12:16], 'little') == 16")
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

# Bound only movement repeats at the raw terminal queue boundary.
python3 - <<'PY'
import importlib.machinery
import importlib.util

loader = importlib.machinery.SourceFileLoader("fatpix_test", "fatpix")
spec = importlib.util.spec_from_loader(loader.name, loader)
fatpix = importlib.util.module_from_spec(spec)
loader.exec_module(fatpix)

def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + message)

def terminal():
    return fatpix.RawTerminal(-1)

t = terminal()
t._input.extend(b"\x1b[6~" * 500)
t._parse_input()
require(list(t._events) == ["PGDN"] * t._MAX_QUEUED_NAVIGATION,
        "encoded PgDn repeat queue was not bounded")

# Non-navigation input remains lossless behind a saturated movement queue.
t._input.extend(b"x")
t._parse_input()
require(list(t._events)[-1] == "x", "non-navigation input was dropped")

# Ctrl-C preempts and discards only navigation; the unrelated event survives.
t._input.extend(b"\x03")
t._parse_input()
require(t.read_key() == "QUIT", "Ctrl-C did not preempt navigation")
require(list(t._events) == ["x"], "Ctrl-C discarded unrelated input")

# Literal command/text bytes are ambiguous until the UI state is known and
# therefore remain lossless at RawTerminal's state-agnostic boundary.
t = terminal()
t._input.extend(b"a" * 500)
t._parse_input()
require(list(t._events) == ["a"] * 500, "literal text was throttled as navigation")

# Ordinary encoded movements retain their established event names.  Drain each
# event to show that repeated reads continue to navigate normally.
for raw, expected in (
    (b"\x1b[A", "UP"), (b"\x1b[B", "DOWN"),
    (b"\x1b[C", "RIGHT"), (b"\x1b[D", "LEFT"),
    (b"\x1b[5~", "PGUP"), (b"\x1b[6~", "PGDN"),
    (b"w", "w"), (b"a", "a"), (b"s", "s"), (b"d", "d"),
):
    t = terminal()
    t._input.extend(raw)
    t._parse_input()
    require(t.read_key() == expected, f"single {expected} event changed")

print("RawTerminal navigation queue: bounded repeats, lossless commands, preemptive quit")
PY

# File-view status remains a compact orientation aid.  Detailed cell metrics
# stay available through inspector_lines(STATS/RANGE/HEX), not in the footer.
python3 - <<'PY'
import importlib.machinery, importlib.util, re

loader = importlib.machinery.SourceFileLoader("fatpix_status_test", "fatpix")
spec = importlib.util.spec_from_loader(loader.name, loader)
fatpix = importlib.util.module_from_spec(spec)
loader.exec_module(fatpix)

app = fatpix.FatPix(file_source=fatpix.ByteSource(data=bytes(range(256))), file_label="/tmp/deep/sample.bin")
status = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", app.render_status())
first, second = status.split("\n", 1)
assert first == "file=sample.bin  scale=1B  pos=0x0  view=literal  clarity=off", first
assert second == "? help", second
for obsolete in ("cursor=", "cell=", "sel=", "byte=", "kind=", " H=", "zero=", "text="):
    assert obsolete not in status, (obsolete, status)

app.file_selection_start = 16
app.file_selection_end = 80
app.message = "selected 64 B"
status = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", app.render_status())
assert "pos=0x10..0x4f" in status, status
assert status.split("\n", 1)[1] == "? help | selected 64 B", status

app.inspect_page = app.inspect_pages.index("STATS")
stats = "\n".join(app.inspector_lines(100, 20))
assert "entropy=" in stats and "zero=" in stats and "printable=" in stats, stats

# Shifted zoom keys jump several positions on the same scale ladder.  They must
# remain distinct from the ordinary one-step keys and retain inspector focus.
source = fatpix.ByteSource(data=bytes(range(256)) * 256)
app = fatpix.FatPix(file_source=source, file_label="zoom.bin")
app.set_file_scale(64)
app.inspect_open = True
app.inspect_focus_addr = 0x1234
app.handle_key("=")
small_in = app.file_bytes_per_cell
assert app.file_cursor_addr == 0x1234
app.set_file_scale(64)
app.handle_key("+")
large_in = app.file_bytes_per_cell
assert large_in < small_in < 64, (large_in, small_in)
assert app.file_cursor_addr == 0x1234
app.set_file_scale(64)
app.handle_key("-")
small_out = app.file_bytes_per_cell
app.set_file_scale(64)
app.handle_key("_")
large_out = app.file_bytes_per_cell
assert 64 < small_out < large_out, (small_out, large_out)

app.run_command("s 10K")
assert app.file_bytes_per_cell == 10 * 1024
app.run_command("scale 1.5M")
assert app.file_bytes_per_cell == 1572864
app.run_command("g 0xBEEF")
assert app.file_cursor_addr == 0xBEEF

# A buffered repeat run updates all requested ladder positions before the first
# expensive viewport read.  Event order stops coalescing at the first other key.
app = fatpix.FatPix(file_source=source, file_label="zoom.bin")
app.set_file_scale(64)
refreshes = 0
original_refresh = app.refresh_file_grid
def counted_refresh():
    global refreshes
    refreshes += 1
    return original_refresh()
app.refresh_file_grid = counted_refresh
term = fatpix.RawTerminal(-1)
term._events.extend(["="] * 6 + ["x", "="])
first = term.read_key()
assert fatpix.handle_key_batch(app, term, first)
assert refreshes == 0, refreshes
assert app.file_bytes_per_cell == fatpix.FILE_SCALE_LADDER[fatpix.FILE_SCALE_LADDER.index(64) - 6]
assert list(term._events) == ["x", "="], list(term._events)
if app.file_dirty:
    app.refresh_file_grid()
assert refreshes == 1, refreshes
print("FatPix file status: compact position, selection, view, and Clarity state")
PY

# Native and Python FatPix share deterministic literal-lens classifications at
# byte scale and at coarse representative-sampling scales.
./fatpix-c --dump-grid 16x4 --scale 1 --offset 0 test/sample.png > "$tmp/fatpix-c-fine.grid"
./fatpix --file test/sample.png --dump-grid 16x4 --scale 1 --offset 0 > "$tmp/fatpix-py-fine.grid"
cmp "$tmp/fatpix-c-fine.grid" "$tmp/fatpix-py-fine.grid"
./fatpix-c --dump-grid 8x4 --scale 10K --offset 7 test/sample.avi > "$tmp/fatpix-c-coarse.grid"
./fatpix --file test/sample.avi --dump-grid 8x4 --scale 10K --offset 7 > "$tmp/fatpix-py-coarse.grid"
cmp "$tmp/fatpix-c-coarse.grid" "$tmp/fatpix-py-coarse.grid"
printf 'FatPix native parity: literal byte and bounded coarse grids agree\n'

# Native presentation-only changes reuse the classified logical grid. Closing
# the source after the first render makes any accidental viewport reread fail;
# the cached inspector bytes also cover a nearby cursor-outline move.
cat > "$tmp/fatpix-cache-test.c" <<'C'
#define main fatpix_program_main
#include "fatpix.c"
#undef main

int main(void) {
    Source source;
    Display display = {0};
    View view = {0};
    RenderCache cache = {0};
    char path[] = "/tmp/fatpix-cache-XXXXXX";
    char alias[128];
    unsigned char bytes[1024];
    int fd, result, panel_x, panel_y;

    for (size_t i = 0; i < sizeof(bytes); i++) bytes[i] = (unsigned char)i;
    fd = mkstemp(path);
    if (fd < 0 || write(fd, bytes, sizeof(bytes)) != (ssize_t)sizeof(bytes)) return 1;
    close(fd);
    if (source_open(&source, path) < 0) return 2;
    snprintf(alias, sizeof(alias), "%s.alias", path);
    if (link(path, alias) < 0) return 2;
    unlink(path);
    display.fd = display.tty = display.mouse = -1;
    display.var.xres = 140; display.var.yres = 100; display.var.bits_per_pixel = 32;
    display.var.red.length = display.var.green.length = display.var.blue.length = 8;
    display.var.red.offset = 16; display.var.green.offset = 8;
    display.fix.line_length = display.var.xres * 4;
    display.map_len = (size_t)display.fix.line_length * display.var.yres;
    display.map = calloc(1, display.map_len); display.back = calloc(1, display.map_len);
    view.scale = 1; view.cell = 14; view.cursor = 128; view.inspect = 1;
    if (!display.map || !display.back || render(&display, &source, &view, &cache, 1) < 0) return 3;
    if (source.read_calls != 2) return 18; /* one viewport batch plus inspector */
    view.selection_start = 0; view.selection_end = 16;
    if (dump_selection(&source, &view, alias) == 0) return 19;
    unlink(alias);

    close(source.fd); source.fd = -1;
    view.cursor++; view.selection_start = 128; view.selection_end = 130;
    display.mouse_x++; display.mouse_y++;
    {
        uint64_t recolors = cache.recolor_count;
        result = render(&display, &source, &view, &cache, 0);
        if (cache.recolor_count != recolors) return 20;
    }
    view.selecting = 1;
    display.mouse_y = display.var.yres - 1;
    mouse_event(&display, &view, &source, &cache, (const uint8_t[]){8, 0, 0});
    if (view.selecting) return 5;
    view.cursor = 0;
    inspector_position(&display, &view, &cache, 60, 40, &panel_x, &panel_y);
    if (panel_x != 72 || panel_y != 52) return 6;
    view.cursor = 49;
    inspector_position(&display, &view, &cache, 60, 40, &panel_x, &panel_y);
    if (panel_x != 8 || panel_y != 8) return 7;
    display.mouse_speed = 0.5; display.mouse_x = 10; display.mouse_y = 10;
    display.mouse_remainder_x = display.mouse_remainder_y = 0.0;
    mouse_event(&display, &view, &source, &cache, (const uint8_t[]){8, 1, 0});
    mouse_event(&display, &view, &source, &cache, (const uint8_t[]){8, 1, 0});
    if (display.mouse_x != 11) return 8;
    display.font_scale = 2; memset(display.back, 0, display.map_len);
    text5(&display, 0, 0, "!", 0xffffff);
    if (!((uint32_t *)display.back)[4] || !((uint32_t *)display.back)[5] ||
        !((uint32_t *)(display.back + display.fix.line_length))[4] ||
        ((uint32_t *)display.back)[2]) return 9;
    if (!memcmp(font5x7['a' - 32], font5x7['A' - 32], 7) ||
        memcmp(font5x7['a' - 32], (const uint8_t[]){0,0,14,1,15,17,15}, 7)) return 10;

    view.view = 0; view.scale = 2; view.cursor = 0;
    for (int step = 1; step <= 7; step++) {
        view.cursor += view.scale;
        keep_cursor_visible(&view, 100, 8);
        if (view.view != 0 || (view.cursor - view.view) / view.scale != (uint64_t)step) return 11;
        if (step == 4 && ((view.cursor - view.view) / view.scale % 4 != 0 ||
                          (view.cursor - view.view) / view.scale / 4 != 1)) return 11;
    }
    view.cursor += view.scale;
    keep_cursor_visible(&view, 100, 8);
    if (view.view != 8 || (view.cursor - view.view) / view.scale != 4) return 12;
    view.cursor += view.scale;
    keep_cursor_visible(&view, 100, 8);
    if (view.view != 8 || (view.cursor - view.view) / view.scale != 5) return 13;
    if (zoom_scale(4, 0, 1) != 6 || zoom_scale(4, 1, 1) != 3 ||
        zoom_scale(4, 0, 4) != 12 || zoom_scale(4, 1, 4) != 1) return 14;
    if (half_page_bytes(9, 3) != 12 || representative_start(100, 2048) != 612) return 21;
    view.help = 1; if (mouse_gestures_allowed(&view, 0)) return 23;
    view.help = 0; if (mouse_gestures_allowed(&view, 1) || !mouse_gestures_allowed(&view, 0)) return 23;
    display.var.xres = 800; display.var.yres = 600; display.font_scale = 1;
    display.mouse_x = 100; display.mouse_y = 300; display.mouse_speed = 1.0;
    source.size = 16 * 1024 * 1024; view.cell = 10; view.view = 0; view.scale = 2048;
    view.cursor = 0; view.inspect = 1;
    mouse_event(&display, &view, &source, &cache, (const uint8_t[]){9, 0, 0});
    mouse_event(&display, &view, &source, &cache, (const uint8_t[]){9, 10, 0});
    if (view.inspect_focus != representative_start(view.cursor, view.scale)) return 22;
    mouse_event(&display, &view, &source, &cache, (const uint8_t[]){8, 0, 0});
    if (classify_lens(2, (const uint8_t[]){0xaa,0xaa}, 2, 0xaa, NULL, 0, NULL, 0).color != 0 ||
        classify_lens(3, (const uint8_t[]){0,255}, 2, 0, NULL, 0, NULL, 0).color != 7 ||
        lens_number("neighbor") != 5 || lens_number("d") != 3) return 15;
    {
        char g[] = "g 17", go[] = "goto 19", s[] = "s 3", scale[] = "scale 6";
        char named[] = "view cursor", numbered[] = "view 2";
        view.inspect = 1;
        view.inspect_focus = 11; source.size = 1024;
        if (run_file_command(&source, &view, g) != 2 || view.cursor != 17 ||
            run_file_command(&source, &view, go) != 2 || view.cursor != 19 ||
            run_file_command(&source, &view, s) != 2 || view.scale != 3 || view.cursor != 19 ||
            run_file_command(&source, &view, scale) != 2 || view.scale != 6 ||
            run_file_command(&source, &view, named) != 1 || view.lens != 6 ||
            run_file_command(&source, &view, numbered) != 1 || view.lens != 2) return 16;
        view.cursor = 700; view.scale = 6; center_view(&view, 1024, 8);
        if (view.view != 672) return 17;
    }
    {
        Source commands = {.size = 4096, .path = "/tmp/source"};
        View a = {.scale = 1, .inspect_focus = UINT64_MAX}, b = a;
        char g1[] = "g 0x321", g2[] = "goto 0x321", s1[] = "s 1.5K", s2[] = "scale 1.5K";
        char named[] = "view neighbor";
        if (run_file_command(&commands, &a, g1) != 2 || run_file_command(&commands, &b, g2) != 2 ||
            a.cursor != b.cursor || run_file_command(&commands, &a, s1) != 2 ||
            run_file_command(&commands, &b, s2) != 2 || a.scale != b.scale ||
            run_file_command(&commands, &a, named) != 1 || a.lens != 5) return 16;
        a.cursor = 700; a.scale = 10; a.view = 0; center_view(&a, 4096, 80);
        if (a.view != 300) return 17;
    }
    free(cache.cells); free(cache.literal_cells); free(cache.samples); free(cache.contexts); free(cache.previous); free(cache.sample_n); free(cache.context_n);
    free(display.map); free(display.back);
    return result < 0 ? 4 : 0;
}
C
${CC:-cc} ${CFLAGS:--O2 -std=c99 -Wall -Wextra -Wpedantic} -I. "$tmp/fatpix-cache-test.c" -lm -lz -o "$tmp/fatpix-cache-test"
"$tmp/fatpix-cache-test"
printf 'FatPix native rendering: caches, cursor recentering, lowercase text, inspector, mouse speed, and text scale agree\n'

printf 'FatPix native behavior: zoom ladder, centering, command aliases, and six lens classifiers checked\n'

cat > "$tmp/fatpix-lens-probe.c" <<'C'
#define main fatpix_program_main
#include "fatpix.c"
#undef main
int main(int argc, char **argv) {
    Source source; View view = {0}; RenderCache cache = {0}; size_t i;
    if (argc != 4 || source_open(&source, argv[1]) < 0) return 1;
    view.scale = strtoull(argv[2], NULL, 10); view.lens = atoi(argv[3]);
    cache.count = 8; cache.cells = calloc(cache.count, sizeof(*cache.cells));
    cache.samples = calloc(cache.count, SAMPLE_MAX); cache.contexts = calloc(cache.count, SAMPLE_MAX);
    cache.previous = calloc(cache.count, 1); cache.sample_n = calloc(cache.count, sizeof(*cache.sample_n));
    cache.context_n = calloc(cache.count, sizeof(*cache.context_n));
    if (!cache.cells || !cache.samples || !cache.contexts || !cache.previous || !cache.sample_n || !cache.context_n ||
        make_grid_data(&source, 0, view.scale, cache.count, cache.cells, cache.samples, cache.contexts,
                       cache.previous, cache.sample_n, cache.context_n) < 0) return 2;
    if (view.scale > BATCH_MAX / cache.count && source.size >= view.scale * cache.count &&
        source.read_calls != cache.count) return 3;
    if (view.lens != 1) recolor_grid(&view, &cache);
    for (i = 0; i < cache.count; i++) printf("%u%c", cache.cells[i].color, i == 7 ? '\n' : ' ');
    return 0;
}
C
${CC:-cc} ${CFLAGS:--O2 -std=c99 -Wall -Wextra -Wpedantic} -I. "$tmp/fatpix-lens-probe.c" -lm -lz -o "$tmp/fatpix-lens-probe"
for scale in 1 300; do
    for lens in 1 2 3 4 5 6; do
        c_out="$tmp/c-$scale-$lens"; py="$tmp/py-$scale-$lens"
        "$tmp/fatpix-lens-probe" test/sample.png "$scale" "$lens" > "$c_out"
        python3 - test/sample.png "$scale" "$lens" > "$py" <<'PY'
import runpy, sys
ns = runpy.run_path("fatpix")
source = ns["ByteSource"](path=sys.argv[1])
app = ns["FatPix"](file_source=source, file_label=sys.argv[1])
app.w, app.h = 8, 1
app.file_bytes_per_cell = int(sys.argv[2])
app.file_view_start = app.file_cursor_addr = 0
app.refresh_file_grid()
app.set_file_lens(int(sys.argv[3]))
print(" ".join(str(value) for value in app.grid[0]))
source.close()
PY
        cmp "$c_out" "$py"
    done
done
"$tmp/fatpix-lens-probe" test/ext2.img 2097152 4 > "$tmp/c-coarse-lens"
python3 - test/ext2.img 2097152 4 > "$tmp/py-coarse-lens" <<'PY'
import runpy, sys
ns = runpy.run_path("fatpix")
source = ns["ByteSource"](path=sys.argv[1])
app = ns["FatPix"](file_source=source, file_label=sys.argv[1])
app.w, app.h = 8, 1
app.file_bytes_per_cell = int(sys.argv[2])
app.file_view_start = app.file_cursor_addr = 0
app.refresh_file_grid(); app.set_file_lens(int(sys.argv[3]))
print(" ".join(str(value) for value in app.grid[0]))
source.close()
PY
cmp "$tmp/c-coarse-lens" "$tmp/py-coarse-lens"
printf 'FatPix Python/C parity: all six lenses agree at byte and context-sampling scales\n'

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
def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

obj = json.load(open(sys.argv[1], encoding="utf-8"))
regions = obj["structure"]["regions"]
require([(r['start'], r['end'], r['kind']) for r in regions] == [(0, 1024, 'ascii_compatible'), (1024, 2048, 'fill'), (2048, 3072, 'high_entropy'), (3072, 4096, 'other')], "assertion failed: [(r['start'], r['end'], r['kind']) for r in regions] == [(0, 1024, 'ascii_compatible'), (1024, 2048, 'fill'), (2048, 3072, 'high_entropy'), (3072, 4096, 'other')]")
require(regions[1]['fill_byte'] == 255, "assertion failed: regions[1]['fill_byte'] == 255")
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
def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

obj = json.load(open(sys.argv[1], encoding="utf-8"))
claims = [c for c in obj["claims"] if c["kind"] == "mbr_partition_table"]
require(len(claims) == 1 and claims[0]['offset'] == 8192, "assertion failed: len(claims) == 1 and claims[0]['offset'] == 8192")
require(obj['base_offset'] == 8192, "assertion failed: obj['base_offset'] == 8192")
view = obj["views"][0]
require(view['strong_identity'] is True, "assertion failed: view['strong_identity'] is True")
require(view['shape_source'] == 'kaitai/filesystem/mbr_partition_table.ksy', "assertion failed: view['shape_source'] == 'kaitai/filesystem/mbr_partition_table.ksy'")
by_path = {a["path"]: a for a in view["annotations"]}
require((by_path['mbr.bootstrap_code']['start'], by_path['mbr.bootstrap_code']['end']) == (8192, 8638), "assertion failed: (by_path['mbr.bootstrap_code']['start'], by_path['mbr.bootstrap_code']['end']) == (8192, 8638)")
require((by_path['mbr.partitions[0].lba_start']['start'], by_path['mbr.partitions[0].lba_start']['end']) == (8646, 8650), "assertion failed: (by_path['mbr.partitions[0].lba_start']['start'], by_path['mbr.partitions[0].lba_start']['end']) == (8646, 8650)")
require(by_path['mbr.partitions[0].lba_start']['value'] == 2048, "assertion failed: by_path['mbr.partitions[0].lba_start']['value'] == 2048")
PY
cp "$tmp/mbr.bin" "$tmp/mbr-damaged.bin"
printf '\0\0' | dd of="$tmp/mbr-damaged.bin" bs=1 seek=510 conv=notrunc status=none
python3 clarity.py --json "$tmp/mbr-damaged.bin" > "$tmp/mbr-damaged.json"
python3 - "$tmp/mbr-damaged.json" <<'PY'
import json, sys
def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

obj = json.load(open(sys.argv[1], encoding="utf-8"))
require(not [c for c in obj['claims'] if c['kind'] == 'mbr_partition_table'], "assertion failed: not [c for c in obj['claims'] if c['kind'] == 'mbr_partition_table']")
require(len(obj['views']) == 1, "assertion failed: len(obj['views']) == 1")
view = obj["views"][0]
require(view['checks_passed'] == 9 and (not view['strong_identity']), "assertion failed: view['checks_passed'] == 9 and (not view['strong_identity'])")
require('boot signature 55 aa absent' in view['hard_contradictions'], "assertion failed: 'boot signature 55 aa absent' in view['hard_contradictions']")
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
def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

obj = json.load(open(sys.argv[1], encoding="utf-8"))
require(obj['stats']['bytes'] > 0, "assertion failed: obj['stats']['bytes'] > 0")
require(isinstance(obj['claims'], list), "assertion failed: isinstance(obj['claims'], list)")
require(isinstance(obj['abstentions'], list), "assertion failed: isinstance(obj['abstentions'], list)")
require(isinstance(obj['views'], list), "assertion failed: isinstance(obj['views'], list)")
require(obj['base_offset'] == 0, "assertion failed: obj['base_offset'] == 0")
require(obj['known_plaintext']['kind'] == 'fixed_byte_substitution', "assertion failed: obj['known_plaintext']['kind'] == 'fixed_byte_substitution'")
require(obj['known_plaintext']['offset'] == 16, "assertion failed: obj['known_plaintext']['offset'] == 16")
require(obj['known_plaintext']['observed_symbols'] == 256, "assertion failed: obj['known_plaintext']['observed_symbols'] == 256")
require(obj['known_plaintext']['mapping_pr'].startswith('PR:['), "assertion failed: obj['known_plaintext']['mapping_pr'].startswith('PR:[')")
PY
python3 clarity.py --json --private --known "$tmp/probe-plain.bin" "$tmp/probe-subst.grb" > "$tmp/private.json"
python3 - "$tmp/private.json" <<'PY'
import json, sys
def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

obj = json.load(open(sys.argv[1], encoding="utf-8"))
require(obj['known_plaintext']['mapping_pr'] == 'PR:[redacted by --private]', "assertion failed: obj['known_plaintext']['mapping_pr'] == 'PR:[redacted by --private]'")
PY
python3 clarity.py --json --known "$tmp/probe-plain.bin" "$tmp/probe-shuffle.grb" > "$tmp/shuffle.json"
python3 - "$tmp/shuffle.json" <<'PY'
import json, sys
def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

obj = json.load(open(sys.argv[1], encoding="utf-8"))
require(obj['known_plaintext']['kind'] == 'fixed_block_position_permutation', "assertion failed: obj['known_plaintext']['kind'] == 'fixed_block_position_permutation'")
require(obj['known_plaintext']['offset'] == 16, "assertion failed: obj['known_plaintext']['offset'] == 16")
require(obj['known_plaintext']['block_size'] == 16, "assertion failed: obj['known_plaintext']['block_size'] == 16")
require(obj['known_plaintext']['verified_bytes'] % 16 == 0, "assertion failed: obj['known_plaintext']['verified_bytes'] % 16 == 0")
require(obj['known_plaintext']['trailing_bytes'] == 8, "assertion failed: obj['known_plaintext']['trailing_bytes'] == 8")
require(obj['known_plaintext']['mapping_pr'].startswith('PR:[out->in '), "assertion failed: obj['known_plaintext']['mapping_pr'].startswith('PR:[out->in ')")
PY

# --- Bullshit-fuzzer 1: ciphertext-only periodicity claim vs hostile near-misses. ---
# Exactly 300 deterministic specimens. A wrong period is a false claim, not a near miss.
python3 - <<'PY'
import random
import clarity

def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

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

require(tp + fn == 100, 'assertion failed: tp + fn == 100')
require(fp + tn == 200, 'assertion failed: fp + tn == 200')
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

def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

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

require(tp + fn == 100, 'assertion failed: tp + fn == 100')
require(fp + tn == 200, 'assertion failed: fp + tn == 200')
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

def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

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

require(tp + fn == 100, 'assertion failed: tp + fn == 100')
require(fp + tn == 200, 'assertion failed: fp + tn == 200')
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

def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

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

require(tp + fn == 100, 'assertion failed: tp + fn == 100')
require(partial_ok + partial_wrong == 100, 'assertion failed: partial_ok + partial_wrong == 100')
require(fp + tn == 100, 'assertion failed: fp + tn == 100')
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
check_real_identity() {
    specimen=$1
    expected=$2
    ./clarity.py --analyze --json "$specimen" > "$tmp/real-ksy.json"
    python3 - "$tmp/real-ksy.json" "$expected" "$specimen" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
expected, specimen = sys.argv[2:]
def require(condition, message):
    if not condition:
        raise SystemExit(f"FAIL: {specimen}: {message}")
views = obj.get("views", [])
matches = [v for v in views if v.get("ksy_id") == expected and v.get("strong_identity")]
if not matches:
    detail = [(v.get("ksy_id", v.get("kind")), v.get("issues", [])[:1]) for v in views]
    raise SystemExit(f"FAIL: {specimen} did not earn {expected} identity; views={detail}")
for view in matches:
    evidence = view.get("evidence", {})
    require(evidence.get("anchor") == 1, "identity lacks its anchor evidence")
    require(any(value for key, value in evidence.items() if key != "anchor"),
            f"identity lacks independent evidence: {evidence}")
PY
}

check_real_identity test/gpt.img gpt_partition_table
check_real_identity test/sample.png png
check_real_identity test/x86_64.elf elf
check_real_identity test/george.zip zip
check_real_identity test/george.gz gzip
check_real_identity test/george.tar.gz gzip
check_real_identity test/sample.iso iso9660
check_real_identity test/sample.sqlite sqlite3
check_real_identity test/sample.avi avi
check_real_identity test/sample.mp3 id3v2_3
# This specimen's suffix is misleading; its bytes are an ordinary gzip stream.
check_real_identity test/george2.jpg jpeg
check_real_identity test/sample.wav wav
check_real_identity test/fat.img vfat
check_real_identity test/ext2.img ext2
[ -f test/cmd.exe ] || { echo "FAIL: missing acceptance specimen test/cmd.exe" >&2; exit 1; }
check_real_identity test/cmd.exe microsoft_pe

# The in-stream specimen is a truncated cpio member: its ELF header and scalar
# constraints are present at offset 832, while its section table lies beyond the
# available bytes.  Identify the embedded object while retaining its incomplete
# projection and without describing the enclosing stream as an ELF root.
./clarity.py --analyze --json test/elf_x86_64_in-stream.elf > "$tmp/in-stream-elf.json"
python3 - "$tmp/in-stream-elf.json" <<'PY'
import json, sys

obj = json.load(open(sys.argv[1], encoding="utf-8"))
views = [
    view for view in obj.get("views", [])
    if view.get("ksy_id") == "elf" and view.get("offset") == 832
]
if len(views) != 1:
    raise SystemExit(f"FAIL: expected one ELF structural view at offset 832; got {len(views)}")
view = views[0]
if not view.get("partial") or not view.get("strong_identity"):
    raise SystemExit("FAIL: truncated embedded ELF must retain identity and a partial projection")
if not any("section_headers offset outside selected stream" in issue for issue in view.get("issues", [])):
    raise SystemExit(f"FAIL: missing ELF truncation reason: {view.get('issues', [])}")
claims = [claim for claim in obj.get("claims", []) if claim.get("kind") == "elf"]
if len(claims) != 1 or claims[0].get("offset") != 832:
    raise SystemExit(f"FAIL: missing embedded ELF identity claim: {claims}")
if not claims[0].get("partial") or claims[0].get("class_bits") != 64 or claims[0].get("endian") != "little":
    raise SystemExit("FAIL: embedded ELF identity lost projection completeness")
values = {a.get("path"): a.get("value") for a in view.get("annotations", [])}
expected = {
    "elf.bits": 2,
    "elf.endian": 1,
    "elf.ei_version": 1,
    "elf.header.e_type": 1,
    "elf.header.machine": 62,
    "elf.header.e_version": 1,
    "elf.header.e_ehsize": 64,
    "elf.header.section_header_entry_size": 64,
    "elf.header.qty_section_header": 77,
}
if any(values.get(path) != value for path, value in expected.items()):
    raise SystemExit(f"FAIL: embedded ELF header validation changed: {values}")
PY

# FatPix supplies a bounded window and an absolute base offset.  It must receive
# the same embedded object and absolute annotation coordinates.
dd if=test/elf_x86_64_in-stream.elf of="$tmp/elf-window.bin" bs=1 skip=768 status=none
./clarity.py --analyze --json --windowed --base-offset 0x300 "$tmp/elf-window.bin" > "$tmp/elf-window.json"
python3 - "$tmp/elf-window.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
views = [v for v in obj.get("views", []) if v.get("ksy_id") == "elf"]
if len(views) != 1 or views[0].get("offset") != 832 or not views[0].get("strong_identity"):
    raise SystemExit(f"FAIL: windowed embedded ELF identity/offset changed: {views}")
claims = [c for c in obj.get("claims", []) if c.get("kind") == "elf"]
if len(claims) != 1 or claims[0].get("offset") != 832 or not claims[0].get("partial"):
    raise SystemExit(f"FAIL: windowed embedded ELF claim changed: {claims}")
if not all(int(a["start"]) >= 768 for a in views[0].get("annotations", [])):
    raise SystemExit("FAIL: windowed ELF annotations are not absolute")
PY

# Magic alone nominates nothing: malformed header geometry and values cannot
# earn either a structural identity view or an ELF identity claim.
printf 'prefix\177ELFbroken incidental bytes' > "$tmp/incidental-elf.bin"
./clarity.py --analyze --json "$tmp/incidental-elf.bin" > "$tmp/incidental-elf.json"
python3 - "$tmp/incidental-elf.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
if any(v.get("ksy_id") == "elf" and v.get("strong_identity") for v in obj.get("views", [])):
    raise SystemExit("FAIL: incidental ELF magic earned structural identity")
if any(c.get("kind") in {"elf", "ksy_identity"} for c in obj.get("claims", [])):
    raise SystemExit("FAIL: incidental ELF magic earned an identity claim")
PY

# Identity and byte-map acceptance are deliberately separate.  A known whole
# file is fully projected only when annotations owned by its primary format
# cover byte 0 through EOF.  JPEG and gzip are positive controls.  PNG, ZIP,
# and SQLite record their presently known uncovered tails rather than being
# mislabeled as projection passes.  ISO9660 has device/filesystem geometry and
# is intentionally outside this whole-file rule for now.
check_real_projection() {
    specimen=$1
    expected=$2
    ./clarity.py --analyze --json "$specimen" > "$tmp/real-projection.json"
    python3 - "$tmp/real-projection.json" "$specimen" "$expected" <<'PY'
import json, os, sys

result_path, specimen, expected = sys.argv[1:]
obj = json.load(open(result_path, encoding="utf-8"))
size = os.path.getsize(specimen)
roots = [
    v for v in obj.get("views", [])
    if v.get("ksy_id") == expected and v.get("offset") == 0 and v.get("strong_identity")
]
if len(roots) != 1:
    raise SystemExit(f"FAIL: {specimen} expected one strong {expected} root at 0; got {len(roots)}")
view = roots[0]
intervals = sorted(
    (max(0, int(a["start"])), min(size, int(a["end"])))
    for a in view.get("annotations", [])
    if int(a.get("end", 0)) > int(a.get("start", 0))
)
covered = []
for start, end in intervals:
    if end <= start:
        continue
    if covered and start <= covered[-1][1]:
        covered[-1][1] = max(covered[-1][1], end)
    else:
        covered.append([start, end])
holes = []
cursor = 0
for start, end in covered:
    if start > cursor:
        holes.append([cursor, start])
    cursor = max(cursor, end)
if cursor < size:
    holes.append([cursor, size])
competing = [
    (v.get("ksy_id", v.get("kind")), v.get("offset"), v.get("extent"),
     v.get("strong_identity"), v.get("partial"), v.get("issues"))
    for v in obj.get("views", []) if v is not view
    if int(v.get("offset", -1)) < size and int(v.get("offset", -1)) + int(v.get("extent", 0)) > 0
]
print(
    f"projection audit: {specimen} expected=0:{size} identity={expected} "
    f"view={(view.get('offset'), view.get('extent'))} covered={covered} holes={holes} "
    f"partial={view.get('partial')} issues={view.get('issues')} competing={competing}"
)
if holes:
    raise SystemExit(f"FAIL: {specimen} {expected} leaves uncovered ranges {holes}")
PY
}

check_real_projection test/george2.jpg jpeg
check_real_projection test/george.gz gzip
check_real_projection test/george.tar.gz gzip

check_real_projection test/sample.png png
check_real_projection test/george.zip zip
check_real_projection test/sample.sqlite sqlite3
check_real_projection test/sample.wav wav

# SQLite's opaque later pages are justified by an authored KSY extent
# relationship, not by searching arbitrary parsed integers for a product that
# happens to equal EOF.
./clarity.py --analyze --json test/sample.sqlite > "$tmp/sqlite-extent-proof.json"
python3 - "$tmp/sqlite-extent-proof.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
sqlite = [v for v in obj["views"] if v.get("ksy_id") == "sqlite3" and v.get("offset") == 0]
if len(sqlite) != 1:
    raise SystemExit(f"FAIL: expected one root SQLite view, got {len(sqlite)}")
opaque = [a for a in sqlite[0]["annotations"] if a.get("path") == "sqlite3.opaque_allocation_units"]
if len(opaque) != 1:
    raise SystemExit(f"FAIL: expected one SQLite opaque-page annotation, got {len(opaque)}")
proof = opaque[0]
if proof.get("extent_instance") != "len_database":
    raise SystemExit(f"FAIL: SQLite extent lacks KSY instance provenance: {proof}")
if proof.get("size_rule") != "len_page * num_pages":
    raise SystemExit(f"FAIL: SQLite extent lacks authored size/count relationship: {proof}")
if proof.get("extent_operands") != ["len_page", "num_pages"]:
    raise SystemExit(f"FAIL: SQLite extent operands are not explicit: {proof}")
PY

# The shared RIFF anchor may nominate AVI, but its contradicted form-type
# literal must not survive beside the strongly corroborated WAV root.
./clarity.py --analyze --json test/sample.wav > "$tmp/wav-projection-audit.json"
python3 - "$tmp/wav-projection-audit.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
avi = [v for v in obj["views"] if v.get("ksy_id") == "avi"]
if avi:
    raise SystemExit(f"FAIL: contradicted AVI view still overlaps known WAV: {avi}")
PY

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
if not views or not any(v.get("partial") and v.get("issues") for v in views):
    raise SystemExit("FAIL: expected explicit partial/issues state for " + sys.argv[2])
PY
done

# Preserve the global clue while disproving a predicted secondary literal. The
# candidate remains inspectable as a partial structural hypothesis, but a hard
# contradiction must withhold identity.
cp test/sample.png "$tmp/png-near-miss"
printf 'JUNK' | dd of="$tmp/png-near-miss" bs=1 seek=12 conv=notrunc status=none
./clarity.py --analyze --json "$tmp/png-near-miss" > "$tmp/png-near-miss.json"
python3 - "$tmp/png-near-miss.json" <<'PY'
import json, sys
def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

obj = json.load(open(sys.argv[1], encoding="utf-8"))
views = [v for v in obj["views"] if v.get("ksy_id") == "png"]
require(views, 'PNG signature should still nominate a visible candidate')
require(not any((v.get('strong_identity') for v in views)), "assertion failed: not any((v.get('strong_identity') for v in views))")
require(any((v.get('hard_contradictions') for v in views)), "assertion failed: any((v.get('hard_contradictions') for v in views))")
PY

# PE's cheap MZ clue survives, but the root-relative PE signature predicted by
# e_lfanew is contradicted. This specifically guards against MZ-only identity.
cp test/cmd.exe "$tmp/pe-near-miss"
python3 - "$tmp/pe-near-miss" <<'PY'
import sys
def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

p = sys.argv[1]
b = bytearray(open(p, "rb").read())
ofs = int.from_bytes(b[0x3c:0x40], "little")
require(b[ofs:ofs + 4] == b'PE\x00\x00', "assertion failed: b[ofs:ofs + 4] == b'PE\\x00\\x00'")
b[ofs:ofs + 4] = b"PX\0\0"
open(p, "wb").write(b)
PY
./clarity.py --analyze --json "$tmp/pe-near-miss" > "$tmp/pe-near-miss.json"
python3 - "$tmp/pe-near-miss.json" <<'PY'
import json, sys
def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

obj = json.load(open(sys.argv[1], encoding="utf-8"))
views = [v for v in obj["views"] if v.get("ksy_id") == "microsoft_pe"]
require(views, 'MZ should retain the PE candidate hypothesis')
require(not any((v.get('strong_identity') for v in views)), "assertion failed: not any((v.get('strong_identity') for v in views))")
require(any((v.get('hard_contradictions') for v in views)), "assertion failed: any((v.get('hard_contradictions') for v in views))")
PY

# Strong anchors remain root-relative during structural scanning. Two complete
# PNGs at nonzero offsets must yield two embedded identities, while common PK
# bytes in the surrounding payload must not nominate embedded ZIP identities.
python3 - <<'PY' > "$tmp/two-embedded-pngs"
import sys
png = open("test/sample.png", "rb").read()
sys.stdout.buffer.write(b"prefix-PK-noise" + png + b"middle-PK-noise" + png + b"tail")
PY
./clarity.py --analyze --json --windowed "$tmp/two-embedded-pngs" > "$tmp/two-embedded.json"
python3 - "$tmp/two-embedded.json" <<'PY'
import json, sys
def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

obj = json.load(open(sys.argv[1], encoding="utf-8"))
pngs = [v for v in obj["views"] if v.get("ksy_id") == "png"]
require(len({v['offset'] for v in pngs}) == 2, "assertion failed: len({v['offset'] for v in pngs}) == 2")
require(all((v.get('strong_identity') for v in pngs)), "assertion failed: all((v.get('strong_identity') for v in pngs))")
claims = [c for c in obj.get('claims', []) if c.get('kind') == 'ksy_identity' and c.get('ksy_id') == 'png']
require({c['offset'] for c in claims} == {v['offset'] for v in pngs}, "embedded PNG claims do not match views")
require(not any((v.get('ksy_id') == 'zip' for v in obj['views'])), "assertion failed: not any((v.get('ksy_id') == 'zip' for v in obj['views']))")
PY

# Real MBR acceptance must follow the same public paths as a user.  Keep both
# renderers here: checking a helper (or JSON alone) can conceal a broken text
# command, and checking Clarity alone says nothing about FatPix's C-key bridge.
./clarity.py --analyze test/mbr.img > "$tmp/real-mbr.txt"
grep -F "View: MBR-shaped sector at 0x0 (strong fit)" "$tmp/real-mbr.txt" >/dev/null
grep -F "CLAIM: structurally consistent MBR partition table" "$tmp/real-mbr.txt" >/dev/null

./clarity.py --analyze --json test/mbr.img > "$tmp/real-mbr.json"
python3 - "$tmp/real-mbr.json" <<'PY'
import json, sys
def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

obj = json.load(open(sys.argv[1], encoding="utf-8"))
require(any((c.get('kind') == 'mbr_partition_table' for c in obj.get('claims', []))), "assertion failed: any((c.get('kind') == 'mbr_partition_table' for c in obj.get('claims', [])))")
views = [v for v in obj.get("views", []) if v.get("kind") == "mbr_partition_table"]
require(any((v.get('offset') == 0 and v.get('strong_identity') for v in views)), "assertion failed: any((v.get('offset') == 0 and v.get('strong_identity') for v in views))")
require(any((a.get('path') == 'mbr.boot_signature' for v in views if v.get('offset') == 0 for a in v.get('annotations', []))), "assertion failed: any((a.get('path') == 'mbr.boot_signature' for v in views if v.get('offset') == 0 for a in v.get('annotations', [])))")
PY

# Drive the real terminal application through a pseudo-terminal: launch the
# public command, press C, open the semantic legend with c, and verify that the
# retained overlay contains fields supplied by Clarity's MBR view.
python3 - "$tmp/fatpix-mbr.tty" <<'PY'
import os, pty, select, subprocess, sys, time

def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

capture = sys.argv[1]
master, slave = pty.openpty()
proc = subprocess.Popen(
    ["./fatpix", "--file", "test/mbr.img"],
    stdin=slave,
    stdout=slave,
    stderr=slave,
    env={**os.environ, "TERM": "xterm-256color"},
    close_fds=True,
)
os.close(slave)
output = bytearray()

def drain_until(needle, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.1)
        if ready:
            try:
                output.extend(os.read(master, 65536))
            except OSError:
                break
        if needle in output:
            return True
    return needle in output

try:
    require(drain_until(b'resized terminal', 3), 'FatPix did not reach its public file view')
    os.write(master, b"C")
    require(drain_until(b'Clarity semantic view:', 15), 'C did not activate the Clarity bridge')
    os.write(master, b"c")
    require(drain_until(b'bootstrap_code', 3), 'FatPix did not retain/render the MBR structural view')
    require(b'boot_signature' in output, 'MBR signature annotation was not retained')
    os.write(master, b"q")
    proc.wait(timeout=3)
    require(proc.returncode == 0, 'assertion failed: proc.returncode == 0')
finally:
    if proc.poll() is None:
        proc.kill()
        proc.wait()
    os.close(master)
    open(capture, "wb").write(output)
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
def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + str(message))

obj = json.load(open(sys.argv[1], encoding="utf-8"))
require(not any((v.get('strong_identity') for v in obj.get('views', []))), "assertion failed: not any((v.get('strong_identity') for v in obj.get('views', [])))")
PY
done

echo "PASS: mechanics + metrology + stats/analyze/JSON contracts + 1800-case truth universe + real KSY acceptance"
