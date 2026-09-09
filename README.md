# FatPix, Clarity, and Garble

Small, local tools for seeing, interpreting, and experimentally transforming
opaque bytes. FatPix is a terminal visualizer, Clarity is an evidence-conscious
binary analyzer, and Garble provides reversible transformations.

## Native FatPix

Build the framebuffer viewer with `make fatpix-c`, then run it from a Linux VT
with `./fatpix-c FILE`. It writes directly to `/dev/fb0` (override with
`--fb PATH`) and uses no window-system or terminal UI library. Arrow keys or
WASD move, Page Up/Down move half a viewport, `-`/`=` zoom, `g` prompts for an
offset, `:g OFFSET` and `:s SCALE` provide direct navigation, and `q` exits.
Press `i` for a centered hex/ASCII inspector around the cursor; `i` or Escape
closes it. A mouse available through `/dev/input/mice` gets a framebuffer
crosshair: click selects one fat-pixel byte range and drag extends a contiguous
selection. Use `--mouse PATH` for another compatible PS/2 packet device or
`--no-mouse` for keyboard-only operation. Scale values accept binary suffixes
such as `10K` and `1.5M`.

For framebuffer-independent inspection and parity testing, both implementations
can emit literal classifications:

```text
./fatpix-c --dump-grid 16x8 --scale 1K FILE
./fatpix --file FILE --dump-grid 16x8 --scale 1K
```

## Changelog

### 2026-09-09

- Added the native FatPix hex inspector and direct mouse selection, including
  drag ranges, selection outlines, and an on-screen pointer.
- Added a native Linux framebuffer FatPix viewer with regular-file and block-
  device sources, bounded representative sampling, literal colors, navigation,
  direct scale and goto commands, VT restoration, and the built-in 5x7 font.
- Added matching deterministic logical-grid output to the Python and C viewers
  for literal-lens parity checks without a framebuffer.
- Ensured native builds are available to `make check` and made idle signals and
  raw Ctrl-C promptly leave the input loop so VT state is restored.

### 2026-09-08

- Coalesced buffered FatPix zoom repeats so only the final requested viewport is
  read and rendered.
- Restored separate small and large FatPix zoom steps and added abbreviated
  `goto`/`scale` commands with fractional binary-unit scale targets.
- Displayed FatPix selections as inclusive human-readable byte ranges while
  retaining half-open ranges internally.
- Identified corroborated ELF objects embedded within larger byte streams while
  reporting truncated projections separately from identity confidence.
- Simplified FatPix's permanent file footer and moved cell diagnostics into its
  inspector pages.
- Removed a stale acceptance reference to a deleted corrupt JPEG fixture.
- Grounded SQLite opaque-page ownership in an explicit KSY page-size/page-count
  extent relationship instead of inferring geometry from matching scalars.
- Completed whole-file projection for the real PNG, ZIP, SQLite, and WAV
  specimens and suppressed contradicted same-root views beside strong identity.
- Separated real-file identity checks from structural-coverage checks, recording
  known PNG, ZIP, and SQLite gaps, WAV/AVI overlap, and full JPEG/gzip maps.
- Bounded queued navigation repeats and made terminal quit input preempt stale
  movement without dropping commands, text, or mouse events.
- Added public-command MBR regressions for Clarity's text and JSON output and
  FatPix's interactive `C` semantic-view path, and made `fatpix` executable.
- Restored the general Clarity, Garble, falsification, privacy, and JSON contract
  tests while keeping real-corpus KSY format acceptance separate.
- Prevented FAT boot sectors from being promoted as MBR identity through generic
  KSY signature nomination.
- Restored root-relative embedded scanning for distinctive KSY clues while
  keeping short clues local to an existing candidate root.
- Added real AVI and ID3/MP3 acceptance and root-relative multi-object scanning
  coverage.
- Added real FAT, ext2, JPEG, and WAV acceptance, retaining explicit unresolved
  reasons for partial filesystem projections.
- Replaced annotation-count identity promotion with categorized structural
  evidence accounting and added required anonymous PE acceptance for `test/cmd.exe`.
- Removed typed-structure traversal as standalone identity evidence and added
  anchor-preserving PNG and PE contradiction tests.

### 2026-09-08

- Clarity now nominates short KSY signatures conservatively, retains proven
  structure after later parser failures, and automatically recognizes real PNG,
  ELF, ZIP, gzip, ISO9660, and SQLite specimens.
- Replaced generated KSY format tests with end-to-end acceptance tests using the
  repository's real Kaitai corpus and ordinary files under `test/`.
