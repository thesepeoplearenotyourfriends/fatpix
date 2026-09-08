# FatPix, Clarity, and Garble

Small, local tools for seeing, interpreting, and experimentally transforming
opaque bytes. FatPix is a terminal visualizer, Clarity is an evidence-conscious
binary analyzer, and Garble provides reversible transformations.

## Changelog

### 2026-09-08

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
