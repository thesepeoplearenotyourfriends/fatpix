# fatpix family in a nutshell:

What it has started to feel like is not really “three little binary utilities,” but an attempt to build a small, self-contained way of making opaque bytes intelligible.

Not intelligible in the sense of handing a file to some enormous forensic suite and getting a taxonomy dump back. More like having a few good instruments on a bench. Garble lets you deliberately disturb the material and see what survives. FatPix lets you look at the material spatially, at scales where patterns become obvious before you necessarily know what they mean. Clarity tries to put language around what can actually be justified from the evidence. They overlap, but none of them is supposed to swallow the others.

There’s a kind of hierarchy emerging naturally:

FatPix is perception. Clarity is interpretation. Garble is experiment.

FatPix is intentionally primitive in the complimentary sense: bytes become blocks, structure becomes geography, and you can zoom from tiny local changes out to enormous regions without pretending the underlying thing has become something other than bytes. The terminal-only constraint is part of its character, not merely an implementation shortcut. It should remain the sort of thing that could eventually become a scorching-fast little C binary you could carry into an initrd and point at anything.

Clarity is the more ambitious half. It isn’t supposed to be “a Kaitai viewer.” Kaitai is one source of accumulated structural knowledge; magic.mgc may eventually be another. Clarity’s real job is to sit above those and reason about what the available evidence permits it to say. Sometimes that means “this is a PNG.” Sometimes “this region has the shape of part of an ext2 structure.” Sometimes “these bytes exhibit a repeating transformation.” And sometimes the correct answer is simply “I don’t know.” The distinction between those states matters more than breadth of recognition.

That, to me, is probably the central spirit of the whole thing: legibility without bullshit.

A lot of binary tooling is very good at producing authoritative-looking output. This project seems more interested in making the boundary between observation and inference visible. Structure, identity, transformation, and recovery are different claims. A damaged object can still contain true local structure. A short magic value can nominate a possibility without proving it. A parser failing later in the file should not retroactively make the bytes it already understood unknowable. Clarity’s name became increasingly appropriate in that sense.

The last several hours with the KSY work were painful, but they actually sharpened that philosophy. The fake reduced KSY tests were exactly the kind of thing this project ought to distrust: a closed little world in which the implementation and the evidence had quietly been arranged to agree. Everything was green because the test universe had been made friendly. The real files immediately broke that illusion. That is almost comically on-theme for Clarity: the test suite itself needed to be subjected to the same rule as the data — do not confuse a convenient model with the thing being observed.

There’s also a consistent engineering ethic underneath all three programs. Import accumulated knowledge, not accumulated infrastructure. Use the real Kaitai definitions, but don’t drag in a giant parser ecosystem merely to read them. Maybe consume magic.mgc, but don’t turn file(1) into a required runtime religion. Prefer a few thousand understandable lines over frameworks and background services. Keep the filesystem as truth. Stay offline-capable. Make failures inspectable. Avoid dependencies that become more substantial than the tool itself.

So if I had to compress the endeavor into one description, I’d probably call it:

A tiny field kit for binary literacy: tools for seeing, perturbing, and reasoning about arbitrary bytes while preserving the distinction between what is visible, what is known, and what is merely suspected.

And there’s a pleasingly old-computer quality to it. Not nostalgia exactly — more the idea that a program should be small enough to comprehend, useful without a network, willing to operate on raw things directly, and capable of telling you something interesting without first demanding that the world be imported into its database.


## Project shape

This repository contains a small family of related binary-inspection tools:

- **FatPix** — a terminal-only visual explorer for files, disks, and other byte streams.
- **Clarity** — a general-purpose CLI analyzer for identifying, measuring, and describing binary structure.
- **Garble** — a small reversible binary transformation tool used for experimentation and as part of the same project family.

These tools are intended to stay small, local, understandable, and useful on ordinary Unix-like systems.

## Direction

Python is the current implementation language because it is fast to iterate on and well suited to prototyping parsers and analysis logic. It should be treated as a likely staging language for a later, smaller C implementation where that makes sense.

Do not introduce Rust, GUI frameworks, large runtimes, package ecosystems, or architectural layers without a compelling project-specific reason.

Prefer the Python standard library and small self-contained code.

## FatPix

FatPix is intentionally a **terminal program**.

The intended direction is:

- no X11
- no Wayland dependency
- no framebuffer GUI
- no Qt / GTK / SDL-style application layer
- no requirement for a desktop session

Its identity is the retro terminal block grid. Do not replace that with high-density pixel rendering.

FatPix should remain useful in constrained environments, including machines where a graphical stack is absent or undesirable.

Clarity mode in FatPix is a **semantic lens**: recognized structure can determine block color and structural boundaries, while unknown bytes retain the ordinary FatPix rendering.

FatPix should consume Clarity's proven structural results rather than developing a separate competing recognizer.

## Clarity

Clarity is not merely a Kaitai frontend.

It is intended to remain a useful standalone CLI tool for in-depth binary analysis, including:

- byte/statistical metrology
- entropy and compressibility observations
- periodicity / repeating relationships
- known-plaintext and transformation relationships
- structural-character observations
- executable / filesystem / container evidence
- partial and damaged structures
- generic structural parsing via Kaitai definitions

The core rule is:

> Claim what the evidence supports; abstain where it does not.

Partial evidence should remain visible. A later truncation, unsupported construct, or unresolved reference should not erase earlier facts that were already proven.

Clarity should distinguish structure, identity, transformation, and recovery rather than treating them as interchangeable claims.

### Kaitai

`/kaitai` is the authoritative Kaitai Struct format corpus for this repository.

Do not substitute simplified or test-only KSY definitions when claiming format support.

The acceptance path is:

```text
real specimen
  -> anonymous input
  -> candidate nomination
  -> real /kaitai KSY
  -> structural parse
  -> evidence-backed Clarity result
```

`/test` is the primary acceptance corpus. Real files there should drive integration work.

Synthetic byte fixtures are fine for narrow interpreter/unit tests, but they must not be used as evidence that a real format is supported.

Prefer generic improvements to KSY interpretation, candidate nomination, partial parsing, evidence accounting, and projection over handwritten format-specific parsers.

### Future format knowledge

There is an aspiration to also use the `file(1)` magic database (`magic.mgc`) as another source of accumulated format knowledge.

The intended relationship is roughly:

```text
magic.mgc  -> what might this be?
.ksy       -> if it is this, what are its parts?
Clarity    -> what evidence is actually present, including partial resemblance?
```

Do not make `file(1)` or Kaitai compiler runtimes mandatory dependencies merely to gain access to their accumulated definitions if the useful data can be consumed directly.

## Garble

Garble belongs to the same family but has a different role: small reversible transforms for experimentation, pedagogy, and producing interesting binary structure.

It is not intended to pretend that simple reversible transforms are cryptography.

Keep Garble small and mechanically clear.

## Testing

Tests should protect truth, not merely implementation convenience.

Important principles:

- real `/kaitai` definitions for format-support tests
- real `/test` specimens for end-to-end recognition tests
- negative/random/blank inputs to catch false positives
- wrong confident claims are worse than abstention
- preserve separate unit tests for parser mechanics, but do not confuse them with format acceptance

When a real file fails, reproduce the failure through the CLI first:

```bash
./clarity.py --analyze test/<specimen>
```

Fix the common mechanism if possible before adding format-specific exceptions.

FatPix should then use the same proven logic, with the caveat that a viewport may contain only part of an object.

## Operational character

This project is deliberately hostile to dependency sprawl and unnecessary infrastructure.

Prefer:

- local/offline operation
- deterministic behavior
- small code
- explicit data flow
- ordinary files and Unix interfaces
- useful output without network access
- understandable failure modes

Avoid silently adding network behavior, telemetry, background services, heavyweight build systems, or desktop assumptions.

Keep changes proportional to the problem. The project should remain something a person can understand by reading the source rather than a framework that happens to contain a binary inspector.

## Validation: 

Codex owns validation. Before opening or updating a PR, run the relevant tests yourself and report the actual results; do not merely add tests for someone else to run. The test suite is cumulative: extend existing coverage rather than replacing or deleting unrelated regression tests to make room for new acceptance tests. test.sh should retain Clarity/Garble mechanics, metrology, falsification, and regression coverage while also exercising real /test specimens end-to-end against the authoritative /kaitai corpus. Checked-in /test specimens and /kaitai definitions are inputs to the tests; do not regenerate, substitute, or download replacements for them during ordinary test runs.

## On scope: 

When changing the KSY interpreter itself, tie the change to a specific construct encountered in a real /kaitai definition or a demonstrated parser defect; do not broaden the parser speculatively.

## Changelog maintenance:

Maintain the project changelog in README.md, newest entries first. Every PR must update it. Treat the changelog as a concise historical record, not a second copy of the PR description: say plainly what changed, what was added, fixed, removed, or altered in behavior, and leave out promotional language, ceremony, implementation play-by-play, and inflated summaries. A reader scanning the README months later should be able to understand the project’s evolution quickly from the changelog alone.
