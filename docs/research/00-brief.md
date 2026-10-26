# Research brief

This directory holds stage research for `bouncer`. Each document belongs to one
stage and is reviewed before implementation starts.

## Shared context

Read [`../design.md`](../design.md) first. Fixed decisions (do not re-litigate):

- Module `github.com/sparklyi/bouncer`, MIT, `go 1.26.0`, core has **zero**
  third-party dependencies. Optional backends live in their own `go.mod`.
- L0 sealed ticket + atomic `Consume`/`Attempt`; L1 PoW with escalation;
  L2 slide with server-side trajectory scoring and a sealed target `x`.
- `Store` failures default to fail-closed.
- No image-text CAPTCHA, no audio CAPTCHA, no risk engine, no service.

## Rules for authors

1. Write exactly one file, the one assigned to you. Do not touch other files.
2. **Do not run any git command.** The maintainer commits and opens PRs.
3. **No heavy local work**: no benchmarks, no training, no browser automation runs,
   no container builds. Research by reading sources and citing them. Keep the
   machine idle; a few HTTP fetches are fine.
4. Prefer primary sources (stdlib docs, RFCs, papers, upstream code) with exact
   versions and links. Mark anything you could not verify as `unverified`.
5. Do not include personal data, credentials, internal hostnames, private URLs, or
   anything that cannot be published publicly.
6. Write in English, concise, skimmable. Target 800–1400 words.

## Required structure for every document

```
# <topic>
## Verdict            — 5 bullet answers the maintainer can act on
## Facts              — verified facts with links/versions
## Options            — comparison table with trade-offs
## Recommendation     — concrete choices for bouncer, with numbers
## Risks & unknowns   — what could be wrong, what needs measurement later
## Sources            — numbered list, URLs
```

## Stage map

| Doc | Stage | Owner scope |
| --- | --- | --- |
| `01-go-library-architecture.md` | M0/M1 | Go library layout, design patterns, API/error/testing conventions |
| `02-ticket-crypto-and-store.md` | M1/M2 | AEAD tickets, HKDF rotation, Redis/memory store atomics, fuzzing |
| `03-proof-of-work.md` | L1 | PoW construction, difficulty calibration, browser solver |
| `04-slide-trajectory.md` | L2 | Trajectory features, bot forgery, datasets, procedural backgrounds |
| `05-attack-baseline.md` | M4 | Reproducible break-rate experiments, competitor attacks, ethics |
