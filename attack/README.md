# Attack baseline

**Status: methodology only.** No numbers are published yet, and this repository
will not publish a break rate without the raw data, the harness commit, the
library versions and the hardware next to it.

## Why this directory exists

"Better than the alternatives" is a claim that has to be measured on the same
attack script, at the same time, on the same machine. No public, reproducible
break-rate measurement exists for the Go CAPTCHA libraries we compared, so the
only honest option is to build one.

## Adversary tiers

| Tier | Implementation | What it measures |
| --- | --- | --- |
| T0 | protocol abuse: replayed ticket, empty answer, cross-subject reuse, expired ticket | L0 correctness |
| T1 | POST loop with no solver | whether a challenge is required at all |
| T2 | tesseract 5 + `tessdata_best` | legibility of image challenges |
| T3 | small CNN trained on 2k-10k harvested samples | image entropy |
| T4 | headless Chromium + in-page solver | end-to-end, including JS |
| T5 | Bezier/jitter/pause trajectory faker | L2 scoring |
| T6 | price list only, never buy solves | cost ceiling |

## Protocol

- 1,000 challenges per arm, three seeds, Wilson 95% confidence intervals.
- Report `break@k` (fraction solved within k attempts), attempts-to-success
  (median, Kaplan-Meier if censored), wall time p50/p95, and server time as
  ns/verify.
- Publish every arm, not the best one, and include negative results.
- Loopback instances only, pinned versions, recorded configuration.

## Cost model

```
$/1k successes = 1000 * (2^degree / H) * cost_per_gpu_second / break_rate
```

Reference inputs (verified 2026-10-26): RTX 4090 SHA-256 at 21,975 MH/s; human
slider solving at $1.20/1k; residential proxies at $2.50-$7.00/GB. At 20 bits a
GPU attacker pays well under one cent per thousand attempts, which is why the
README describes PoW as a rate limiter rather than a wall.

## Rules

- Test only deployments you started.
- Never point a harness at a vendor demo, a customer, or a third-party site.
- Never buy or scrape solutions; use published price lists for the T6 ceiling.
- Disclose findings to the affected maintainer before publishing.
- Delete traces that could identify a person; publish only opt-in corpora.
