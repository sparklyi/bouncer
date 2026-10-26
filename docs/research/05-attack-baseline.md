# Measuring "better" honestly: attack baseline and competitor comparison

## Verdict

- Publish **cost per 1,000 successful breaks** per adversary class, with hardware,
  price date and library version. A bare "break rate" is not comparable.
- The defensible L1 claim is *zero human supply chain and ~zero defender cost*, not
  "expensive for attackers": 2^28 hashes is 12 ms on one RTX 4090 (≈$0.002/1k).
- We found no public, reproducible break-rate measurement for any of the five Go
  libraries (searched 2026-10-26). The baseline must be built here.
- Fix the README claim first: in go-captcha v2.0.5 `ModeBasic` sets `DY = Y`, so
  the official example's `tile_y` *is* the answer's y; `DX` is only the drag start.
  `GetData()` returns both.
- Use 1,000 challenges per arm, three seeds, Wilson 95% CIs. ~430/arm is the floor
  for a 10%→5% claim at 80% power, so do not claim smaller deltas.

## Facts

### Versions (proxy.golang.org, 2026-10-26)

| Module | Latest | Published |
| --- | --- | --- |
| `github.com/mojocn/base64Captcha` | v1.3.8 | 2025-01-09 |
| `github.com/dchest/captcha` | v1.1.0 | 2024-12-11 |
| `github.com/wenlng/go-captcha/v2` | v2.0.5 | 2026-03-07 |
| `github.com/afocus/captcha` | untagged (pseudo) | 2026-10-10 |
| `github.com/steambap/captcha` | v1.4.1 | 2021-08-25 |

### Verified code-level properties

- **base64Captcha v1.3.8.** `Generate() (id, b64s, answer, err)` returns the answer
  in the caller's tuple. `Verify(id, answer, clear)` does `store.Get(id, clear)` and
  `EqualFold`; with `clear=false` the same id is retried indefinitely. No issuance
  cap, no subject binding, TTL GC only.
- **dchest/captcha v1.1.0.** The README states the captcha "can be broken by
  advanced OCR captcha breaking algorithms". Verify removes the id; default
  `Expiration = 10 * time.Minute`.
- **go-captcha/v2 v2.0.5.** `GetData()` returns JSON-tagged `x`,`y` (target) beside
  `dx`,`dy` (display). `ModeBasic` sets `TileY = Y` and `DY = Y`, but `DX` is a
  random drag start; `slide.Validate` compares the submitted point to `block.X/Y`
  (±5). The example ships `tile_y = DY`, i.e. the correct y, so a script only
  searches x (~225 px); marshalling the whole block leaks both.
- **afocus/captcha (untagged).** `Create(num, t) (*Image, string)` returns the
  answer; no store, TTL or attempt budget. Issue #12 (2024-03-19) argues machines
  crack it easily while humans struggle: no connecting lines, so easy to segment,
  and thin lines can be filtered out; closed unchanged.
- **steambap/captcha v1.4.1.** `Data.Text` is the solution and the README says to
  put it in a session; no store, TTL or attempt limit ships. Math mode leaves a tiny
  answer space.
- **OSV.** Zero advisories for all five modules (2026-10-26).

### Public attacks

No measured, reproducible break rate was found for any of the five — GitHub issue
and web searches, plus OSV, all negative on 2026-10-26. That is *absence of
evidence*, not strength. What exists is generic and applies to every image CAPTCHA:
segmentation attacks (Bursztein et al., CCS 2011) and small-CNN pipelines trained on
~1,000 harvested samples in minutes (2017 write-up). Both remain `unverified`
for these libraries.

### Prices and rates (verified unless marked)

| Input | Value | Note |
| --- | --- | --- |
| RTX 4090, SHA2-256 | 21,975.5 MH/s | hashcat v6.2.6, stock clocks |
| 2Captcha, normal image | $0.50–1.00 / 1k | list, load-dependent |
| 2Captcha, slider / click | $1.20 / 1k | L2 human-farm floor |
| Residential proxy | $7.00/GB (1 GB), $5.25/GB (10 GB) | IPRoyal PAYG |
| Residential proxy | $6/GB small, $2.50/GB at 125 GB | Oxylabs list |
| Cloud GPU rental | ~$0.30–0.70/h (4090) | `unverified`, volatile |

## Options

| Tier | Implementation | Tests | Cost driver |
| --- | --- | --- | --- |
| T0 | replay, cross-subject, expired, empty answer | protocol correctness | HTTP only |
| T1 | POST loop, no solver | missing state/binding | HTTP |
| T2 | tesseract 5.5.3 + `tessdata_best` | image legibility | 10–50 ms CPU (est.) |
| T3 | ≤10M-param CNN, 2k–10k samples | image entropy | GPU-minutes |
| T4 | Chromium via CDP, page JS runs | end-to-end, in-page solver | browser + proxy |
| T5 | Bézier + jitter + pause model | L2 scoring | developer time |
| T6 | price list only, never buy solves | upper bound | $0.50–1.20 / 1k |

| Mode | Fidelity | Reproducible | Use for |
| --- | --- | --- | --- |
| Live loopback end-to-end | high | medium | headline numbers |
| Fixture replay | medium | high | T2/T3 accuracy, regressions |
| Model-only offline | low | high | ablations |

## Recommendation

**Harness.** One Go binary, `-target` flag, each library on loopback at the pinned
version and a recorded config, with no non-loopback egress. Ship `attack` as a test
harness with an authorized-use notice, not a bypass.

**Design.** 1,000 challenges per arm × 3 seeds × 6 tiers, pre-registering n.
`break@k` = fraction solved within k attempts; attempts-to-success = median among
successes, Kaplan–Meier if censored; wall time p50/p95; server time as ns/verify.
Report every arm, not the best one.

**Sample size.** Wilson 95% half-width at n=1,000: ±1.9 pp at p=10%, ±3.1 pp at 50%,
±0.6 pp at 1%; rule of three gives <0.3% with zero breaks. At n=200 it is
±4.2 pp at p=10%. Per-arm n for 80% power: ~200 for 20%→10%, ~430 for 10%→5%,
~1,500 for 5%→3%.

**Determinism.** Upstream libraries use package-global `math/rand`, auto-seeded since
Go 1.20, so regeneration is not reproducible. Record a 2,000-challenge JSONL corpus
per target (id, params, image hash, ground truth, generator version) and replay it
for T2/T3. Freeze TTL through `bouncer.Clock`, or wrap the store when the library
calls `time.Now()` itself. Record weights hash, tesseract version and harness
commit.

**Cost model.** Compute, never assert:

```
$/1k successes = 1000 × (2^degree / H) × cost_per_gpu_second / break_rate
```

| degree | hashes | RTX 4090 | 1k solves | $/1k @ $0.50/GPU-h | 1 core @2 MH/s |
| --- | --- | --- | --- | --- | --- |
| 16 | 65 k | 3 µs | 3 ms | <$0.00001 | 0.03 s |
| 20 | 1.05 M | 48 µs | 48 ms | $0.000007 | 0.5 s |
| 24 | 16.8 M | 0.76 ms | 0.76 s | $0.0001 | 8.4 s |
| 28 | 268 M | 12.2 ms | 12.2 s | $0.0017 | 134 s |

A GPU attacker pays ~$0.002/1k at 28 bits against $1.20/1k for human slider
solving, ~600× gap. Say so: good result (no human supply, no defender cost), but
not a wall. Below 24 bits the hash costs less than an HTTP round-trip, so any
"cost" claim there is really a request-rate claim.

**README block.** Columns: tier, break@10 with 95% CI, n, median wall time, $/1k
successes, target version and config, harness commit, date, hardware. One scope
sentence (date, target version, config, taxonomy limit) and one limitation sentence
("lower bounds on attacker capability, not guarantees"). Publish raw JSON, include
negative results, disclose that the authors wrote both attack and defence.

## Risks & unknowns

- The harness is weaker than a motivated attacker, so every break rate is an upper
  bound; T3 understates a tuned model.
- The 2 MH/s core figure is an estimate; L1 conclusions swing with hardware class,
  so print the assumption.
- Farm and proxy prices change monthly and depend on terms of service; quote the
  fetch date.
- False-reject rate needs a consented human panel and is deferred; until then claim
  attacker cost only, never usability.
- Run only loopback instances you started; never vendor demos or third-party sites;
  never scrape or buy solves.
- Disclose the go-captcha y-leak to the maintainers before publishing; keep the
  README at "do not serialise the block".

## Sources

1. base64Captcha v1.3.8 — <https://github.com/mojocn/base64Captcha/blob/master/captcha.go>
2. base64Captcha memory store — <https://github.com/mojocn/base64Captcha/blob/master/store_memory.go>
3. dchest/captcha v1.1.0 — <https://github.com/dchest/captcha>
4. go-captcha slide block/validate — <https://github.com/wenlng/go-captcha/blob/master/v2/slide/block.go>
5. go-captcha example handler — <https://github.com/wenlng/go-captcha-example/blob/master/golang/internal/logic/captdata/slide_basic.go>
6. afocus/captcha — <https://github.com/afocus/captcha/blob/master/captcha.go>
7. afocus/captcha issue #12 — <https://github.com/afocus/captcha/issues/12>
8. steambap/captcha v1.4.1 — <https://github.com/steambap/captcha>
9. OSV query API — <https://api.osv.dev/v1/query>
10. hashcat v6.2.6 RTX 4090 benchmark — <https://gist.github.com/Chick3nman/32e662a5bb63bc4f51b847bb422222fd>
11. 2Captcha pricing — <https://2captcha.com/pricing>
12. IPRoyal residential pricing — <https://iproyal.com/pricing/residential-proxies/>
13. Oxylabs residential pricing — <https://oxylabs.io/products/residential-proxy-pool>
14. Searles et al., USENIX Security 2023 — <https://www.usenix.org/conference/usenixsecurity23/presentation/searles>
15. Bursztein et al., CCS 2011 — <https://dl.acm.org/doi/10.1145/2046707.2046771>
16. Sivakorn et al., Black Hat Asia 2016 — <https://www.blackhat.com/docs/asia-16/materials/asia-16-Sivakorn-Im-Not-a-Human-Breaking-the-Google-reCAPTCHA-wp.pdf>
