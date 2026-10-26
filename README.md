# bouncer

Drop-in human verification for Go. **One middleware, no image CAPTCHA, zero
dependencies.**

## Three lines

```go
gate, _ := bouncer.New(bouncer.WithSecretFile("data/bouncer.key")) // created on first run
guard := httpx.NewGuard(gate)
http.ListenAndServe(":8080", guard.Protect(mux))
```

That is the whole integration. The guard serves the challenge endpoints and the
browser widget, gates every route, and hands unverified page loads a
self-solving interstitial. Add one tag to keep navigations instant:

```html
<script src="/_bouncer/widget.js" defer></script>
```

Single-page apps can await the check before a protected request:

```js
await bouncer.verify();
```

### With your framework

| Stack | Wiring |
| --- | --- |
| `net/http`, `chi` | `guard.Protect(mux)` |
| Gin | `router.Any("/_bouncer/*any", gin.WrapH(guard.Handler()))`; call `guard.RequirePass(c.Request)` on the endpoint you protect |
| Echo | `e.Use(echo.WrapMiddleware(guard.Middleware()))`; `guard.RequirePass(c.Request())` where you keep your own error format |
| Any custom router | mount `guard.Handler()` and call `guard.RequirePass(r)` |

Nothing else is required: no secret in the environment, no frontend build step,
no template change, no i18n keys.

## How it works

| Layer | What it does | Server cost |
| --- | --- | --- |
| **L0 state** | AEAD-sealed ticket; the answer never leaves the server; atomic one-time redemption; attempt budgets; subject binding; short TTL | one atomic store op |
| **L1 cost** | proof of work, 18 bits by default and escalating with failures | one SHA-256 |
| **L2 interaction** | slide puzzle scored on the pointer trajectory; the target `x` is sealed and never sent | a few dozen float ops |

`Escalate(failures)` moves from 18 to 24 bits and then to the slide challenge.
The library does not implement a risk engine; the caller owns the signals.

## Why another one

Every Go CAPTCHA library we looked at shares at least one structural defect:

| Library | Defect |
| --- | --- |
| `mojocn/base64Captcha` | `Generate()` returns the answer to the caller; `Verify(id, answer, clear=false)` allows unlimited retries; comparison is case-insensitive |
| `wenlng/go-captcha` | `slide.Validate` is a padded-rectangle test on one point, and `Block` marshals the target `x`/`y` next to the display offsets; in `ModeBasic` the display `DY` equals the answer |
| `dchest/captcha` | global mutable store, one configuration per process; its own README warns the image is OCR-breakable |
| `steambap/captcha` | `Data.Text` is the answer and no store, TTL or attempt budget ships |
| `afocus/captcha` | returns the answer, no store, not even a `go.mod` |

bouncer fixes the trust boundary first and the puzzle second.

## Measured on this repository

Reference run on an Apple-silicon laptop, `go test -bench . -benchtime 50x`
(single run; run it yourself before quoting it):

| Benchmark | Time | Allocs |
| --- | --- | --- |
| `Issue` (ticket seal) | 2.6 µs | 13 |
| `Verify` (16-bit PoW) | 674 ns | 7 |
| `Issue` (slide, procedural PNG) | 14.7 ms | 91 |

The slide number is image generation, not verification; it is the reason slide
challenges are reserved for escalated risk instead of being the default.

Break rates are **not** published yet. The methodology, adversary tiers and cost
model are in [`attack/README.md`](attack/README.md); numbers will ship with raw
data only.

## Honest limits

- Proof of work is a rate limiter, not an economic wall: 2^20 hashes cost a GPU
  about 50 µs and a browser about a second.
- A funded attacker with residential proxies, a human solve farm, or a tuned
  headless browser is not stopped. Cost and detection surface go up; that is all.
- The default store is per process. Multiple replicas need a shared store.
- Slide scoring rejects recorded human traces only when they are replayed, not
  when they are forged by a model trained on real traces. L0 exists because of
  this.

It proves work, not humanity. Call it a human check, not a CAPTCHA.

## Install

```
go get github.com/sparklyi/bouncer@latest
```

Requires Go 1.26 or newer. The core module has no `go.sum`.

## Packages

| Package | Purpose |
| --- | --- |
| `bouncer` | gate, tickets, errors, store and clock ports |
| `pow` | proof-of-work primitives, including a Go solver for tests and CLIs |
| `slide` | procedural slide challenge with server-side trajectory scoring |
| `store/memory` | default bounded store (65,536 entries, sharded, swept) |
| `store/storetest`, `challengetest` | contract suites for third-party adapters |
| `httpx` | drop-in `Guard` (endpoints, widget, interstitial), `Protect`, `RequirePass`, status mapping |
| `web` | zero-dependency browser solver; no build step, runs in a worker |

A Redis store lives in a separate module so that the core never gains a
dependency; it is tracked for v0.2.0.

## Threat model

In scope: scripted credential stuffing, bulk registration, form spam, naive
scrapers, accessibility (no image or audio is required for the default tier).

Out of scope: targeted attackers with budget, human solve farms, device
attestation, and any claim about "human vs AI".

## Documentation

- [`docs/design.md`](docs/design.md) — protocol, ticket layout, public API
- [`docs/research/`](docs/research/) — stage research, including the corrections
  it forced on the design
- [`attack/README.md`](attack/README.md) — how "better" will be measured

## License

MIT
