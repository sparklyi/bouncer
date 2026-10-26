# Slide challenges: the real signal is the pointer trajectory

## Verdict

- **Score motion, not position.** The notch must be visible to solve the puzzle,
  so `x` is recoverable from the image the user already has. Sealing `x` stops
  scripts, not solvers: keep it, but make the trajectory the decision boundary and
  keep tolerance generous.
- **`wenlng/go-captcha` v2.0.5 is not a behaviour CAPTCHA.** `slide.Validate` is a
  padded-rectangle test on one final point (upstream example: `padding = 5` on
  300×220). In the default `ModeBasic` the tile's display `DY` *equals* the answer
  `Y`, and the shipped example forwards it as `tile_y` — the y-answer is handed to
  the client.
- **Four cheap rules catch every off-the-shelf bot:** peak/mean velocity ratio
  (humans ≈1.4–2.4; minimum-jerk exactly 1.875; linear interpolation ≈1.0),
  terminal velocity before release, event count vs duration, monotone in-range
  timestamps. Playwright and Puppeteer `mouse.move` default to `steps: 1` and
  interpolate linearly; ghost-cursor adds Bézier curvature but no dwell, no
  `buttons` during drag, no coalesced events.
- **Rules beat one-class models at this sample size.** With ~200 traces a
  one-class SVM or isolation forest overfits device and subject and yields an
  opaque threshold. Eight dimensionless weighted features are explainable, cheap,
  and thresholdable from the same 200 traces.
- **Escalate, do not deny.** Reject only physically impossible traces; send the
  ambiguous band back to PoW. A false positive costs a real user a login.

## Facts

### Why the target position is inherently visible

A jigsaw slide shows the piece's destination *cut into* the background: a notch
with an edge or shadow. It is the only thing to aim at, so it must be rendered;
any client that sees the canvas can locate it. So:

- Not sending `x` raises attacker cost from "one POST" to "render, then correlate"
  — a one-time few-hours cost per site, not per attempt: a filter against naive
  scripts, not a security boundary.
- `go-captcha`'s `Block` is `{"x","y",...,"tile_x","tile_y","dx","dy"}`; `X`/`Y`
  *are* the answer, `DX`/`DY` the display position. Any handler that marshals
  `GetData()` to the client leaks the answer verbatim.

### go-captcha v2.0.5, concretely

`slide.Validate(sx, sy, dx, dy, padding)` returns
`sx ∈ [dx±padding] ∧ sy ∈ [dy±padding]`, a `2·padding` square; the example calls
`slide.Validate(sx, sy, dct.X, dct.Y, 5)` — ±5 px on 300×220 with a 60–70 px piece
([1], [2]). `ModeBasic` sets `TileY = Y` and `DY = Y` before `TileX`/`DX` get a
random display position ([1]), and `slide_basic.go` returns
`"tile_y": blockData.DY` ([2]). Three attacks follow:

1. **Template match.** The tile PNG *is* the cutout; one normalized
   cross-correlation of tile against background recovers `x` deterministically.
2. **JSON read.** Read `x`/`y`/`dx`/`dy` straight off the block JSON. A client
   that "deletes `x`/`y`" before rendering still received them.
3. **Guess.** Only `x` is unknown; the range is ≈`300 − 65 − 10 = 225` px, ±5 px
   accepts 11 values, so a random guess wins ≈4.9% of the time. Four attempts give
   `1 − 0.951⁴ ≈ 18%` — worse than the PoW it replaces.

A point-only check is therefore a guessing game with an 18% ceiling.

### Human motion features

Fitts' law, `MT = a + b·log2(2D/W)`, bounds plausible duration [10], [11].
Minimum-jerk reaching has a bell-shaped speed profile peaking at **1.875×** the
mean — an exact constant, and the most useful shape feature [12]. Meyer et al.
show aimed movements decompose into a ballistic submovement plus corrections,
which is why real traces overshoot, reverse, and arrive near zero velocity [13].
Harris & Wolpert explain why that noise is signal-dependent: forged motion that is
"too clean" is the tell [14].

| Feature | Human expectation (hypothesis — measure it) |
| --- | --- |
| `v_peak / v_mean` | 1.4–2.4 (min-jerk 1.875, linear 1.0) |
| `v_last / v_mean` before `up` | < 0.3 |
| `MT` for 200–300 px | 600–1400 ms |
| events / `MT` | 40–150 over 0.6–1.2 s |
| x-reversals | 0–3, correlated with overshoot |
| pause before release | 50–250 ms dwell |
| dt CV / 8-bin dt entropy | 0.3–0.6 / ≈2.5–3.5 bits |
| `pointerType`, `isTrusted`, coalesced count | protocol envelope |

`isTrusted` is useless against CDP: `Input.dispatchMouseEvent` builds a
`blink::WebMouseEvent` forwarded via `RenderWidgetHost::ForwardMouseEvent`, i.e.
through the real input pipeline, so pages see `isTrusted === true` ([6], [7], [8]).
It catches only `dispatchEvent(new MouseEvent(...))`. Coalesced events are better:
a one-event-per-step bot can never populate the list ([9]) — but real low-rate mice
also produce empty lists, so treat that as weak evidence.

### How bots forge motion

- **Playwright** `mouse.move(x, y, {steps})`, `steps` default **1**, interpolating
  `from + (to−from)·i/steps` with one CDP round trip per point [3]: uniform
  spacing, near-uniform `dt`, `v_peak/v_mean ≈ 1.0`, no dwell, no overshoot, and a
  duration set by IPC latency rather than Fitts' law.
- **Puppeteer** is the same shape (`steps` default 1, linear, `buttons` preserved)
  [4].
- **ghost-cursor** (~1.6k stars) fits a cubic Bézier with random anchors, samples
  `ceil((log2(fitts)+baseTime)·3)` points (min 25), overshoots above 500 px, and
  dispatches raw `Input.dispatchMouseEvent` [5]. It *does* fake curvature and
  overshoot. It does **not** fake dwell (`waitForClick` default 0), `buttons: 1`
  during a drag (its move path never sets `buttons`, so a drag reads as hover),
  coalesced events, or signal-dependent noise. With `useTimestamps: true` it puts
  `Date.now()` **milliseconds** into a seconds-since-epoch field; Chromium
  converts via `base::Seconds` [7], placing the event ~55,000 years ahead. The
  unit mismatch is certain in source; the page-visible `event.timeStamp` effect is
  **unverified**.

## Options

| Approach | Catches | Cost | Weakness |
| --- | --- | --- | --- |
| Point-only ±5 px (go-captcha) | Nothing that renders | ~0 | 5% guess rate; JSON/CV leak |
| Point + 8 rule features | All stock automation | ~200 float ops | Bypassable once features are public |
| One-class SVM / isolation forest | Novel shapes | ~1k traces, tuning, model file | Opaque, overfits device |
| Supervised classifier | Training distribution | Bot corpus, drift | Zero-day bots pass |

Backgrounds:

| Option | Bytes (est.) | Contrast control | Notes |
| --- | --- | --- | --- |
| fBm value noise, 3 octaves | 60–120 KB PNG | re-roll on low local σ | pretty, compresses badly |
| 24–48 shapes + gradient | 8–20 KB PNG | guaranteed edges | cheapest, always solvable |
| Shipped photo assets | large | none | rejected by design §1 |

## Recommendation

- **Two bands, hard-fail first.** Reject (and consume the attempt) on
  non-monotone or negative `dt`, `T` beyond `now − Started`, `< 8` events for a
  drag `> 100` px, `|Δ|` outside 2× canvas, `> 512` events, or `v_peak/v_mean <
  1.15` with `< 12` events. Then score: `≥ 5` reject, `3–5` force PoW, else pass.
- **Dimensionless features.** Normalise shape by drag distance and duration so
  DPR (1/1.5/2/3) and canvas size drop out; DPR then changes only px/s, not shape.
  `PointerEvent.X/Y` are `int` CSS pixels (design §5); build no sub-pixel features
  on them, and state units in `Params`.
- **Thresholds from N = 200 traces, no training.** Per feature use `[p1, p99]`
  padded 20%, score 1 outside and 0 inside. At per-feature FP 2%,
  `P(≥3 of 8) ≈ 4×10⁻⁴` under independence (≈5×10⁻³ at 5%). Independence is false —
  a trackpad flick trips several at once — hence escalate rather than deny.
- **Per-deployment jitter.** Derive `HKDF(secret, "bouncer.v1", "slide-scoring")`,
  pick 6 of 10 features, jitter thresholds ±20%. MIT plus published features means
  a published bypass unless parameters are deployment-specific.
- **Backgrounds: shapes, not noise.** 24–48 overlapping filled circles/polygons on
  a two-stop gradient, seeded by `ChaCha8` from the ticket nonce (`math/rand/v2`)
  [17]. Guard: local luma σ in a 48×48 window around the notch `≥ 28/255` and
  `≥ 0.35 ×` global σ; re-roll up to 8 seeds, then overlay a forced contrast
  shape. Add a 1 px rim plus shadow to the piece. Inline base64 PNG in `Params` to
  avoid a protocol change; cap 48 KB.
- **Keep tolerance loose:** `tol = max(4, 0.08·pieceW)`. Strictness there only
  punishes humans; the trajectory does the work.
- **Corpora.** Store the events the client already produced, keyed to challenge id
  only — no subject, IP, UA or cookie, 14-day retention, publish only on opt-in.
  Bot corpora: ≥200 traces per pinned generator and version, committed as gzipped
  JSONL plus a sha256 manifest; ghost-cursor's unseeded `Math.random()` means
  fixtures, not regeneration, are the reproducible artifact.

## Risks & unknowns

- Every number above is a hypothesis, not a measurement: the 5% guess rate and
  the entropy/dwell bands need real traces before shipping.
- Keyboard-only, switch, and assistive-input users will trip several features at
  once. Escalate-not-deny mitigates but does not remove the accessibility risk; a
  pointer-free tier must stay reachable.
- `pointerType` is named in design §2 but absent from `PointerEvent`; it must ride
  inside the answer JSON or `Type`, as must `buttons` and DPR.
- Traces are behavioural data: store without subject/IP/UA linkage, short
  retention; publishing a corpus needs explicit consent. Whether scoring-only
  traces are "biometric data" under GDPR Art. 4(14) is **unverified** (and this is
  not legal advice).
- Bot corpora also need the generator's pinned dependencies; a `Math.random()`
  path replayed on a different runtime drifts.

## Sources

1. wenlng/go-captcha v2.0.5 — <https://github.com/wenlng/go-captcha>
   (`v2/slide/validate.go`, `block.go`, `slide.go`, `default.go`)
2. wenlng/go-captcha-example — <https://github.com/wenlng/go-captcha-example>
   (`golang/internal/logic/checkdata/slide.go`, `captdata/slide_basic.go`)
3. Playwright `mouse.move` — <https://playwright.dev/docs/api/class-mouse#mouse-move>;
   source `packages/playwright-core/src/server/input.ts`
4. Puppeteer `Mouse.move` — <https://pptr.dev/api/puppeteer.mouse.move>;
   source `packages/puppeteer-core/src/cdp/Input.ts`
5. Xetera/ghost-cursor — <https://github.com/Xetera/ghost-cursor>
   (`src/spoof.ts`, `src/math.ts`)
6. CDP `Input.dispatchMouseEvent` —
   <https://chromedevtools.github.io/devtools-protocol/tot/Input/#method-dispatchMouseEvent>
7. Chromium `content/browser/devtools/protocol/input_handler.cc` —
   <https://chromium.googlesource.com/chromium/src/+/main/content/browser/devtools/protocol/input_handler.cc>
8. DOM Standard, `Event.isTrusted` — <https://dom.spec.whatwg.org/#dom-event-istrusted>
9. Pointer Events Level 3, `getCoalescedEvents` — <https://w3c.github.io/pointerevents/>
10. P. Fitts, *J. Exp. Psychol.* 47(6):381–391, 1954, doi:10.1037/h0055392
11. I. S. MacKenzie, *Human–Computer Interaction* 7(1):91–139, 1992,
    doi:10.1207/s15327051hci0701_3
12. T. Flash, N. Hogan, *J. Neurosci.* 5(7):1688–1703, 1985,
    doi:10.1523/JNEUROSCI.05-07-01688.1985
13. D. E. Meyer et al., *Psychol. Rev.* 95(3):340–370, 1988,
    doi:10.1037/0033-295X.95.3.340
14. C. M. Harris, D. M. Wolpert, *Nature* 394:780–784, 1998, doi:10.1038/29528
15. Z. Chu, S. Gianvecchio, H. Wang, "Bot or Human? A Behavior-Based Online Bot
    Detection System", LNCS, 2018, doi:10.1007/978-3-030-04834-1_21
16. B. Schölkopf et al., *Neural Computation* 13(7):1443–1471, 2001,
    doi:10.1162/089976601750264965; F. T. Liu et al., "Isolation Forest", ICDM
    2008, doi:10.1109/ICDM.2008.17
17. Go `math/rand/v2` (ChaCha8, Go 1.22+) — <https://pkg.go.dev/math/rand/v2>
18. K. Perlin, "An Image Synthesizer", SIGGRAPH 1985, doi:10.1145/325334.325247
