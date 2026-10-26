# Proof of work as a cost layer

## Verdict

- **Keep SHA-256 over a sealed 16-byte salt, counting leading zero bits.** Verification is one hash (~1 µs). Memory-hard functions cost the verifier what they cost the solver, which disqualifies them before browser limits matter.
- **20 bits is a poor browser default.** Expected work is `2^20` hashes, but the tail is what users feel: p50 ≈ 1.2 s, p99 ≈ 8 s on a mid-range phone. Use base **18**, escalating 18 → 20 → 22 → 24; the web solver should refuse ≥ 24.
- **Per-call overhead, not hashing, dominates.** One `await crypto.subtle.digest()` per nonce yields ~10^4–10^5 H/s; a single-block WASM or pure-JS loop yields ~10^6 H/s. Never call WebCrypto per attempt.
- **Canonical encoding is a protocol requirement.** Preimage ≤ 55 bytes (one SHA-256 block; now 37), nonce fixed-width 16 hex chars, difficulty only in sealed state.
- **PoW is a rate limiter, not a bot detector.** A 20-bit challenge costs a GPU ~1 ms and native code ~5 ms; it prices out non-JS clients and makes volume linear in attacker CPU.

## Facts

**Lineage.** Dwork–Naor priced junk mail with computation in 1992 [2]. Back's Hashcash (1997; paper 2002) stamps `1:20:date:resource::rand:counter`; `bits` counts leading zero bits of a SHA-1 digest, and the canonical 20-bit stamp is "the 5 most significant hex digits", ~2^20 attempts [1][3]. Bitcoin replaced the literal rule with a 256-bit target (`nBits`), trading 2× steps for continuous difficulty [4].

**Why memory-hard is wrong here.** Memory-hard KDFs remove the ASIC/GPU advantage by making memory bandwidth the bottleneck [5][6]. In a browser PoW the defender's device is the weakest machine, so it cancels the attacker's advantage only in theory while multiplying the client's cost. RFC 9106 recommends 2 GiB (t=1, p=4) or 64 MiB (t=3, p=4) [5]; noble-hashes measures Argon2id at 128 MiB/t=1 at **276 ms/op** and scrypt at n=2^19, r=8 at **751 ms/op** on an Apple M4 [7]. Decisively, verification is a full recompute: 64 MiB × 3 passes turns each check into tens of milliseconds and 64 MiB of allocation, destroying the one-hash property.

**Measured throughput.**

| Path | 32-byte hash | Rate |
| --- | --- | --- |
| noble-hashes (pure JS), Apple M4 [7] | 438 ns | ~2.3 MH/s |
| hash-wasm 4.10 (WASM), desktop [8] | 64 MB/s at 32 B | ~2.0 MH/s |
| OpenSSL `sha256`, 16-byte blocks, free-tier cloud vCPU [13] | — | **2.3 MH/s** |
| `crypto.subtle.digest` per nonce | ~3–50 µs | 20–300 kH/s (estimate, unverified) |
| Anubis, 16 bits, desktop, 2025 client [11] | 1–2 s total | ~35–65 kH/s |

The last row is the point: 16 bits is 65 k hashes, so 1–2 s implies ~40 µs/hash — 10× worse than pure JS, ~100× worse than native. Anubis awaits `crypto.subtle.digest` per nonce and drops WebCrypto on Firefox/Goanna [12]; native code solved it in **17 ms** [13].

**Real deployments.**

- **Anubis 1.28.2** — SHA-256 over `challenge‖decimal nonce`, difficulty in leading zero **nibbles**: tiers 2/4/6 = 8/16/24 bits, 7-day cookie [10][12][13]. Its WASM variants count **bits** (`fast 4` ≈ `sha256 16` ≈ `hashx 15`), so one key means 4 bits or 1 bit and 4 → 5 multiplies work by 16 [9][11].
- **SiteGround sg-captcha** — SHA-1, 20 bits, 8 workers, 50–500 ms, fallback after 10 s [17].
- **ALTCHA v3** — PBKDF2/SHA-256 default, 2 workers, `minDuration` 500 ms, optional Argon2id/Scrypt with an out-of-memory retry [14].
- **PrivateCaptcha** — Blake2b default, Argon2id optional from 1.45.0; difficulty is relative "% resources", scaled automatically [15].
- **Friendly Captcha** — SHA-256 in WASM workers, adaptive; publishes variance control, not bit counts [16].

**Difficulty math.** Trials are geometric with `p = 2^-d`: `E = 2^d`, `p50 = 0.693·2^d`, `p95 = 3.00·2^d`, `p99 = 4.61·2^d`, `P(no solution in 2^d tries) = e^-1 ≈ 37%`. The tail is intrinsic.

| d | p50 | p99 | mid phone p50 / p99 (0.6 MH/s, est.) |
| --- | --- | --- | --- |
| 16 | 45,400 | 302,000 | 0.08 s / 0.50 s |
| 18 | 182,000 | 1,207,000 | 0.30 s / 2.0 s |
| 20 | 727,000 | 4,829,000 | 1.2 s / 8.0 s |
| 24 | 11,628,000 | 77,255,000 | 19 s / 129 s |

Pick `d` from a p99 budget, not a mean: `d = floor(log2(budget_hashes / 4.61))`. A 4 s p99 budget at 0.6 MH/s gives 2.4 M hashes → `d = 18`; a desktop at 3 MH/s hits the same budget at 22 bits. Phones under load draw ~1–3 W, so a second costs 1–3 J, ~0.003–0.008% of a 15 Wh battery (estimate): battery is negligible, latency and throttling are not.

**Anti-outsourcing.** PoW is transferable: any solver can compute it for any client. What limits abuse is the per-ticket random salt, TTL (no stockpiling), one-time redemption, and subject binding (no cross-session resale) — not the bit count. A 20-bit solve costs a rented GPU ~1 ms (~$1e-7), 24 bits ~$1e-5, while human-solve farms bill ~$0.5–1 per 1000 [unverified]: any browser-tolerable setting is 3–4 orders of magnitude cheaper for the attacker. Binding to a subject changes economics only when the subject is costly to obtain (account, device-bound key); otherwise the farm proxies the token. Native solvers run ~100× faster than the slowest browser, and a 7-day cookie amortizes one solve over a week [13].

## Options

| Construction | Client cost | Verifier cost | Fit |
| --- | --- | --- | --- |
| SHA-256, leading zero bits | 2^d one-block hashes | 1 hash | best; 2× granularity |
| SHA-256, 256-bit target | same | 1 compare | best; fractional bits |
| PBKDF2-HMAC-SHA256 | ~2 compressions/iter | full recompute | 2–3× slower per unit |
| scrypt | 751 ms, 16–32 MiB | full recompute | GC/OOM on mobile |
| Argon2id | 276 ms, 128 MiB | full recompute | disqualifying |

## Recommendation

1. **Preimage:** `"bouncer/pow/v1" || salt16 || nonce_be64` = 37 bytes, one SHA-256 block. Keep it ≤ 55 bytes forever; a longer tag or inlined subject costs a second compression (~2×).
2. **Nonce:** exactly 16 lowercase hex chars, big-endian. Reject `0x` prefixes, leading-zero variants, `+`, whitespace, overlength. Anubis takes decimal nonces verbatim, so `007` and `7` are distinct valid answers [12]; do not repeat that.
3. **Difficulty:** read `degree` only from sealed state, never from params or the answer. Clamp at issue, accept only `1 ≤ degree ≤ 32` at verify, log `Verdict.Degree` from state, and test that a client-supplied degree is ignored.
4. **Defaults:** base 18 for browser traffic, 20 after 2–3 failures; reserve 22–24 for repeat offenders and non-browser clients. Document 20+ as desktop/API only and make the `web` solver fail closed above 24.
5. **Tag separation and solver:** AAD already binds the type; bind the algorithm into the preimage tag so a future `pow/v2`, hashx, or L0 ticket cannot satisfy a PoW check. Ship one ~1 KB WASM module with a preallocated 64-byte block, `min(4, hardwareConcurrency/2)` workers and randomized starts, aborting at ~8 s. Recompute, compare all 32 bytes in constant time, then count bits; never trust a client hash or timing.

## Risks & unknowns

- WebCrypto per-call figures (3–50 µs) and mobile rates are estimates; they need measurement on mid-range Android and iOS, where pure-JS fallback, disabled JIT, and low-power modes can be 2–10× slower.
- 18 bits trades margin for p99 latency; revisit with real telemetry. iOS background-tab suspension, Low Power Mode, and WebView memory limits are unverified and can strand a solver.

## Sources

1. A. Back, "Hashcash", 2002. http://www.hashcash.org/papers/hashcash.pdf
2. C. Dwork, M. Naor, "Pricing via Processing or Combatting Junk Mail", CRYPTO '92. https://doi.org/10.1007/3-540-48071-4_10
3. Wikipedia, "Hashcash" (secondary). https://en.wikipedia.org/wiki/Hashcash
4. S. Nakamoto, "Bitcoin: A Peer-to-Peer Electronic Cash System", 2008. https://bitcoin.org/bitcoin.pdf
5. RFC 9106, "Argon2 Memory-Hard Function", §4. https://www.rfc-editor.org/rfc/rfc9106.html
6. RFC 7914, "scrypt Password-Based Key Derivation Function". https://www.rfc-editor.org/rfc/rfc7914.html
7. noble-hashes README, Apple M4 benchmarks. https://github.com/paulmillr/noble-hashes
8. hash-wasm 4.10.0 README benchmarks. https://github.com/Daninet/hash-wasm
9. Anubis docs, "Proof of Work (WebAssembly)" — bit/nibble table. https://anubis.techaro.lol/docs/admin/configuration/challenges/wasm
10. Anubis default bot policy. https://github.com/TecharoHQ/anubis/blob/main/data/botPolicies.yaml
11. Anubis issue #106. https://github.com/TecharoHQ/anubis/issues/106
12. Anubis source (proofofwork.go, sha256.ts). https://github.com/TecharoHQ/anubis
13. T. Ormandy, "Anubis" (measured timings). https://lock.cmpxchg8b.com/anubis.html
14. ALTCHA README (algorithms, minDuration, OOM retry). https://github.com/altcha-org/altcha
15. PrivateCaptcha docs, "Property settings". https://docs.privatecaptcha.com/docs/reference/property-settings/
16. Friendly Captcha, "Controlling Algorithm Variance". https://friendlycaptcha.com/insights/proof-of-work-captcha/
17. Sprocket Security, "Bypassing JavaScript Proof-of-Work CAPTCHAs" (third-party). https://www.sprocketsecurity.com/blog/please-show-your-work-bypassing-javascript-proof-of-work-captchas
