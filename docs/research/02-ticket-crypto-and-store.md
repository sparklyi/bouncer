# Sealed ticket cryptography and atomic store backends

## Verdict

- **Keep AES-256-GCM**, but move `type` into the cleartext header: the design binds
  `AAD = "bouncer.v1" || type` while `type` is only readable *after* decryption —
  a chicken-and-egg bug. `type` is already public in the `/challenge` JSON.
- Fresh 12-byte random nonce per `Seal`; rotate at **2^31 seals or 30 days**; keep
  the old key for `2 × MaxTTL`; a 1-byte `kid` is a hint, not an identity (1.17%
  collision at 3 keys).
- Reject JWT/PASETO/Branca: JWS is readable, the others need non-stdlib primitives,
  and all are ~2× larger than this token.
- Redis `Consume` = `SET k 1 NX PX ttl` (2.6.12+); `Attempt` = one Lua script.
  `INCR` + `PEXPIRE` is two commands: a crash or failover can leave a permanent
  counter with **no TTL**, locking a subject out.
- The memory store needs a cap and a sweeper; `runtime.AddCleanup` cannot replace
  `Close`.

## Facts

### AEAD choice

- Go 1.26's stdlib has GCM but **no `crypto/chacha20poly1305`** (verified with
  `go doc` on the local 1.26.0 toolchain); ChaCha needs `golang.org/x/crypto`, which
  breaks the zero-dependency rule.
- GCM uses AES-NI + PCLMULQDQ on amd64 and `HasAES && HasPMULL` on arm64
  (`crypto/tls/cipher_suites.go`, Go 1.26). That file says with AES hardware
  "AES-128-GCM and AES-256-GCM are faster than ChaCha20Poly1305", without it AES is
  "much slower" [6][7].
- Both are ~1–3 cycles/byte with hardware or AVX2/NEON, so a 150-byte plaintext is
  sub-microsecond on amd64 and Apple-silicon arm64; the gap matters only on AES-less
  ARM. **Estimates; `bench/` must measure them** (unverified).
- 12-byte nonce, 16-byte tag; `NewGCMWithRandomNonce` documents a **2^32 message cap
  per key** [8]. AES-256 costs ~30–40% more than AES-128 (14 vs 10 rounds).
- RFC 8439 requires a unique 96-bit nonce per key [2]; reuse leaks the GHASH key and
  enables **universal forgery**.

### HKDF, rotation, kid

- `crypto/hkdf` (Go 1.24, RFC 5869) [1][9]:
  `hkdf.Key(sha256.New, secret, salt, info, 32)`. A static salt is fine for a uniform
  32-byte IKM; `info` is the domain separator — use `"bouncer/v1/token-aead"`.
- `kid = SHA256(key)[0]`: 8 bits; P(collision) with 3 keys = 1 −
  (256·255·254)/256³ = **1.17%**. Keep `kid → []key` and let the GCM tag
  authenticate; prefer 2 bytes if the format is still unfrozen.
- Old keys only for `2 × MaxTTL`; an old key is a permanent forgery oracle.

### Token size

Plaintext = 38 B + `len(type)` + `len(subject)` + `len(state)`; wire = `3` (`b1.`)
+ base64url(1 kid + 12 nonce + plaintext + 16 tag).

| Case | Binary | Token |
| --- | --- | --- |
| PoW, 16 B subject, no state | 86 B | **118 chars** |
| Slide, 16 B subject, 64 B state | 152 B | **206 chars** |

Raw base64url leaks exact lengths; pad to 16-byte buckets (+≤22 chars) if subject
size is sensitive.

### Why not JWT / PASETO / Branca

- **JWT** (RFC 7519) is *signed*: the slide target `x`, subject and state would be
  client-readable — fatal for L2. JWE fixes that but adds JSON, algorithm negotiation
  and compression channels; RFC 8725 lists the pitfalls [3][4][5].
- **PASETO v4.local** needs XChaCha20 + keyed BLAKE2b (non-stdlib), ~238 chars, and
  the whole versioned protocol reproduced for compatibility [10].
- **Branca**: 29-byte header, XChaCha20, base62, no `kid`/type; ~226 chars, still
  `x/crypto` [11].
- Custom: 118–206 chars, no algorithm field, strict length-checked parser, `b1.`
  prefix.

### Pitfalls to encode in tests

- **Nonce reuse**: never derive from a cross-process counter or the jti; random
  96-bit nonces are the safe default.
- **Timing**: one sentinel error; no message branching on tag failure. Redis leaks
  key existence by design (`SET NX`), which is fine.
- **Replay**: marker TTL = `remaining + 30s`, so skew cannot reopen the window.
- **Key compromise**: a leaked key forges any subject and decrypts slide targets;
  scope per deployment, rotate, log `kid` use.

### Redis semantics

- `SET ... NX PX ms` returns `OK` on write, `nil` if the key exists. `SET` is 1.0.0;
  **NX/PX 2.6.12**, `KEEPTTL` 6.0.0, `GET`+`NX` 7.0.0 [12]. `SET ... KEEPTTL`
  preserves the TTL on overwrite but cannot increment, so it does not replace `INCR`.
- `SET` clears TTL, `INCR` preserves it. So `INCR` + `PEXPIRE` is not atomic: a crash
  between them leaves a permanent key; `PEXPIRE` per call slides the window; async
  replication can keep the `INCR` and lose the `PEXPIRE` after failover.
- Lua (`INCR`; `PEXPIRE` only when `n == 1`; return `n`) is atomic but blocks the
  server [13]. `MULTI/EXEC` works without branching, costs 2 RTT and never rolls
  back [14]. Fallback `SET 1 NX PX` / `INCR` / `PEXPIRE NX`: 2–3 RTT.
- Cluster: 16384 slots; single keys are safe, multi-key scripts need hash tags [15].
  Sentinel/Cluster replicate asynchronously: markers vanish on failover; `WAIT`
  narrows but does not close it [16].
- Redis stores absolute ms and uses its own clock; expiry error is 0–1 ms [17].

### In-memory store

- 256 shards, `map[[16]byte]entry`; entry is ~16 B, ~50–80 B/entry with map overhead.
- Lazy expiry leaks: every `Issue` inserts. At 10k rps over a 3-minute TTL, ~1.8M
  entries (~150 MB) accumulate. Sweep every TTL/4 (≥30 s) and enforce a cap.
- `AddCleanup` (Go 1.24) cannot evict: values are reachable, and a sweeper goroutine
  blocks collection [18]. Use it only as defence in depth.
- No hot-key `singleflight`: each caller needs its own answer (exactly one `true`); a
  shard mutex (~20–50 ns) is already cheap.

## Options

| AEAD | Stdlib | Short-msg speed | Verdict |
| --- | --- | --- | --- |
| AES-256-GCM | yes | fastest with AES-NI/PMULL | **chosen** |
| AES-128-GCM | yes | ~30% faster (est.) | viable, design fixes 256 |
| ChaCha20-Poly1305 | no (`x/crypto`) | similar with AVX2/NEON | rejected: dependency |

Backends: memory (shard lock, per-process only) · Redis standalone (`SET NX PX` /
Lua, 1 RTT, async replication → replay on failover) · Sentinel (same, loses recent
writes) · Cluster (single slot/key, per-shard).

## Recommendation

1. **Header:** `kid(1) || type(1) || nonce(12) || ct`, AAD =
   `"bouncer.v1" || type || kid`. Costs 1 byte, removes the deadlock. Keep `ver` and
   strict checks inside the plaintext.
2. **Crypto:** AES-256-GCM, 12 random bytes from `crypto/rand` (or
   `cipher.NewGCMWithRandomNonce`). Rotate at 2^31 seals/30 days; accept previous
   keys for 30 min; map `kid` to `[]key` and try all.
3. **Sizes:** ≤128 chars for PoW, ≤208 for slide; pad only if subject length is
   sensitive.
4. **Redis:** require 7.0 (6.2 if Lua is allowed). `Consume` =
   `SET bouncer:v1:c:<hex> 1 NX PX <remaining+30s>`; `Attempt` = one `EVAL` returning
   `n`, `PEXPIRE` only when `n == 1`. Fail-open only for `Attempt`; the single
   `WithStoreFailure` option is too coarse.
5. **Memory:** 256 shards, lazy expiry + sweep, cap 65,536 entries (~5 MB), reject
   `Issue` when full (`503`), never evict unexpired markers. Bound Redis concurrency
   with a semaphore, not singleflight.
6. **Tests:** `-race -shuffle=on`; `testing/synctest` (stable in 1.25) for TTL and
   sweep; fuzz the decoder and assert every single-byte mutation of a valid token
   fails auth; property tests for `Escalate` monotonicity, `Degree ∈ [16,28]`,
   exactly-once `Consume` under N goroutines and `Attempt` monotonicity;
   `govulncheck ./...` in CI [19][20].

## Risks & unknowns

- The AAD/type ordering is a real spec defect; if unchanged, `Open` must receive the
  expected type or try every type.
- 1-byte `kid` collides; widening to 2 bytes is cheap now, expensive later.
- AES-less arm64 makes GCM several times slower; tokens are tiny, but measure first.
- Failover replay window and clock-skew tolerance are unquantified; add a chaos test.
- Memory-cap behaviour under an `Issue` flood is a deliberate trade-off; document 503.
- Performance numbers are estimates; `bench/` must measure amd64/arm64 Seal/Open
  before v1.0.0.

## Sources

1. RFC 5869 HKDF — https://www.rfc-editor.org/rfc/rfc5869
2. RFC 8439 ChaCha20-Poly1305 — https://www.rfc-editor.org/rfc/rfc8439
3. RFC 7519 JWT — https://www.rfc-editor.org/rfc/rfc7519
4. RFC 8725 JWT BCP — https://www.rfc-editor.org/rfc/rfc8725
5. RFC 7516 JWE — https://www.rfc-editor.org/rfc/rfc7516
6. Go 1.26 `crypto/tls/cipher_suites.go` — https://cs.opensource.google/go/go/+/master:src/crypto/tls/cipher_suites.go
7. Go 1.26 `crypto/internal/fips140/aes/gcm/gcm.go` — https://cs.opensource.google/go/go/+/master:src/crypto/internal/fips140/aes/gcm/gcm.go
8. `crypto/cipher.NewGCMWithRandomNonce` — https://pkg.go.dev/crypto/cipher#NewGCMWithRandomNonce
9. Go 1.24 release notes — https://go.dev/doc/go1.24
10. PASETO v4 — https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md
11. Branca spec — https://github.com/tuupola/branca-spec
12. Redis `SET` — https://redis.io/docs/latest/commands/set/
13. Redis EVAL atomicity — https://redis.io/docs/latest/develop/programmability/eval-intro/
14. Redis transactions — https://redis.io/docs/latest/develop/using-commands/transactions/
15. Redis Cluster spec — https://redis.io/docs/latest/operate/oss_and_stack/reference/cluster-spec/
16. Redis replication — https://redis.io/docs/latest/operate/oss_and_stack/management/replication/
17. Redis `EXPIRE` — https://redis.io/docs/latest/commands/expire/
18. `runtime.AddCleanup` — https://pkg.go.dev/runtime#AddCleanup
19. `testing/synctest` — https://go.dev/doc/go1.25
20. govulncheck — https://go.dev/doc/security/vuln/
