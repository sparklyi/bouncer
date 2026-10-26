# bouncer design

Status: implemented for v0.1.0. This document is the source of truth for the
public API and protocol until v1.0.0.

## 1. Positioning

A Go library that makes human verification a composable core: zero third-party
dependencies, no images in the default path, one SHA-256 per server-side check.
Replay protection, attempt budgets and HTTP integration are correct by default.

It proves computational and interaction effort, not humanity. It is not an image
CAPTCHA library, not a risk engine, not a service.

## 2. Three layers

| Layer | Mechanism | Server cost |
| --- | --- | --- |
| L0 state | AEAD-sealed ticket; answer never sent to the client; atomic one-time redemption (`Consume`); attempt budget (`Attempt`); subject binding; TTL | 1 atomic store op |
| L1 cost | Proof of work: `SHA-256("bouncer/pow/v1" || salt16 || nonce_be64)`, `degree` leading zero bits; difficulty escalates with failures | 1 hash |
| L2 interaction | Slide challenge; server scores pointer trajectory; the target `x` is sealed and never sent | tens of float ops + one PNG decode-free check |

Escalation (`Escalate(failures) (Tier, uint8)`): `0-1 → 18 bits`, `2-3 → 20`,
`4-5 → 22`, `>=6 → slide`. The caller owns the failure count and may force a tier.

**L1 is a rate limiter, not an economic wall.** A 20-bit challenge costs one RTX
4090 about 50 microseconds and a browser about a second, so PoW prices out
non-JS clients and makes attacker volume linear in CPU. The economics come from
L0: per-ticket salt, short TTL, one-time redemption, subject binding.

## 3. Ticket format

```
token = "b1." + base64url( header || nonce(12) || AEAD ciphertext+tag(16) )

header (cleartext, authenticated as AAD):
  1B ver | 2B kid | 1B type_len | nB type

plaintext (AES-256-GCM):
  1B ver | 1B degree | 8B issued_at | 8B expires_at | 1B sub_len | sB subject
  | 16B jti | 2B state_len | mB state
```

- `tokenKey = HKDF-SHA256(ikm=secret, salt="bouncer.v1", info="token-aead")`,
  derived once. `kid = SHA256(key)[:2]`; previous keys decrypt only.
- `type` is in the cleartext header because AAD must exist before decryption;
  `AAD = "bouncer.v1" || header` prevents cross-type confusion.
- Sealed, not signed: future challenges have private answers.
- Binary, not JSON: strict length-checked parsing, no type ambiguity, ~110 bytes.

## 4. Verification order

```
parse header → AEAD decrypt → type match → expiry → subject binding
             → Store.Attempt (only for attempt-limited challenges)
             → Challenger.Verify → Store.Consume
```

Consume is last so that a wrong answer cannot burn a ticket. Challenges whose
answer is guessable declare `MaxAttempts()`.

## 5. Public API

```go
package bouncer

type Tier uint8
const (TierPoW Tier = iota; TierSlide)
func Escalate(failures int) (Tier, uint8)

type Gate struct{}
func New(opts ...Option) (*Gate, error)
func (g *Gate) Issue(ctx context.Context, req Request) (*Challenge, error)
func (g *Gate) Verify(ctx context.Context, sol Solution, opts ...VerifyOption) (*Verdict, error)
func (g *Gate) IssuePass(ctx context.Context, subject string, ttl time.Duration) (string, time.Time, error)
func (g *Gate) VerifyPass(ctx context.Context, token string, opts ...VerifyOption) (*Verdict, error)
func (g *Gate) Close() error

type Request struct{ Subject string; Tier Tier; Degree uint8 }
type Challenge struct{ ID, Type, Token string; Expires time.Time; Params json.RawMessage }
type Solution struct{ Token, Answer string } // slog.LogValuer, redacted
type Verdict struct{ Type, Subject string; Degree uint8; IssuedAt time.Time }
type PointerEvent struct{ X, Y int; T int64; PointerType string; Buttons int }

type Challenger interface {
    Tier() Tier
    Type() string
    Issue(ctx context.Context, in IssueInput) (params []byte, state []byte, err error)
    Verify(ctx context.Context, in VerifyInput) error
}
type IssueInput struct{ Degree uint8 }
type VerifyInput struct{ Params json.RawMessage; State []byte; Answer string }

type Store interface {
    Attempt(ctx context.Context, id string, ttl time.Duration, max int32) (n int32, exceeded bool, err error)
    Consume(ctx context.Context, id string, ttl time.Duration) (ok bool, err error)
}
type Clock interface{ Now() time.Time }

func WithSecret(secret []byte, previous ...[]byte) Option
func WithSecretFile(path string) Option              // load or create with 0600
func WithChallenger(ch Challenger) Option       // registered by ch.Tier()
func WithStore(s Store) Option                  // default bounded memory
func WithStoreFailure(m FailureMode) Option     // Consume, default FailClosed
func WithAttemptFailure(m FailureMode) Option   // Attempt, default FailClosed
func WithTTL(d time.Duration) Option            // default 3m, max 15m
func WithDegree(bits uint8) Option              // default 18, clamp [16,24]
func WithClock(c Clock) Option
func WithLogger(l *slog.Logger) Option

func BoundToSubject(subject string) VerifyOption
func ReusePass() VerifyOption
```

Subpackages:

- `pow`: primitives (`Tag`, `Params`, `Preimage`, `Hash`, `Verify`, `Solve`,
  `ParseAnswer`, `FormatAnswer`).
- `slide`: `New(opts...) *Challenge` implementing `bouncer.Challenger`, plus
  procedural backgrounds and trajectory scoring.
- `store/memory`: the default bounded `Store` (65,536 entries, sharded).
- `store/storetest`, `challengetest`: contract suites for third-party adapters.
- `httpx`: `Guard` (the drop-in: endpoints + embedded widget + interstitial),
  `ChallengeHandler`, `VerifyHandler`, `Protect`, `VerifyPass`, `RequirePass`,
  `FromContext`, `StatusCode`, cookie options.
- `web`: zero-dependency browser solver (worker + helper, no build step).

`store/redis` is a separate module (`github.com/sparklyi/bouncer/store/redis`)
so the core module never gains a dependency.

## 6. HTTP contract

```
POST /_bouncer/challenge   {"tier":"pow"|"slide","degree":N,"subject":"..."}
  → 201 {"id","type","token","expires_at","params"}

POST /_bouncer/verify      {"token":"...","answer":"..."}
  → 200 {"ok":true,"expires_at"} + Set-Cookie: bouncer_pass
  → 400 malformed | 403 wrong_answer|challenge_required|attempts_exceeded
  → 409 replay | 410 expired | 503 store_unavailable
```

`Protect` accepts the pass from the cookie or the `X-Bouncer-Pass` header. Passes
are single use by default (`WithReusablePass` opts out).

`httpx.NewGuard(gate)` serves `/_bouncer/{challenge,verify,widget.js,worker.js}`
and gates everything else. A browser navigation without a pass receives an
interstitial that solves the challenge and reloads; API calls receive 403 JSON.
The widget and worker are embedded in the binary, so a deployment has no static
asset to copy and no frontend build step.

## 7. PoW parameters

- Preimage is 37 bytes, one SHA-256 block; keep it at or below 55 bytes.
- Answer is exactly 16 lowercase hex characters; non-canonical forms are rejected.
- Difficulty comes only from sealed state; a client cannot downgrade it.
- Base 18 for browsers (p50 ~0.3 s, p99 ~2 s on a mid-range phone); the shipped
  worker refuses degrees above 24.

## 8. Slide parameters

- Tolerance `max(4 px, 8% of piece width)`; trajectory scoring does the work.
- Hard-fail only physically impossible traces; three statistical violations
  reject; ambiguous cases are handled by escalating the next challenge to PoW.
- Backgrounds are procedural (gradient + 24-48 shapes, seeded), re-rolled when
  local contrast around the notch is below 12 luma units.
- Scoring rules are published. Per-deployment jitter is the planned mitigation;
  recorded human traces can still be replayed, which is why L0 exists.

## 9. Known limits

- A funded attacker with residential proxies, a human solver farm, or a tuned
  headless browser is not stopped; cost and detection surface are raised.
- No public break-rate numbers are shipped yet; the attack harness design is in
  [`research/05-attack-baseline.md`](research/05-attack-baseline.md).
- The memory store is per process. Multi-replica deployments need a shared store.
