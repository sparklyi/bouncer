# bouncer design

Status: approved 2026-10-27. This document is the single source of truth for the
public API and protocol until v1.0.0.

## 1. Positioning

A Go library that makes human verification a composable core: zero third-party
dependencies, no images, no fingerprinting, one SHA-256 per server-side check.
Replay protection, attempt budgets and HTTP integration are correct by default.

It proves computational work, not humanity. It is not an image CAPTCHA library,
not a risk engine, not a service.

## 2. Three layers

| Layer | Mechanism | Server cost |
| --- | --- | --- |
| L0 state | AEAD-sealed ticket; answer never sent to the client; atomic one-time redemption (`Consume`); attempt budget (`Attempt`); subject binding; TTL | 1 atomic store op |
| L1 cost | Proof of work: `SHA-256("bouncer/pow/v1" || salt16 || nonce_be64)`, `degree` leading zero bits; difficulty escalates with failures | 1 hash |
| L2 interaction | Slide challenge; server scores pointer trajectory (velocity shape, dt entropy, reversals, event count, pointer type); the target `x` is sealed and never sent | tens of float ops |

Escalation: `0-1 failures → degree 18`, `2-3 → degree 20`, `4-5 → degree 22`,
`>=6 → slide`. The caller may force a tier and pass a risk hint; the library does not
implement a risk engine.

**L1 is a rate limiter, not an economic wall.** A 20-bit challenge costs one RTX 4090
about 50 microseconds and a browser about a second, so PoW prices out non-JS clients
and makes attacker volume linear in CPU, while human-solve farms stay 3-4 orders of
magnitude cheaper. The README must say this. The economics of L0 (per-ticket salt,
short TTL, one-time redemption, subject binding) matter more than the bit count.

## 3. Ticket format

```
token = "b1." + base64url( header || nonce(12) || AEAD ciphertext+tag(16) )

header (cleartext, authenticated as AAD):
  1B ver | 2B kid | 1B type_len | nB type

plaintext (AES-256-GCM):
  1B degree | 8B issued_at | 8B expires_at | 1B sub_len | sB subject
  | 16B id (jti) | 2B state_len | mB state
```

- Keys: `tokenKey = HKDF-SHA256(ikm=secret, salt="bouncer.v1", info="token-aead")`,
  derived once at construction. `kid = SHA256(key)[:2]`; rotation keeps previous keys
  for decryption. Two bytes, because a 1-byte id collides with probability 1.17% at
  three keys and the format is still unfrozen.
- `type` is in the cleartext header because AAD must be known *before* decryption.
  Binding it as `AAD = "bouncer.v1" || header` keeps the cross-type guarantee without
  the chicken-and-egg deadlock.
- Binary, not JSON: smaller, strict length-checked parsing, no type ambiguity.
- Sealed, not signed: future challenges have private answers; the protocol must not
  change when they land.

## 4. Verification order

```
parse header → AEAD decrypt (AAD = header) → type match → expiry → subject binding
             → Challenger.Verify → store.Consume(id)
```

Consume is last on purpose: consuming first lets anyone holding a ticket burn it with
a garbage answer. Challenges that need attempt limits (slide) use `store.Attempt`
before verification; PoW needs no attempt limit because guessing is solving.

Ticket padding: when the subject length is sensitive, pad the plaintext to 16-byte
buckets so raw base64 length does not leak it. Off by default (costs up to 22 chars).

## 5. Public API

```go
package bouncer

type Tier uint8
const (TierState Tier = iota; TierPoW; TierSlide)

type Gate struct{}
func New(opts ...Option) (*Gate, error)
func (g *Gate) Issue(ctx context.Context, req Request) (*Challenge, error)
func (g *Gate) Verify(ctx context.Context, sol Solution, opts ...VerifyOption) (*Verdict, error)
func (g *Gate) Close() error

type Request struct{ Subject string; Tier Tier; Risk int }
type Challenge struct{ ID, Type, Token string; Expires time.Time; Params json.RawMessage }
type Solution struct{ Token, Answer string }        // slog.LogValuer, redacted
type Verdict struct{ Type, Subject string; Degree uint8; IssuedAt time.Time }

type Challenger interface {
    Type() string
    Issue(ctx context.Context, in IssueInput) (params json.RawMessage, state []byte, err error)
    Verify(ctx context.Context, in VerifyInput) error
}
type IssueInput struct{ Degree uint8 }
type VerifyInput struct{ Params json.RawMessage; State []byte; Answer string }

type InteractionValidator interface { ValidateInteraction(ctx context.Context, in InteractionInput) error }
type InteractionInput struct{ State []byte; Events []PointerEvent; Started time.Time }
type PointerEvent struct{ X, Y, T int; PointerType string; Buttons int }

type Store interface {
    Attempt(ctx context.Context, id string, ttl time.Duration, max int32) (n int32, exceeded bool, err error)
    Consume(ctx context.Context, id string, ttl time.Duration) (ok bool, err error)
}
type Clock interface{ Now() time.Time }

func WithSecret(secret []byte, previous ...[]byte) Option
func WithChallenger(c Challenger) Option
func WithStore(s Store) Option              // default bounded memory, 65536 entries
func WithStoreFailure(m FailureMode) Option // Consume, default FailClosed
func WithAttemptFailure(m FailureMode) Option // Attempt, default FailClosed
func WithTTL(d time.Duration) Option         // default 3m, max 15m
func WithDegree(bits uint8) Option           // default 18, clamp [16,24]
func WithClock(c Clock) Option
func BoundToSubject(subject string) VerifyOption

func Escalate(failures int) Tier
```

Subpackages: `pow`, `store/memory`, `store/redis` (separate go.mod), `httpx`,
`challengetest`, `store/storetest`, `web` (1 KB worker solver), `attack`, `bench`.

Wire protocol (http): `POST /_bouncer/challenge` → 201 `{id,type,token,expires_at,params}`;
`POST /_bouncer/verify` → 200 + `Set-Cookie: bouncer_pass` (10 min, HttpOnly, Secure,
SameSite=Lax) or 4xx `{error}`.

## 6. PoW parameters

- Preimage is 37 bytes (`"bouncer/pow/v1"` (16) || salt (16) || nonce_be64 (8)), which
  fits one SHA-256 block. Keep it at or below 55 bytes; a second block doubles cost.
- Answer is exactly 16 lowercase hex characters. Reject `0x`, leading-zero variants,
  `+`, whitespace, and overlength. (Anubis accepts `007` and `7` as distinct answers;
  do not repeat that.)
- Difficulty comes only from sealed state. The verifier never reads it from `Params`
  or the answer, and a test asserts a client-supplied degree is ignored.
- Base 18 for browser traffic; p50 ~0.3 s and p99 ~2 s on a mid-range phone. Degrees
  above 24 are refused by the shipped web solver (fail closed).

## 7. Slide parameters

- Tolerance is generous: `max(4 px, 8% of piece width)`. Trajectory scoring does the
  work; strict position tolerance only punishes humans.
- Two bands: hard-fail only physically impossible traces (non-monotone time, more
  events than duration allows, drag shorter than 8 events); score the rest and send
  the ambiguous band back to PoW rather than denying the user.
- Backgrounds are 24-48 filled shapes over a gradient (not fBm), re-rolled when local
  contrast around the notch is below 28/255, rendered into `Params` as inline PNG
  capped at 48 KB.
- Scoring parameters are jittered per deployment from
  `HKDF(secret, "bouncer.v1", "slide-scoring")`; published-default thresholds would be
  a published bypass.
