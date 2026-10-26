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

Escalation: `0-1 failures → PoW`, `2-3 → harder PoW`, `>=4 → slide`. The caller may
force a tier and pass a risk hint; the library does not implement a risk engine.

## 3. Ticket format

```
token = "b1." + base64url(kid(1) || nonce(12) || AEAD ciphertext+tag(16))

plaintext (AES-256-GCM, AAD = "bouncer.v1" || type):
  1B ver | 1B type_len | nB type | 1B degree | 8B issued_at | 8B expires_at
  | 1B sub_len | sB subject | 16B id (jti) | 2B state_len | mB state
```

- Keys: `tokenKey = HKDF-SHA256(ikm=secret, salt="bouncer.v1", info="token-aead")`,
  derived once at construction. `kid = SHA256(key)[0]`; rotation keeps the previous
  keys for decryption.
- Binary, not JSON: smaller, strict length-checked parsing, no type ambiguity.
- Sealed, not signed: future challenges have private answers; the protocol must not
  change when they land.
- AAD binds the type, preventing cross-type confusion.

## 4. Verification order

```
parse → AEAD decrypt → type match → expiry → subject binding → Challenger.Verify
      → store.Consume(id)
```

Consume is last on purpose: consuming first lets anyone holding a ticket burn it with
a garbage answer. Challenges that need attempt limits (slide) use `store.Attempt`
before verification; PoW needs no attempt limit because guessing is solving.

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
type PointerEvent struct{ X, Y, T int; Type string }

type Store interface {
    Attempt(ctx context.Context, id string, ttl time.Duration, max int32) (n int32, exceeded bool, err error)
    Consume(ctx context.Context, id string, ttl time.Duration) (ok bool, err error)
}
type Clock interface{ Now() time.Time }

func WithSecret(secret []byte, previous ...[]byte) Option
func WithChallenger(c Challenger) Option
func WithStore(s Store) Option
func WithStoreFailure(m FailureMode) Option // default FailClosed
func WithTTL(d time.Duration) Option        // default 3m, max 15m
func WithDegree(bits uint8) Option          // default 20, clamp [16,28]
func WithClock(c Clock) Option
func BoundToSubject(subject string) VerifyOption

func Escalate(failures int) Tier
```

Subpackages: `pow`, `store/memory`, `store/redis` (separate go.mod), `httpx`,
`challengetest`, `store/storetest`, `web` (1 KB worker solver), `attack`, `bench`.

Wire protocol (http): `POST /_bouncer/challenge` → 201 `{id,type,token,expires_at,params}`;
`POST /_bouncer/verify` → 200 + `Set-Cookie: bouncer_pass` (10 min, HttpOnly, Secure,
SameSite=Lax) or 4xx `{error}`.
