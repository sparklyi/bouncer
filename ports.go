package bouncer

import (
	"context"
	"time"
)

// Challenger is one verification layer. Implementations must be safe for
// concurrent use and must not retain State between calls.
type Challenger interface {
	// Tier reports which layer this challenge implements.
	Tier() Tier
	// Type is a stable identifier such as "pow/sha256".
	Type() string
	// Issue returns public parameters for the client and the private state to
	// seal into the ticket. State is limited to 4096 bytes.
	Issue(ctx context.Context, in IssueInput) (params []byte, state []byte, err error)
	// Verify reports whether answer solves the challenge held in in.State.
	// It must return ErrWrongAnswer (possibly wrapped) on a bad answer.
	Verify(ctx context.Context, in VerifyInput) error
}

// Store is the atomic backing store for attempt budgets and one-time
// redemption. Implementations must never implement it as read-then-write.
type Store interface {
	// Attempt atomically increments the counter for id and reports the new
	// value. exceeded is true when the count is greater than max.
	Attempt(ctx context.Context, id string, ttl time.Duration, max int32) (n int32, exceeded bool, err error)
	// Consume atomically marks id as used until ttl elapses. It reports ok
	// only for the first caller.
	Consume(ctx context.Context, id string, ttl time.Duration) (ok bool, err error)
}

// Clock supplies the current time. Injecting it keeps expiry logic testable.
type Clock interface {
	Now() time.Time
}

// FailureMode decides what happens when the Store is unreachable.
type FailureMode uint8

const (
	// FailClosed rejects the request when the store fails. This is the default
	// because ignoring a store error silently disables replay protection.
	FailClosed FailureMode = iota
	// FailOpen accepts the request when the store fails, trading security for
	// availability. Only choose it deliberately.
	FailOpen
)

// attemptLimited is implemented by challenges that need a per-ticket attempt
// budget (anything whose answer can be guessed cheaply).
type attemptLimited interface {
	MaxAttempts() int32
}

const passType = "bouncer/pass"

// Clock and store bounds shared with challenges.
const (
	// MinDegree and MaxDegree bound the proof-of-work difficulty.
	MinDegree uint8 = 16
	// MaxDegree keeps browser solve time within a human latency budget.
	MaxDegree uint8 = 24
	// DefaultDegree is the browser default (p50 ~0.3s, p99 ~2s on a phone).
	DefaultDegree uint8 = 18
	// DefaultTTL is how long a challenge stays redeemable.
	DefaultTTL = 3 * time.Minute
	// MaxTTL caps the configured ticket lifetime.
	MaxTTL = 15 * time.Minute
	// maxState bounds the sealed challenge state.
	maxState = 4096
	// maxSubject bounds the subject binding.
	maxSubject = 128
	// maxToken bounds allocation from untrusted input.
	maxToken = 8192
	// markerSlack keeps replay markers alive past the ticket expiry.
	markerSlack = 30 * time.Second
)
