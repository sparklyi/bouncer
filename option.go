package bouncer

import (
	"log/slog"
	"time"
)

// Option configures a Gate. Options apply once, at construction.
type Option func(*gateConfig)

type gateConfig struct {
	err            error
	secret         []byte
	previous       [][]byte
	challengers    map[Tier]Challenger
	store          Store
	storeFailure   FailureMode
	attemptFailure FailureMode
	ttl            time.Duration
	degree         uint8
	clock          Clock
	logger         *slog.Logger
}

// WithSecret sets the master secret used to derive ticket keys. It must be at
// least 32 bytes. previous keys are accepted for decryption only, which allows
// rotation without invalidating tickets that are still in flight.
func WithSecret(secret []byte, previous ...[]byte) Option {
	return func(c *gateConfig) {
		c.secret = append([]byte(nil), secret...)
		c.previous = make([][]byte, len(previous))
		for i, key := range previous {
			c.previous[i] = append([]byte(nil), key...)
		}
	}
}

// WithSecretFile loads the master secret from path, generating it with 0600
// permissions when the file does not exist. It is the zero-configuration
// alternative to WithSecret.
func WithSecretFile(path string) Option {
	return func(c *gateConfig) {
		key, err := LoadOrCreateSecret(path)
		if err != nil {
			c.err = err
			return
		}
		c.secret = key
	}
}

// WithChallenger registers a challenge for its tier, replacing any earlier one.
func WithChallenger(ch Challenger) Option {
	return func(c *gateConfig) {
		if ch != nil {
			c.challengers[ch.Tier()] = ch
		}
	}
}

// WithStore replaces the default in-memory store. A Store supplied here is not
// closed by Gate.Close: the caller owns its lifecycle.
func WithStore(s Store) Option {
	return func(c *gateConfig) { c.store = s }
}

// WithStoreFailure sets the behaviour when Store.Consume fails. FailClosed is
// the default; FailOpen disables replay protection while the store is down.
func WithStoreFailure(m FailureMode) Option {
	return func(c *gateConfig) { c.storeFailure = m }
}

// WithAttemptFailure sets the behaviour when Store.Attempt fails. FailClosed is
// the default; FailOpen trades attempt budgets for availability.
func WithAttemptFailure(m FailureMode) Option {
	return func(c *gateConfig) { c.attemptFailure = m }
}

// WithTTL sets how long issued tickets stay redeemable. Values outside
// (0, MaxTTL] are clamped.
func WithTTL(d time.Duration) Option {
	return func(c *gateConfig) {
		if d <= 0 {
			return
		}
		if d > MaxTTL {
			d = MaxTTL
		}
		c.ttl = d
	}
}

// WithDegree sets the default proof-of-work difficulty. Values outside
// [MinDegree, MaxDegree] are clamped.
func WithDegree(bits uint8) Option {
	return func(c *gateConfig) {
		if bits == 0 {
			return
		}
		c.degree = clampDegree(bits)
	}
}

// WithClock replaces the clock used for expiry. It exists for tests.
func WithClock(clock Clock) Option {
	return func(c *gateConfig) {
		if clock != nil {
			c.clock = clock
		}
	}
}

// WithLogger sets the logger used for store-failure warnings.
func WithLogger(l *slog.Logger) Option {
	return func(c *gateConfig) {
		if l != nil {
			c.logger = l
		}
	}
}

func clampDegree(bits uint8) uint8 {
	switch {
	case bits < MinDegree:
		return MinDegree
	case bits > MaxDegree:
		return MaxDegree
	default:
		return bits
	}
}

// VerifyOption adjusts a single verification.
type VerifyOption func(*verifyConfig)

type verifyConfig struct {
	subject   string
	reusePass bool
}

// BoundToSubject requires the ticket to have been issued for subject.
func BoundToSubject(subject string) VerifyOption {
	return func(c *verifyConfig) { c.subject = subject }
}

// ReusePass lets a pass ticket be verified more than once within its lifetime.
// Single use is the default.
func ReusePass() VerifyOption {
	return func(c *verifyConfig) { c.reusePass = true }
}
