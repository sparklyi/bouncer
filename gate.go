package bouncer

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sparklyi/bouncer/store/memory"
)

// Gate issues and verifies challenges. Create one with New and reuse it; it is
// safe for concurrent use. The zero value is not usable.
type Gate struct {
	keys     *keyring
	byTier   map[Tier]Challenger
	byType   map[string]Challenger
	store    Store
	ownStore bool

	clock          Clock
	ttl            time.Duration
	degree         uint8
	storeFailure   FailureMode
	attemptFailure FailureMode
	logger         *slog.Logger

	closed    atomic.Bool
	closeOnce sync.Once
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// New builds a Gate. WithSecret is required.
func New(opts ...Option) (*Gate, error) {
	cfg := gateConfig{
		challengers:    make(map[Tier]Challenger, 2),
		storeFailure:   FailClosed,
		attemptFailure: FailClosed,
		ttl:            DefaultTTL,
		degree:         DefaultDegree,
		logger:         slog.Default(),
	}
	cfg.challengers[TierPoW] = newPoWChallenge()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.err != nil {
		return nil, wrap("new", cfg.err)
	}
	if len(cfg.secret) < keyLen {
		return nil, wrap("new", ErrNoSecret)
	}
	keys, err := newKeyring(cfg.secret, cfg.previous)
	if err != nil {
		return nil, wrap("new", err)
	}
	if cfg.clock == nil {
		cfg.clock = systemClock{}
	}
	ownStore := false
	if cfg.store == nil {
		cfg.store = memory.New()
		ownStore = true
	}
	g := &Gate{
		keys:           keys,
		byTier:         cfg.challengers,
		byType:         make(map[string]Challenger, len(cfg.challengers)),
		store:          cfg.store,
		ownStore:       ownStore,
		clock:          cfg.clock,
		ttl:            cfg.ttl,
		degree:         clampDegree(cfg.degree),
		storeFailure:   cfg.storeFailure,
		attemptFailure: cfg.attemptFailure,
		logger:         cfg.logger,
	}
	for _, ch := range cfg.challengers {
		g.byType[ch.Type()] = ch
	}
	return g, nil
}

// Issue creates a challenge and a sealed ticket for it.
func (g *Gate) Issue(ctx context.Context, req Request) (*Challenge, error) {
	if g.closed.Load() {
		return nil, wrap("issue", ErrClosed)
	}
	ch, ok := g.byTier[req.Tier]
	if !ok {
		return nil, wrap("issue", ErrUnsupportedType)
	}
	degree := req.Degree
	if degree == 0 {
		degree = g.degree
	}
	degree = clampDegree(degree)
	if len(req.Subject) > maxSubject {
		return nil, wrap("issue", ErrMalformed)
	}
	params, state, err := ch.Issue(ctx, IssueInput{Degree: degree})
	if err != nil {
		return nil, wrap("issue", err)
	}
	jti, err := randomJTI()
	if err != nil {
		return nil, wrap("issue", err)
	}
	now := g.clock.Now()
	expires := now.Add(g.ttl)
	token, err := g.keys.seal(ch.Type(), payload{
		degree:    degree,
		issuedAt:  now.Unix(),
		expiresAt: expires.Unix(),
		subject:   req.Subject,
		jti:       jti,
		state:     state,
	})
	if err != nil {
		return nil, wrap("issue", err)
	}
	return &Challenge{
		ID:      hex.EncodeToString(jti[:]),
		Type:    ch.Type(),
		Token:   token,
		Expires: expires.UTC(),
		Params:  params,
	}, nil
}

// Verify checks a solution and consumes its ticket on success.
func (g *Gate) Verify(ctx context.Context, sol Solution, opts ...VerifyOption) (*Verdict, error) {
	if g.closed.Load() {
		return nil, wrap("verify", ErrClosed)
	}
	cfg := verifyConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	typ, p, err := g.keys.open(sol.Token)
	if err != nil {
		return nil, wrap("verify", err)
	}
	ch, ok := g.byType[typ]
	if !ok {
		return nil, wrap("verify", ErrUnsupportedType)
	}
	now := g.clock.Now()
	if now.Unix() > p.expiresAt {
		return nil, wrap("verify", ErrExpired)
	}
	if cfg.subject != "" && p.subject != cfg.subject {
		return nil, wrap("verify", ErrSubjectMismatch)
	}
	id := hex.EncodeToString(p.jti[:])
	ttl := g.markerTTL(now, p.expiresAt)

	if limit, limited := ch.(attemptLimited); limited && limit.MaxAttempts() > 0 {
		_, exceeded, err := g.store.Attempt(ctx, id, ttl, limit.MaxAttempts())
		if err != nil {
			if failErr := g.storeFailureErr("attempt", err, g.attemptFailure); failErr != nil {
				return nil, failErr
			}
		} else if exceeded {
			// The ticket is unusable from now on: a new challenge is required.
			_, _ = g.store.Consume(ctx, id, ttl)
			return nil, wrap("verify", ErrAttemptsExceeded)
		}
	}

	if err := ch.Verify(ctx, VerifyInput{State: p.state, Answer: sol.Answer}); err != nil {
		return nil, wrap("verify", err)
	}

	ok, err = g.store.Consume(ctx, id, ttl)
	if err != nil {
		if failErr := g.storeFailureErr("consume", err, g.storeFailure); failErr != nil {
			return nil, failErr
		}
	} else if !ok {
		return nil, wrap("verify", ErrReplay)
	}
	return &Verdict{
		Type:     typ,
		Subject:  p.subject,
		Degree:   p.degree,
		IssuedAt: time.Unix(p.issuedAt, 0).UTC(),
	}, nil
}

// IssuePass mints a pass ticket for a subject. Passes record that verification
// already happened and are meant to be carried in a cookie.
func (g *Gate) IssuePass(_ context.Context, subject string, ttl time.Duration) (string, time.Time, error) {
	if g.closed.Load() {
		return "", time.Time{}, wrap("issue pass", ErrClosed)
	}
	if len(subject) > maxSubject {
		return "", time.Time{}, wrap("issue pass", ErrMalformed)
	}
	if ttl <= 0 || ttl > MaxTTL {
		ttl = MaxTTL
	}
	jti, err := randomJTI()
	if err != nil {
		return "", time.Time{}, wrap("issue pass", err)
	}
	now := g.clock.Now()
	expires := now.Add(ttl)
	token, err := g.keys.seal(passType, payload{
		issuedAt:  now.Unix(),
		expiresAt: expires.Unix(),
		subject:   subject,
		jti:       jti,
	})
	if err != nil {
		return "", time.Time{}, wrap("issue pass", err)
	}
	return token, expires.UTC(), nil
}

// VerifyPass checks a pass ticket. By default a pass is single use; ReusePass
// allows repeated checks until it expires.
func (g *Gate) VerifyPass(ctx context.Context, token string, opts ...VerifyOption) (*Verdict, error) {
	if g.closed.Load() {
		return nil, wrap("verify pass", ErrClosed)
	}
	cfg := verifyConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	typ, p, err := g.keys.open(token)
	if err != nil {
		return nil, wrap("verify pass", err)
	}
	if typ != passType {
		return nil, wrap("verify pass", ErrBadToken)
	}
	now := g.clock.Now()
	if now.Unix() > p.expiresAt {
		return nil, wrap("verify pass", ErrExpired)
	}
	if cfg.subject != "" && p.subject != cfg.subject {
		return nil, wrap("verify pass", ErrSubjectMismatch)
	}
	if !cfg.reusePass {
		ok, err := g.store.Consume(ctx, hex.EncodeToString(p.jti[:]), g.markerTTL(now, p.expiresAt))
		if err != nil {
			if failErr := g.storeFailureErr("consume pass", err, g.storeFailure); failErr != nil {
				return nil, failErr
			}
		} else if !ok {
			return nil, wrap("verify pass", ErrReplay)
		}
	}
	return &Verdict{
		Type:     typ,
		Subject:  p.subject,
		IssuedAt: time.Unix(p.issuedAt, 0).UTC(),
	}, nil
}

// Close releases the default store. An injected Store is left untouched.
func (g *Gate) Close() error {
	var err error
	g.closeOnce.Do(func() {
		g.closed.Store(true)
		if g.ownStore {
			if closer, ok := g.store.(interface{ Close() error }); ok {
				err = closer.Close()
			}
		}
	})
	return err
}

func (g *Gate) markerTTL(now time.Time, expiresAt int64) time.Duration {
	remaining := time.Unix(expiresAt, 0).Sub(now)
	if remaining < 0 {
		remaining = 0
	}
	return remaining + markerSlack
}

func (g *Gate) storeFailureErr(op string, err error, mode FailureMode) error {
	if err == nil {
		return nil
	}
	if g.logger != nil {
		g.logger.Warn("bouncer: store failure", "op", op, "fail_open", mode == FailOpen, "err", err)
	}
	if mode == FailOpen {
		return nil
	}
	return &Error{Op: op, Err: errors.Join(ErrStore, err)}
}
