// Package httpx wires a bouncer.Gate into net/http.
//
// Three pieces: a challenge endpoint, a verify endpoint that mints a pass
// cookie, and a Protect middleware that requires that cookie. Framework users
// (Gin, Echo, chi) can mount the handlers with their own adapter, or call
// VerifyPass from their own middleware to keep their error format.
package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sparklyi/bouncer"
)

const (
	defaultCookieName = "bouncer_pass"
	defaultPrefix     = "/_bouncer"
	defaultPassTTL    = 10 * time.Minute
	passHeader        = "X-Bouncer-Pass"
	maxBody           = 64 << 10
)

// Option configures the handlers.
type Option func(*options)

type options struct {
	cookieName string
	passTTL    time.Duration
	path       string
	secure     bool
	reusePass  bool
	singleUse  bool
	prefix     string
	tier       bouncer.Tier
	exempt     func(*http.Request) bool
}

func defaultOptions() options {
	return options{
		cookieName: defaultCookieName,
		passTTL:    defaultPassTTL,
		path:       "/",
		prefix:     defaultPrefix,
		tier:       bouncer.TierPoW,
	}
}

// WithCookieName sets the pass cookie name.
func WithCookieName(name string) Option {
	return func(o *options) {
		if name != "" {
			o.cookieName = name
		}
	}
}

// WithPassTTL sets how long a pass cookie stays valid.
func WithPassTTL(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.passTTL = d
		}
	}
}

// WithCookiePath sets the cookie path. "/" is the default.
func WithCookiePath(path string) Option {
	return func(o *options) {
		if path != "" {
			o.path = path
		}
	}
}

// WithSecure marks the pass cookie Secure. Enable it whenever the site runs on
// HTTPS; it must stay off for plain-HTTP loopback development.
func WithSecure(secure bool) Option {
	return func(o *options) { o.secure = secure }
}

// WithReusablePass lets one pass authorise several requests until it expires.
// The low-level VerifyPass default consumes the pass on first use.
func WithReusablePass() Option {
	return func(o *options) { o.reusePass = true }
}

// WithPassSingleUse makes every protected request consume its pass. Use it for
// endpoints where each attempt must pay for a fresh challenge, such as a login.
func WithPassSingleUse() Option {
	return func(o *options) { o.singleUse = true }
}

type challengeRequest struct {
	Tier    string `json:"tier,omitempty"`
	Degree  uint8  `json:"degree,omitempty"`
	Subject string `json:"subject,omitempty"`
}

type challengeResponse struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Token     string          `json:"token"`
	ExpiresAt time.Time       `json:"expires_at"`
	Params    json.RawMessage `json:"params"`
}

type verifyRequest struct {
	Token  string `json:"token"`
	Answer string `json:"answer"`
}

type verifyResponse struct {
	OK        bool      `json:"ok"`
	Type      string    `json:"type,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// ChallengeHandler serves POST /_bouncer/challenge.
func ChallengeHandler(g *bouncer.Gate, opts ...Option) http.Handler {
	o := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
			return
		}
		var req challengeRequest
		if err := decode(w, r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "malformed", "invalid request body")
			return
		}
		tier, err := parseTier(req.Tier, o.tier)
		if err != nil {
			writeError(w, http.StatusBadRequest, "malformed", "unknown tier")
			return
		}
		ch, err := g.Issue(r.Context(), bouncer.Request{Tier: tier, Degree: req.Degree, Subject: req.Subject})
		if err != nil {
			status, code := failure(err)
			writeError(w, status, code, "cannot issue a challenge")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusCreated, challengeResponse{
			ID: ch.ID, Type: ch.Type, Token: ch.Token, ExpiresAt: ch.Expires, Params: ch.Params,
		})
	})
}

// VerifyHandler serves POST /_bouncer/verify and sets the pass cookie.
func VerifyHandler(g *bouncer.Gate, opts ...Option) http.Handler {
	o := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
			return
		}
		var req verifyRequest
		if err := decode(w, r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "malformed", "invalid request body")
			return
		}
		verdict, err := g.Verify(r.Context(), bouncer.Solution{Token: req.Token, Answer: req.Answer})
		if err != nil {
			status, code := failure(err)
			writeError(w, status, code, "verification failed")
			return
		}
		p, expires, err := g.IssuePass(r.Context(), "", o.passTTL)
		if err != nil {
			status, code := failure(err)
			writeError(w, status, code, "cannot issue a pass")
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     o.cookieName,
			Value:    p,
			Path:     o.path,
			Expires:  expires,
			HttpOnly: true,
			Secure:   o.secure,
			SameSite: http.SameSiteLaxMode,
		})
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, verifyResponse{OK: true, Type: verdict.Type, ExpiresAt: expires})
	})
}

type ctxKey struct{}

// Protect requires a valid pass before calling next.
func Protect(g *bouncer.Gate, next http.Handler, opts ...Option) http.Handler {
	o := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verdict, err := verifyPass(g, r, o)
		if err != nil {
			status, code := failure(err)
			writeError(w, status, code, "human verification required")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, verdict)))
	})
}

// VerifyPass checks the pass carried by the request. Use it from a custom
// middleware to keep an application's own error format.
func VerifyPass(g *bouncer.Gate, r *http.Request, opts ...Option) (*bouncer.Verdict, error) {
	o := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return verifyPass(g, r, o)
}

func verifyPass(g *bouncer.Gate, r *http.Request, o options) (*bouncer.Verdict, error) {
	token := r.Header.Get(passHeader)
	if token == "" {
		if c, err := r.Cookie(o.cookieName); err == nil {
			token = c.Value
		}
	}
	if token == "" {
		return nil, bouncer.ErrBadToken
	}
	var vopts []bouncer.VerifyOption
	if o.reusePass {
		vopts = append(vopts, bouncer.ReusePass())
	}
	return g.VerifyPass(r.Context(), token, vopts...)
}

// FromContext returns the verdict stored by Protect.
func FromContext(ctx context.Context) (*bouncer.Verdict, bool) {
	v, ok := ctx.Value(ctxKey{}).(*bouncer.Verdict)
	return v, ok
}

// StatusCode maps a bouncer error to an HTTP status.
func StatusCode(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, bouncer.ErrExpired):
		return http.StatusGone
	case errors.Is(err, bouncer.ErrReplay):
		return http.StatusConflict
	case errors.Is(err, bouncer.ErrMalformed):
		return http.StatusBadRequest
	case errors.Is(err, bouncer.ErrStore), errors.Is(err, bouncer.ErrClosed):
		return http.StatusServiceUnavailable
	case errors.Is(err, bouncer.ErrBadToken),
		errors.Is(err, bouncer.ErrSubjectMismatch),
		errors.Is(err, bouncer.ErrWrongAnswer),
		errors.Is(err, bouncer.ErrAttemptsExceeded),
		errors.Is(err, bouncer.ErrUnsupportedType):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

func failure(err error) (int, string) {
	switch {
	case errors.Is(err, bouncer.ErrExpired):
		return http.StatusGone, "expired"
	case errors.Is(err, bouncer.ErrReplay):
		return http.StatusConflict, "replay"
	case errors.Is(err, bouncer.ErrMalformed):
		return http.StatusBadRequest, "malformed"
	case errors.Is(err, bouncer.ErrStore), errors.Is(err, bouncer.ErrClosed):
		return http.StatusServiceUnavailable, "store_unavailable"
	case errors.Is(err, bouncer.ErrAttemptsExceeded):
		return http.StatusForbidden, "attempts_exceeded"
	case errors.Is(err, bouncer.ErrWrongAnswer):
		return http.StatusForbidden, "wrong_answer"
	case errors.Is(err, bouncer.ErrBadToken), errors.Is(err, bouncer.ErrSubjectMismatch):
		return http.StatusForbidden, "challenge_required"
	default:
		return http.StatusInternalServerError, "internal"
	}
}

func parseTier(s string, fallback bouncer.Tier) (bouncer.Tier, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return fallback, nil
	case "pow":
		return bouncer.TierPoW, nil
	case "slide":
		return bouncer.TierSlide, nil
	default:
		return 0, bouncer.ErrUnsupportedType
	}
}

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	defer func() { _, _ = io.Copy(io.Discard, r.Body) }()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Error: code, Message: message})
}
