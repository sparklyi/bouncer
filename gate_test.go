package bouncer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sparklyi/bouncer"
	"github.com/sparklyi/bouncer/pow"
	"github.com/sparklyi/bouncer/store/memory"
)

var secret = bytes.Repeat([]byte{7}, 32)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time      { return c.now }
func (c *fakeClock) Add(d time.Duration) { c.now = c.now.Add(d) }
func newClock() *fakeClock               { return &fakeClock{now: time.Unix(1_800_000_000, 0)} }
func mustGate(t *testing.T, opts ...bouncer.Option) *bouncer.Gate {
	t.Helper()
	g, err := bouncer.New(opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

func solve(t *testing.T, ch *bouncer.Challenge) string {
	t.Helper()
	var params pow.Params
	if err := json.Unmarshal(ch.Params, &params); err != nil {
		t.Fatalf("params: %v", err)
	}
	answer, err := pow.Solve(context.Background(), params)
	if err != nil {
		t.Fatalf("solve: %v", err)
	}
	return answer
}

func TestGateIssueAndVerify(t *testing.T) {
	clock := newClock()
	g := mustGate(t, bouncer.WithSecret(secret), bouncer.WithClock(clock), bouncer.WithDegree(16))

	ch, err := g.Issue(context.Background(), bouncer.Request{Subject: "user:1"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if ch.Type != "pow/sha256" || ch.ID == "" || ch.Token == "" {
		t.Fatalf("unexpected challenge: %+v", ch)
	}
	if len(ch.Params) == 0 {
		t.Fatal("missing params")
	}
	verdict, err := g.Verify(context.Background(), bouncer.Solution{Token: ch.Token, Answer: solve(t, ch)}, bouncer.BoundToSubject("user:1"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verdict.Subject != "user:1" || verdict.Degree != 16 {
		t.Fatalf("unexpected verdict: %+v", verdict)
	}
}

func TestGateRejectsReplay(t *testing.T) {
	clock := newClock()
	g := mustGate(t, bouncer.WithSecret(secret), bouncer.WithClock(clock), bouncer.WithDegree(16))
	ch, err := g.Issue(context.Background(), bouncer.Request{})
	if err != nil {
		t.Fatal(err)
	}
	answer := solve(t, ch)
	if _, err := g.Verify(context.Background(), bouncer.Solution{Token: ch.Token, Answer: answer}); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	_, err = g.Verify(context.Background(), bouncer.Solution{Token: ch.Token, Answer: answer})
	if !errors.Is(err, bouncer.ErrReplay) {
		t.Fatalf("want ErrReplay, got %v", err)
	}
}

func TestGateRejectsExpired(t *testing.T) {
	clock := newClock()
	g := mustGate(t, bouncer.WithSecret(secret), bouncer.WithClock(clock), bouncer.WithTTL(time.Minute), bouncer.WithDegree(16))
	ch, err := g.Issue(context.Background(), bouncer.Request{})
	if err != nil {
		t.Fatal(err)
	}
	answer := solve(t, ch)
	clock.Add(2 * time.Minute)
	_, err = g.Verify(context.Background(), bouncer.Solution{Token: ch.Token, Answer: answer})
	if !errors.Is(err, bouncer.ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestGateSubjectBinding(t *testing.T) {
	g := mustGate(t, bouncer.WithSecret(secret), bouncer.WithDegree(16))
	ch, err := g.Issue(context.Background(), bouncer.Request{Subject: "user:1"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = g.Verify(context.Background(), bouncer.Solution{Token: ch.Token, Answer: solve(t, ch)}, bouncer.BoundToSubject("user:2"))
	if !errors.Is(err, bouncer.ErrSubjectMismatch) {
		t.Fatalf("want ErrSubjectMismatch, got %v", err)
	}
}

func TestGateRejectsWrongAnswerWithoutConsuming(t *testing.T) {
	g := mustGate(t, bouncer.WithSecret(secret), bouncer.WithDegree(16))
	ch, err := g.Issue(context.Background(), bouncer.Request{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = g.Verify(context.Background(), bouncer.Solution{Token: ch.Token, Answer: strings.Repeat("0", 16)})
	if !errors.Is(err, bouncer.ErrWrongAnswer) {
		t.Fatalf("want ErrWrongAnswer, got %v", err)
	}
	if _, err := g.Verify(context.Background(), bouncer.Solution{Token: ch.Token, Answer: solve(t, ch)}); err != nil {
		t.Fatalf("ticket must remain redeemable after a wrong answer: %v", err)
	}
}

func TestGateRejectsTamperedToken(t *testing.T) {
	g := mustGate(t, bouncer.WithSecret(secret), bouncer.WithDegree(16))
	ch, err := g.Issue(context.Background(), bouncer.Request{})
	if err != nil {
		t.Fatal(err)
	}
	answer := solve(t, ch)
	tampered := []byte(ch.Token)
	tampered[len(tampered)-3] ^= 1 // ciphertext byte
	_, err = g.Verify(context.Background(), bouncer.Solution{Token: string(tampered), Answer: answer})
	if !errors.Is(err, bouncer.ErrBadToken) {
		t.Fatalf("want ErrBadToken, got %v", err)
	}
}

func TestGateRejectsUnknownTier(t *testing.T) {
	g := mustGate(t, bouncer.WithSecret(secret))
	if _, err := g.Issue(context.Background(), bouncer.Request{Tier: bouncer.TierSlide}); !errors.Is(err, bouncer.ErrUnsupportedType) {
		t.Fatalf("want ErrUnsupportedType, got %v", err)
	}
}

func TestGateDegreeClamp(t *testing.T) {
	g := mustGate(t, bouncer.WithSecret(secret), bouncer.WithDegree(1))
	ch, err := g.Issue(context.Background(), bouncer.Request{Degree: 200})
	if err != nil {
		t.Fatal(err)
	}
	var params pow.Params
	if err := json.Unmarshal(ch.Params, &params); err != nil {
		t.Fatal(err)
	}
	if params.Degree != bouncer.MaxDegree {
		t.Fatalf("degree = %d, want %d", params.Degree, bouncer.MaxDegree)
	}
}

func TestGateClose(t *testing.T) {
	g := mustGate(t, bouncer.WithSecret(secret))
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Issue(context.Background(), bouncer.Request{}); !errors.Is(err, bouncer.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}

func TestGateRequiresSecret(t *testing.T) {
	if _, err := bouncer.New(); !errors.Is(err, bouncer.ErrNoSecret) {
		t.Fatalf("want ErrNoSecret, got %v", err)
	}
	if _, err := bouncer.New(bouncer.WithSecret([]byte("short"))); !errors.Is(err, bouncer.ErrNoSecret) {
		t.Fatalf("want ErrNoSecret, got %v", err)
	}
}

func TestPassSingleUseAndReuse(t *testing.T) {
	clock := newClock()
	g := mustGate(t, bouncer.WithSecret(secret), bouncer.WithClock(clock))

	token, expires, err := g.IssuePass(context.Background(), "user:1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !expires.Equal(clock.Now().Add(time.Minute)) {
		t.Fatalf("expires = %v", expires)
	}
	if _, err := g.VerifyPass(context.Background(), token); err != nil {
		t.Fatalf("first VerifyPass: %v", err)
	}
	if _, err := g.VerifyPass(context.Background(), token); !errors.Is(err, bouncer.ErrReplay) {
		t.Fatalf("want ErrReplay, got %v", err)
	}
	token2, _, err := g.IssuePass(context.Background(), "user:1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := g.VerifyPass(context.Background(), token2, bouncer.ReusePass()); err != nil {
			t.Fatalf("reuse %d: %v", i, err)
		}
	}
}

type failingStore struct{}

func (failingStore) Attempt(context.Context, string, time.Duration, int32) (int32, bool, error) {
	return 0, false, errors.New("down")
}
func (failingStore) Consume(context.Context, string, time.Duration) (bool, error) {
	return false, errors.New("down")
}

func TestStoreFailureModes(t *testing.T) {
	clock := newClock()
	closed := mustGate(t, bouncer.WithSecret(secret), bouncer.WithClock(clock), bouncer.WithStore(failingStore{}), bouncer.WithDegree(16))
	ch, err := closed.Issue(context.Background(), bouncer.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := closed.Verify(context.Background(), bouncer.Solution{Token: ch.Token, Answer: solve(t, ch)}); !errors.Is(err, bouncer.ErrStore) {
		t.Fatalf("want ErrStore, got %v", err)
	}

	open := mustGate(t, bouncer.WithSecret(secret), bouncer.WithClock(clock), bouncer.WithStore(failingStore{}), bouncer.WithStoreFailure(bouncer.FailOpen), bouncer.WithDegree(16))
	ch, err = open.Issue(context.Background(), bouncer.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := open.Verify(context.Background(), bouncer.Solution{Token: ch.Token, Answer: solve(t, ch)}); err != nil {
		t.Fatalf("fail-open Verify: %v", err)
	}
}

func TestSecretRotation(t *testing.T) {
	clock := newClock()
	old := bytes.Repeat([]byte{1}, 32)
	next := bytes.Repeat([]byte{2}, 32)
	oldGate := mustGate(t, bouncer.WithSecret(old), bouncer.WithClock(clock), bouncer.WithDegree(16))
	ch, err := oldGate.Issue(context.Background(), bouncer.Request{})
	if err != nil {
		t.Fatal(err)
	}
	answer := solve(t, ch)

	rotated := mustGate(t, bouncer.WithSecret(next, old), bouncer.WithClock(clock), bouncer.WithDegree(16))
	if _, err := rotated.Verify(context.Background(), bouncer.Solution{Token: ch.Token, Answer: answer}); err != nil {
		t.Fatalf("old key must still verify: %v", err)
	}
	fresh := mustGate(t, bouncer.WithSecret(next), bouncer.WithClock(clock), bouncer.WithDegree(16))
	if _, err := fresh.Verify(context.Background(), bouncer.Solution{Token: ch.Token, Answer: answer}); !errors.Is(err, bouncer.ErrBadToken) {
		t.Fatalf("want ErrBadToken without the old key, got %v", err)
	}
}

func TestEscalate(t *testing.T) {
	prev := -1
	for failures := 0; failures < 10; failures++ {
		tier, degree := bouncer.Escalate(failures)
		if degree < bouncer.MinDegree || degree > bouncer.MaxDegree {
			t.Fatalf("failures=%d degree=%d out of range", failures, degree)
		}
		if int(degree) < prev {
			t.Fatalf("degree must not decrease: failures=%d", failures)
		}
		prev = int(degree)
		if failures >= 6 && tier != bouncer.TierSlide {
			t.Fatalf("failures=%d tier=%v, want slide", failures, tier)
		}
	}
}

var _ = memory.New
