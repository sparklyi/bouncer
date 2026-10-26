// Package challengetest is a contract suite for bouncer.Challenger
// implementations.
package challengetest

import (
	"context"
	"testing"

	"github.com/sparklyi/bouncer"
)

// Run checks the properties every Challenger must satisfy without knowing how
// to solve it.
func Run(t *testing.T, newChallenger func(t *testing.T) bouncer.Challenger) {
	t.Helper()
	ctx := context.Background()

	ch := newChallenger(t)
	if ch.Type() == "" {
		t.Fatal("Type must not be empty")
	}
	if ch.Tier() != bouncer.TierPoW && ch.Tier() != bouncer.TierSlide {
		t.Fatalf("unexpected tier %v", ch.Tier())
	}

	params, state, err := ch.Issue(ctx, bouncer.IssueInput{Degree: bouncer.DefaultDegree})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(params) == 0 {
		t.Fatal("Issue returned no params")
	}
	if len(state) == 0 {
		t.Fatal("Issue returned no state")
	}
	if len(state) > 4096 {
		t.Fatalf("state is %d bytes, above the 4096 limit", len(state))
	}

	t.Run("rejects garbage answer", func(t *testing.T) {
		for _, answer := range []string{"", "garbage", "\x00\xff"} {
			if err := ch.Verify(ctx, bouncer.VerifyInput{Params: params, State: state, Answer: answer}); err == nil {
				t.Fatalf("answer %q must be rejected", answer)
			}
		}
	})

	t.Run("rejects corrupted state", func(t *testing.T) {
		bad := append([]byte(nil), state...)
		bad[0] ^= 0xff
		if err := ch.Verify(ctx, bouncer.VerifyInput{Params: params, State: bad, Answer: "x"}); err == nil {
			t.Fatal("corrupted state must not verify")
		}
	})

	t.Run("verification is deterministic", func(t *testing.T) {
		err1 := ch.Verify(ctx, bouncer.VerifyInput{Params: params, State: state, Answer: "garbage"})
		err2 := ch.Verify(ctx, bouncer.VerifyInput{Params: params, State: state, Answer: "garbage"})
		if (err1 == nil) != (err2 == nil) {
			t.Fatal("Verify is not deterministic for the same input")
		}
	})
}
