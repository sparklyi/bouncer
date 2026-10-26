package bouncer

import (
	"context"
	"errors"
	"testing"

	"github.com/sparklyi/bouncer/pow"
)

func TestPoWChallengeIssueAndVerify(t *testing.T) {
	ch := newPoWChallenge()
	if ch.Type() != "pow/sha256" || ch.Tier() != TierPoW {
		t.Fatalf("unexpected identity: %q %v", ch.Type(), ch.Tier())
	}
	params, state, err := ch.Issue(context.Background(), IssueInput{Degree: 16})
	if err != nil {
		t.Fatal(err)
	}
	if len(params) == 0 || len(state) != 17 {
		t.Fatalf("params=%d state=%d", len(params), len(state))
	}
	var salt [16]byte
	copy(salt[:], state[:16])
	answer, err := pow.Solve(context.Background(), pow.Params{Alg: "sha256", Salt: pow.EncodeSalt(salt), Degree: state[16]})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Verify(context.Background(), VerifyInput{State: state, Answer: answer}); err != nil {
		t.Fatalf("valid answer rejected: %v", err)
	}
	for _, bad := range []string{"", "garbage", "0"} {
		if err := ch.Verify(context.Background(), VerifyInput{State: state, Answer: bad}); !errors.Is(err, ErrWrongAnswer) {
			t.Fatalf("answer %q: want ErrWrongAnswer, got %v", bad, err)
		}
	}
	// The degree lives in sealed state; mutating it must invalidate the answer.
	state[16] = 32
	if err := ch.Verify(context.Background(), VerifyInput{State: state, Answer: answer}); !errors.Is(err, ErrWrongAnswer) {
		t.Fatalf("want ErrWrongAnswer with a raised degree, got %v", err)
	}
}
