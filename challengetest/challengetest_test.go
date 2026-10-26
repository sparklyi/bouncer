package challengetest_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sparklyi/bouncer"
	"github.com/sparklyi/bouncer/challengetest"
)

type fake struct{}

func (fake) Tier() bouncer.Tier { return bouncer.TierPoW }
func (fake) Type() string       { return "fake" }
func (fake) Issue(context.Context, bouncer.IssueInput) ([]byte, []byte, error) {
	return []byte(`{}`), []byte("state"), nil
}
func (fake) Verify(_ context.Context, in bouncer.VerifyInput) error {
	if in.Answer != "ok" || string(in.State) != "state" {
		return errors.New("rejected")
	}
	return nil
}

func TestRun(t *testing.T) {
	challengetest.Run(t, func(t *testing.T) bouncer.Challenger { return fake{} })
}
