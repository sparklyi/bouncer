package bouncer_test

import (
	"context"
	"testing"

	"github.com/sparklyi/bouncer"
)

func FuzzVerifyToken(f *testing.F) {
	g, err := bouncer.New(bouncer.WithSecret(secret), bouncer.WithDegree(16))
	if err != nil {
		f.Fatal(err)
	}
	defer func() { _ = g.Close() }()

	f.Add("b1.", "0000000000000000")
	f.Add("b1.AAAA", "")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, token, answer string) {
		if len(token) > 9000 || len(answer) > 128 {
			return
		}
		_, _ = g.Verify(context.Background(), bouncer.Solution{Token: token, Answer: answer})
	})
}
