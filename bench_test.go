package bouncer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sparklyi/bouncer"
	"github.com/sparklyi/bouncer/pow"
	"github.com/sparklyi/bouncer/slide"
)

// noopStore isolates crypto and challenge cost from store cost.
type noopStore struct{}

func (noopStore) Attempt(context.Context, string, time.Duration, int32) (int32, bool, error) {
	return 1, false, nil
}
func (noopStore) Consume(context.Context, string, time.Duration) (bool, error) { return true, nil }

func benchGate(b *testing.B, opts ...bouncer.Option) *bouncer.Gate {
	b.Helper()
	base := []bouncer.Option{bouncer.WithSecret(bytes.Repeat([]byte{4}, 32)), bouncer.WithStore(noopStore{}), bouncer.WithDegree(bouncer.MinDegree)}
	g, err := bouncer.New(append(base, opts...)...)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = g.Close() })
	return g
}

func BenchmarkIssue(b *testing.B) {
	g := benchGate(b)
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := g.Issue(ctx, bouncer.Request{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyPoW(b *testing.B) {
	g := benchGate(b)
	ctx := context.Background()
	ch, err := g.Issue(ctx, bouncer.Request{})
	if err != nil {
		b.Fatal(err)
	}
	var params pow.Params
	if err := json.Unmarshal(ch.Params, &params); err != nil {
		b.Fatal(err)
	}
	answer, err := pow.Solve(ctx, params)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := g.Verify(ctx, bouncer.Solution{Token: ch.Token, Answer: answer}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSlideIssue(b *testing.B) {
	g := benchGate(b, bouncer.WithChallenger(slide.New()))
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := g.Issue(ctx, bouncer.Request{Tier: bouncer.TierSlide}); err != nil {
			b.Fatal(err)
		}
	}
}
