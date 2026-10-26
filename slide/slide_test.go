package slide

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/sparklyi/bouncer"
)

func stateTarget(t *testing.T, state []byte) int {
	t.Helper()
	if len(state) != 6 {
		t.Fatalf("state length = %d", len(state))
	}
	return int(binary.BigEndian.Uint16(state[0:2]))
}

func humanTrace(target int) []bouncer.PointerEvent {
	events := make([]bouncer.PointerEvent, 0, 50)
	var tms int64
	const n = 44
	for i := 0; i <= n; i++ {
		p := float64(i) / n
		e := p * p * (3 - 2*p) // ease-in-out, the shape minimum-jerk motion produces
		x := int(e * float64(target))
		if i < 8 {
			x = -8 + i
		}
		jitter := 0
		if i > 2 && i < n-2 {
			jitter = int(math.Sin(float64(i) * 2.7))
		}
		tms += 14 + int64(i%4)
		events = append(events, bouncer.PointerEvent{X: x + jitter, Y: 80 + jitter, T: tms, PointerType: "mouse", Buttons: 1})
	}
	for i := 0; i < 6; i++ { // dwell and a final correction
		tms += 20 + int64(i)
		events = append(events, bouncer.PointerEvent{X: target - i%2, Y: 80, T: tms, PointerType: "mouse", Buttons: 1})
	}
	return events
}

func botTrace(target int) []bouncer.PointerEvent {
	events := make([]bouncer.PointerEvent, 0, 12)
	for i := 0; i <= 10; i++ {
		events = append(events, bouncer.PointerEvent{X: i * target / 10, Y: 80, T: int64(i * 16), PointerType: "mouse", Buttons: 1})
	}
	return events
}

func TestHumanTraceIsTrusted(t *testing.T) {
	for _, target := range []int{40, 120, 200, 250} {
		if !trustedTrajectory(humanTrace(target), 320, 200, 56, 8) {
			t.Fatalf("human trace to %d rejected", target)
		}
	}
}

func TestBotTraceIsRejected(t *testing.T) {
	for _, target := range []int{40, 120, 200, 250} {
		if trustedTrajectory(botTrace(target), 320, 200, 56, 8) {
			t.Fatalf("bot trace to %d accepted", target)
		}
	}
}

func TestTeleportAndEmptyTracesAreRejected(t *testing.T) {
	cases := map[string][]bouncer.PointerEvent{
		"empty": nil,
		"two-point": {
			{X: 0, T: 0}, {X: 150, T: 300},
		},
		"non-monotone": {
			{X: 0, T: 100}, {X: 20, T: 90}, {X: 40, T: 80}, {X: 60, T: 70}, {X: 80, T: 60}, {X: 100, T: 50},
		},
	}
	for name, events := range cases {
		if trustedTrajectory(events, 320, 200, 56, 8) {
			t.Fatalf("%s trace accepted", name)
		}
	}
}

func TestVerifyAcceptsHumanAnswer(t *testing.T) {
	ch := New()
	_, state, err := ch.Issue(context.Background(), bouncer.IssueInput{})
	if err != nil {
		t.Fatal(err)
	}
	target := stateTarget(t, state)
	raw, _ := json.Marshal(map[string]any{"x": target, "events": humanTrace(target)})
	if err := ch.Verify(context.Background(), bouncer.VerifyInput{State: state, Answer: string(raw)}); err != nil {
		t.Fatalf("human answer rejected: %v", err)
	}
}

func TestVerifyRejectsBotAnswer(t *testing.T) {
	ch := New()
	_, state, err := ch.Issue(context.Background(), bouncer.IssueInput{})
	if err != nil {
		t.Fatal(err)
	}
	target := stateTarget(t, state)
	raw, _ := json.Marshal(map[string]any{"x": target, "events": botTrace(target)})
	if err := ch.Verify(context.Background(), bouncer.VerifyInput{State: state, Answer: string(raw)}); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("want ErrUntrusted, got %v", err)
	}
}

func TestVerifyRejectsWrongPosition(t *testing.T) {
	ch := New()
	_, state, err := ch.Issue(context.Background(), bouncer.IssueInput{})
	if err != nil {
		t.Fatal(err)
	}
	target := stateTarget(t, state)
	raw, _ := json.Marshal(map[string]any{"x": target - 100, "events": humanTrace(target)})
	if err := ch.Verify(context.Background(), bouncer.VerifyInput{State: state, Answer: string(raw)}); !errors.Is(err, bouncer.ErrWrongAnswer) {
		t.Fatalf("want ErrWrongAnswer, got %v", err)
	}
}

func TestParamsDoNotLeakTarget(t *testing.T) {
	ch := New()
	params, _, err := ch.Issue(context.Background(), bouncer.IssueInput{})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(params, &fields); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"x", "target", "answer", "dx"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("params leak %q", forbidden)
		}
	}
	if _, ok := fields["image"]; !ok {
		t.Fatal("params missing image")
	}
}

func TestGateEnforcesAttemptBudget(t *testing.T) {
	g, err := bouncer.New(bouncer.WithSecret(bytes.Repeat([]byte{3}, 32)), bouncer.WithChallenger(New()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })

	ch, err := g.Issue(context.Background(), bouncer.Request{Tier: bouncer.TierSlide})
	if err != nil {
		t.Fatal(err)
	}
	bad, _ := json.Marshal(map[string]any{"x": -50, "events": humanTrace(10)})
	for i := 0; i < 3; i++ {
		if _, err := g.Verify(context.Background(), bouncer.Solution{Token: ch.Token, Answer: string(bad)}); !errors.Is(err, bouncer.ErrWrongAnswer) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := g.Verify(context.Background(), bouncer.Solution{Token: ch.Token, Answer: string(bad)}); !errors.Is(err, bouncer.ErrAttemptsExceeded) {
		t.Fatalf("want ErrAttemptsExceeded, got %v", err)
	}
}
