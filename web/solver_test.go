package web_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/sparklyi/bouncer"
	"github.com/sparklyi/bouncer/pow"
)

// These tests keep the browser solver and the Go verifier from drifting apart.
// They skip when node is not installed so that Go-only CI stays green.

func TestJavaScriptSHA256MatchesReference(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "--test", "sha256.test.mjs").CombinedOutput()
	if err != nil {
		t.Fatalf("node --test failed: %v\n%s", err, out)
	}
}

func TestJavaScriptSolverSatisfiesGoVerifier(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	g, err := bouncer.New(
		bouncer.WithSecret(bytes.Repeat([]byte{5}, 32)),
		bouncer.WithDegree(bouncer.MinDegree),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })

	ch, err := g.Issue(context.Background(), bouncer.Request{})
	if err != nil {
		t.Fatal(err)
	}
	var params pow.Params
	if err := json.Unmarshal(ch.Params, &params); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, "solve.mjs", params.Salt, fmt.Sprint(params.Degree)).Output()
	if err != nil {
		t.Fatalf("node solve: %v", err)
	}
	answer := strings.TrimSpace(string(out))
	if _, err := g.Verify(context.Background(), bouncer.Solution{Token: ch.Token, Answer: answer}); err != nil {
		t.Fatalf("Go rejected the JavaScript answer %q: %v", answer, err)
	}
}
