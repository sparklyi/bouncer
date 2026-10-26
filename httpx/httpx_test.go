package httpx_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sparklyi/bouncer"
	"github.com/sparklyi/bouncer/httpx"
	"github.com/sparklyi/bouncer/pow"
)

func newGate(t *testing.T) *bouncer.Gate {
	t.Helper()
	g, err := bouncer.New(bouncer.WithSecret(bytes.Repeat([]byte{9}, 32)), bouncer.WithDegree(16))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

func post(t *testing.T, h http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestChallengeVerifyProtect(t *testing.T) {
	g := newGate(t)
	mux := http.NewServeMux()
	mux.Handle("POST /_bouncer/challenge", httpx.ChallengeHandler(g))
	mux.Handle("POST /_bouncer/verify", httpx.VerifyHandler(g))
	mux.Handle("GET /private", httpx.Protect(g, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := httpx.FromContext(r.Context())
		if !ok {
			t.Error("missing verdict in context")
		}
		if v.Subject != "" {
			t.Errorf("unexpected subject %q", v.Subject)
		}
		w.WriteHeader(http.StatusNoContent)
	})))

	rec := post(t, mux, "/_bouncer/challenge", map[string]any{})
	if rec.Code != http.StatusCreated {
		t.Fatalf("challenge status = %d: %s", rec.Code, rec.Body)
	}
	var ch struct {
		Token  string     `json:"token"`
		Params pow.Params `json:"params"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	answer, err := pow.Solve(context.Background(), ch.Params)
	if err != nil {
		t.Fatal(err)
	}

	// Private route before verification.
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	private := httptest.NewRecorder()
	mux.ServeHTTP(private, req)
	if private.Code != http.StatusForbidden {
		t.Fatalf("private before pass = %d, want 403", private.Code)
	}

	verify := post(t, mux, "/_bouncer/verify", map[string]string{"token": ch.Token, "answer": answer})
	if verify.Code != http.StatusOK {
		t.Fatalf("verify status = %d: %s", verify.Code, verify.Body)
	}
	cookies := verify.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly {
		t.Fatalf("expected one HttpOnly pass cookie, got %+v", cookies)
	}

	req = httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(cookies[0])
	private = httptest.NewRecorder()
	mux.ServeHTTP(private, req)
	if private.Code != http.StatusNoContent {
		t.Fatalf("private with pass = %d, want 204: %s", private.Code, private.Body)
	}

	// The pass is single use by default.
	private = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(cookies[0])
	mux.ServeHTTP(private, req)
	if private.Code != http.StatusConflict {
		t.Fatalf("replayed pass = %d, want 409", private.Code)
	}
}

func TestVerifyHandlerRejectsWrongAnswer(t *testing.T) {
	g := newGate(t)
	mux := http.NewServeMux()
	mux.Handle("POST /_bouncer/challenge", httpx.ChallengeHandler(g))
	mux.Handle("POST /_bouncer/verify", httpx.VerifyHandler(g))

	rec := post(t, mux, "/_bouncer/challenge", map[string]any{})
	var ch struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	bad := post(t, mux, "/_bouncer/verify", map[string]string{"token": ch.Token, "answer": "0000000000000000"})
	if bad.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", bad.Code)
	}
	var body struct{ Error string }
	if err := json.Unmarshal(bad.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != "wrong_answer" {
		t.Fatalf("error = %q, want wrong_answer", body.Error)
	}
}

func TestChallengeHandlerRejectsGet(t *testing.T) {
	g := newGate(t)
	rec := httptest.NewRecorder()
	httpx.ChallengeHandler(g).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/_bouncer/challenge", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestStatusCode(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{bouncer.ErrExpired, http.StatusGone},
		{bouncer.ErrReplay, http.StatusConflict},
		{bouncer.ErrMalformed, http.StatusBadRequest},
		{bouncer.ErrStore, http.StatusServiceUnavailable},
		{bouncer.ErrWrongAnswer, http.StatusForbidden},
		{errors.New("other"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		if got := httpx.StatusCode(c.err); got != c.want {
			t.Fatalf("StatusCode(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}

func TestProtectReusablePass(t *testing.T) {
	g := newGate(t)
	var hits int
	h := httpx.Protect(g, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusNoContent)
	}), httpx.WithReusablePass())

	pass, _, err := g.IssuePass(context.Background(), "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/p", nil)
		req.Header.Set("X-Bouncer-Pass", pass)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("request %d = %d", i, rec.Code)
		}
	}
	if hits != 2 {
		t.Fatalf("hits = %d, want 2", hits)
	}
}
