package httpx_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sparklyi/bouncer"
	"github.com/sparklyi/bouncer/httpx"
	"github.com/sparklyi/bouncer/pow"
)

func TestGuardServesDropInAssets(t *testing.T) {
	g := newGate(t)
	guard := httpx.NewGuard(g)
	protected := guard.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("private"))
	}))

	for _, asset := range []string{"/_bouncer/widget.js", "/_bouncer/worker.js"} {
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, asset, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s = %d", asset, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
			t.Fatalf("%s content type = %q", asset, ct)
		}
		if rec.Body.Len() < 500 {
			t.Fatalf("%s body too small: %d", asset, rec.Body.Len())
		}
	}
}

func TestGuardInterstitialForPages(t *testing.T) {
	guard := httpx.NewGuard(newGate(t))
	protected := guard.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/app", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("page without pass = %d, want 403", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/_bouncer/widget.js") || !strings.Contains(body, "bouncer.verify()") {
		t.Fatalf("interstitial does not boot the widget:\n%s", body)
	}
}

func TestGuardJSONForAPIs(t *testing.T) {
	guard := httpx.NewGuard(newGate(t))
	protected := guard.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/action", strings.NewReader("{}"))
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("api without pass = %d, want 403", rec.Code)
	}
	var payload struct{ Error string }
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Error != "challenge_required" {
		t.Fatalf("error = %q", payload.Error)
	}
}

func TestGuardFullFlow(t *testing.T) {
	guard := httpx.NewGuard(newGate(t))
	protected := guard.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := httpx.FromContext(r.Context()); ok {
			t.Error("Protect must not need a context verdict")
		}
		_, _ = w.Write([]byte("private"))
	}))

	// Challenge through the same handler a one-line mount would use.
	req := httptest.NewRequest(http.MethodPost, "/_bouncer/challenge", bytes.NewReader([]byte(`{}`)))
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("challenge = %d: %s", rec.Code, rec.Body)
	}
	var challenge struct {
		Token  string     `json:"token"`
		Params pow.Params `json:"params"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	answer, err := pow.Solve(context.Background(), challenge.Params)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"token": challenge.Token, "answer": answer})
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/_bouncer/verify", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("verify = %d: %s", rec.Code, rec.Body)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d", len(cookies))
	}

	req = httptest.NewRequest(http.MethodGet, "/app", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "private" {
		t.Fatalf("with pass = %d %q", rec.Code, rec.Body)
	}
}

func TestGuardExempt(t *testing.T) {
	guard := httpx.NewGuard(newGate(t), httpx.WithExempt(func(r *http.Request) bool {
		return r.URL.Path == "/healthz"
	}))
	protected := guard.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("exempt = %d, want 204", rec.Code)
	}
}

func TestGuardCustomPrefix(t *testing.T) {
	guard := httpx.NewGuard(newGate(t), httpx.WithPrefix("/human/check"))
	if guard.Prefix() != "/human/check" {
		t.Fatalf("prefix = %q", guard.Prefix())
	}
	rec := httptest.NewRecorder()
	guard.Protect(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/human/check/widget.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("widget under custom prefix = %d", rec.Code)
	}
}

var _ = bouncer.TierPoW

func TestGuardPassIsReusableByDefault(t *testing.T) {
	guard := httpx.NewGuard(newGate(t))
	protected := guard.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	// Obtain a pass through the plugin endpoints, then use it for two requests:
	// a page load with subresources must not burn the pass on the first one.
	req := httptest.NewRequest(http.MethodPost, "/_bouncer/challenge", bytes.NewReader([]byte(`{}`)))
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	var challenge struct {
		Token  string     `json:"token"`
		Params pow.Params `json:"params"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	answer, err := pow.Solve(context.Background(), challenge.Params)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"token": challenge.Token, "answer": answer})
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/_bouncer/verify", bytes.NewReader(body)))
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d", len(cookies))
	}
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/app", nil)
		req.AddCookie(cookies[0])
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("request %d = %d", i, rec.Code)
		}
	}
}

func TestGuardPassSingleUse(t *testing.T) {
	guard := httpx.NewGuard(newGate(t), httpx.WithPassSingleUse())
	protected := guard.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/_bouncer/challenge", bytes.NewReader([]byte(`{}`)))
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	var challenge struct {
		Token  string     `json:"token"`
		Params pow.Params `json:"params"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	answer, err := pow.Solve(context.Background(), challenge.Params)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"token": challenge.Token, "answer": answer})
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/_bouncer/verify", bytes.NewReader(body)))
	cookies := rec.Result().Cookies()
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/app", nil)
		req.AddCookie(cookies[0])
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		want := http.StatusNoContent
		if i == 1 {
			want = http.StatusForbidden
		}
		if rec.Code != want {
			t.Fatalf("request %d = %d, want %d", i, rec.Code, want)
		}
	}
}
