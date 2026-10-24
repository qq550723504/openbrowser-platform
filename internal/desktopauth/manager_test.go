package desktopauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func contextForTest() context.Context { return context.Background() }

type testClock struct {
	mu    sync.Mutex
	value time.Time
}

func (c *testClock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.value }
func (c *testClock) advance(d time.Duration) { c.mu.Lock(); c.value = c.value.Add(d); c.mu.Unlock() }

var signingKey struct {
	once sync.Once
	key  *rsa.PrivateKey
}

func fixtureKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	signingKey.once.Do(func() {
		var err error
		signingKey.key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
	})
	return signingKey.key
}

type mockIssuer struct {
	server            *httptest.Server
	issuer            string
	mu                sync.Mutex
	subject           string
	codes             map[string]url.Values
	requests          int
	requestPaths      map[string]int
	mutation          func(map[string]any)
	tokenMutation     func(map[string]any)
	discoveryMutation func(map[string]any)
	tokenEntered      chan struct{}
	tokenRelease      chan struct{}
	jwksHook          func()
	clock             *testClock
	key               *rsa.PrivateKey
}

func newIssuer(t *testing.T) *mockIssuer {
	t.Helper()
	p := &mockIssuer{subject: "account-a", codes: map[string]url.Values{}, requestPaths: map[string]int{}, clock: &testClock{value: time.Now().UTC()}, key: fixtureKey(t)}
	p.server = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	p.issuer = p.server.URL + "/issuer"
	t.Cleanup(p.server.Close)
	// Fail with the local fixture's transport error rather than hiding a blocked
	// loopback environment behind the production's intentionally generic error.
	response, err := p.server.Client().Get(p.issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("local TLS fixture unavailable: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	var discovered discovery
	if err != nil || strictJSON(body, &discovered) != nil || !discovered.valid(Config{Issuer: p.issuer, ClientID: "desktop-public"}) {
		t.Fatalf("local fixture metadata invalid: %#v", discovered)
	}
	return p
}

func (p *mockIssuer) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.requestPaths[r.URL.Path]++
	p.mu.Unlock()
	switch r.URL.Path {
	case "/issuer/.well-known/openid-configuration":
		value := map[string]any{"issuer": p.issuer, "authorization_endpoint": p.server.URL + "/authorize", "token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/jwks", "code_challenge_methods_supported": []string{"S256"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "response_types_supported": []string{"code"}}
		if p.discoveryMutation != nil {
			p.discoveryMutation(value)
		}
		_ = json.NewEncoder(w).Encode(value)
	case "/authorize":
		q := r.URL.Query()
		if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" {
			http.Error(w, "bad authorize", 400)
			return
		}
		p.mu.Lock()
		code := "code-" + time.Now().Format("150405.000000000")
		p.codes[code] = q
		p.mu.Unlock()
		redirect, _ := url.Parse(q.Get("redirect_uri"))
		values := redirect.Query()
		values.Set("code", code)
		values.Set("state", q.Get("state"))
		values.Set("iss", p.issuer)
		redirect.RawQuery = values.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	case "/token":
		_ = r.ParseForm()
		p.mu.Lock()
		p.requests++
		original, ok := p.codes[r.Form.Get("code")]
		delete(p.codes, r.Form.Get("code"))
		subject := p.subject
		claimMutation, tokenMutation := p.mutation, p.tokenMutation
		tokenEntered, tokenRelease := p.tokenEntered, p.tokenRelease
		p.mu.Unlock()
		challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || original.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(challenge[:]) ||
			r.Form.Get("client_id") != "desktop-public" || r.Form.Get("redirect_uri") != original.Get("redirect_uri") ||
			r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("client_secret") != "" || r.Header.Get("Authorization") != "" {
			http.Error(w, "bad public client exchange", 400)
			return
		}
		if tokenEntered != nil {
			close(tokenEntered)
			<-tokenRelease
		}
		claims := map[string]any{"iss": p.issuer, "sub": subject, "aud": "desktop-public", "nonce": original.Get("nonce"), "iat": p.clock.now().Unix(), "exp": p.clock.now().Add(time.Hour).Unix()}
		if claimMutation != nil {
			claimMutation(claims)
		}
		response := map[string]any{"access_token": "fixture-access-token-never-persist", "token_type": "Bearer", "expires_in": 3600, "id_token": signJWT(p.key, claims)}
		if tokenMutation != nil {
			tokenMutation(response)
		}
		_ = json.NewEncoder(w).Encode(response)
	case "/jwks":
		if p.jwksHook != nil {
			p.jwksHook()
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "fixture-key", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.E)).Bytes())}}})
	default:
		http.NotFound(w, r)
	}
}

func signJWT(key *rsa.PrivateKey, c any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "fixture-key", "typ": "JWT"})
	body, _ := json.Marshal(c)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (p *mockIssuer) manager(t *testing.T) *Manager {
	t.Helper()
	m := newManager(Config{Issuer: p.issuer, ClientID: "desktop-public"}, p.server.Client(), p.clock.now)
	t.Cleanup(m.Close)
	return m
}

func authorize(t *testing.T, p *mockIssuer, authURL string) int {
	t.Helper()
	client := p.server.Client()
	client.Timeout = 5 * time.Second
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("mock authorization failed (transport only): %T", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func login(t *testing.T, p *mockIssuer, m *Manager) {
	t.Helper()
	authURL, err := m.Begin()
	if err != nil {
		t.Fatal("begin failed", err)
	}
	if code := authorize(t, p, authURL); code != 200 {
		t.Fatalf("mock callback status %d", code)
	}
	if m.Status().State != "signed_in" {
		t.Fatal("expected verified session")
	}
}

func TestUnconfiguredAndHTTPSFailClosed(t *testing.T) {
	for _, cfg := range []Config{{}, {Issuer: "http://127.0.0.1:7777", ClientID: "desktop"}, {Issuer: "https://issuer.example?bad=1", ClientID: "desktop"}, {Issuer: "https://issuer.example", ClientID: ""}} {
		m := NewManager(cfg)
		if m.Status().Configured {
			t.Fatal("invalid configuration accepted")
		}
		if _, err := m.Begin(); !errors.Is(err, ErrConfiguration) {
			t.Fatal("expected configuration error")
		}
		if err := m.WithIdentity(m.Status().Generation, func(Identity) error { t.Fatal("must not execute"); return nil }); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("guard failed")
		}
		m.Close()
	}
}

func TestPKCELoginExpiryAndNoRendererTokens(t *testing.T) {
	p := newIssuer(t)
	m := p.manager(t)
	login(t, p, m)
	status := m.Status()
	if status.Issuer != p.issuer || status.Subject != "account-a" {
		t.Fatal("wrong verified principal")
	}
	renderer, _ := json.Marshal(status)
	for _, secret := range []string{"access_token", "id_token", "fixture-access-token", "code_verifier", "refresh_token"} {
		if strings.Contains(string(renderer), secret) {
			t.Fatal("renderer token leak")
		}
	}
	if err := m.WithIdentity(m.Status().Generation, func(i Identity) error {
		if i.Subject != "account-a" {
			t.Fatal("identity mismatch")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	p.clock.advance(2 * time.Hour)
	if m.Status().State != "expired" {
		t.Fatal("expired session remained usable")
	}
	if err := m.WithIdentity(m.Status().Generation, func(Identity) error { t.Fatal("expired session bypass"); return nil }); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
}

func TestRejectTokenClaimsAndDiscovery(t *testing.T) {
	for name, mutation := range map[string]func(map[string]any){
		"nonce": func(c map[string]any) { c["nonce"] = "wrong" }, "issuer": func(c map[string]any) { c["iss"] = "https://other.example" },
		"audience": func(c map[string]any) { c["aud"] = "other-client" }, "expired": func(c map[string]any) { c["exp"] = int64(1) },
		"future-iat": func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() }, "subject": func(c map[string]any) { c["sub"] = "" },
		"azp": func(c map[string]any) { c["aud"] = []string{"desktop-public", "other"}; c["azp"] = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			p := newIssuer(t)
			p.mutation = mutation
			m := p.manager(t)
			u, err := m.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if authorize(t, p, u) != 400 || m.Status().State == "signed_in" {
				t.Fatal("invalid token accepted")
			}
		})
	}
	for name, mutation := range map[string]func(map[string]any){
		"issuer-mixup":        func(d map[string]any) { d["issuer"] = "https://other.example" },
		"http-token-endpoint": func(d map[string]any) { d["token_endpoint"] = "http://127.0.0.1/token" },
		"missing-s256":        func(d map[string]any) { d["code_challenge_methods_supported"] = []string{"plain"} },
	} {
		t.Run(name, func(t *testing.T) {
			p := newIssuer(t)
			p.discoveryMutation = mutation
			m := p.manager(t)
			if _, err := m.Begin(); !errors.Is(err, ErrLogin) {
				t.Fatal("invalid discovery accepted")
			}
		})
	}
}

func TestWrongStateDoesNotConsumeAttemptAndReplayRejected(t *testing.T) {
	p := newIssuer(t)
	m := p.manager(t)
	u, err := m.Begin()
	if err != nil {
		t.Fatal(err)
	}
	bad, _ := url.Parse(u)
	q := bad.Query()
	q.Set("state", "attacker")
	bad.RawQuery = q.Encode()
	if authorize(t, p, bad.String()) != 400 || m.Status().State != "signing_in" {
		t.Fatal("bad state accepted or consumed valid attempt")
	}
	m.mu.Lock()
	tx := m.pending
	m.mu.Unlock()
	if authorize(t, p, u) != 200 {
		t.Fatal("valid state failed")
	}
	request := httptest.NewRequest("GET", tx.redirect+"?state="+url.QueryEscape(tx.state)+"&code=replay", nil)
	response := httptest.NewRecorder()
	m.callback(contextForTest(), tx, response, request)
	if response.Code != 400 {
		t.Fatal("callback replay accepted")
	}
	p.mu.Lock()
	requests := p.requests
	p.mu.Unlock()
	if requests != 1 {
		t.Fatal("unexpected token exchange count")
	}
}

func TestLogoutWinsAgainstInFlightExchange(t *testing.T) {
	p := newIssuer(t)
	p.tokenEntered = make(chan struct{})
	p.tokenRelease = make(chan struct{})
	m := p.manager(t)
	u, err := m.Begin()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		client := p.server.Client()
		client.Timeout = 5 * time.Second
		resp, _ := client.Get(u)
		if resp != nil {
			resp.Body.Close()
		}
		close(done)
	}()
	select {
	case <-p.tokenEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("exchange not reached")
	}
	m.Logout()
	close(p.tokenRelease)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not stop")
	}
	if m.Status().State != "signed_out" {
		t.Fatal("cancelled exchange resurrected session")
	}
}

func TestCallbackMethodHostDuplicateStateAndTimeout(t *testing.T) {
	p := newIssuer(t)
	m := p.manager(t)
	if _, err := m.Begin(); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	tx := m.pending
	m.mu.Unlock()
	for name, mutate := range map[string]func(*http.Request){
		"method": func(r *http.Request) { r.Method = "POST" }, "host": func(r *http.Request) { r.Host = "evil.example" },
		"duplicate-state": func(r *http.Request) { r.URL.RawQuery += "&state=duplicate" },
		"path":            func(r *http.Request) { r.URL.Path = "/different" },
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tx.redirect+"?state="+url.QueryEscape(tx.state)+"&code=code", nil)
			mutate(r)
			w := httptest.NewRecorder()
			m.callback(contextForTest(), tx, w, r)
			if w.Code != 400 {
				t.Fatal("invalid callback accepted")
			}
		})
	}
	p.clock.advance(6 * time.Minute)
	r := httptest.NewRequest("GET", tx.redirect+"?state="+url.QueryEscape(tx.state)+"&code=code", nil)
	w := httptest.NewRecorder()
	m.callback(contextForTest(), tx, w, r)
	if w.Code != 400 {
		t.Fatal("expired callback accepted")
	}
}
