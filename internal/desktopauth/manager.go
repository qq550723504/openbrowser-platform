package desktopauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const loginLifetime = 5 * time.Minute

func listenCallback() (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }

type transaction struct {
	state, nonce, verifier, redirect string
	discovery                        discovery
	deadline                         time.Time
	server                           *http.Server
	listener                         net.Listener
	cancel                           context.CancelFunc
	claimed                          bool
}

type session struct {
	identity    Identity
	deadline    time.Time
	accessToken string // memory only; never returned by Status or to the renderer
}

type Manager struct {
	mu                 sync.Mutex
	cfg                Config
	client             *http.Client
	now                func() time.Time
	pending            *transaction
	session            *session
	state, errorCode   string
	generation         uint64
	closed             bool
	apiGrantGeneration uint64
	apiGranted         bool
}

func NewManager(cfg Config) *Manager { return newManager(cfg, http.DefaultClient, time.Now) }

// Private injection seam for TLS mock-provider tests; not a production config switch.
func newManager(cfg Config, client *http.Client, now func() time.Time) *Manager {
	copyClient := *client
	copyClient.Timeout = 15 * time.Second
	copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	m := &Manager{cfg: cfg, client: &copyClient, now: now, state: "signed_out"}
	if !cfg.valid() {
		m.state = "unconfigured"
		m.errorCode = "identity_configuration_required"
	}
	return m
}

func randomString() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", ErrLogin
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

type loginAttempt struct {
	url        string
	generation uint64
}

// Begin is for trusted Go callers; renderer actions must supply their generation.
func (m *Manager) Begin() (string, error) {
	m.mu.Lock()
	generation := m.statusLocked().Generation
	m.mu.Unlock()
	attempt, err := m.begin(generation)
	return attempt.url, err
}

// begin returns the immutable attempt generation with its URL, never to JavaScript.
func (m *Manager) begin(expectedGeneration uint64) (loginAttempt, error) {
	m.mu.Lock()
	if m.closed || !m.cfg.valid() {
		m.mu.Unlock()
		return loginAttempt{}, ErrConfiguration
	}
	if m.statusLocked().Generation != expectedGeneration {
		m.mu.Unlock()
		return loginAttempt{}, ErrCancelled
	}
	m.resetLocked("signing_in", "")
	generation := m.generation
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), loginLifetime)
	fail := func() (loginAttempt, error) {
		cancel()
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.generation == generation {
			m.resetLocked("signed_out", "identity_login_failed")
		}
		return loginAttempt{}, ErrLogin
	}
	var d discovery
	body, err := m.request(ctx, "GET", strings.TrimRight(m.cfg.Issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil || strictJSON(body, &d) != nil || !d.valid(m.cfg) {
		return fail()
	}
	state, err := randomString()
	if err != nil {
		return fail()
	}
	nonce, err := randomString()
	if err != nil {
		return fail()
	}
	verifier, err := randomString()
	if err != nil {
		return fail()
	}
	ln, err := listenCallback()
	if err != nil {
		return fail()
	}
	tx := &transaction{state: state, nonce: nonce, verifier: verifier, discovery: d, deadline: m.now().Add(loginLifetime), listener: ln, cancel: cancel}
	// Keep the path registerable; only the ephemeral port varies (RFC 8252).
	tx.redirect = "http://" + ln.Addr().String() + "/oauth/callback"
	tx.server = &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	tx.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { m.callback(ctx, tx, w, r) })
	m.mu.Lock()
	if m.closed || m.generation != generation {
		m.mu.Unlock()
		cancel()
		ln.Close()
		return loginAttempt{}, ErrCancelled
	}
	m.pending = tx
	m.mu.Unlock()
	go func() { _ = tx.server.Serve(ln) }()
	go func() {
		<-ctx.Done()
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.pending == tx {
			m.resetLocked("signed_out", "identity_login_expired")
		}
	}()
	u, _ := url.Parse(d.Authorization)
	query := u.Query()
	challenge := sha256.Sum256([]byte(verifier))
	query.Set("client_id", m.cfg.ClientID)
	query.Set("response_type", "code")
	query.Set("redirect_uri", tx.redirect)
	query.Set("scope", "openid profile")
	query.Set("state", state)
	query.Set("nonce", nonce)
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	query.Set("code_challenge_method", "S256")
	u.RawQuery = query.Encode()
	return loginAttempt{url: u.String(), generation: generation}, nil
}

func (m *Manager) request(ctx context.Context, method, endpoint string, form url.Values) ([]byte, error) {
	var reader io.Reader
	if form != nil {
		reader = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, ErrLogin
	}
	req.Header.Set("Accept", "application/json")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := m.client.Do(req)
	if err != nil {
		return nil, ErrLogin
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrLogin
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(body) > 1024*1024 {
		return nil, ErrLogin
	}
	return body, nil
}

func (m *Manager) callback(ctx context.Context, tx *transaction, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	u, _ := url.Parse(tx.redirect)
	if r.Method != "GET" || r.URL.Path != u.Path || r.Host != u.Host || len(r.URL.RawQuery) > 16384 {
		http.Error(w, "Invalid login response", http.StatusBadRequest)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query["state"]) != 1 || len(query["code"]) > 1 || len(query["error"]) > 1 || len(query["iss"]) > 1 ||
		subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(tx.state)) != 1 {
		http.Error(w, "Invalid login response", http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	if m.closed || m.pending != tx || tx.claimed || !m.now().Before(tx.deadline) {
		m.mu.Unlock()
		http.Error(w, "Login expired", http.StatusBadRequest)
		return
	}
	tx.claimed = true
	m.mu.Unlock()
	// Close can abort this handler's buffered HTTP response before net/http
	// flushes it. Stop accepting and let the owned callback finish first.
	// Authentication state/deadlines are unchanged; bound shutdown separately.
	defer func() {
		go func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if tx.server.Shutdown(closeCtx) != nil {
				_ = tx.server.Close()
			}
		}()
	}()
	if query.Get("error") != "" || query.Get("code") == "" || (query.Get("iss") != "" && query.Get("iss") != m.cfg.Issuer) {
		m.finish(tx, nil, "identity_login_failed")
		http.Error(w, "Login was not completed", http.StatusBadRequest)
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {m.cfg.ClientID}, "code": {query.Get("code")}, "redirect_uri": {tx.redirect}, "code_verifier": {tx.verifier}}
	body, err := m.request(ctx, "POST", tx.discovery.Token, form)
	// expires_in starts at receipt of this response, before any JWKS delay.
	tokenReceivedAt := m.now()
	var token struct {
		RefreshToken json.RawMessage `json:"refresh_token"`
		AccessToken  string          `json:"access_token"`
		IDToken      string          `json:"id_token"`
		TokenType    string          `json:"token_type"`
		ExpiresIn    jsonNumber      `json:"expires_in"`
	}
	if err != nil || strictJSON(body, &token) != nil || len(token.RefreshToken) != 0 || token.AccessToken == "" || len(token.AccessToken) > 32768 ||
		!strings.EqualFold(token.TokenType, "Bearer") || token.IDToken == "" || token.ExpiresIn <= 0 || token.ExpiresIn > jsonNumber((1<<63-1)/time.Second) {
		m.finish(tx, nil, "identity_login_failed")
		http.Error(w, "Login failed", http.StatusBadRequest)
		return
	}
	keys, err := m.request(ctx, "GET", tx.discovery.JWKS, nil)
	identity, expires, verifyErr := verifyIDToken(token.IDToken, tx.nonce, m.cfg, keys, m.now())
	if err != nil || verifyErr != nil {
		m.finish(tx, nil, "identity_login_failed")
		http.Error(w, "Login failed", 400)
		return
	}
	deadline := expires
	// The response validation above bounds multiplication before converting to a
	// duration; compare absolute times without rounding away fractional seconds.
	accessDeadline := tokenReceivedAt.Add(time.Duration(token.ExpiresIn) * time.Second)
	if accessDeadline.Before(deadline) {
		deadline = accessDeadline
	}
	if !m.now().Before(deadline) {
		m.finish(tx, nil, "identity_login_failed")
		http.Error(w, "Login failed", 400)
		return
	}
	verified := &session{identity: identity, deadline: deadline, accessToken: token.AccessToken}
	if !m.finish(tx, verified, "") {
		http.Error(w, "Login expired", 400)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "Login completed. You may close this window and return to the desktop app.")
}

// Numeric expires_in only; a string or fraction cannot silently extend a session.
type jsonNumber int64

func (n *jsonNumber) UnmarshalJSON(value []byte) error {
	x, err := strconv.ParseInt(string(value), 10, 64)
	if err != nil || x <= 0 {
		return ErrLogin
	}
	*n = jsonNumber(x)
	return nil
}

func (m *Manager) finish(tx *transaction, verified *session, code string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.pending != tx || !m.now().Before(tx.deadline) {
		return false
	}
	if verified != nil && !m.now().Before(verified.deadline) {
		verified = nil
		code = "identity_login_failed"
	}
	m.pending = nil
	tx.cancel()
	if verified == nil {
		m.state = "signed_out"
		m.errorCode = code
		return false
	}
	m.session = verified
	m.state = "signed_in"
	m.errorCode = ""
	return true
}

func (m *Manager) resetLocked(state, code string) {
	m.generation++
	m.apiGranted = false
	if m.pending != nil {
		m.pending.cancel()
		_ = m.pending.listener.Close()
		m.pending = nil
	}
	m.session = nil
	m.state = state
	m.errorCode = code
}

func (m *Manager) statusLocked() Status {
	if m.pending != nil && !m.now().Before(m.pending.deadline) {
		m.resetLocked("signed_out", "identity_login_expired")
	}
	if m.session != nil && !m.now().Before(m.session.deadline) {
		m.resetLocked("expired", "authentication_required")
	}
	result := Status{State: m.state, Configured: m.cfg.valid(), ErrorCode: m.errorCode, Generation: m.generation}
	result.APIGranted = m.apiGranted && m.apiGrantGeneration == m.generation && m.session != nil
	if m.session != nil {
		result.Issuer = m.session.identity.Issuer
		result.Subject = m.session.identity.Subject
		result.ExpiresAt = m.session.deadline
	}
	return result
}

func (m *Manager) Status() Status { m.mu.Lock(); defer m.mu.Unlock(); return m.statusLocked() }
func (m *Manager) Logout() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resetLocked("signed_out", "")
	return m.statusLocked()
}

// Renderer auth controls compare generations under the same lock as mutation.
func (m *Manager) logoutExpected(generation uint64) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := m.statusLocked()
	if m.closed || status.Generation != generation {
		return status, ErrCancelled
	}
	m.resetLocked("signed_out", "")
	return m.statusLocked(), nil
}

func (m *Manager) cancelAttempt(generation uint64) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := m.statusLocked()
	if m.closed || status.Generation != generation || status.State != "signing_in" {
		return status, ErrCancelled
	}
	m.resetLocked("signed_out", "")
	return m.statusLocked(), nil
}
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.resetLocked("signed_out", "")
}

// WithIdentity serializes logout/account replacement against each local operation.
// Callbacks must not reacquire the Manager lock or perform external network operations.
func (m *Manager) WithIdentity(expectedGeneration uint64, operation func(Identity) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireIdentityLocked(expectedGeneration); err != nil {
		return err
	}
	return operation(m.session.identity)
}

// Caller holds m.mu. Admission and query publication use the same identity rule.
func (m *Manager) requireIdentityLocked(expectedGeneration uint64) error {
	if m.closed || m.statusLocked().State != "signed_in" || m.session == nil || m.generation != expectedGeneration {
		return ErrUnauthenticated
	}
	return nil
}

// Queries may use the existing account database initialization/migration path,
// but must not perform domain writes or publish preview tickets in this callback.
// Mutations retain WithIdentity's admission semantics: a completed write cannot
// be relabeled as unauthenticated merely because its session has since expired.
func queryWithIdentity[T any](m *Manager, generation uint64, query func(Identity) (T, error)) (result T, err error) {
	err = m.WithIdentity(generation, func(identity Identity) error {
		value, queryErr := query(identity)
		if err := m.requireIdentityLocked(generation); err != nil {
			return err
		}
		result = value
		return queryErr
	})
	if err != nil {
		var empty T
		return empty, err
	}
	return result, nil
}
