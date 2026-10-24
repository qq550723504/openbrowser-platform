package launchcode

import (
	"ant-chrome/backend/internal/browser"
	"errors"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type mockIdentity struct {
	generation atomic.Uint64
	grant      atomic.Bool
}

func (m *mockIdentity) Check(g uint64) error {
	if g != m.generation.Load() || !m.grant.Load() {
		return errRequestRevoked
	}
	return nil
}
func (m *mockIdentity) CheckAPI() (uint64, error) { g := m.generation.Load(); return g, m.Check(g) }

type mockStarter struct{ calls atomic.Int32 }

func (m *mockStarter) StartInstance(string) (*browser.Profile, error) {
	m.calls.Add(1)
	return &browser.Profile{ProfileId: "synthetic"}, nil
}
func (m *mockStarter) CreateProfile(browser.ProfileInput) (*browser.Profile, error) {
	m.calls.Add(1)
	return &browser.Profile{ProfileId: "synthetic"}, nil
}
func identityFixture() (*LaunchServer, *mockIdentity, *mockStarter) {
	s := NewLaunchServer(nil, nil, nil, 0)
	m := &mockIdentity{}
	m.generation.Store(7)
	m.grant.Store(true)
	starter := &mockStarter{}
	s.SetIdentityAuthority(m, func(g uint64) (BrowserStarter, error) {
		if err := m.Check(g); err != nil {
			return nil, err
		}
		return starter, nil
	})
	s.SetAPIAuthConfig(APIAuthConfig{Enabled: true, APIKey: "synthetic-key"})
	return s, m, starter
}

func TestIdentityAllIngressPathsFailClosed(t *testing.T) {
	paths := []string{"/api/profiles", "/api/profiles/one", "/api/runtime/active", "/api/runtime/session", "/api/runtime/status", "/api/runtime/stop", "/api/launch", "/api/launch/tasks", "/api/launch/logs", "/api/launch/key", "/api/automation/scripts", "/api/automation/scripts/run", "/api/automation/scripts/runs", "/api/automation/hooks/key", "/json/version", "/devtools/browser/one", "/unknown"}
	for _, mode := range []string{"missing-authority", "revoked", "missing-key", "wrong-key"} {
		t.Run(mode, func(t *testing.T) {
			s, m, starter := identityFixture()
			key := "synthetic-key"
			switch mode {
			case "missing-authority":
				s.identity = nil
			case "revoked":
				m.grant.Store(false)
			case "missing-key":
				s.SetAPIAuthConfig(APIAuthConfig{})
			case "wrong-key":
				key = "wrong"
			}
			handler := NewTestHandler(s)
			for _, path := range paths {
				r := httptest.NewRequest("GET", "http://127.0.0.1"+path, nil)
				r.Header.Set(DefaultAPIKeyHeader, key)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if w.Code != 401 {
					t.Fatalf("%s status %d", path, w.Code)
				}
			}
			if starter.calls.Load() != 0 {
				t.Fatal("business starter entered")
			}
			r := httptest.NewRequest("GET", "http://127.0.0.1/api/health", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatal("liveness unavailable")
			}
		})
	}
}

type gatedBody struct {
	entered, release chan struct{}
	reader           io.Reader
	once             atomic.Bool
}

func (b *gatedBody) Read(p []byte) (int, error) {
	if b.once.CompareAndSwap(false, true) {
		close(b.entered)
		<-b.release
	}
	return b.reader.Read(p)
}
func TestIdentityLateBodyCannotUseReplacementSession(t *testing.T) {
	s, m, starter := identityFixture()
	body := &gatedBody{entered: make(chan struct{}), release: make(chan struct{}), reader: strings.NewReader(`{"profile":{"profileName":"synthetic"}}`)}
	r := httptest.NewRequest("POST", "http://127.0.0.1/api/profiles", body)
	r.Header.Set(DefaultAPIKeyHeader, "synthetic-key")
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { NewTestHandler(s).ServeHTTP(w, r); close(done) }()
	<-body.entered
	m.generation.Add(1)
	close(body.release)
	<-done
	if starter.calls.Load() != 0 || w.Code < 400 {
		t.Fatalf("late request entered replacement: %d %d", starter.calls.Load(), w.Code)
	}
}

func TestIdentityRevokesActualCDPUpgradeWithoutBrowserClose(t *testing.T) {
	backendClosed := make(chan struct{})
	var messages atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		defer close(backendClosed)
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				return
			}
			messages.Add(1)
		}
	}))
	defer target.Close()
	parsed, _ := url.Parse(target.URL)
	port, _ := strconv.Atoi(parsed.Port())
	s, m, _ := identityFixture()
	s.SetActiveProfile(&browser.Profile{ProfileId: "owned-mock", Running: true, DebugReady: true, DebugPort: port})
	proxy := httptest.NewServer(NewTestHandler(s))
	defer proxy.Close()
	headers := http.Header{}
	headers.Set(DefaultAPIKeyHeader, "synthetic-key")
	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(proxy.URL, "http")+"/devtools/browser/mock", headers)
	if err != nil {
		if resp != nil {
			t.Fatalf("upgrade status %d", resp.StatusCode)
		}
		t.Fatal(err)
	}
	defer conn.Close()
	m.grant.Store(false)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Fatal("upgrade survived logout")
	}
	select {
	case <-backendClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream connection retained")
	}
	if messages.Load() != 0 {
		t.Fatal("revocation sent a browser command")
	}
	// Only mock httptest listeners run; LaunchServer.Start and Chromium never run.
	if !errors.Is(m.Check(7), errRequestRevoked) {
		t.Fatal("revocation missing")
	}
}
