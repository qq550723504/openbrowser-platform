package backend

import (
	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/config"
	"ant-chrome/backend/internal/launchcode"
	"ant-chrome/internal/desktopauth"
	"context"
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Private package fixture; no production API/config can install a principal.
type mockSession struct {
	mu          sync.Mutex
	status      desktopauth.Status
	grant       bool
	beforeCheck func()
	afterCheck  func()
}

func newMockSession() *mockSession {
	return &mockSession{status: desktopauth.Status{Generation: 7, State: "signed_in", Configured: true, Issuer: "https://mock.invalid", Subject: "test-subject", ExpiresAt: time.Now().Add(time.Hour)}}
}
func (m *mockSession) Status() desktopauth.Status { m.mu.Lock(); defer m.mu.Unlock(); return m.status }
func (m *mockSession) Check(g uint64) error {
	m.mu.Lock()
	hook := m.beforeCheck
	m.mu.Unlock()
	if hook != nil {
		hook()
	}
	s := m.Status()
	if s.State != "signed_in" || s.Generation != g || !s.ExpiresAt.After(time.Now()) {
		return desktopauth.ErrUnauthenticated
	}
	m.mu.Lock()
	after := m.afterCheck
	m.mu.Unlock()
	if after != nil {
		after()
	}
	return nil
}
func (m *mockSession) Login(uint64, func(string) error) (desktopauth.Status, error) {
	return m.Status(), errors.New("mock_login_not_supported")
}
func (m *mockSession) Cancel(uint64) (desktopauth.Status, error) {
	return m.Status(), desktopauth.ErrCancelled
}
func (m *mockSession) SignOut(g uint64) (desktopauth.Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status.Generation != g {
		return m.status, desktopauth.ErrCancelled
	}
	m.status.Generation++
	m.status.State = "signed_out"
	m.grant = false
	return m.status, nil
}
func (m *mockSession) GrantAPI(g uint64, enabled bool) error {
	if err := m.Check(g); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.grant = enabled
	return nil
}
func (m *mockSession) CheckAPI() (uint64, error) {
	s := m.Status()
	if err := m.Check(s.Generation); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.grant {
		return 0, desktopauth.ErrUnauthenticated
	}
	return s.Generation, nil
}
func (m *mockSession) Close() { _, _ = m.SignOut(m.Status().Generation) }
func (m *mockSession) replace() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status.Generation++
	m.status.State = "signed_in"
	m.status.Subject = "replacement"
	m.grant = false
}
func authFixture(t *testing.T) (*App, *AuthBoundApp, *mockSession) {
	t.Helper()
	a := NewApp(t.TempDir(), "auth-test")
	m := newMockSession()
	a.identity = m
	a.businessReady = true
	return a, NewAuthBoundApp(a), m
}

func TestAuthBoundRejectsEveryBusinessMethodBeforeDelegation(t *testing.T) {
	_, bound, m := authFixture(t)
	typ := reflect.TypeOf(bound)
	value := reflect.ValueOf(bound)
	for _, state := range []string{"signed_out", "unconfigured", "expired", "stale"} {
		t.Run(state, func(t *testing.T) {
			m.mu.Lock()
			m.status.State = state
			m.mu.Unlock()
			for i := 0; i < typ.NumMethod(); i++ {
				method := typ.Method(i)
				if strings.HasPrefix(method.Name, "Auth") || method.Name == "QuitAppOnly" || method.Name == "CloseOwnedBrowser" {
					continue
				}
				t.Run(method.Name, func(t *testing.T) {
					fn := value.Method(i)
					ft := fn.Type()
					if ft.NumIn() == 0 || ft.In(ft.NumIn()-1).Kind() != reflect.Uint64 {
						t.Fatal("missing generation on facade")
					}
					args := make([]reflect.Value, ft.NumIn())
					for j := range args {
						args[j] = reflect.Zero(ft.In(j))
					}
					args[len(args)-1] = reflect.ValueOf(uint64(7))
					out := fn.Call(args)
					err, ok := out[len(out)-1].Interface().(error)
					if !ok || !errors.Is(err, desktopauth.ErrUnauthenticated) {
						t.Fatalf("admission result = %v", out)
					}
				})
			}
		})
	}
	if _, ok := typ.MethodByName("GetInterceptor"); ok {
		t.Fatal("internal interceptor escaped binding")
	}
}

func TestAuthBoundDelegatesOriginalAndPreservesSharedState(t *testing.T) {
	a, b, m := authFixture(t)
	a.config = config.DefaultConfig()
	got, err := b.GetAppConfig(7)
	if err != nil || !reflect.DeepEqual(got, a.GetAppConfig()) {
		t.Fatalf("original delegation: %v %v", got, err)
	}
	old, err := a.scoped(7)
	if err != nil {
		t.Fatal(err)
	}
	if old.appState != a.appState {
		t.Fatal("native state copied")
	}
	check := old.captureAdmission()
	_, _ = b.AuthLogout(7)
	m.replace()
	if check() == nil {
		t.Fatal("old scope adopted replacement")
	}
	if _, err := b.GetAppConfig(7); !errors.Is(err, desktopauth.ErrUnauthenticated) {
		t.Fatal("stale RPC admitted")
	}
	if _, err := b.GetAppConfig(m.Status().Generation); err != nil {
		t.Fatal(err)
	}
	if a.forceQuit {
		t.Fatal("logout killed runtime")
	}
}

func TestAuthBoundPreviewCannotCrossSession(t *testing.T) {
	a, path := newProfilePackageImportTestApp(t, []browser.Profile{{ProfileId: "source", ProfileName: "B", UserDataDir: "data/source"}}, map[string]string{"source/Default/fixture": "synthetic"})
	m := newMockSession()
	a.identity = m
	a.businessReady = true
	b := NewAuthBoundApp(a)
	if _, err := b.BrowserProfilePackagePrepareImportFromPath(path, 7); err != nil {
		t.Fatal(err)
	}
	_, _ = b.AuthLogout(7)
	m.replace()
	generation := m.Status().Generation
	if _, err := b.BrowserProfilePackageImportWithOptions(path, ProfilePackageImportOptions{}, generation); !errors.Is(err, desktopauth.ErrUnauthenticated) {
		t.Fatal("stale preview committed")
	}
	if _, err := b.BrowserProfilePackagePrepareImportFromPath(path, generation); err != nil {
		t.Fatal(err)
	}
	result, err := b.BrowserProfilePackageImportWithOptions(path, ProfilePackageImportOptions{}, generation)
	if err != nil || result.CreatedCount != 1 {
		t.Fatalf("original import: %+v %v", result, err)
	}
}

func TestAuthBoundLateBackgroundDispatchIsDenied(t *testing.T) {
	a, _, m := authFixture(t)
	a.setRuntimeContext(context.Background())
	scoped, err := a.scoped(7)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = m.SignOut(7)
	m.replace()
	var called atomic.Int32
	if err := scoped.startBackgroundTask(func(context.Context) { called.Add(1) }); !errors.Is(err, desktopauth.ErrUnauthenticated) {
		t.Fatal("old task queued")
	}
	if called.Load() != 0 {
		t.Fatal("old background task ran")
	}
	if a.shouldStopRuntimeServicesOnShutdown() {
		t.Fatal("ordinary exit would kill browsers")
	}
}

func TestAuthBoundRestartedHTTPKeepsIdentityAndKeyBoundary(t *testing.T) {
	a, _, m := authFixture(t)
	a.config = config.DefaultConfig()
	a.config.LaunchServer.Auth.Enabled = true
	a.config.LaunchServer.Auth.APIKey = "synthetic-api-key"
	m.grant = true
	var rebuilt *launchcode.LaunchServer
	if err := a.restartLaunchServerWith(23456, func(s *launchcode.LaunchServer) error { rebuilt = s; return nil }); err != nil {
		t.Fatal(err)
	}
	// Production reconstruction and router, no product HTTP listener.
	handler := launchcode.NewTestHandler(rebuilt)
	request := func(key string) int {
		r := httptest.NewRequest("GET", "http://127.0.0.1/api/launch/tasks", nil)
		r.Header.Set(launchcode.DefaultAPIKeyHeader, key)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	if got := request("synthetic-api-key"); got != 200 {
		t.Fatalf("reconstructed route = %d", got)
	}
	if got := request("wrong"); got != 401 {
		t.Fatalf("key bypass = %d", got)
	}
	_, _ = m.SignOut(7)
	if got := request("synthetic-api-key"); got != 401 {
		t.Fatalf("key replaced login = %d", got)
	}
}
