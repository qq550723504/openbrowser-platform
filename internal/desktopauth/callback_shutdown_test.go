package desktopauth

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// Hold the outer HTTP handler after callback returns, before net/http flushes
// its buffered response. Immediate Server.Close can lose it in this window.
// All requests go only to this test's synthetic TLS issuer/loopback callback.
func TestCallbackResponseFlushesBeforeServerShutdown(t *testing.T) {
	p := newIssuer(t)
	m := p.manager(t)
	authURL, err := m.Begin()
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	server := m.pending.server
	m.mu.Unlock()
	original := server.Handler
	returned, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseHandler := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseHandler()
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { original.ServeHTTP(w, r); close(returned); <-release })
	type response struct {
		status int
		body   string
		err    error
	}
	replies := make(chan response, 1)
	go func() {
		client := p.server.Client()
		client.Timeout = 3 * time.Second
		r, e := client.Get(authURL)
		result := response{err: e}
		if e == nil {
			b, be := io.ReadAll(r.Body)
			ce := r.Body.Close()
			result.status = r.StatusCode
			result.body = string(b)
			result.err = be
			if ce != nil {
				result.err = ce
			}
		}
		replies <- result
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("synthetic callback did not return")
	}
	select {
	case result := <-replies:
		t.Fatalf("callback connection closed before response flush: status=%d errorType=%T", result.status, result.err)
	case <-time.After(50 * time.Millisecond):
	}
	// Let the HTTP server flush, then allow its graceful shutdown to complete.
	// The deferred close also unblocks the handler on any assertion failure.
	releaseHandler()
	select {
	case result := <-replies:
		if result.err != nil || result.status != http.StatusOK || !strings.HasPrefix(result.body, "Login completed.") {
			t.Fatalf("incomplete synthetic response: status=%d errorType=%T", result.status, result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("synthetic response not flushed")
	}
	if m.Status().State != "signed_in" {
		t.Fatal("verified session missing")
	}
}
