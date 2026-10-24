package backend

import (
	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/config"
	"encoding/json"
	"errors"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAuthBoundOwnedCleanupUsesProofAndOneNormalCommand(t *testing.T) {
	for _, mode := range []string{"verified", "creation-mismatch", "recovered", "unknown-ack", "foreign-endpoint"} {
		t.Run(mode, func(t *testing.T) {
			var commands atomic.Int32
			var target *httptest.Server
			target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/json/version" {
					endpoint := "ws" + strings.TrimPrefix(target.URL, "http") + "/devtools/browser/synthetic"
					if mode == "foreign-endpoint" {
						endpoint = "ws://example.invalid/devtools/browser/foreign"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"webSocketDebuggerUrl": endpoint})
					return
				}
				conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				var request cdpMessage
				if conn.ReadJSON(&request) != nil {
					return
				}
				if request.Method != "Browser.close" {
					t.Error("cleanup sent a non-close command")
				}
				commands.Add(1)
				if mode == "unknown-ack" {
					return
				}
				_ = conn.WriteJSON(map[string]any{"id": request.Id, "result": map[string]any{}})
			}))
			defer target.Close()
			u, _ := url.Parse(target.URL)
			port, _ := strconv.Atoi(u.Port())
			a, b, m := authFixture(t)
			a.config = config.DefaultConfig()
			a.browserMgr = browser.NewManager(a.config, a.appRoot)
			directory := filepath.Join(t.TempDir(), "synthetic-profile")
			cmd := &exec.Cmd{Process: &os.Process{Pid: 12345}}
			monitor := &browserProcessMonitor{cmd: cmd, waitDone: make(chan struct{})}
			a.browserMgr.Profiles["owned"] = &browser.Profile{ProfileId: "owned", UserDataDir: directory, Pid: 12345, DebugPort: port, Running: true}
			a.browserMgr.BrowserProcesses["owned"] = cmd
			a.browserProcessMonitors["owned"] = monitor
			oldCreation, oldEndpoint := readOwnedProcessCreation, verifyOwnedProcessEndpoint
			t.Cleanup(func() { readOwnedProcessCreation = oldCreation; verifyOwnedProcessEndpoint = oldEndpoint })
			readOwnedProcessCreation = func(pid int) (string, error) {
				if pid != 12345 {
					t.Fatal("arbitrary PID proof requested")
				}
				return "synthetic-creation", nil
			}
			verifyOwnedProcessEndpoint = func(pid int, path string, p int) error {
				if pid != 12345 || path != directory || p != port {
					t.Fatal("ownership tuple changed")
				}
				return nil
			}
			scope, err := a.scoped(7)
			if err != nil {
				t.Fatal(err)
			}
			scope.rememberOwnedBrowser("owned", directory, port, cmd, monitor)
			_, _ = m.SignOut(7)
			if mode == "creation-mismatch" {
				readOwnedProcessCreation = func(int) (string, error) { return "reused-pid", nil }
			}
			if mode == "recovered" {
				a.browserMgr.BrowserProcesses["owned"] = nil
			}
			err = b.CloseOwnedBrowser("owned")
			if mode == "verified" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, errOwnedCleanupUnknown) {
				t.Fatalf("unknown/unproven close accepted: %v", err)
			}
			expected := int32(0)
			if mode == "verified" || mode == "unknown-ack" {
				expected = 1
			}
			if commands.Load() != expected {
				t.Fatalf("normal commands %d, expected %d", commands.Load(), expected)
			}
			if err := b.CloseOwnedBrowser("owned"); !errors.Is(err, errOwnedCleanupUnknown) {
				t.Fatal("cleanup replayed")
			}
			if commands.Load() != expected {
				t.Fatal("unknown cleanup automatically retried")
			}
			if a.forceQuit || !a.browserMgr.Profiles["owned"].Running {
				t.Fatal("cleanup invoked force/metadata fallback")
			}
		})
	}
}

func TestAuthBoundTrayExitWithoutSessionKeepsInstances(t *testing.T) {
	a, _, m := authFixture(t)
	_, _ = m.SignOut(7)
	QuitFromTray(a)
	if a.shouldStopRuntimeServicesOnShutdown() {
		t.Fatal("tray bypassed login to full runtime shutdown")
	}
}
