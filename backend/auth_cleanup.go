package backend

import (
	"errors"
	"os/exec"
	"path/filepath"
	"sync"
)

var errOwnedCleanupUnknown = errors.New("owned_browser_close_unknown: close the browser window manually; no automatic retry")

// Private OS seams; production always uses native identity/endpoint proof.
var readOwnedProcessCreation = ownedProcessCreation
var verifyOwnedProcessEndpoint = ownedProcessEndpoint

type ownedBrowserReceipt struct {
	profileID, userDataDir, creation string
	port                             int
	cmd                              *exec.Cmd
	monitor                          *browserProcessMonitor
	attempted                        bool
}

type ownedBrowserReceipts struct {
	mu    sync.Mutex
	items map[string]ownedBrowserReceipt
}

func (a *App) rememberOwnedBrowser(profileID, userDataDir string, port int, cmd *exec.Cmd, monitor *browserProcessMonitor) {
	// Recovered/disk-only processes do not acquire cleanup authority. This scoped
	// receiver exists only for a command admitted before its actual cmd.Start.
	if a.admission == nil || cmd == nil || cmd.Process == nil || monitor == nil {
		return
	}
	creation, err := readOwnedProcessCreation(cmd.Process.Pid)
	if err != nil {
		return
	}
	receipt := ownedBrowserReceipt{profileID: profileID, userDataDir: filepath.Clean(userDataDir), port: port, cmd: cmd, monitor: monitor, creation: creation}
	a.ownedBrowsers.mu.Lock()
	defer a.ownedBrowsers.mu.Unlock()
	if a.ownedBrowsers.items == nil {
		a.ownedBrowsers.items = make(map[string]ownedBrowserReceipt)
	}
	a.ownedBrowsers.items[profileID] = receipt
}

// CloseOwnedBrowser is the sole unauthenticated browser cleanup binding. It
// takes a profile ID, never a PID, port or filesystem path. All authority comes
// from this host process's admitted start and current OS/monitor proof.
func (a *AuthBoundApp) CloseOwnedBrowser(profileID string) error {
	core := a.core
	core.ownedBrowsers.mu.Lock()
	receipt, ok := core.ownedBrowsers.items[profileID]
	if !ok || receipt.attempted {
		core.ownedBrowsers.mu.Unlock()
		return errOwnedCleanupUnknown
	}
	receipt.attempted = true
	core.ownedBrowsers.items[profileID] = receipt
	core.ownedBrowsers.mu.Unlock()
	verify := func() error { return core.verifyOwnedBrowser(receipt) }
	if _, err := cdpBrowserCallVerified(receipt.port, "Browser.close", nil, verify); err != nil {
		return errOwnedCleanupUnknown
	}
	return nil
}

func (a *App) verifyOwnedBrowser(receipt ownedBrowserReceipt) error {
	if receipt.cmd == nil || receipt.cmd.Process == nil || receipt.monitor == nil || receipt.monitor.HasExited() || a.browserMgr == nil {
		return errOwnedCleanupUnknown
	}
	a.browserMgr.Mutex.Lock()
	profile := a.browserMgr.Profiles[receipt.profileID]
	matches := profile != nil && a.browserMgr.BrowserProcesses[receipt.profileID] == receipt.cmd && a.browserProcessMonitors[receipt.profileID] == receipt.monitor && profile.Pid == receipt.cmd.Process.Pid && profile.DebugPort == receipt.port && filepath.Clean(a.browserMgr.ResolveUserDataDir(profile)) == receipt.userDataDir
	a.browserMgr.Mutex.Unlock()
	if !matches {
		return errOwnedCleanupUnknown
	}
	creation, err := readOwnedProcessCreation(receipt.cmd.Process.Pid)
	if err != nil || creation != receipt.creation {
		return errOwnedCleanupUnknown
	}
	return verifyOwnedProcessEndpoint(receipt.cmd.Process.Pid, receipt.userDataDir, receipt.port)
}
