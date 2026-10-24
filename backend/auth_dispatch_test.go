package backend

import (
	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/config"
	"ant-chrome/internal/desktopauth"
	"context"
	"errors"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func waitAuthTest(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("bounded mock synchronization timed out")
	}
}

func TestAuthBoundQueuedBackgroundRechecksBeforeDispatch(t *testing.T) {
	a, _, m := authFixture(t)
	a.setRuntimeContext(context.Background())
	scope, err := a.scoped(7)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var checks, work atomic.Int32
	m.mu.Lock()
	m.beforeCheck = func() {
		if checks.Add(1) == 2 {
			close(entered)
			<-release
		}
	}
	m.mu.Unlock()
	if err := scope.startBackgroundTask(func(context.Context) { work.Add(1) }); err != nil {
		t.Fatal(err)
	}
	waitAuthTest(t, entered)
	_, _ = m.SignOut(7)
	m.replace()
	close(release)
	done := make(chan struct{})
	go func() { a.backgroundTasks.Wait(); close(done) }()
	waitAuthTest(t, done)
	if work.Load() != 0 {
		t.Fatal("queued work borrowed replacement identity")
	}
}

func TestAuthBoundDeferredTabsKeepOriginalAdmission(t *testing.T) {
	a, _, m := authFixture(t)
	scope, err := a.scoped(7)
	if err != nil {
		t.Fatal(err)
	}
	plan := deferredStartTargetsPlan{targets: []string{"https://example.invalid/synthetic"}, admission: scope.captureAdmission()}
	_, _ = m.SignOut(7)
	m.replace()
	if err := openDeferredStartTargets(0, plan); !errors.Is(err, desktopauth.ErrUnauthenticated) {
		t.Fatalf("old deferred tabs reached CDP: %v", err)
	}
}

func TestAuthBoundBackupSchedulerDoesNotReplayRevokedDispatch(t *testing.T) {
	a, _, m := authFixture(t)
	a.config = config.DefaultConfig()
	scheduler := newBackupScheduler(a)
	now := time.Now()
	scheduler.settings.Schedule.Enabled = true
	scheduler.settings.Schedule.DailyTime = now.Format("15:04")
	entered, release := make(chan struct{}), make(chan struct{})
	var checks atomic.Int32
	m.mu.Lock()
	m.beforeCheck = func() {
		if checks.Add(1) == 2 {
			close(entered)
			<-release
		}
	}
	m.mu.Unlock()
	scheduler.check(now)
	waitAuthTest(t, entered)
	_, _ = m.SignOut(7)
	m.replace()
	close(release)
	done := make(chan struct{})
	go func() { scheduler.wg.Wait(); close(done) }()
	waitAuthTest(t, done)
	if scheduler.running || scheduler.state.Status != backupScheduleStatusSkipped || scheduler.lastDate != now.Format("2006-01-02") {
		t.Fatal("revoked backup remained running or replayable")
	}
}

func TestAuthBoundNativeDialogCannotAdoptReplacement(t *testing.T) {
	a, path := newProfilePackageImportTestApp(t, []browser.Profile{{ProfileId: "synthetic", ProfileName: "B"}}, nil)
	m := newMockSession()
	a.identity = m
	a.businessReady = true
	a.ctx = context.Background()
	b := NewAuthBoundApp(a)
	old := openNativeFileDialog
	t.Cleanup(func() { openNativeFileDialog = old })
	entered, release := make(chan struct{}), make(chan struct{})
	openNativeFileDialog = func(context.Context, wailsruntime.OpenDialogOptions) (string, error) {
		close(entered)
		<-release
		return path, nil
	}
	result := make(chan error, 1)
	go func() { _, err := b.BrowserProfilePackagePrepareImport(7); result <- err }()
	waitAuthTest(t, entered)
	// Logout completes while the native dialog is held: no identity/session lock
	// spans the dialog, and the returned path still belongs to generation 7.
	if _, err := b.AuthLogout(7); err != nil {
		t.Fatal(err)
	}
	m.replace()
	close(release)
	select {
	case err := <-result:
		if !errors.Is(err, desktopauth.ErrUnauthenticated) {
			t.Fatalf("late dialog: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dialog deadlocked identity control")
	}
	if a.importPreviewPath != "" {
		t.Fatal("stale dialog published a preview")
	}
}

func TestAuthBoundLogoutAndAppOnlyExitPreserveRunningInstance(t *testing.T) {
	a, b, _ := authFixture(t)
	a.config = config.DefaultConfig()
	a.browserMgr = browser.NewManager(a.config, a.appRoot)
	a.browserMgr.Profiles["synthetic"] = &browser.Profile{ProfileId: "synthetic", Running: true, Pid: 12345}
	if _, err := b.AuthLogout(7); err != nil {
		t.Fatal(err)
	}
	if err := b.ForceQuit(7); !errors.Is(err, desktopauth.ErrUnauthenticated) {
		t.Fatal("unauthenticated force quit admitted")
	}
	b.QuitAppOnly()
	if a.shouldStopRuntimeServicesOnShutdown() || !a.browserMgr.Profiles["synthetic"].Running || a.browserMgr.Profiles["synthetic"].Pid != 12345 {
		t.Fatal("app-only exit killed or changed browser state")
	}
}

func TestAuthBoundUnconfiguredDoesNotActivateBusinessAndFailedInitIsRetained(t *testing.T) {
	t.Setenv("ABFREE_OIDC_ISSUER", "")
	t.Setenv("ABFREE_OIDC_CLIENT_ID", "")
	root := t.TempDir()
	a := NewApp(root)
	b := NewAuthBoundApp(a)
	if _, err := b.GetAppConfig(0); !errors.Is(err, desktopauth.ErrUnauthenticated) {
		t.Fatal("unconfigured admitted")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("unconfigured business initialization wrote data")
	}
	a.identity = newMockSession()
	a.businessInitAttempted = true
	failure := errors.New("retained_initialization_failure")
	a.businessInitErr = failure
	if _, err := b.AuthStatus(); !errors.Is(err, failure) {
		t.Fatal("failed initialization was retried")
	}
}

func TestAuthBoundBackupPreviewCanConfirmWithinItsSession(t *testing.T) {
	for _, flow := range []string{"local-history", "file-picker"} {
		t.Run(flow, func(t *testing.T) {
			a, path := newProfilePackageImportTestApp(t, []browser.Profile{{ProfileId: "source", ProfileName: "B"}}, nil)
			m := newMockSession()
			a.identity = m
			a.businessReady = true
			a.runtimeStopped = true // no native event bridge in this offline fixture
			b := NewAuthBoundApp(a)
			old := openNativeFileDialog
			t.Cleanup(func() { openNativeFileDialog = old })
			openNativeFileDialog = func(context.Context, wailsruntime.OpenDialogOptions) (string, error) { return path, nil }
			prepare := func(generation uint64) (map[string]interface{}, error) {
				if flow == "file-picker" {
					return b.BackupImportPackage(generation)
				}
				return b.BackupRestoreLocalPackage(path, generation)
			}
			result, err := prepare(7)
			if err != nil {
				t.Fatal(err)
			}
			if result["requiresProfileImportConfirmation"] != true {
				t.Fatal("original backup confirmation flow missing")
			}
			_, _ = b.AuthLogout(7)
			m.replace()
			generation := m.Status().Generation
			if _, err := b.BrowserProfilePackageImportWithOptions(path, ProfilePackageImportOptions{ConfirmConflict: true}, generation); !errors.Is(err, desktopauth.ErrUnauthenticated) {
				t.Fatal("old backup preview crossed sessions")
			}
			result, err = prepare(generation)
			if err != nil {
				t.Fatal(err)
			}
			preview, ok := result["profileImportPreview"].(ProfilePackageImportPreview)
			if !ok {
				t.Fatal("backup did not return the original preview DTO")
			}
			imported, err := b.BrowserProfilePackageImportWithOptions(preview.ZipPath, ProfilePackageImportOptions{ConfirmConflict: true}, generation)
			if err != nil || imported.CreatedCount != 1 {
				t.Fatalf("fresh same-session backup preview rejected: created=%d error=%v", imported.CreatedCount, err)
			}
		})
	}
}

func TestAuthBoundMaintenanceWaitCannotCommitAfterRevocation(t *testing.T) {
	a, path := newProfilePackageImportTestApp(t, []browser.Profile{{ProfileId: "source", ProfileName: "B"}}, nil)
	m := newMockSession()
	a.identity = m
	a.businessReady = true
	a.runtimeStopped = true
	b := NewAuthBoundApp(a)
	if _, err := b.BrowserProfilePackagePrepareImportFromPath(path, 7); err != nil {
		t.Fatal(err)
	}
	before := len(a.browserMgr.List())
	a.maintenanceMu.Lock()
	admitted, resume := make(chan struct{}), make(chan struct{})
	var checks atomic.Int32
	m.mu.Lock()
	m.afterCheck = func() {
		if checks.Add(1) == 4 {
			close(admitted)
			<-resume
		}
	}
	m.mu.Unlock()
	type outcome struct {
		created int
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := b.BrowserProfilePackageImportWithOptions(path, ProfilePackageImportOptions{ConfirmConflict: true}, 7)
		done <- outcome{result.CreatedCount, err}
	}()
	waitAuthTest(t, admitted)
	_, _ = b.AuthLogout(7)
	m.replace()
	close(resume)
	a.maintenanceMu.Unlock()
	select {
	case result := <-done:
		if !errors.Is(result.err, desktopauth.ErrUnauthenticated) || result.created != 0 {
			t.Fatalf("revoked waiter committed: created=%d error=%v", result.created, result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revoked waiter did not settle")
	}
	if len(a.browserMgr.List()) != before {
		t.Fatal("revoked waiter changed the native catalog")
	}
	generation := m.Status().Generation
	if _, err := b.BrowserProfilePackagePrepareImportFromPath(path, generation); err != nil {
		t.Fatal(err)
	}
	imported, err := b.BrowserProfilePackageImportWithOptions(path, ProfilePackageImportOptions{ConfirmConflict: true}, generation)
	if err != nil || imported.CreatedCount != 1 {
		t.Fatalf("fresh caller could not reuse released maintenance lock: %+v %v", imported, err)
	}
}
