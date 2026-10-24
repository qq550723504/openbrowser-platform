package automation

import (
	"ant-chrome/backend/internal/config"
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
)

func TestAdmissionBlocksInstallAndTaskDispatchBeforeAnyRuntimeWork(t *testing.T) {
	root := t.TempDir()
	denied := errors.New("authentication_required")
	var generation atomic.Uint64
	generation.Store(7)
	check := func() error {
		if generation.Load() != 7 {
			return denied
		}
		return nil
	}
	ctx := WithAdmission(context.Background(), check)
	manager := NewManager(root, config.DefaultConfig(), nil, Options{CaptureAdmission: func() func() error { return func() error { return nil } }})
	generation.Store(9)
	manager.InstallAsync(ctx)
	if state:=manager.CurrentState(ctx);state.Ready||state.LastError!=denied.Error(){t.Fatal("old runtime query lost its admission")}
	if _,err:=manager.RunScriptTask(ctx,ScriptTaskRequest{});!errors.Is(err,denied){t.Fatal("old script task admitted")}
	if _,err:=manager.SelfCheck(ctx);!errors.Is(err,denied){t.Fatal("old self-check admitted")}
	if _,err:=manager.probeNodeExecutable(ctx,"not-a-real-node");!errors.Is(err,denied){t.Fatal("old system-node probe admitted")}
	if manager.installing {
		t.Fatal("old install queued")
	}
	if err := manager.EnsureInstalled(ctx); !errors.Is(err, denied) {
		t.Fatal("old install adopted fresh fallback")
	}
	if _, _, _, _, err := manager.executeTask(ctx, "synthetic", taskRunnerPayload{}, "", "", 0); !errors.Is(err, denied) {
		t.Fatal("old task adopted fresh fallback")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("denied runtime work wrote files")
	}
}
