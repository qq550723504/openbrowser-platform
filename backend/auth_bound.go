package backend

import (
	"ant-chrome/backend/internal/automation"
	"ant-chrome/backend/internal/launchcode"
	"ant-chrome/internal/desktopauth"
	"path/filepath"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// AuthBoundApp is the only Wails business binding. The original App must remain
// private: embedding it would promote every unguarded method into Wails again.
type AuthBoundApp struct{ core *App }

type sessionAuthority interface {
	Status() desktopauth.Status
	Check(uint64) error
	Login(uint64, func(string) error) (desktopauth.Status, error)
	Cancel(uint64) (desktopauth.Status, error)
	SignOut(uint64) (desktopauth.Status, error)
	GrantAPI(uint64, bool) error
	CheckAPI() (uint64, error)
	Close()
}

func NewAuthBoundApp(core *App) *AuthBoundApp { return &AuthBoundApp{core: core} }

func (a *AuthBoundApp) admit(generation uint64) error {
	if a == nil || a.core == nil || a.core.identity == nil {
		return desktopauth.ErrUnauthenticated
	}
	if err := a.core.identity.Check(generation); err != nil {
		return err
	}
	return a.core.ensureBusinessReady(generation)
}

func (a *AuthBoundApp) AuthStatus() (desktopauth.Status, error) {
	status := a.core.identity.Status()
	if status.State == "signed_in" {
		if err := a.admit(status.Generation); err != nil {
			return status, err
		}
	}
	return a.core.identity.Status(), nil
}

func (a *AuthBoundApp) scoped(generation uint64) (*App, error) {
	if err := a.admit(generation); err != nil {
		return nil, err
	}
	return a.core.scoped(generation)
}

// Per-call authority is immutable; all native state keeps its original owner.
func (a *App) scoped(generation uint64) (*App, error) {
	check := func() error { return a.identity.Check(generation) }
	if err := check(); err != nil {
		return nil, err
	}
	return &App{appState: a.appState, ctx: automation.WithAdmission(a.ctx, check), admission: check, authGeneration: generation}, nil
}

func (a *App) scopedHTTP(generation uint64) (launchcode.BrowserStarter, error) {
	scoped, err := a.scoped(generation)
	if err != nil {
		return nil, err
	}
	check := func() error {
		current, err := a.identity.CheckAPI()
		if err != nil || current != generation {
			return desktopauth.ErrUnauthenticated
		}
		return a.identity.Check(generation)
	}
	if err := check(); err != nil {
		return nil, err
	}
	scoped.admission = check
	scoped.ctx = automation.WithAdmission(a.ctx, check)
	return scoped, nil
}

func (a *AuthBoundApp) AuthLogin(generation uint64) (desktopauth.Status, error) {
	return a.core.identity.Login(generation, func(url string) error {
		runtime.BrowserOpenURL(a.core.ctx, url)
		return nil
	})
}

func (a *AuthBoundApp) AuthCancel(generation uint64) (desktopauth.Status, error) {
	return a.core.identity.Cancel(generation)
}
func (a *AuthBoundApp) AuthLogout(generation uint64) (desktopauth.Status, error) {
	return a.core.identity.SignOut(generation)
}
func (a *AuthBoundApp) AuthGrantAPI(generation uint64, enabled bool) error {
	if err := a.admit(generation); err != nil {
		return err
	}
	if enabled && (a.core.launchServer == nil || !a.core.launchServer.APIAuthEnabled()) {
		return desktopauth.ErrConfiguration
	}
	return a.core.identity.GrantAPI(generation, enabled)
}
func (a *AuthBoundApp) QuitAppOnly() { a.core.QuitAppOnly() }

// Host startup is deliberately distinct from the existing domain startup. All
// managers, data paths and lifecycle code are retained, and activated only after
// login. Logout never calls Stop/ForceQuit or replaces the profile database.
func (a *App) ensureBusinessReady(generation uint64) error {
	a.businessInitMu.Lock()
	defer a.businessInitMu.Unlock()
	if err := a.identity.Check(generation); err != nil {
		return err
	}
	if a.businessReady {
		return nil
	}
	if a.businessInitAttempted {
		return a.businessInitErr
	}
	if a.ctx == nil {
		return desktopauth.ErrUnauthenticated
	}
	a.businessInitAttempted = true
	check := func() error { return a.identity.Check(generation) }
	a.businessInitErr = a.startupBusiness(a.ctx, check)
	a.businessReady = a.businessInitErr == nil
	return a.businessInitErr
}

func (a *App) currentAdmission() (func() error, error) {
	// A nil authority is possible only for legacy package unit fixtures assembled
	// as &App{}. NewApp always constructs the real authority before exposure.
	if a.identity == nil {
		return func() error { return nil }, nil
	}
	if a.admission != nil {
		return a.admission, a.admission()
	}
	generation := a.identity.Status().Generation
	check := func() error { return a.identity.Check(generation) }
	return check, check()
}

func (a *App) captureAdmission() func() error { check, _ := a.currentAdmission(); return check }

// Native startup and legacy core unit fixtures are trusted Go callers. Every
// Wails/HTTP action has an immutable scoped check; never adopt a new generation
// after waiting for the original maintenance mutex.
func (a *App) checkScopedAdmission() error {
	if a.admission != nil {
		return a.admission()
	}
	return nil
}

func (a *App) rememberImportPreview(path string, generation uint64) error {
	if err := a.identity.Check(generation); err != nil {
		return err
	}
	a.importPreviewMu.Lock()
	defer a.importPreviewMu.Unlock()
	a.importPreviewPath = filepath.Clean(path)
	a.importPreviewGeneration = generation
	return nil
}
func (a *App) requireImportPreview(path string, generation uint64) error {
	a.importPreviewMu.Lock()
	defer a.importPreviewMu.Unlock()
	if a.importPreviewPath == "" || filepath.Clean(path) != a.importPreviewPath || generation != a.importPreviewGeneration {
		return desktopauth.ErrUnauthenticated
	}
	return a.identity.Check(generation)
}
