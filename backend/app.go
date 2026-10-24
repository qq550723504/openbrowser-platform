package backend

import (
	"ant-chrome/backend/internal/automation"
	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/config"
	"ant-chrome/backend/internal/database"
	"ant-chrome/backend/internal/launchcode"
	"ant-chrome/backend/internal/logger"
	"ant-chrome/backend/internal/proxy"
	"ant-chrome/internal/desktopauth"
	"context"
	"os"
	"strings"
	"sync"
)

type quitMode uint8

const (
	quitModeFull quitMode = iota
	quitModeAppOnly
)

// App 应用结构体
type App struct {
	*appState
	ctx            context.Context
	admission      func() error
	authGeneration uint64
}

// Scoped receivers share original native state; managers and mutexes are never copied.
type appState struct {
	businessInitAttempted   bool
	businessInitErr         error
	ownedBrowsers           ownedBrowserReceipts
	importPreviewMu         sync.Mutex
	importPreviewPath       string
	importPreviewGeneration uint64
	identity                sessionAuthority
	businessInitMu          sync.Mutex
	businessReady           bool
	config                  *config.Config
	db                      *database.DB
	interceptor             *logger.MethodInterceptor
	browserMgr              *browser.Manager
	xrayMgr                 *proxy.XrayManager
	clashMgr                *proxy.ClashManager
	singboxMgr              *proxy.SingBoxManager
	launchCodeSvc           *launchcode.LaunchCodeService
	launchServer            *launchcode.LaunchServer
	automationMgr           *automation.Manager
	speedScheduler          *browser.ProxySpeedScheduler
	backupScheduler         *backupScheduler
	appRoot                 string
	version                 string

	forceQuit                     bool
	quitMode                      quitMode
	quitMu                        sync.RWMutex
	runtimeMu                     sync.RWMutex
	runtimeStopped                bool
	backgroundTaskCtx             context.Context
	backgroundTaskCancel          context.CancelFunc
	backgroundTasks               sync.WaitGroup
	backgroundTasksBlocked        bool
	maintenanceMu                 sync.Mutex
	bridgeMu                      sync.Mutex
	profileBridgeRefs             map[string]profileProxyBridgeRef
	deferredStartTargetsMu        sync.Mutex
	deferredStartTargets          map[string]deferredStartTargetsPlan
	automationTargetMu            sync.Mutex
	automationTargetCursor        map[string]string
	profileWindowMarkersMu        sync.Mutex
	profileWindowMarkers          map[string]*profileWindowMarker
	browserProcessMonitors        map[string]*browserProcessMonitor
	backupLocalConfigPathOverride string
	stopServicesOnce              sync.Once
	finalizeOnce                  sync.Once
}

// NewApp 创建新的应用实例
func NewApp(appRoot string, appVersion ...string) *App {
	version := ""
	if len(appVersion) > 0 {
		version = strings.TrimSpace(appVersion[0])
	}
	return &App{appState: &appState{
		identity:               desktopauth.NewManager(desktopauth.Config{Issuer: os.Getenv("ABFREE_OIDC_ISSUER"), ClientID: os.Getenv("ABFREE_OIDC_CLIENT_ID")}),
		appRoot:                strings.TrimSpace(appRoot),
		version:                version,
		profileBridgeRefs:      make(map[string]profileProxyBridgeRef),
		deferredStartTargets:   make(map[string]deferredStartTargetsPlan),
		automationTargetCursor: make(map[string]string),
		profileWindowMarkers:   make(map[string]*profileWindowMarker),
		browserProcessMonitors: make(map[string]*browserProcessMonitor),
	}}
}

func (a *App) appName() string {
	if a.config != nil {
		if name := strings.TrimSpace(a.config.App.Name); name != "" {
			return name
		}
	}
	return "Ant Browser"
}

func (a *App) appVersion() string {
	version := strings.TrimSpace(a.version)
	if version == "" {
		return "unknown"
	}
	return version
}
