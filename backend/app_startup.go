package backend

import (
	"ant-chrome/backend/internal/apppath"
	"ant-chrome/backend/internal/automation"
	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/config"
	"ant-chrome/backend/internal/database"
	"ant-chrome/backend/internal/launchcode"
	"ant-chrome/backend/internal/logger"
	"ant-chrome/backend/internal/proxy"
	"context"
	"fmt"
	"net/http"
	"os"
	"time"
)

// startup 应用启动时调用
func (a *App) startup(ctx context.Context) {
	a.setRuntimeContext(ctx)
	a.emitRuntimeEvent("app:ready")
}

func (a *App) startupBusiness(ctx context.Context, check func() error) error {
	if err := check(); err != nil {
		return err
	}
	if err := apppath.EnsureWritableLayout(a.appRoot); err != nil {
		return fmt.Errorf("初始化用户数据目录失败: %w", err)
	}

	cfg := a.startupLoadConfig()
	a.config = cfg
	a.applyRuntimeConfig(cfg.Runtime)

	log := a.startupInitLogger(ctx, cfg)
	if err := check(); err != nil {
		return err
	}
	if err := killResidualRuntimeProcesses(a.appRoot); err != nil {
		log.Warn("清理上次异常退出遗留的代理进程失败", logger.F("error", err))
	}
	a.startupLogEnvironment(log, cfg)
	a.activateStableBackupLocalConfig()
	if err := a.prepareBackupLocalConfig(); err != nil {
		log.Error("本地备份配置初始化失败", logger.F("error", err))
	}

	if err := os.MkdirAll(a.resolveAppPath("data"), 0o755); err != nil {
		log.Error("创建 data 目录失败", logger.F("error", err))
	}

	if err := check(); err != nil {
		return err
	}
	a.ensureDefaultCores()
	a.startupInitInterceptor(log, cfg)

	db, err := a.startupInitDatabase(cfg)
	if err != nil {
		log.Error("初始化数据库失败", logger.F("error", err))
		return fmt.Errorf("初始化数据库失败: %w", err)
	}
	a.db = db
	if err := check(); err != nil {
		return err
	}
	if err := db.Migrate(); err != nil {
		log.Error("数据库迁移失败", logger.F("error", err))
		return err
	}

	if err := a.startupInitManagers(cfg, db, check); err != nil {
		return err
	}
	a.startupInitLaunchCode(log)
	if err := check(); err != nil {
		return err
	}
	if err := a.startupInitLaunchServer(log); err != nil {
		return err
	}
	a.startupInitAutomation()
	a.startupInitBridgeHooks()
	a.startupInitSpeedScheduler()
	a.startupInitBackupScheduler()
	a.emitRuntimeEvent("app:ready")

	log.Info("应用启动成功")
	return check()
}

func (a *App) startupLoadConfig() *config.Config {
	cfg, err := LoadConfig(a.resolveAppPath("config.yaml"))
	if err != nil {
		return config.DefaultConfig()
	}
	return cfg
}

func (a *App) startupInitLogger(ctx context.Context, cfg *config.Config) *logger.Logger {
	logConfig := logger.LoggerConfig{
		Level:           cfg.Logging.Level,
		FileEnabled:     cfg.Logging.FileEnabled,
		FilePath:        a.resolveAppPath(cfg.Logging.FilePath),
		Format:          cfg.Logging.Format,
		BufferSize:      cfg.Logging.BufferSize,
		AsyncQueueSize:  cfg.Logging.AsyncQueueSize,
		FlushIntervalMs: cfg.Logging.FlushIntervalMs,
		Rotation: logger.RotationConfig{
			Enabled:      cfg.Logging.Rotation.Enabled,
			MaxSizeMB:    cfg.Logging.Rotation.MaxSizeMB,
			MaxAge:       cfg.Logging.Rotation.MaxAge,
			MaxBackups:   cfg.Logging.Rotation.MaxBackups,
			TimeInterval: cfg.Logging.Rotation.TimeInterval,
		},
	}
	logger.InitWithConfig(ctx, logConfig)
	return logger.New("App")
}

func (a *App) startupLogEnvironment(log *logger.Logger, cfg *config.Config) {
	log.Info("应用启动中...",
		logger.F("version", a.appVersion()),
		logger.F("max_memory_mb", cfg.Runtime.MaxMemoryMB),
		logger.F("gc_percent", cfg.Runtime.GCPercent),
	)
	if apppath.IsDetached(a.appRoot) {
		log.Info("检测到安装目录需要只读运行，已切换到用户数据目录",
			logger.F("install_root", apppath.InstallRoot(a.appRoot)),
			logger.F("state_root", apppath.StateRoot(a.appRoot)),
		)
	}
}

func (a *App) startupInitInterceptor(log *logger.Logger, cfg *config.Config) {
	if !cfg.Logging.Interceptor.Enabled {
		return
	}
	interceptorConfig := logger.InterceptorConfig{
		Enabled:         cfg.Logging.Interceptor.Enabled,
		LogParameters:   cfg.Logging.Interceptor.LogParameters,
		LogResults:      cfg.Logging.Interceptor.LogResults,
		SensitiveFields: cfg.Logging.Interceptor.SensitiveFields,
	}
	a.interceptor = logger.NewMethodInterceptor(log, interceptorConfig)
}

func (a *App) startupInitDatabase(cfg *config.Config) (*database.DB, error) {
	return database.NewDB(a.resolveAppPath(cfg.Database.SQLite.Path))
}

func (a *App) startupInitManagers(cfg *config.Config, db *database.DB, check func() error) error {
	if err := check(); err != nil {
		return err
	}
	a.browserMgr = browser.NewManager(cfg, a.appRoot)
	a.browserMgr.EventEmitter = a.emitRuntimeEvent
	a.xrayMgr = proxy.NewXrayManager(cfg, a.appRoot)
	a.clashMgr = proxy.NewClashManager(cfg, a.appRoot)
	a.singboxMgr = proxy.NewSingBoxManager(cfg, a.appRoot)
	a.browserMgr.CoreDownloadHTTPClientFactory = func(proxyConfig string, timeout time.Duration) (*http.Client, error) {
		client, _, err := a.unifiedProxyCoreHTTPClient(timeout, proxyConfig)
		return client, err
	}

	conn := db.GetConn()
	a.browserMgr.ProfileDAO = browser.NewSQLiteProfileDAO(conn)
	a.browserMgr.ProxyDAO = browser.NewSQLiteProxyDAO(conn)
	a.browserMgr.CoreDAO = browser.NewSQLiteCoreDAO(conn)
	a.browserMgr.BookmarkDAO = browser.NewSQLiteBookmarkDAO(conn)
	a.browserMgr.GroupDAO = browser.NewSQLiteGroupDAO(conn)
	a.browserMgr.ExtensionDAO = browser.NewSQLiteExtensionDAO(conn)

	if err := check(); err != nil {
		return err
	}
	a.migrateToSQLite()

	a.browserMgr.InitData()
	if err := check(); err != nil {
		return err
	}
	if err := a.browserMgr.CleanupExpiredTrash(); err != nil {
		logger.New("Browser").Error("启动清理回收站失败", logger.F("error", err))
	}
	if err := check(); err != nil {
		return err
	}
	a.autoDetectCores()
	a.loadProxies()
	a.reconcileProfileProxyBindings()
	return check()
}

func (a *App) startupInitLaunchCode(log *logger.Logger) {
	launchCodeDAO := launchcode.NewSQLiteLaunchCodeDAO(a.db.GetConn())
	a.launchCodeSvc = launchcode.NewLaunchCodeService(launchCodeDAO)
	if err := a.launchCodeSvc.LoadAll(); err != nil {
		log.Error("LaunchCode 加载失败", logger.F("error", err))
	}
	a.browserMgr.CodeProvider = a.launchCodeSvc
}

func (a *App) startupInitLaunchServer(log *logger.Logger) error {
	port := a.config.LaunchServer.Port
	a.launchServer = launchcode.NewLaunchServer(a.launchCodeSvc, a, a.browserMgr, port)
	a.launchServer.SetIdentityAuthority(a.identity, a.scopedHTTP)
	a.launchServer.SetAPIAuthConfig(launchcode.APIAuthConfig{
		Enabled: a.config.LaunchServer.Auth.Enabled,
		APIKey:  a.config.LaunchServer.Auth.APIKey,
		Header:  a.config.LaunchServer.Auth.Header,
	})
	if err := a.launchServer.Start(); err != nil {
		log.Error("LaunchServer 启动失败", logger.F("error", err))
		return err
	}
	log.Debug("LaunchServer 监听地址",
		logger.F("url", fmt.Sprintf("http://127.0.0.1:%d", a.launchServer.Port())),
		logger.F("preferred_port", port),
	)
	return nil
}

func (a *App) startupInitAutomation() {
	a.automationMgr = automation.NewManager(a.appRoot, a.config, func(event string, payload any) {
		a.emitRuntimeEvent(event, payload)
	}, automation.Options{CaptureAdmission: a.captureAdmission})
}

func (a *App) startupInitBridgeHooks() {
	a.xrayMgr.OnBridgeDied = func(key string, err error) {
		a.emitRuntimeEvent("proxy:bridge:died", map[string]interface{}{
			"engine": "xray",
			"key":    bridgeEventKey(key),
			"error":  errorMessage(err),
		})
	}
	a.singboxMgr.OnBridgeDied = func(key string, err error) {
		a.emitRuntimeEvent("proxy:bridge:died", map[string]interface{}{
			"engine": "singbox",
			"key":    bridgeEventKey(key),
			"error":  errorMessage(err),
		})
	}
}

func bridgeEventKey(key string) string {
	if len(key) <= 8 {
		return key
	}
	return key[:8]
}

func errorMessage(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (a *App) startupInitSpeedScheduler() {
	a.ensureSpeedScheduler()
}

func (a *App) ensureSpeedScheduler() {
	if a == nil || a.config == nil || a.browserMgr == nil || a.browserMgr.ProxyDAO == nil {
		return
	}
	if a.speedScheduler == nil {
		a.speedScheduler = browser.NewProxySpeedScheduler(
			a.browserMgr.ProxyDAO,
			func(proxyId string) (bool, int64, string) {
				check, err := a.currentAdmission()
				if err != nil {
					return false, 0, err.Error()
				}
				if err := check(); err != nil {
					return false, 0, err.Error()
				}
				connectorType := config.NormalizeBrowserConnectorType(a.config.Browser.DefaultConnectorType)
				r := a.testProxySpeedWithConnector(proxyId, a.getLatestProxies(), connectorType)
				return r.Ok, r.LatencyMs, r.Error
			},
			browser.DefaultProxySpeedInterval,
			browser.DefaultProxySpeedConcurrency,
		)
		a.speedScheduler.CaptureAdmission = a.captureAdmission
	}
	a.speedScheduler.Start()
}
