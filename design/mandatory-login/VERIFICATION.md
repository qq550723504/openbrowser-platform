# Issue #3: offline implementation and verification

The implementation is on `codex/mandatory-login`, based on accepted busy-fix
`2e75ad2e5c3b8146ad8e97e9d6136fd50dec2442` (Draft PR #2). This is an offline
code/build batch, not real OIDC or complete native product acceptance.

The original managers, database paths, browser launch/stop and business pages
remain in use. The bound facade adds typed generation checks. `App` and HTTP
request receivers share pointers to original state; mutexes/once values are not
copied. Auth controls do not wait for business I/O or native dialogs. Startup
business work waits for login and retains an initialization failure without
automatically retrying it. Logout revokes new work, not running browsers.

The generated binding policy contains 193 protected methods and seven explicit
auth/cleanup methods. `GetInterceptor` is not bound. HTTP/CDP requires both the
configured API key and a grant from the current login generation. A safe health
response is public. Deferred/background work and dialog completions retain their
initiating admission. The original native tray exit also checks the Go session.

Normal cleanup requires this process's admitted start receipt, matching current
monitor/command, PID creation time, directory and loopback endpoint proof. It
sends only `Browser.close`, once; missing proof or an unknown acknowledgement
has no force/retry fallback. OS proof is implemented for Windows. Other systems
fail closed and retain manual browser-window closure and app-only exit.

Verification completed on 2026-10-24 (Asia/Singapore):

- Frontend: 34 tests PASS, including the existing 22 busy regressions, session
  generation/expiry/late results, all 200 real SDK arities, Record arguments,
  dynamic module loading, login/exit shell and late log rejection.
- Race-enabled production binding/backend/browser/automation regression: four
  packages PASS, 35 top-level tests and 816 tests/subtests. It exercises the real
  binding object, original ZIP import, native-dialog seam, queued background and
  scheduled backup dispatch, deferred tabs, proxy batches, automation admission,
  app-only/tray exit and normal cleanup protocol. Only private mock auth, mock
  OS proof and in-process test HTTP/WebSocket peers are used.
- Race-enabled `internal/desktopauth` and `backend/internal/launchcode` suites
  PASS: mock TLS OIDC/PKCE, claims/signature/strict JSON, expiry/logout races,
  explicit API grants, actual router rejection, late bodies and CDP revocation.
- `go vet` across main and the five relevant backend/auth packages: PASS.
- TypeScript + clean Vite build: PASS. Existing Browserslist data-age warning is
  retained; no dependency/security configuration was changed to suppress it.
- Windows `desktop,production` native compilation: PASS, using cached modules
  with `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`, `-mod=readonly`.

Reproduce the generated boundary from the repository root:

```powershell
go run ./scripts/generate-auth
node frontend/scripts/bootstrap-auth-sdk.mjs
```

Normal Wails SDK generation remains compatible with the same facade. The offline
bootstrap uses the existing TypeScript parser; it never splits generic types on
commas. Boundary tests reject policy/signature drift and exposed internal getters.

Limits: no real IdP contact, login, credential generation, product GUI/kernel or
product service startup. Mock listeners are test-only. The compiled EXE was not
executed. Public issuer/Native-client and callback/TLS metadata remain pending.
Local profiles are shared native data; this is not per-account data isolation or
a lock on an already running Chromium window/direct CDP port. Main/PR GitHub CI
is NOT_RUN: current upstream workflows are tag/manual only, with no check/run on
the verified busy head. Do not treat these local results as remote CI.

Raw logs, exit receipts and the compiled EXE are retained locally under ignored
`build/dist/` paths. Existing trial data, frozen busy EXE/ZIP and source backups
remain separate and are not uploaded with this source change.

## Bounded follow-up review

The follow-up stayed within the original PR's 95 files and found two concrete
regressions against `83e55fb`:

- `BackupImportPackage` and `BackupRestoreLocalPackage` return a profile preview
  through the shared producer, but only the instance-list facade had registered
  its ownership. A fresh logged-in confirmation therefore failed with
  `authentication_required`. Ownership now belongs to the shared preview
  producer and the immutable initiating generation. Both backup routes can
  confirm; an old backup preview still cannot cross login generations.
- An import admitted before waiting for `maintenanceMu` could commit after its
  session was revoked; the failing counterexample created one profile. The
  existing maintenance-lock sites in the reviewed App files now recheck their
  original scoped admission immediately after acquiring the lock. Existing
  mutexes and business code remain in place. A revoked waiter creates nothing
  and a fresh caller can acquire the released lock and use the original import.

No live identity/provider, GUI/kernel or product-service run is part of this
review. It does not certify unrelated domain locks or complete product behavior.

The follow-up's applicable four-package race run passes 37 top-level tests and
820 tests/subtests; vet and Windows production compilation pass. Frontend source
and SDK bytes did not change, so the prior 34 frontend tests/clean build remain
applicable. The new EXE SHA256 is
`6910b46fc9c46c5ff7ab414d700d77e0ea698c691a8cc2819e5a4cc5dae5fc90`;
it was not executed. The first `83e55fb` binary and previous frozen busy artifacts
remain retained separately.
