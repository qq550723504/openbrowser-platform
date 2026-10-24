# Mandatory login: bounded offline implementation

Tracking: [formal Issue #3](https://github.com/qq550723504/openbrowser-platform/issues/3).
`ISSUE-draft.md` preserves the earlier preparation snapshot; implementation began
before the formal Issue and was paused until the remote/Issue workflow existed.
This offline batch uses the existing `codex/mandatory-login` branch, based on
accepted upstream/busy-fix commit
`2e75ad2e5c3b8146ad8e97e9d6136fd50dec2442`.

- Reuse the original pages, profile database/path, managers, launch and shutdown
  behavior. Reuse only the isolated OIDC/session core from the sealed source
  backup; do not import its Workspace, runner, CAS or alternate desktop product.
- One Go identity authority must guard actual Wails, HTTP/CDP and background
  dispatch. Missing configuration is closed. Test injection is private/test-only;
  there is no production fake-login, skip-login or secret-bearing renderer API.
- Unauthenticated/expired/logged-out/stale calls cannot start new business work.
  Login preserves original business delegation. Logout does not kill instances;
  app-only exit and narrowly proven graceful ownership cleanup remain available.
- Keep static UI/auth status distinct from business data. Preserve the busy fix
  and reject stale auth/view callbacks without replaying unknown writes.
- This batch permits offline/mock tests and compilation only. Do not contact a
  real IdP, generate/save real credentials, start product GUI/kernel/page service,
  change security settings, or write a remote. Real public issuer/client metadata
  is pending; this does not block independent offline code.

The authentication PR depends on the unmerged busy-fix Draft PR #2. Its base is
`codex/fix-profile-import-preview-busy` to isolate the auth diff; retarget to
`main` only after that dependency is merged through its own review workflow.

Verification must exercise the actual bound facade, router/middleware and
background admission points, not a detached copy. Keep real OIDC/native and full
product acceptance NOT_RUN. Existing frozen packages and trial data stay intact.
