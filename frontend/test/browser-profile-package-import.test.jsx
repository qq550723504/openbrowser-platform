import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, create } from 'react-test-renderer'
import { BrowserListPage } from '../src/modules/browser/pages/BrowserListPage'
import { BrowserListHeader } from '../src/modules/browser/components/BrowserListLayout'
import { BatchToolbar } from '../src/modules/browser/components/BrowserListWidgets'
import { BrowserProfilesPanel } from '../src/modules/browser/components/BrowserProfilesPanel'
import { BrowserListDialogs } from '../src/modules/browser/pages/browserList/BrowserListDialogs'
import { exportBrowserProfilePackage, importBrowserProfilePackageWithOptions, prepareBrowserProfilePackageImport } from '../src/modules/browser/api'
import { toast } from '../src/shared/components'

const fixtures = vi.hoisted(() => ({
  profiles: [{ profileId: 'source', profileName: 'B', running: false }],
  loadProfiles: vi.fn(),
}))

// Keep the real page, dialog wiring, conflict editor and Button. Only replace
// the DOM portal, native bridge/data hooks and unrelated page sections.
vi.mock('../src/shared/components', async () => ({
  Button: (await import('../src/shared/components/Button')).Button,
  Modal: ({ open, onClose, title, children, footer }) => open ? (
    <section aria-label={title}>
      <button aria-label="close" onClick={onClose}>×</button>
      {children}{footer}
    </section>
  ) : null,
  toast: { success: vi.fn(), warning: vi.fn(), error: vi.fn() },
}))
vi.mock('../src/modules/browser/components/BrowserListLayout', () => ({
  BrowserListHeader: () => null,
  BrowserListSettingsModal: () => null,
  BrowserCoreEditorModal: () => null,
}))
vi.mock('../src/modules/browser/components/BrowserListWidgets', () => ({ BatchToolbar: () => null }))
vi.mock('../src/modules/browser/components/BrowserProfilesPanel', () => ({ BrowserProfilesPanel: () => null }))
vi.mock('../src/modules/browser/components/ProxyPickerModal', () => ({ ProxyPickerModal: () => null }))
vi.mock('../src/modules/browser/components/ProfileExtensionModal', () => ({ ProfileExtensionModal: () => null }))
vi.mock('../src/modules/browser/components/BrowserProfileCopyForm', () => ({ BrowserProfileCopyForm: () => null }))
vi.mock('../src/modules/browser/components/KeywordsModal', () => ({ KeywordsModal: () => null }))
vi.mock('../src/modules/browser/pages/browserList/useBrowserListViewState', () => ({
  useBrowserListViewState: () => ({ filters: {} }),
  useBrowserListDerived: () => ({ filteredProfiles: fixtures.profiles }),
}))
vi.mock('../src/modules/browser/pages/browserList/useBrowserListSettings', () => ({
  useBrowserListSettings: () => ({ cores: [] }),
}))
vi.mock('../src/modules/browser/pages/browserList/useBrowserListData', () => ({
  useBrowserListData: () => ({
    profiles: fixtures.profiles, proxies: [], groups: [],
    startingIds: new Set(), stoppingIds: new Set(), loadProfiles: fixtures.loadProfiles,
  }),
}))
vi.mock('../src/modules/browser/pages/browserList/useBrowserProfileActions', () => ({
  useBrowserProfileActions: () => ({}),
}))
vi.mock('../src/modules/browser/utils/proxyWarmup', () => ({ warmupProfileProxyBeforeStart: vi.fn() }))
vi.mock('../src/modules/browser/api', () => ({
  copyBrowserProfile: vi.fn(), deleteBrowserProfile: vi.fn(),
  exportBrowserProfilePackage: vi.fn(), fetchBrowserProfileTrash: vi.fn(),
  importBrowserProfilePackageWithOptions: vi.fn(), prepareBrowserProfilePackageImport: vi.fn(),
  permanentlyDeleteBrowserProfile: vi.fn(), restoreBrowserProfile: vi.fn(),
  startBrowserInstance: vi.fn(), stopBrowserInstance: vi.fn(),
  updateBrowserProfile: vi.fn(), openUserDataDir: vi.fn(),
}))

function deferred() {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

function preview(zipPath = 'B.zip') {
  return {
    zipPath, profileCount: 1, conflictCount: 1,
    profiles: [{ sourceIndex: 0, sourceProfileId: 'source', sourceProfileName: 'B',
      suggestedProfileName: 'B-copy', targetProfileName: 'B', canOverwrite: true }],
  }
}

const result = { importedCount: 1, createdCount: 1, overwrittenCount: 0, renamedCount: 0 }
const newActions = [{ sourceIndex: 0, sourceProfileId: 'source', mode: 'new', profileName: '' }]
let renderer
const props = (component) => renderer.root.findByType(component).props
const importProps = () => props(BrowserListDialogs)
const buttons = () => renderer.root.findAllByType('button')
const button = (label) => buttons().find(node => node.children.filter(child => typeof child === 'string').join('') === label || node.props['aria-label'] === label)

async function openPreview(value = preview()) {
  prepareBrowserProfilePackageImport.mockResolvedValueOnce(value)
  await act(async () => { await props(BrowserListHeader).onImportProfiles() })
  return value
}

beforeEach(async () => {
  vi.resetAllMocks()
  fixtures.loadProfiles.mockResolvedValue(undefined)
  await act(async () => { renderer = create(<BrowserListPage />) })
})
afterEach(async () => { await act(async () => { renderer.unmount() }) })

describe('native profile package import flow (offline)', () => {
  it('releases busy when the preview is ready, enabling selection, confirm and cancel', async () => {
    const value = await openPreview()
    expect(importProps().profileImportPreview).toBe(value)
    expect(importProps().profileImportBusy).toBe(false)
    expect(props(BrowserListHeader).importingProfiles).toBe(false)
    expect(renderer.root.findByType('select').props.disabled).toBe(false)
    expect(button('确认还原').props.disabled).toBe(false)
    expect(button('取消').props.disabled).toBe(false)
    await act(async () => { button('close').props.onClick() })
    expect(importProps().profileImportPreview).toBeNull()
    expect(importBrowserProfilePackageWithOptions).not.toHaveBeenCalled()
  })

  it.each(['new', 'overwrite', 'rename'])('submits %s once through the original API and refreshes on success', async (mode) => {
    const commit = deferred()
    importBrowserProfilePackageWithOptions.mockReturnValueOnce(commit.promise)
    await act(async () => { props(BrowserProfilesPanel).onToggleSelect('source') })
    await openPreview()
    await act(async () => { renderer.root.findByType('select').props.onChange({ target: { value: mode } }) })
    if (mode === 'rename') {
      await act(async () => { renderer.root.findByType('input').props.onChange({ target: { value: '  C  ' } }) })
    }
    expect(button('确认还原').props.disabled).toBe(false)
    await act(async () => { button('确认还原').props.onClick() })
    expect(importBrowserProfilePackageWithOptions).toHaveBeenCalledExactlyOnceWith('B.zip', 'new', true, [
      { ...newActions[0], mode, profileName: mode === 'rename' ? 'C' : '' },
    ])
    expect(importProps().profileImportBusy).toBe(true)
    expect(importProps().profileImportPreview).toBeNull()
    expect(props(BrowserProfilesPanel).selectedIds.size).toBe(1)
    expect(fixtures.loadProfiles).not.toHaveBeenCalled()
    await act(async () => { commit.resolve(result) })
    expect(importProps().profileImportBusy).toBe(false)
    expect(props(BrowserProfilesPanel).selectedIds.size).toBe(0)
    expect(fixtures.loadProfiles).toHaveBeenCalledTimes(1)
    expect(toast.success).toHaveBeenCalledExactlyOnceWith('已处理：新建 1 个，覆盖 0 个，重命名 0 个')
  })

  it.each(['cancel', 'error'])('releases preparation busy on %s without importing', async (outcome) => {
    if (outcome === 'error') prepareBrowserProfilePackageImport.mockRejectedValueOnce(new Error('preview failed'))
    else prepareBrowserProfilePackageImport.mockResolvedValueOnce({ cancelled: true })
    await act(async () => { await props(BrowserListHeader).onImportProfiles() })
    expect(importProps().profileImportBusy).toBe(false)
    expect(importProps().profileImportPreview).toBeNull()
    expect(importBrowserProfilePackageWithOptions).not.toHaveBeenCalled()
    expect(toast.success).not.toHaveBeenCalled()
    if (outcome === 'error') expect(toast.error).toHaveBeenCalledExactlyOnceWith('preview failed')
    else expect(toast.error).not.toHaveBeenCalled()
  })

  it('cancels an editable preview without importing and allows another preview', async () => {
    await openPreview()
    expect(button('取消').props.disabled).toBe(false)
    await act(async () => { button('取消').props.onClick() })
    expect(importProps().profileImportPreview).toBeNull()
    const next = await openPreview(preview('next.zip'))
    expect(importProps().profileImportPreview).toBe(next)
    expect(importProps().profileImportBusy).toBe(false)
    expect(importBrowserProfilePackageWithOptions).not.toHaveBeenCalled()
  })

  it.each(['cancel', 'error'])('releases import busy on %s without false success or automatic retry', async (outcome) => {
    const commit = deferred()
    importBrowserProfilePackageWithOptions.mockReturnValueOnce(commit.promise)
    await act(async () => { props(BrowserProfilesPanel).onToggleSelect('source') })
    await openPreview()
    await act(async () => { importProps().onConfirmProfileImport(newActions) })
    expect(importProps().profileImportBusy).toBe(true)
    await act(async () => {
      if (outcome === 'error') commit.reject(new Error('import failed'))
      else commit.resolve({ cancelled: true })
    })
    expect(importProps().profileImportBusy).toBe(false)
    expect(importBrowserProfilePackageWithOptions).toHaveBeenCalledTimes(1)
    expect(fixtures.loadProfiles).not.toHaveBeenCalled()
    expect(props(BrowserProfilesPanel).selectedIds.size).toBe(1)
    expect(toast.success).not.toHaveBeenCalled()
    if (outcome === 'error') expect(toast.error).toHaveBeenCalledExactlyOnceWith('import failed')
    else expect(toast.error).not.toHaveBeenCalled()
  })

  it('preserves warning feedback and legacy count fallback', async () => {
    importBrowserProfilePackageWithOptions.mockResolvedValueOnce({
      importedCount: 3, overwrittenCount: 1, renamedCount: 1, warnings: ['warning'],
    })
    await openPreview()
    await act(async () => { button('确认还原').props.onClick() })
    expect(toast.warning).toHaveBeenCalledExactlyOnceWith('已处理：新建 2 个，覆盖 1 个，重命名 1 个，1 条提示：warning')
    expect(toast.success).not.toHaveBeenCalled()
    expect(fixtures.loadProfiles).toHaveBeenCalledTimes(1)
  })

  it('blocks duplicate prepare clicks before React rerenders and while preparation is pending', async () => {
    const pending = deferred()
    prepareBrowserProfilePackageImport.mockReturnValue(pending.promise)
    const start = props(BrowserListHeader).onImportProfiles
    await act(async () => { void start(); void start() })
    expect(prepareBrowserProfilePackageImport).toHaveBeenCalledTimes(1)
    expect(importProps().profileImportBusy).toBe(true)
    await act(async () => { await props(BrowserListHeader).onImportProfiles() })
    expect(prepareBrowserProfilePackageImport).toHaveBeenCalledTimes(1)
    await act(async () => { pending.resolve(preview()) })
    expect(importProps().profileImportBusy).toBe(false)
  })

  it('blocks duplicate confirmation and stale cancel without unlocking an in-flight import', async () => {
    const pending = deferred()
    importBrowserProfilePackageWithOptions.mockReturnValue(pending.promise)
    await openPreview()
    const { onConfirmProfileImport: confirm, onCloseProfileImport: close } = importProps()
    await act(async () => { confirm(newActions); close(); confirm(newActions) })
    expect(importBrowserProfilePackageWithOptions).toHaveBeenCalledTimes(1)
    expect(importProps().profileImportBusy).toBe(true)
    await act(async () => { await props(BrowserListHeader).onImportProfiles() })
    expect(prepareBrowserProfilePackageImport).toHaveBeenCalledTimes(1)
    await act(async () => { pending.resolve(result) })
    expect(importProps().profileImportBusy).toBe(false)
  })

  it('ignores callbacks from a closed preview after the next preview is ready', async () => {
    await openPreview()
    const old = importProps()
    await act(async () => { old.onCloseProfileImport() })
    const current = await openPreview(preview('next.zip'))
    await act(async () => { old.onConfirmProfileImport(newActions); old.onCloseProfileImport() })
    expect(importBrowserProfilePackageWithOptions).not.toHaveBeenCalled()
    expect(importProps().profileImportPreview).toBe(current)
    expect(importProps().profileImportBusy).toBe(false)
  })

  it('invalidates an old preview while preparing its replacement', async () => {
    await openPreview()
    const old = importProps()
    const pending = deferred()
    prepareBrowserProfilePackageImport.mockReturnValueOnce(pending.promise)
    await act(async () => { void props(BrowserListHeader).onImportProfiles() })
    await act(async () => { old.onCloseProfileImport(); old.onConfirmProfileImport(newActions) })
    expect(importProps().profileImportBusy).toBe(true)
    expect(importProps().profileImportPreview).toBeNull()
    expect(importBrowserProfilePackageWithOptions).not.toHaveBeenCalled()
    const next = preview('next.zip')
    await act(async () => { pending.resolve(next) })
    expect(importProps().profileImportPreview).toBe(next)
    expect(importProps().profileImportBusy).toBe(false)
  })

  it('does not submit an empty ZIP path or leave the page busy', async () => {
    await openPreview(preview('  '))
    await act(async () => { button('确认还原').props.onClick() })
    expect(importBrowserProfilePackageWithOptions).not.toHaveBeenCalled()
    expect(importProps().profileImportPreview).toBeNull()
    expect(importProps().profileImportBusy).toBe(false)
  })

  it('keeps submission locked until the original list refresh completes', async () => {
    const refresh = deferred()
    fixtures.loadProfiles.mockReturnValueOnce(refresh.promise)
    importBrowserProfilePackageWithOptions.mockResolvedValueOnce(result)
    await openPreview()
    await act(async () => { button('确认还原').props.onClick() })
    expect(importProps().profileImportBusy).toBe(true)
    await act(async () => { await props(BrowserListHeader).onImportProfiles() })
    expect(prepareBrowserProfilePackageImport).toHaveBeenCalledTimes(1)
    await act(async () => { refresh.resolve() })
    expect(importProps().profileImportBusy).toBe(false)
    expect(fixtures.loadProfiles).toHaveBeenCalledTimes(1)
  })

  it.each(['resolve', 'reject'])('ignores late preparation %s after unmount', async (outcome) => {
    const pending = deferred()
    prepareBrowserProfilePackageImport.mockReturnValueOnce(pending.promise)
    await act(async () => { void props(BrowserListHeader).onImportProfiles() })
    await act(async () => { renderer.unmount() })
    await act(async () => {
      if (outcome === 'reject') pending.reject(new Error('late preview'))
      else pending.resolve(preview())
    })
    expect(toast.error).not.toHaveBeenCalled()
    expect(importBrowserProfilePackageWithOptions).not.toHaveBeenCalled()
    expect(renderer.toJSON()).toBeNull()
  })

  it.each(['resolve', 'reject'])('ignores late import %s after unmount', async (outcome) => {
    const pending = deferred()
    importBrowserProfilePackageWithOptions.mockReturnValueOnce(pending.promise)
    await openPreview()
    await act(async () => { importProps().onConfirmProfileImport(newActions) })
    await act(async () => { renderer.unmount() })
    await act(async () => {
      if (outcome === 'reject') pending.reject(new Error('late import'))
      else pending.resolve(result)
    })
    expect(toast.success).not.toHaveBeenCalled()
    expect(toast.error).not.toHaveBeenCalled()
    expect(fixtures.loadProfiles).not.toHaveBeenCalled()
  })

  it('shares the busy lock with export so package requests cannot overlap', async () => {
    const pending = deferred()
    exportBrowserProfilePackage.mockReturnValueOnce(pending.promise)
    await act(async () => { props(BrowserProfilesPanel).onToggleSelect('source') })
    const exportBatch = props(BatchToolbar).onBatchExport
    const importProfiles = props(BrowserListHeader).onImportProfiles
    await act(async () => { void exportBatch(); void importProfiles() })
    expect(exportBrowserProfilePackage).toHaveBeenCalledTimes(1)
    expect(prepareBrowserProfilePackageImport).not.toHaveBeenCalled()
    expect(importProps().profileImportBusy).toBe(true)
    await act(async () => { pending.resolve({ cancelled: true }) })
    expect(importProps().profileImportBusy).toBe(false)
    expect(toast.success).not.toHaveBeenCalled()
  })

  it('fences duplicate single exports and releases the same lock on export failure', async () => {
    const pending = deferred()
    exportBrowserProfilePackage.mockReturnValueOnce(pending.promise)
    const exportProfile = props(BrowserProfilesPanel).onExport
    await act(async () => { exportProfile(fixtures.profiles[0]); exportProfile(fixtures.profiles[0]) })
    expect(exportBrowserProfilePackage).toHaveBeenCalledExactlyOnceWith(['source'])
    expect(importProps().profileImportBusy).toBe(true)
    await act(async () => { pending.reject(new Error('export failed')) })
    expect(importProps().profileImportBusy).toBe(false)
    expect(toast.error).toHaveBeenCalledExactlyOnceWith('export failed')
    expect(toast.success).not.toHaveBeenCalled()
  })
})
