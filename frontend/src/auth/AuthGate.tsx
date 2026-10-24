import { useEffect, useRef, useState, useSyncExternalStore, type ReactNode } from 'react';
import { AuthCancel, AuthGrantAPI, AuthLogin, AuthLogout, AuthStatus as NativeAuthStatus, QuitAppOnly } from '../wailsjs/go/main/App';
import { Button, Loading } from '../shared/components';
import { acceptAuth, authEpoch, authSnapshot, beginAuthAction, signedIn, subscribeAuth } from './session';

export const useAuthStatus = () => useSyncExternalStore(subscribeAuth, authSnapshot, authSnapshot);

export function AuthGate({ children }: { children: ReactNode }) {
  const status = useAuthStatus();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const actionBusy = useRef(false);
  const statusUnknown = useRef(false);

  useEffect(() => {
    let disposed = false;
    let pending = false;
    const poll = async () => {
      if (pending || busy || statusUnknown.current) return;
      pending = true;
      const ticket = authEpoch();
      try {
        const next = await NativeAuthStatus();
        if (!disposed) { acceptAuth(next, ticket); setError(''); }
      } catch {
        if (!disposed && ticket === authEpoch()) { statusUnknown.current = true; beginAuthAction(); setError('无法确认登录状态，请保留现场后退出应用。'); }
      } finally { pending = false; }
    };
    void poll();
    const timer = window.setInterval(() => { void poll(); }, 1000);
    return () => { disposed = true; window.clearInterval(timer); };
  }, [busy]);

  const action = async (kind: 'login' | 'cancel' | 'logout') => {
    if (actionBusy.current || statusUnknown.current) return;
    actionBusy.current = true;
    const generation = status.generation;
    const ticket = beginAuthAction();
    setBusy(true); setError('');
    try {
      const next = await ({ login: AuthLogin, cancel: AuthCancel, logout: AuthLogout }[kind])(generation);
      acceptAuth(next, ticket);
    } catch {
      // No replay of a login, logout or unknown business operation.
      setError('认证操作未完成，请核对登录状态。');
    } finally { actionBusy.current = false; setBusy(false); }
  };

  if (signedIn()) return (
    <div className="flex h-screen flex-col">
      <div className="flex shrink-0 items-center justify-end gap-3 border-b border-[var(--color-border)] px-4 py-2 text-sm">
        <span>{status.subject}</span>
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={!!status.apiGranted} disabled={busy} onChange={async (event) => {
            if (actionBusy.current || statusUnknown.current) return;
            actionBusy.current = true;
            const generation = status.generation;
            const ticket = authEpoch();
            setBusy(true); setError('');
            try { await AuthGrantAPI(generation, event.target.checked); acceptAuth(await NativeAuthStatus(), ticket); }
            catch { setError('本机 API 授权未完成，请核对 API key 配置。'); }
            finally { actionBusy.current = false; setBusy(false); }
          }} />允许本机 API
        </label>
        <Button variant="secondary" size="sm" onClick={() => { void action('logout'); }} disabled={busy}>退出登录</Button>
      </div>
      {error && <p role="alert" className="px-4 py-2 text-red-600">{error}</p>}
      <div className="min-h-0 flex-1" key={`${status.generation}:${status.issuer}:${status.subject}`}>{children}</div>
    </div>
  );

  return (
    <main className="flex h-screen items-center justify-center bg-[var(--color-bg-primary)] text-[var(--color-text-primary)]">
      <div className="w-full max-w-sm space-y-5 px-6">
        <h1 className="text-2xl font-semibold">登录 Ant Browser</h1>
        <p className="text-sm text-[var(--color-text-secondary)]">登录后继续使用本机浏览器档案。</p>
        {status.state === 'loading' ? <Loading text="确认登录状态..." /> : null}
        {!status.configured && status.state !== 'loading' ? <p role="status">尚未配置登录服务，请联系管理员提供公开客户端配置。</p> : null}
        {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
        {status.errorCode && <p role="status" className="text-sm">登录状态已失效，请重新登录。</p>}
        {status.state === 'signing_in' ? <>
          <p>请在系统浏览器中完成登录。</p>
          <Button variant="secondary" disabled={busy} onClick={() => { void action('cancel'); }}>取消登录</Button>
        </> : <Button className="w-full" disabled={!status.configured || busy || statusUnknown.current || status.state === 'loading'} loading={busy} onClick={() => { void action('login'); }}>通过浏览器登录</Button>}
        <Button variant="secondary" className="w-full" onClick={() => { void QuitAppOnly(); }}>仅退出应用</Button>
      </div>
    </main>
  );
}
