import bindingPolicy from './bindings.json';

export interface AuthStatus {
  generation: number;
  state: string;
  configured: boolean;
  subject?: string;
  issuer?: string;
  expiresAt?: string;
  errorCode?: string;
  apiGranted?: boolean;
}

let status: AuthStatus = { generation: 0, state: 'loading', configured: false };
let epoch = 0;
const listeners = new Set<() => void>();
export const authSnapshot = () => status;
export const authEpoch = () => epoch;
export const subscribeAuth = (listener: () => void) => { listeners.add(listener); return () => { listeners.delete(listener); }; };
const publish = () => { for (const listener of listeners) listener(); };

export function beginAuthAction() {
  epoch += 1;
  status = { ...status, state: 'transitioning' };
  publish();
  return epoch;
}

export function acceptAuth(next: AuthStatus, expectedEpoch: number) {
  if (expectedEpoch !== epoch || next.generation < status.generation) return false;
  if (next.generation === status.generation && status.state === 'signed_in' && next.state === 'signing_in') return false;
  status = next;
  publish();
  return true;
}

export function signedIn() {
  return status.state === 'signed_in' && !!status.expiresAt && Date.parse(status.expiresAt) > Date.now();
}

export class AuthContextChanged extends Error {
  constructor() { super('authentication_context_changed: 操作结果属于先前会话，请核对后再操作'); }
}

// A captured scope can be retained across awaits. Neither queued continuations
// nor resolved values are ever silently rebound to the next identity.
export function captureBusiness() {
  const generation = status.generation;
  const expectedEpoch = epoch;
  const live = () => signedIn() && generation === status.generation && expectedEpoch === epoch;
  return async (method: (...args: any[]) => Promise<any>, args: unknown[]) => {
    if (!live()) throw new AuthContextChanged();
    const value = await method(...args, generation);
    if (!live()) throw new AuthContextChanged();
    return value;
  };
}

export function callBusiness(method: (...args: any[]) => Promise<any>, args: unknown[]) {
  return captureBusiness()(method, args);
}

export function getBusinessApp(): any {
  const app = (globalThis as any).go?.main?.App;
  if (!app) return null;
  const invoke = captureBusiness();
  return new Proxy(app, { get(target, key) {
    if (typeof key !== 'string' || key.startsWith('Auth') || key === 'GetInterceptor') return undefined;
    const entry = (bindingPolicy as Record<string, {policy:string}>)[key];
    if (!entry) return undefined;
    const method = target[key];
    if (typeof method !== 'function') return undefined;
    if (entry.policy === 'cleanup') return method;
    return (...args: unknown[]) => invoke(method, args);
  } });
}
