import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import * as Native from '../src/wailsjs/go/main/App';
import policy from '../src/auth/bindings.json';
import { acceptAuth, authSnapshot, beginAuthAction } from '../src/auth/session';
import { BackupScheduledSaveSettings } from '../src/auth/bridge';
import { loadBusinessBridge } from '../src/auth/loadBridge';

beforeEach(() => { globalThis.window = {go:{main:{App:{}}}}; });
afterEach(() => { delete globalThis.window; });
it('matches every actual SDK arity to the Go facade policy', () => {
  expect(Object.keys(Native).sort()).toEqual(Object.keys(policy).sort());
  for (const [name, entry] of Object.entries(policy)) expect(Native[name].length, name).toBe(entry.arguments);
  expect(Native.GetInterceptor).toBeUndefined();
});
it('captures before dynamic module loading rather than adopting a replacement session', async () => {
  const generation=authSnapshot().generation+1;
  let epoch=beginAuthAction();acceptAuth({generation,state:'signed_in',configured:true,expiresAt:new Date(Date.now()+60000).toISOString()},epoch);
  const pending=loadBusinessBridge();
  epoch=beginAuthAction();acceptAuth({generation:generation+1,state:'signed_in',configured:true,expiresAt:new Date(Date.now()+60000).toISOString()},epoch);
  const bindings=await pending;const native=vi.fn();window.go.main.App.BackupScheduledSaveSettings=native;
  await expect(bindings.BackupScheduledSaveSettings({})).rejects.toThrow('authentication_context_changed');
  expect(native).not.toHaveBeenCalled();
});
it('passes a Record and generation exactly once through the actual generated SDK', async () => {
  const native=vi.fn().mockResolvedValue({saved:true});window.go.main.App.BackupScheduledSaveSettings=native;
  const generation=authSnapshot().generation+1;
  const epoch=beginAuthAction();acceptAuth({generation,state:'signed_in',configured:true,expiresAt:new Date(Date.now()+60000).toISOString()},epoch);
  const input={dailyTime:'03:00'};await BackupScheduledSaveSettings(input);
  expect(native).toHaveBeenCalledExactlyOnceWith(input,generation);
});
it('does not turn a late rejected business log into an unhandled operation failure', async () => {
  const generation=authSnapshot().generation+1;const epoch=beginAuthAction();acceptAuth({generation,state:'signed_in',configured:true,expiresAt:new Date(Date.now()+60000).toISOString()},epoch);
  const logger=vi.fn().mockRejectedValue(new Error('authentication_required'));
  window.go.main.App={SaveBrowserSettings:vi.fn().mockResolvedValue('saved'),FrontendOperationLog:logger};
  (await import('../src/utils/wailsOperationLogger')).installWailsOperationLogger();
  await expect(window.go.main.App.SaveBrowserSettings({},generation)).resolves.toBe('saved');
  await Promise.resolve();expect(logger).toHaveBeenCalledTimes(1);
});
