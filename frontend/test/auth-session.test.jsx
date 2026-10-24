import { beforeEach, describe, expect, it, vi } from 'vitest';

let session;
const live = (generation = 7) => ({generation, state:'signed_in', configured:true, issuer:'https://mock.invalid', subject:'synthetic', expiresAt:new Date(Date.now()+3600000).toISOString()});
beforeEach(async () => {vi.resetModules();session=await import('../src/auth/session');delete globalThis.go;});

describe('actual shared business bridge session boundary', () => {
 it('does not invoke native business code before login or after expiry', async () => {
  const native=vi.fn().mockResolvedValue('value');
  await expect(session.callBusiness(native,[])).rejects.toThrow('authentication_context_changed');
  session.acceptAuth({...live(),expiresAt:new Date(Date.now()-1).toISOString()},session.authEpoch());
  await expect(session.callBusiness(native,[])).rejects.toThrow('authentication_context_changed');
  expect(native).not.toHaveBeenCalled();
 });
 it('passes the original generation and rejects a late result without replay', async () => {
  session.acceptAuth(live(),session.authEpoch());let release;
  const native=vi.fn(() => new Promise(resolve => {release=resolve;}));
  const result=session.callBusiness(native,['original']);
  expect(native).toHaveBeenCalledWith('original',7);
  const ticket=session.beginAuthAction();session.acceptAuth(live(9),ticket);release({committed:true});
  await expect(result).rejects.toThrow('操作结果属于先前会话');expect(native).toHaveBeenCalledTimes(1);
 });
 it('retains a raw-call scope across awaits and account replacement', async () => {
  session.acceptAuth(live(),session.authEpoch());const native=vi.fn().mockResolvedValue('ok');globalThis.go={main:{App:{SaveBrowserSettings:native}}};
  const old=session.getBusinessApp();const ticket=session.beginAuthAction();session.acceptAuth(live(9),ticket);
  await expect(old.SaveBrowserSettings('late')).rejects.toThrow('authentication_context_changed');expect(native).not.toHaveBeenCalled();
  await session.getBusinessApp().SaveBrowserSettings('fresh');expect(native).toHaveBeenCalledWith('fresh',9);
 });
 it('ignores old polls and signing-in callbacks', () => {
  const old=session.authEpoch();const current=session.beginAuthAction();expect(session.acceptAuth(live(9),old)).toBe(false);
  expect(session.acceptAuth(live(9),current)).toBe(true);
  expect(session.acceptAuth({...live(9),state:'signing_in'},current)).toBe(false);
  expect(session.authSnapshot().state).toBe('signed_in');
 });
});
