import { captureBusiness } from './session';

// Capture before dynamic import, so module loading cannot adopt another login.
export async function loadBusinessBridge() {
  const invoke = captureBusiness();
  return (await import('./bridge')).captureBridge(invoke);
}
