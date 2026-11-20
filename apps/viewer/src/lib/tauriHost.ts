import { invoke } from '@tauri-apps/api/core';
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow';
import type { PrefsStore, RemoteDesktopHost } from '@breeze/remote-desktop-ui';
import { createTauriClipboardIO } from './clipboardIO';
import { createNativeSessionEnd } from './nativeSessionEnd';

let prefsStore: Promise<PrefsStore | null> | null = null;

// Shared by every session window (the plugin hands back the same store for
// the same file). Null when the plugin is unavailable.
function getPrefsStore(): Promise<PrefsStore | null> {
  if (!prefsStore) {
    prefsStore = import('@tauri-apps/plugin-store')
      .then(({ load }) => load('viewer-prefs.json', { defaults: {}, autoSave: 200 }))
      .then((store): PrefsStore => ({
        get: (key) => store.get(key),
        set: (key, value) => store.set(key, value),
      }))
      .catch((err) => {
        console.warn('[devicePrefs]', `store unavailable: ${err instanceof Error ? err.message : String(err)}`);
        return null;
      });
  }
  return prefsStore;
}

export const tauriHost: RemoteDesktopHost = {
  clipboard: createTauriClipboardIO(),

  async readClipboardText() {
    try {
      // Use Tauri native clipboard to bypass macOS "Allow Paste" prompt
      const { readText } = await import('@tauri-apps/plugin-clipboard-manager');
      return await readText();
    } catch (tauriErr) {
      console.warn('Tauri clipboard read failed, trying browser API:', tauriErr);
      try {
        return await navigator.clipboard.readText();
      } catch (browserErr) {
        console.warn('Browser clipboard read also failed:', browserErr);
        return null;
      }
    }
  },

  getPrefsStore,

  setTitle: (hostname) => invoke<void>('update_session_hostname', { hostname }),
  registerSession: (sessionId) => invoke<void>('register_session', { sessionId }),
  registerDevice: (deviceId) => invoke<void>('register_device', { deviceId }),
  unregisterSession: () => invoke<void>('unregister_session'),
  saveScreenshot: (bytes) => invoke<string>('save_screenshot', bytes),

  // Rust owns the window close (src-tauri/src/session_end.rs). Do NOT use
  // onCloseRequested here: with a page listener registered, Tauri holds every
  // close until the page destroys the window itself, which a hung page never does.
  onWindowClosing: (handler) => getCurrentWebviewWindow().listen('session-window-closing', handler),

  createSessionEnd: createNativeSessionEnd,
};
