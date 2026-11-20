import type { LocalClipboardIO } from './clipboardSync';
import type { AuthenticatedConnectionParams } from './webrtc';

/** The slice of a key-value store the viewer's per-device preferences use. */
export interface PrefsStore {
  get(key: string): Promise<unknown>;
  set(key: string, value: unknown): Promise<void>;
}

/**
 * Tells the host which desktop session this window shows, so the host can end
 * it when the window closes. `track` receives every value assigned to the
 * viewer's auth and returns it unchanged; `disarm` stops the host from ending
 * a session the viewer has already ended. Neither throws or rejects.
 */
export interface SessionEndTracker {
  track<T extends AuthenticatedConnectionParams | null>(auth: T): T;
  disarm(sessionId: string | null | undefined): Promise<void>;
}

/**
 * Everything the viewer needs from the app that embeds it. The embedding app
 * implements this once; the viewer never reaches for a platform API directly.
 */
export interface RemoteDesktopHost {
  /** Reads and writes the local clipboard as the sync feature needs it. */
  clipboard: LocalClipboardIO;
  /** The local clipboard's text for paste-as-keystrokes. Null when it cannot be read. Never rejects. */
  readClipboardText(): Promise<string | null>;
  /** The preferences store shared by every session window. Null when none is available. Never rejects. */
  getPrefsStore(): Promise<PrefsStore | null>;
  /** Names the session window after the remote device. */
  setTitle(hostname: string): Promise<void>;
  /** Marks this window as showing a live session (or, for registerDevice, device), so a second link to it is detected. */
  registerSession(sessionId: string): Promise<void>;
  registerDevice(deviceId: string): Promise<void>;
  unregisterSession(): Promise<void>;
  /** Saves a PNG the viewer captured. Resolves to where it went, for the notice. */
  saveScreenshot(bytes: Uint8Array): Promise<string>;
  /** Calls `handler` when the host is closing the window and ending the session itself. Resolves to the unsubscribe. */
  onWindowClosing(handler: () => void): Promise<() => void>;
  createSessionEnd(): SessionEndTracker;
}
