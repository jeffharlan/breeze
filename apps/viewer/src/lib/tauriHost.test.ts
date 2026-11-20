import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import source from './tauriHost.ts?raw';

const tauri = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(),
  readText: vi.fn(),
  writeText: vi.fn(),
  load: vi.fn(),
}));

vi.mock('@tauri-apps/api/core', () => ({ invoke: tauri.invoke }));
vi.mock('@tauri-apps/api/webviewWindow', () => ({ getCurrentWebviewWindow: () => ({ listen: tauri.listen }) }));
vi.mock('@tauri-apps/plugin-clipboard-manager', () => ({ readText: tauri.readText, writeText: tauri.writeText }));
vi.mock('@tauri-apps/plugin-store', () => ({ load: tauri.load }));

// The prefs store is cached per module instance, so each test gets a fresh one.
async function freshHost() {
  vi.resetModules();
  return (await import('./tauriHost')).tauriHost;
}

beforeEach(() => {
  for (const f of Object.values(tauri)) f.mockReset();
  tauri.invoke.mockResolvedValue(undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
  Reflect.deleteProperty(navigator, 'clipboard');
});

describe('tauriHost commands', () => {
  it('names the window after the device through update_session_hostname', async () => {
    const host = await freshHost();
    await host.setTitle('FRONT-DESK-01');
    expect(tauri.invoke).toHaveBeenCalledWith('update_session_hostname', { hostname: 'FRONT-DESK-01' });
  });

  it('registers and unregisters the session and device through the matching commands', async () => {
    const host = await freshHost();
    await host.registerSession('s-1');
    await host.registerDevice('d-1');
    await host.unregisterSession();
    expect(tauri.invoke.mock.calls).toEqual([
      ['register_session', { sessionId: 's-1' }],
      ['register_device', { deviceId: 'd-1' }],
      ['unregister_session'],
    ]);
  });

  it('saves a screenshot by sending the raw bytes to save_screenshot and resolves to the saved path', async () => {
    const host = await freshHost();
    const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47]);
    tauri.invoke.mockResolvedValueOnce('/home/tech/Pictures/shot.png');
    await expect(host.saveScreenshot(bytes)).resolves.toBe('/home/tech/Pictures/shot.png');
    expect(tauri.invoke).toHaveBeenCalledWith('save_screenshot', bytes);
  });

  it('passes a failing command through so the viewer can show its own notice', async () => {
    const host = await freshHost();
    tauri.invoke.mockRejectedValueOnce(new Error('disk full'));
    await expect(host.saveScreenshot(new Uint8Array(1))).rejects.toThrow('disk full');
  });

  it('arms the native close hook through the session-end tracker', async () => {
    const host = await freshHost();
    host.createSessionEnd().track({ apiUrl: 'https://api.example.com', accessToken: 'tok', sessionId: 's-1' });
    await Promise.resolve();
    expect(tauri.invoke).toHaveBeenCalledWith('arm_session_end', {
      apiUrl: 'https://api.example.com',
      accessToken: 'tok',
      sessionId: 's-1',
    });
  });
});

describe('tauriHost window closing', () => {
  it('listens for the close Rust holds, and hands back the unsubscribe', async () => {
    const host = await freshHost();
    const unlisten = vi.fn();
    tauri.listen.mockResolvedValueOnce(unlisten);
    const handler = vi.fn();
    await expect(host.onWindowClosing(handler)).resolves.toBe(unlisten);
    expect(tauri.listen).toHaveBeenCalledWith('session-window-closing', handler);
  });

  it('never registers a page close listener, which would make Tauri hold every close for the page', () => {
    expect(source).not.toContain('onCloseRequested(');
  });
});

describe('tauriHost clipboard', () => {
  it('writes through the Tauri clipboard plugin, not the browser API', async () => {
    const host = await freshHost();
    await host.clipboard.writeText('hello');
    expect(tauri.writeText).toHaveBeenCalledWith('hello');
  });

  it('reads paste text from the Tauri plugin first', async () => {
    const host = await freshHost();
    const browserRead = vi.fn();
    Object.defineProperty(navigator, 'clipboard', { value: { readText: browserRead }, configurable: true });
    tauri.readText.mockResolvedValueOnce('from tauri');
    await expect(host.readClipboardText()).resolves.toBe('from tauri');
    expect(browserRead).not.toHaveBeenCalled();
  });

  it('falls back to the browser clipboard when the plugin cannot read', async () => {
    const host = await freshHost();
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    Object.defineProperty(navigator, 'clipboard', { value: { readText: vi.fn(async () => 'from browser') }, configurable: true });
    tauri.readText.mockRejectedValueOnce(new Error('denied'));
    await expect(host.readClipboardText()).resolves.toBe('from browser');
  });

  it('resolves to null, never rejects, when neither clipboard can be read', async () => {
    const host = await freshHost();
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    Object.defineProperty(navigator, 'clipboard', { value: { readText: vi.fn(async () => { throw new Error('denied'); }) }, configurable: true });
    tauri.readText.mockRejectedValueOnce(new Error('denied'));
    await expect(host.readClipboardText()).resolves.toBeNull();
  });
});

describe('tauriHost prefs store', () => {
  it('opens viewer-prefs.json once and wraps get and set', async () => {
    const host = await freshHost();
    const store = { get: vi.fn(async () => 'v'), set: vi.fn(async () => {}) };
    tauri.load.mockResolvedValue(store);

    const first = await host.getPrefsStore();
    const second = await host.getPrefsStore();

    expect(second).toBe(first);
    expect(tauri.load).toHaveBeenCalledTimes(1);
    expect(tauri.load).toHaveBeenCalledWith('viewer-prefs.json', { defaults: {}, autoSave: 200 });
    await expect(first!.get('k')).resolves.toBe('v');
    await first!.set('k', 1);
    expect(store.set).toHaveBeenCalledWith('k', 1);
  });

  it('resolves to null, never rejects, when the plugin is unavailable', async () => {
    const host = await freshHost();
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    tauri.load.mockRejectedValue(new Error('plugin missing'));
    await expect(host.getPrefsStore()).resolves.toBeNull();
  });
});
