// DesktopViewer talks to the platform only through the RemoteDesktopHost it is
// given. These tests run it against a fake host: what it asks the host for, and
// how it behaves when the host reports denied, unavailable or failed.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import type { ConnectionParams, PrefsStore, RemoteDesktopHost } from '@breeze/remote-desktop-ui';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const transport = vi.hoisted(() => ({
  exchange: vi.fn(),
  connectWebSocket: vi.fn(),
  captureFramePng: vi.fn(),
}));

vi.mock('@breeze/remote-desktop-ui', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@breeze/remote-desktop-ui')>()),
  exchangeDesktopConnectCode: transport.exchange,
  connectWebSocket: transport.connectWebSocket,
  captureFramePng: transport.captureFramePng,
}));

import DesktopViewer from './DesktopViewer';

const DEVICE_ID = 'dev-1';
const SESSION_ID = 'sess-1';

// The connect-code exchange is de-duplicated per code for the life of the module.
let codeSeq = 0;
function desktopParams(): ConnectionParams {
  return { mode: 'desktop', sessionId: SESSION_ID, connectCode: `code-${++codeSeq}`, apiUrl: 'https://api.example.com', deviceId: DEVICE_ID };
}

function fakeHost(over: Partial<RemoteDesktopHost> = {}) {
  const tracker = { track: vi.fn(<T,>(auth: T) => auth), disarm: vi.fn(async () => {}) };
  const unlisten = vi.fn();
  const host = {
    clipboard: {
      readText: vi.fn(async () => null),
      readImagePng: vi.fn(async () => null),
      writeText: vi.fn(async () => {}),
      writeImage: vi.fn(async () => {}),
    },
    readClipboardText: vi.fn(async () => null as string | null),
    getPrefsStore: vi.fn(async () => null as PrefsStore | null),
    setTitle: vi.fn(async () => {}),
    registerSession: vi.fn(async () => {}),
    registerDevice: vi.fn(async () => {}),
    unregisterSession: vi.fn(async () => {}),
    saveScreenshot: vi.fn(async () => '/shots/frame.png'),
    onWindowClosing: vi.fn(async () => unlisten),
    createSessionEnd: vi.fn(() => tracker),
    ...over,
  };
  return { host: host as RemoteDesktopHost & typeof host, tracker, unlisten };
}

let root: Root | null = null;
let container: HTMLDivElement | null = null;
let ws: { kind: 'websocket'; canvasElement: HTMLCanvasElement; inputChannel: { send: ReturnType<typeof vi.fn> }; sendRaw: ReturnType<typeof vi.fn>; close: ReturnType<typeof vi.fn> };

beforeEach(() => {
  ws = { kind: 'websocket', canvasElement: document.createElement('canvas'), inputChannel: { send: vi.fn() }, sendRaw: vi.fn(), close: vi.fn() };
  transport.exchange.mockReset().mockResolvedValue({ accessToken: 'viewer-tok', hostname: 'FRONT-DESK-01', osType: 'windows' });
  transport.connectWebSocket.mockReset().mockImplementation(async (_auth, handlers) => {
    handlers.onConnected({ hostname: 'FRONT-DESK-01', osType: 'windows' });
    return ws;
  });
  transport.captureFramePng.mockReset().mockResolvedValue(new Blob([new Uint8Array([0x89, 0x50, 0x4e, 0x47])], { type: 'image/png' }));
});

afterEach(async () => {
  await act(async () => root?.unmount());
  container?.remove();
  root = null;
  container = null;
  vi.restoreAllMocks();
});

async function settle() {
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
}

async function mount(host: RemoteDesktopHost) {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => {
    root!.render(<DesktopViewer host={host} params={desktopParams()} onDisconnect={vi.fn()} onError={vi.fn()} />);
  });
  await settle();
}

const q = (selector: string) => container!.querySelector(selector) as HTMLButtonElement | null;

async function click(el: HTMLElement | null) {
  expect(el).not.toBeNull();
  await act(async () => { el!.click(); });
  await settle();
}

async function chooseFromMoreMenu(testId: string) {
  await click(q('button[title="More options"]'));
  await click(q(`[data-testid="${testId}"]`));
}

describe('DesktopViewer with a fake host', () => {
  it('names the window, registers the live session and device, and unregisters on unmount', async () => {
    const { host, tracker } = fakeHost();
    await mount(host);

    expect(host.setTitle).toHaveBeenCalledWith('FRONT-DESK-01');
    expect(host.registerSession).toHaveBeenCalledWith(SESSION_ID);
    expect(host.registerDevice).toHaveBeenCalledWith(DEVICE_ID);
    expect(tracker.track).toHaveBeenCalledWith(expect.objectContaining({ sessionId: SESSION_ID, accessToken: 'viewer-tok' }));

    await act(async () => root!.unmount());
    root = null;
    expect(host.unregisterSession).toHaveBeenCalled();
  });

  it('keeps connecting when the host cannot set the title or register the session', async () => {
    const { host } = fakeHost({
      setTitle: vi.fn(async () => { throw new Error('no window'); }),
      registerSession: vi.fn(async () => { throw new Error('no window'); }),
      registerDevice: vi.fn(async () => { throw new Error('no window'); }),
    });
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
    await mount(host);

    expect(host.setTitle).toHaveBeenCalled();
    expect(host.registerSession).toHaveBeenCalled();
    await click(q('button[title="More options"]'));
    expect(q('[data-testid="save-screenshot"]')!.disabled).toBe(false);
  });

  it('stops listening for the window closing when it unmounts, and survives a host that cannot listen', async () => {
    const { host, unlisten } = fakeHost();
    await mount(host);
    expect(host.onWindowClosing).toHaveBeenCalledTimes(1);
    await act(async () => root!.unmount());
    root = null;
    expect(unlisten).toHaveBeenCalled();

    container!.remove();
    container = null;
    const refusing = fakeHost({ onWindowClosing: vi.fn(async () => { throw new Error('no window'); }) });
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await mount(refusing.host);
    expect(warn).toHaveBeenCalledWith('Could not listen for the window closing:', expect.any(Error));
  });
});

describe('prefs', () => {
  it('reads the remembered prefs for the device from the host store', async () => {
    const store: PrefsStore = { get: vi.fn(async () => undefined), set: vi.fn(async () => {}) };
    const { host } = fakeHost({ getPrefsStore: vi.fn(async () => store) });
    await mount(host);
    expect(store.get).toHaveBeenCalledWith(`device:${DEVICE_ID}`);
  });

  it('keeps defaults and still lets the operator change settings when no prefs store is available', async () => {
    const { host } = fakeHost({ getPrefsStore: vi.fn(async () => null) });
    await mount(host);
    await click(q('button[title="More options"]'));
    expect(q('[data-testid="view-scaling-actual"]')!.getAttribute('aria-checked')).toBe('false');
    await click(q('[data-testid="view-scaling-actual"]'));

    expect(host.getPrefsStore).toHaveBeenCalled();
    expect(q('[data-testid="view-scaling-actual"]')!.getAttribute('aria-checked')).toBe('true');
  });

  it('writes a change the operator makes to the host store', async () => {
    const store: PrefsStore = { get: vi.fn(async () => undefined), set: vi.fn(async () => {}) };
    const { host } = fakeHost({ getPrefsStore: vi.fn(async () => store) });
    await mount(host);
    await chooseFromMoreMenu('view-scaling-actual');

    expect(store.set).toHaveBeenCalledWith(`device:${DEVICE_ID}`, expect.objectContaining({ viewScaling: 'actual' }));
  });
});

describe('paste as keystrokes', () => {
  const pasteButton = () => q('button[title^="Paste clipboard text"]');

  it('types what the host reads from the clipboard', async () => {
    const { host } = fakeHost({ readClipboardText: vi.fn(async () => 'a') });
    await mount(host);
    await click(pasteButton());
    await vi.waitFor(() => expect(ws.inputChannel.send).toHaveBeenCalled(), { timeout: 3000 });
    expect(ws.inputChannel.send.mock.calls.map(([json]) => JSON.parse(json).key)).toContain('a');
  });

  it('sends nothing when the host cannot read the clipboard (denied)', async () => {
    const { host } = fakeHost({ readClipboardText: vi.fn(async () => null) });
    await mount(host);
    await click(pasteButton());
    await act(async () => { await new Promise((r) => setTimeout(r, 700)); });

    expect(host.readClipboardText).toHaveBeenCalledTimes(1);
    expect(ws.inputChannel.send).not.toHaveBeenCalled();
    expect(container!.textContent).not.toContain('Paste failed');
  });
});

describe('screenshots', () => {
  it('saves through the host and says where it went', async () => {
    const { host } = fakeHost({ saveScreenshot: vi.fn(async () => '/shots/frame.png') });
    await mount(host);
    await chooseFromMoreMenu('save-screenshot');

    expect(host.saveScreenshot).toHaveBeenCalledWith(new Uint8Array([0x89, 0x50, 0x4e, 0x47]));
    expect(container!.textContent).toContain('Screenshot saved to /shots/frame.png');
  });

  it('tells the operator when the host cannot save it', async () => {
    const { host } = fakeHost({ saveScreenshot: vi.fn(async () => { throw new Error('disk full'); }) });
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    await mount(host);
    await chooseFromMoreMenu('save-screenshot');

    expect(container!.textContent).toContain('Screenshot could not be saved: disk full');
    expect(container!.textContent).not.toContain('Screenshot saved to');
  });

  it('copies through the host clipboard', async () => {
    const { host } = fakeHost();
    await mount(host);
    await chooseFromMoreMenu('copy-screenshot');

    expect(host.clipboard.writeImage).toHaveBeenCalledWith(new Uint8Array([0x89, 0x50, 0x4e, 0x47]), 'png');
    expect(container!.textContent).toContain('Screenshot copied to the clipboard.');
  });

  it('tells the operator when the host clipboard refuses the image (denied)', async () => {
    const { host } = fakeHost();
    vi.mocked(host.clipboard.writeImage).mockRejectedValueOnce(new Error('denied'));
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    await mount(host);
    await chooseFromMoreMenu('copy-screenshot');

    expect(container!.textContent).toContain('Screenshot could not be copied to the clipboard: denied');
  });

  it('says there is no picture yet when no frame can be captured, without calling the host', async () => {
    transport.captureFramePng.mockResolvedValue(null);
    const { host } = fakeHost();
    await mount(host);
    await chooseFromMoreMenu('save-screenshot');

    expect(host.saveScreenshot).not.toHaveBeenCalled();
    expect(container!.textContent).toContain('no picture from the remote yet');
  });
});
