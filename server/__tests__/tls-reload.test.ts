import { describe, test, expect, mock, spyOn, beforeEach, afterAll } from 'bun:test';
import { EXPIRY_WARNING_MS, makeReloadTls, type Served } from '../listener';
import type { TlsFiles, TlsKeypair } from '../tls';

// The reload step in isolation: keypair loading and server start are fakes, so each test
// pins one decision (swap or keep) without sockets or certificates.

const files: TlsFiles = { certFile: '/tls/tls.crt', keyFile: '/tls/tls.key' };
// A fixed notAfter, so two pair('b') calls are equal however much time passes between them.
const NOT_AFTER = new Date('2100-01-01T00:00:00Z');
const pair = (name: string): TlsKeypair => ({ cert: `cert-${name}`, key: `key-${name}`, notAfter: NOT_AFTER });

interface FakeServer {
  name: string;
  stop: ReturnType<typeof mock>;
}
const fakeServer = (name: string): FakeServer => ({ name, stop: mock(() => undefined) });

function setup(opts: { load: () => TlsKeypair; listen?: (p: TlsKeypair) => FakeServer; now?: () => number }) {
  let served: Served<FakeServer> = { keypair: pair('a'), server: fakeServer('a') };
  const original = served.server;
  const listen = mock(opts.listen ?? ((p: TlsKeypair) => fakeServer(p.cert)));
  const reload = makeReloadTls<FakeServer>({
    files,
    load: opts.load,
    listen,
    get: () => served,
    set: (next) => {
      served = next;
    },
    now: opts.now,
  });
  return { reload, listen, original, served: () => served };
}

describe('makeReloadTls', () => {
  test('unchanged keypair → no swap, no new server', () => {
    const t = setup({ load: () => pair('a') });
    expect(t.reload()).toBe(false);
    expect(t.listen).not.toHaveBeenCalled();
    expect(t.served().server).toBe(t.original);
  });

  test('changed keypair → serves it from a new server and stops the previous one', () => {
    const t = setup({ load: () => pair('b') });
    expect(t.reload()).toBe(true);
    expect(t.listen).toHaveBeenCalledWith(pair('b'));
    expect(t.served().keypair.cert).toBe('cert-b');
    expect(t.served().server.name).toBe('cert-b');
    expect(t.original.stop).toHaveBeenCalledTimes(1);
  });

  test('unloadable keypair (mid-rotation or read error) → keeps the current pair and server', () => {
    const t = setup({
      load: () => {
        throw new Error('TLS key does not match certificate');
      },
    });
    expect(t.reload()).toBe(false);
    expect(t.listen).not.toHaveBeenCalled();
    expect(t.served().server).toBe(t.original);
  });

  test('new server fails to start → keeps the current server running', () => {
    const t = setup({
      load: () => pair('b'),
      listen: () => {
        throw new Error('EADDRINUSE');
      },
    });
    expect(t.reload()).toBe(false);
    expect(t.served().keypair.cert).toBe('cert-a');
    expect(t.original.stop).not.toHaveBeenCalled();
  });

  test('after a swap, the next poll compares against the new pair, not the startup one', () => {
    const t = setup({ load: () => pair('b') });
    t.reload();
    expect(t.reload()).toBe(false);
    expect(t.listen).toHaveBeenCalledTimes(1);
  });
});

// Renewal stuck upstream (broken issuer, stuck Secret): the files never change, so the
// unchanged path is the only one that can report it.
describe('makeReloadTls: unrenewed certificate', () => {
  const warn = spyOn(console, 'warn').mockImplementation(() => {});
  const error = spyOn(console, 'error').mockImplementation(() => {});
  beforeEach(() => {
    warn.mockClear();
    error.mockClear();
  });
  afterAll(() => {
    warn.mockRestore();
    error.mockRestore();
  });
  const at = (msBeforeNotAfter: number) => () => NOT_AFTER.getTime() - msBeforeNotAfter;
  const logged = (spy: typeof warn) => spy.mock.calls.map((c) => c.join(' ')).join('\n');

  test('far from notAfter → nothing logged', () => {
    setup({ load: () => pair('a'), now: at(EXPIRY_WARNING_MS + 60_000) }).reload();
    expect(warn).not.toHaveBeenCalled();
    expect(error).not.toHaveBeenCalled();
  });

  test('inside the warning window → warns on the poll', () => {
    setup({ load: () => pair('a'), now: at(EXPIRY_WARNING_MS - 60_000) }).reload();
    expect(logged(warn)).toContain('has not been renewed');
    expect(error).not.toHaveBeenCalled();
  });

  test('past notAfter → logs an error on the poll', () => {
    setup({ load: () => pair('a'), now: at(-60_000) }).reload();
    expect(logged(error)).toContain('expired');
  });
});
