import { describe, test, expect, mock } from 'bun:test';
import { makeReloadTls, type Served } from '../listener';
import type { TlsFiles, TlsKeypair } from '../tls';

// The reload step in isolation: keypair loading and server start are fakes, so each test
// pins one decision (swap or keep) without sockets or certificates.

const files: TlsFiles = { certFile: '/tls/tls.crt', keyFile: '/tls/tls.key' };
const pair = (name: string): TlsKeypair => ({ cert: `cert-${name}`, key: `key-${name}`, notAfter: new Date(Date.now() + 86_400_000) });

interface FakeServer {
  name: string;
  stop: ReturnType<typeof mock>;
}
const fakeServer = (name: string): FakeServer => ({ name, stop: mock(() => undefined) });

function setup(opts: { load: () => TlsKeypair; listen?: (p: TlsKeypair) => FakeServer }) {
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
