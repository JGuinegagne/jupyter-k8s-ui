import { describe, test, expect, beforeAll, afterAll, afterEach } from 'bun:test';
import { spawn } from 'bun';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { connect } from 'tls';
import { startListener, type Listener } from '../listener';
import { handleRequest } from '../middleware/router';
import { makeKeypair, projectSecret } from './tls-helpers';

// Real listeners on ephemeral ports. The TLS files are laid out the way the kubelet
// projects a cert-manager Secret (`..data` symlink swap), so rotation is exercised the
// way it happens in a pod.

let fixtures: string;
let mount: string;
let listener: Listener | undefined;
let version = 0;

const certFile = () => join(mount, 'tls.crt');
const keyFile = () => join(mount, 'tls.key');

function project(cert: string, key: string): void {
  projectSecret(mount, `v${++version}`, { 'tls.crt': join(fixtures, cert), 'tls.key': join(fixtures, key) });
}

function startTls(tlsReloadIntervalMs = 0): Listener {
  listener = startListener({ hostname: '127.0.0.1', port: 0, fetch: handleRequest, tls: { certFile: certFile(), keyFile: keyFile() }, tlsReloadIntervalMs });
  return listener;
}

/** CN of the certificate the server presents on a fresh connection. */
function servedCN(port: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port, rejectUnauthorized: false }, () => {
      const cn = socket.getPeerCertificate().subject.CN;
      socket.end();
      resolve(String(cn));
    });
    socket.on('error', reject);
  });
}

/** Run an `openssl s_client` handshake; returns its combined output. */
async function sClient(port: number, args: string[]): Promise<string> {
  const proc = spawn(['openssl', 's_client', '-connect', `127.0.0.1:${port}`, ...args], { stdin: 'ignore', stdout: 'pipe', stderr: 'pipe' });
  const [out, err] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  await proc.exited;
  return out + err;
}

beforeAll(() => {
  fixtures = mkdtempSync(join(tmpdir(), 'tls-fixtures-'));
  makeKeypair(fixtures, 'a');
  makeKeypair(fixtures, 'b');
});

afterAll(() => rmSync(fixtures, { recursive: true, force: true }));

afterEach(() => {
  listener?.stop();
  listener = undefined;
  if (mount) rmSync(mount, { recursive: true, force: true });
});

function freshMount(): void {
  mount = mkdtempSync(join(tmpdir(), 'tls-mount-'));
}

describe('startListener', () => {
  test('no TLS config → plain HTTP', async () => {
    listener = startListener({ hostname: '127.0.0.1', port: 0, fetch: handleRequest, tlsReloadIntervalMs: 0 });
    expect(listener.protocol).toBe('http');
    const res = await fetch(`http://127.0.0.1:${listener.port}/api/v1/health`);
    expect(res.status).toBe(200);
  });

  test('TLS config → health endpoint over HTTPS, without client cert verification', async () => {
    freshMount();
    project('a.crt', 'a.key');
    const l = startTls();
    expect(l.protocol).toBe('https');
    const res = await fetch(`https://127.0.0.1:${l.port}/api/v1/health`, { tls: { rejectUnauthorized: false } });
    expect(((await res.json()) as { status: string }).status).toBe('ok');
  });

  test('mismatched keypair at startup → throws (fail fast)', () => {
    freshMount();
    project('a.crt', 'b.key');
    expect(() => startTls()).toThrow('does not match');
  });

  test('cert-manager rotation (..data symlink swap) is served by the poll, on the same port', async () => {
    freshMount();
    project('a.crt', 'a.key');
    const l = startTls(25);
    expect(await servedCN(l.port)).toBe('a');

    project('b.crt', 'b.key');
    const deadline = Date.now() + 3000;
    let cn = 'a';
    while (cn !== 'b' && Date.now() < deadline) {
      await Bun.sleep(25);
      cn = await servedCN(l.port);
    }
    expect(cn).toBe('b');
  });
});

const ALLOWED_GROUPS = ['X25519MLKEM768', 'x25519', 'secp256r1', 'secp384r1', 'secp521r1'];
const DISALLOWED_GROUPS = ['x448', 'ffdhe2048', 'brainpoolP256r1tls13'];

// Conformance to TLS_POLICY. Assertions read the
// server's side of the handshake (its alert, or the negotiated parameter), so a client that
// can't offer a parameter itself can't make a test pass.
describe('TLS policy', () => {
  // A client that cannot offer a group fails the handshake on its own, which would pass the
  // "refused" cases for the wrong reason and fail the "negotiated" ones confusingly.
  beforeAll(async () => {
    const proc = spawn(['openssl', 'list', '-tls-groups'], { stdout: 'pipe' });
    const offered = new Set((await new Response(proc.stdout).text()).trim().split(':'));
    const needed = [...ALLOWED_GROUPS, ...DISALLOWED_GROUPS].filter((g) => !offered.has(g));
    if (needed.length) throw new Error(`openssl client cannot offer ${needed.join(', ')}; use OpenSSL >= 3.5`);
  });

  async function handshake(args: string[]): Promise<string> {
    freshMount();
    project('a.crt', 'a.key');
    return sClient(startTls().port, args);
  }

  test.each(['-tls1', '-tls1_1', '-tls1_2'])('%s → refused with a protocol-version alert', async (flag) => {
    expect(await handshake([flag, '-cipher', 'DEFAULT:@SECLEVEL=0'])).toContain('alert protocol version');
  });

  test.each(['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'])('allowed cipher suite %s → negotiated', async (suite) => {
    expect(await handshake(['-tls1_3', '-ciphersuites', suite])).toContain(`Cipher is ${suite}`);
  });

  // secp521r1 is outside Bun's default list, so it also proves the ecdhCurve pin is applied.
  test.each(ALLOWED_GROUPS)('allowed group %s → negotiated', async (group) => {
    expect(await handshake(['-tls1_3', '-groups', group])).toMatch(/^subject=/m);
  });

  test.each(DISALLOWED_GROUPS)('disallowed group %s → refused', async (group) => {
    expect(await handshake(['-tls1_3', '-groups', group])).not.toMatch(/^subject=/m);
  });
});
