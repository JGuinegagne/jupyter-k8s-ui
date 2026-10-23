#!/usr/bin/env bun
// Smoke-test the TLS path of a built image: start it with a throwaway certificate and check,
// from inside the container, that it serves the health endpoint over HTTPS and enforces the
// TLS policy in server/tls.ts on the Bun version the image actually ships.
//
// The policy relies on Bun options that some versions silently ignore, and the image floats
// on oven/bun:1, so this is what catches a Bun release that stops enforcing it.
//
// Usage:
//   bun scripts/smoke-tls.ts <image>
//   CONTAINER_TOOL=finch bun scripts/smoke-tls.ts <image>

import { chmodSync, mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const PORT = 8443;
const TOOL = process.env.CONTAINER_TOOL || 'docker';

interface Check {
  // What the check proves when it passes; printed on failure.
  name: string;
  args: string[];
  // Matched against the server's side of the handshake (its alert, or the certificate it
  // sent), never the client's own error, so a client limitation cannot make a check pass.
  expect: RegExp;
  // true: the output must match `expect`; false: it must not.
  match: boolean;
}

const SERVED = /^subject=/m;

const CHECKS: Check[] = [
  { name: 'TLS 1.2 refused: minVersion is enforced', args: ['-tls1_2', '-cipher', 'DEFAULT:@SECLEVEL=0'], expect: /alert protocol version/, match: true },
  { name: 'P-521 accepted: the pinned key-exchange groups (ecdhCurve) are applied', args: ['-tls1_3', '-groups', 'secp521r1'], expect: SERVED, match: true },
  { name: 'X25519MLKEM768 (hybrid post-quantum) accepted', args: ['-tls1_3', '-groups', 'X25519MLKEM768'], expect: SERVED, match: true },
  { name: 'x448, outside the allowed groups, refused', args: ['-tls1_3', '-groups', 'x448'], expect: SERVED, match: false },
];

function run(cmd: string[], stdin?: string): { code: number; out: string } {
  const res = Bun.spawnSync(cmd, { stdin: stdin === undefined ? 'ignore' : Buffer.from(stdin), stdout: 'pipe', stderr: 'pipe' });
  return { code: res.exitCode, out: res.stdout.toString() + res.stderr.toString() };
}

function fail(message: string): never {
  console.error(`::error::${message}`);
  process.exit(1);
}

/** Handshake with the image's own OpenSSL client (3.5+, which can offer every group above). */
function handshake(cid: string, args: string[]): string {
  return run([TOOL, 'exec', '-i', cid, 'openssl', 's_client', '-connect', `127.0.0.1:${PORT}`, ...args], '').out;
}

function main(): void {
  const image = process.argv[2] ?? fail('usage: bun scripts/smoke-tls.ts <image>');

  const certs = mkdtempSync(join(tmpdir(), 'smoke-tls-'));
  const keygen = run([
    'openssl',
    'req',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:prime256v1',
    '-nodes',
    '-days',
    '1',
    '-subj',
    '/CN=localhost',
    '-keyout',
    join(certs, 'tls.key'),
    '-out',
    join(certs, 'tls.crt'),
  ]);
  if (keygen.code !== 0) fail(`could not generate a test certificate: ${keygen.out}`);
  // The image runs as uid 1000.
  chmodSync(certs, 0o755);
  chmodSync(join(certs, 'tls.key'), 0o644);

  const start = run([
    TOOL,
    'run',
    '-d',
    '-v',
    `${certs}:/tls:ro`,
    '-e',
    'NODE_ENV=production',
    '-e',
    'SESSION_ENABLED=false',
    '-e',
    `PORT=${PORT}`,
    '-e',
    'TLS_CERT_FILE=/tls/tls.crt',
    '-e',
    'TLS_KEY_FILE=/tls/tls.key',
    image,
  ]);
  if (start.code !== 0) fail(`could not start ${image}: ${start.out}`);
  const cid = start.out.trim().split('\n').pop()!;

  // process.exit skips `finally`, so clean up on exit instead.
  process.on('exit', () => {
    console.log(run([TOOL, 'logs', cid]).out.split('\n').slice(-20).join('\n'));
    run([TOOL, 'rm', '-f', cid]);
    rmSync(certs, { recursive: true, force: true });
  });

  let up = false;
  for (let i = 0; i < 30 && !up; i++) {
    up = SERVED.test(handshake(cid, ['-tls1_3']));
    if (!up) Bun.sleepSync(1000);
  }
  if (!up) fail('image did not serve TLS 1.3 within 30s');

  const request = 'GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n';
  const health = run([TOOL, 'exec', '-i', cid, 'openssl', 's_client', '-quiet', '-connect', `127.0.0.1:${PORT}`], request).out;
  if (!health.includes('"status":"ok"')) fail('health endpoint not served over HTTPS');

  for (const check of CHECKS) {
    if (check.expect.test(handshake(cid, check.args)) !== check.match) fail(`failed: ${check.name}`);
    console.log(`ok: ${check.name}`);
  }
  console.log('TLS smoke test passed');
}

main();
