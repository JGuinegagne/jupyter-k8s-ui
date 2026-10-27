import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { assertTlsRuntime, loadKeypair, MIN_BUN_FOR_TLS, resolveTlsFiles } from '../tls';
import { makeKeypair, tlsTestPrereqs } from './tls-helpers';

const { opensslFound } = tlsTestPrereqs();
let dir: string;

beforeAll(() => {
  if (!opensslFound) return;
  dir = mkdtempSync(join(tmpdir(), 'tls-test-'));
  makeKeypair(dir, 'a');
  makeKeypair(dir, 'b');
});

afterAll(() => dir && rmSync(dir, { recursive: true, force: true }));

describe('resolveTlsFiles', () => {
  test('neither path → plain HTTP (off by default)', () => {
    expect(resolveTlsFiles('', '')).toBeUndefined();
  });

  test.each([
    ['cert only', '/c', ''],
    ['key only', '', '/k'],
  ])('%s → throws instead of falling back to HTTP', (_label, cert, key) => {
    expect(() => resolveTlsFiles(cert, key)).toThrow('must be set together');
  });
});

describe.skipIf(!opensslFound)('loadKeypair', () => {
  test('matching pair loads with its expiry', () => {
    const pair = loadKeypair({ certFile: join(dir, 'a.crt'), keyFile: join(dir, 'a.key') });
    expect(pair.notAfter.getTime()).toBeGreaterThan(Date.now());
  });

  test('key from another pair → mismatch', () => {
    expect(() => loadKeypair({ certFile: join(dir, 'a.crt'), keyFile: join(dir, 'b.key') })).toThrow('does not match');
  });

  test('missing file → error names the path', () => {
    const missing = join(dir, 'missing.crt');
    expect(() => loadKeypair({ certFile: missing, keyFile: join(dir, 'a.key') })).toThrow(missing);
  });

  test('cert file that is not PEM → rejected', () => {
    const junk = join(dir, 'junk.crt');
    writeFileSync(junk, 'not a certificate');
    expect(() => loadKeypair({ certFile: junk, keyFile: join(dir, 'a.key') })).toThrow('not a PEM certificate');
  });

  test('key file that is not PEM → rejected', () => {
    const junk = join(dir, 'junk.key');
    writeFileSync(junk, 'not a key');
    expect(() => loadKeypair({ certFile: join(dir, 'a.crt'), keyFile: junk })).toThrow('not an unencrypted PEM private key');
  });
});

describe('assertTlsRuntime', () => {
  // Older Bun accepts the policy options and silently ignores them, which would serve TLS 1.2
  // with SHA-1 signatures.
  test('Bun older than the minimum → throws', () => {
    expect(() => assertTlsRuntime('1.3.11')).toThrow(MIN_BUN_FOR_TLS);
  });

  test('the minimum itself → accepted (inclusive bound)', () => {
    expect(() => assertTlsRuntime(MIN_BUN_FOR_TLS)).not.toThrow();
  });
});
