import { spawnSync } from 'bun';
import { copyFileSync, existsSync, mkdirSync, readlinkSync, renameSync, rmSync, symlinkSync } from 'fs';
import { join } from 'path';
import { MIN_BUN_FOR_TLS } from '../tls';

/** Exit code and stdout of an `openssl` command; null when there is no `openssl` binary. */
function tryOpenssl(args: string[]): { code: number; out: string } | null {
  try {
    const res = spawnSync(['openssl', ...args], { stdout: 'pipe', stderr: 'pipe' });
    return { code: res.exitCode, out: res.stdout.toString() };
  } catch {
    return null;
  }
}

export interface TlsTestPrereqs {
  // Bun enforces TLS_POLICY (TLS refuses to start on older Bun).
  runtimeOk: boolean;
  // An `openssl` binary exists, to generate fixtures.
  opensslFound: boolean;
  // The `openssl` client can offer every group in `groups` (OpenSSL >= 3.5; macOS's LibreSSL
  // has no `list -tls-groups`).
  missingGroups: string[];
}

/**
 * Check the TLS test prerequisites. Locally a missing one skips the dependent tests with a
 * printed reason; under CI it throws, so the TLS tests can never be skipped there.
 */
export function tlsTestPrereqs(groups: string[] = []): TlsTestPrereqs {
  const runtimeOk = Bun.semver.satisfies(Bun.version, `>=${MIN_BUN_FOR_TLS}`);
  const opensslFound = tryOpenssl(['version']) !== null;
  const listed = groups.length ? tryOpenssl(['list', '-tls-groups']) : null;
  const offered = new Set(listed?.code === 0 ? listed.out.trim().split(':') : []);
  const missingGroups = groups.filter((g) => !offered.has(g));

  const why = [
    !runtimeOk && `Bun ${Bun.version} < ${MIN_BUN_FOR_TLS}`,
    !opensslFound && 'no openssl binary',
    opensslFound && missingGroups.length > 0 && `openssl cannot offer ${missingGroups.join(', ')} (need OpenSSL >= 3.5)`,
  ].filter(Boolean);
  if (why.length) {
    if (process.env.CI) throw new Error(`CI must run the TLS tests: ${why.join('; ')}`);
    console.warn(`Skipping TLS tests that need: ${why.join('; ')}`);
  }
  return { runtimeOk, opensslFound, missingGroups };
}

function openssl(args: string[]): void {
  const res = spawnSync(['openssl', ...args], { stderr: 'pipe' });
  if (res.exitCode !== 0) throw new Error(`openssl ${args[0]} failed: ${res.stderr.toString()}`);
}

/**
 * Write `<name>.crt` / `<name>.key` (ECDSA P-256, CN=<name>) into `dir`, the key type the
 * deployment chart's cert-manager Certificate issues. The server never looks at the issuer,
 * so a self-signed fixture exercises the same path as a CA-issued one.
 */
export function makeKeypair(dir: string, name: string): void {
  openssl([
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
    `/CN=${name}`,
    '-keyout',
    join(dir, `${name}.key`),
    '-out',
    join(dir, `${name}.crt`),
  ]);
}

/**
 * Lay out (or update) `dir` the way the kubelet projects a Secret volume: the data lives
 * in a timestamped directory, `..data` symlinks to it, and each key is a symlink through
 * `..data`. An update writes a new directory, atomically renames a fresh symlink over
 * `..data`, then deletes the old directory.
 */
export function projectSecret(dir: string, version: string, files: Record<string, string>): void {
  const dataDir = join(dir, `..${version}`);
  mkdirSync(dataDir);
  for (const [name, src] of Object.entries(files)) {
    copyFileSync(src, join(dataDir, name));
  }
  const tmpLink = join(dir, '..data_tmp');
  symlinkSync(`..${version}`, tmpLink);
  const previous = existsSync(join(dir, '..data')) ? readlinkSync(join(dir, '..data')) : undefined;
  renameSync(tmpLink, join(dir, '..data'));
  for (const name of Object.keys(files)) {
    if (!existsSync(join(dir, name))) symlinkSync(join('..data', name), join(dir, name));
  }
  if (previous) rmSync(join(dir, previous), { recursive: true, force: true });
}
