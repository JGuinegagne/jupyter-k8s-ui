import { spawnSync } from 'bun';
import { copyFileSync, existsSync, mkdirSync, readlinkSync, renameSync, rmSync, symlinkSync } from 'fs';
import { join } from 'path';

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
