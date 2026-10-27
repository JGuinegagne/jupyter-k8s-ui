import { readFileSync } from 'fs';
import { createPrivateKey, X509Certificate } from 'crypto';

export interface TlsFiles {
  certFile: string;
  keyFile: string;
}

export interface TlsKeypair {
  cert: string;
  key: string;
  notAfter: Date;
}

/**
 * The one TLS configuration the server offers.
 *
 * - TLS 1.3 only. Under TLS 1.3 the cipher suites are fixed to three AEAD suites
 *   (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256), and no
 *   SHA-1 or SHA-224 handshake signature exists. TLS 1.2 is left out because Bun has no way
 *   to stop it signing with SHA-1 there.
 * - Key exchange pinned to X25519MLKEM768 (hybrid post-quantum), X25519, P-256, P-384 and
 *   P-521. BoringSSL does not implement SecP256r1MLKEM768 or SecP384r1MLKEM1024.
 *
 * Not narrowable further: Bun cannot drop ChaCha20 or X25519 from TLS 1.3.
 *
 * minVersion and ecdhCurve are not in Bun's TLSOptions type, and Bun before 1.4.4 ignores
 * them without an error, hence MIN_BUN_FOR_TLS.
 */
export const TLS_POLICY = {
  minVersion: 0x0304, // TLS 1.3
  ecdhCurve: 'X25519MLKEM768:X25519:P-256:P-384:P-521',
} as const;

export const MIN_BUN_FOR_TLS = '1.4.4';

/** Refuse to serve TLS on a Bun that would silently ignore TLS_POLICY. */
export function assertTlsRuntime(bunVersion: string = Bun.version): void {
  if (!Bun.semver.satisfies(bunVersion, `>=${MIN_BUN_FOR_TLS}`)) {
    throw new Error(`TLS requires Bun >= ${MIN_BUN_FOR_TLS} (running ${bunVersion}): older versions ignore the TLS policy settings`);
  }
}

/**
 * TLS is on when a cert or key path is configured; setting only one of them is a
 * misconfiguration, never a silent fallback to plain HTTP.
 */
export function resolveTlsFiles(certFile: string, keyFile: string): TlsFiles | undefined {
  if (!certFile && !keyFile) return undefined;
  if (!certFile || !keyFile) {
    throw new Error('TLS_CERT_FILE and TLS_KEY_FILE must be set together');
  }
  return { certFile, keyFile };
}

function readPem(path: string, what: string): string {
  try {
    return readFileSync(path, 'utf8');
  } catch (err) {
    throw new Error(`Cannot read TLS ${what} file ${path}: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * Read and validate the keypair. Throws when a file is unreadable or not PEM, or when the
 * key does not belong to the (leaf) certificate. The cert file may carry the chain after
 * the leaf, as cert-manager's `tls.crt` does.
 */
export function loadKeypair(files: TlsFiles): TlsKeypair {
  const cert = readPem(files.certFile, 'certificate');
  const key = readPem(files.keyFile, 'key');

  let x509: X509Certificate;
  try {
    x509 = new X509Certificate(cert);
  } catch {
    throw new Error(`TLS certificate file ${files.certFile} is not a PEM certificate`);
  }
  let privateKey;
  try {
    privateKey = createPrivateKey(key);
  } catch {
    throw new Error(`TLS key file ${files.keyFile} is not an unencrypted PEM private key`);
  }
  if (!x509.checkPrivateKey(privateKey)) {
    throw new Error(`TLS key ${files.keyFile} does not match certificate ${files.certFile}`);
  }

  return { cert, key, notAfter: x509.validToDate };
}

export function sameKeypair(a: TlsKeypair, b: TlsKeypair): boolean {
  return a.cert === b.cert && a.key === b.key;
}
