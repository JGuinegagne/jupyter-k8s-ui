import { serve } from 'bun';
import { log } from './logger';
import { assertTlsRuntime, loadKeypair, sameKeypair, TLS_POLICY, type TlsFiles, type TlsKeypair } from './tls';

type BunServer = ReturnType<typeof serve>;

export interface ListenerOptions {
  // Bun's default (all interfaces) when undefined.
  hostname?: string;
  port: number;
  fetch: (req: Request) => Response | Promise<Response>;
  // Plain HTTP when undefined.
  tls?: TlsFiles;
  // How often to re-read the keypair; 0 disables the poll.
  tlsReloadIntervalMs: number;
}

export interface Listener {
  readonly port: number;
  readonly protocol: 'http' | 'https';
  stop(): void;
}

interface Stoppable {
  stop(): unknown;
}

/** The keypair being served and the server serving it, replaced together on a rotation. */
export interface Served<S extends Stoppable> {
  keypair: TlsKeypair;
  server: S;
}

export interface ReloadTlsDeps<S extends Stoppable> {
  files: TlsFiles;
  load: (files: TlsFiles) => TlsKeypair;
  // Start a server for the pair on the port already in use (SO_REUSEPORT).
  listen: (pair: TlsKeypair) => S;
  get: () => Served<S>;
  set: (next: Served<S>) => void;
}

/**
 * Build the reload step run on each poll: re-read the keypair and, if it changed, start a
 * server with it, then stop the previous one gracefully. Returns true when it swapped. Any
 * failure keeps the current pair and server, and the next poll retries.
 */
export const makeReloadTls =
  <S extends Stoppable>({ files, load, listen, get, set }: ReloadTlsDeps<S>): (() => boolean) =>
  () => {
    const current = get();

    let next: TlsKeypair;
    try {
      next = load(files);
    } catch (err) {
      // Mid-rotation (key and cert from different writes) or a transient read error.
      log('warn', `TLS reload skipped, still serving the current certificate: ${errorMessage(err)}`);
      return false;
    }
    if (sameKeypair(next, current.keypair)) return false;

    let server: S;
    try {
      server = listen(next);
    } catch (err) {
      log('error', `TLS reload failed to start a listener with the new certificate: ${errorMessage(err)}`);
      return false;
    }
    set({ keypair: next, server });
    void current.server.stop();
    logCertificate('Reloaded', files, next);
    return true;
  };

/**
 * Start the HTTP(S) listener. With TLS, the keypair is validated up front (throws on an
 * unreadable or mismatched pair) and then re-read on a poll, so a rotated certificate is
 * served without restarting the process.
 *
 * The files are re-read by path rather than watched: Kubernetes updates a mounted Secret by
 * swapping the `..data` symlink, which file watches on the old target don't follow.
 *
 * Bun.serve cannot change the certificate of a running server (`server.reload()` swaps
 * handlers only), so a rotation starts a second server on the same port with SO_REUSEPORT,
 * then stops the old one gracefully: it stops accepting, and its open connections finish
 * on the certificate they negotiated. The port is never unbound.
 */
export function startListener(opts: ListenerOptions): Listener {
  const { tls: files } = opts;
  if (files) assertTlsRuntime();
  let keypair: TlsKeypair | undefined = files ? loadKeypair(files) : undefined;

  const listen = (port: number, pair: TlsKeypair | undefined): BunServer =>
    serve({
      hostname: opts.hostname,
      port,
      fetch: opts.fetch,
      idleTimeout: 0,
      ...(pair && {
        reusePort: true,
        tls: { cert: pair.cert, key: pair.key, ...TLS_POLICY },
      }),
    });

  let server = listen(opts.port, keypair);
  // Pin the bound port so the replacement server binds the same one (matters for port 0).
  const port = server.port ?? opts.port;
  if (keypair) logCertificate('Serving', files!, keypair);

  const reloadTls =
    files && keypair
      ? makeReloadTls({
          files,
          load: loadKeypair,
          listen: (pair) => listen(port, pair),
          get: () => ({ keypair: keypair!, server }),
          set: (next) => {
            keypair = next.keypair;
            server = next.server;
          },
        })
      : undefined;

  const timer = reloadTls && opts.tlsReloadIntervalMs > 0 ? setInterval(reloadTls, opts.tlsReloadIntervalMs) : undefined;

  return {
    port,
    protocol: files ? 'https' : 'http',
    stop() {
      clearInterval(timer);
      void server.stop();
    },
  };
}

function logCertificate(action: string, files: TlsFiles, pair: TlsKeypair): void {
  const expired = pair.notAfter.getTime() <= Date.now();
  log(expired ? 'warn' : 'info', `${action} TLS certificate ${files.certFile} (${expired ? 'expired' : 'expires'} ${pair.notAfter.toISOString()})`);
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
