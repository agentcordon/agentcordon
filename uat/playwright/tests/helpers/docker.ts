import { spawnSync } from 'child_process';
import { UAT } from './env';

export interface Run {
  code: number;
  stdout: string;
  stderr: string;
  /** stdout + stderr, which is what most CLI assertions want. */
  out: string;
}

export function docker(args: string[], opts: { timeout?: number } = {}): Run {
  const r = spawnSync('docker', args, {
    encoding: 'utf8',
    timeout: opts.timeout ?? 120_000,
    maxBuffer: 32 * 1024 * 1024,
  });
  const stdout = r.stdout ?? '';
  const stderr = r.stderr ?? '';
  return { code: r.status ?? -1, stdout, stderr, out: stdout + stderr };
}

/** Run a command inside a container, capturing output. */
export function exec(container: string, args: string[]): Run {
  return docker(['exec', container, ...args]);
}

/**
 * Run `agentcordon ...` inside the CLI container, in the enrolled workspace
 * directory. This is the CLI half of every scenario.
 */
export function cli(args: string[]): Run {
  return docker(['exec', '-w', '/home/uat/workspace', UAT.cli, 'agentcordon', ...args]);
}

/**
 * Run `agentcordon ...` inside the CLI container from an arbitrary workspace
 * directory — used by the second workspace S16 enrolls.
 */
export function cliIn(workdir: string, args: string[]): Run {
  return docker(['exec', '-w', workdir, UAT.cli, 'agentcordon', ...args]);
}

/** Run a shell command inside a container. */
export function sh(container: string, command: string): Run {
  return docker(['exec', container, 'sh', '-c', command]);
}

/** Start a detached command in the CLI container (used for the blocking `register`). */
export function cliDetached(shellCommand: string): Run {
  return docker(['exec', '-d', '-w', '/home/uat/workspace', UAT.cli, 'sh', '-c', shellCommand]);
}

export function readFileInContainer(container: string, file: string): string {
  return docker(['exec', container, 'cat', file]).stdout;
}

export function logs(container: string): string {
  return docker(['logs', container]).out;
}

export function containerExists(name: string): boolean {
  return docker(['inspect', '--format', '{{.Name}}', name]).code === 0;
}

export function rm(name: string): void {
  docker(['rm', '-f', name]);
}

export async function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Poll until `fn()` returns a truthy value, or throw after `timeoutMs`. */
export async function waitFor<T>(
  what: string,
  fn: () => T | Promise<T>,
  timeoutMs = 60_000,
  intervalMs = 1000,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let last: unknown;
  while (Date.now() < deadline) {
    try {
      const v = await fn();
      if (v) return v;
      last = v;
    } catch (e) {
      last = e;
    }
    await sleep(intervalMs);
  }
  throw new Error(`timed out after ${timeoutMs}ms waiting for ${what} (last: ${String(last)})`);
}

/** Wait until the server answers /health on the published host port. */
export async function waitForServerHealthy(timeoutMs = 120_000): Promise<void> {
  await waitFor(
    'server /health',
    async () => {
      try {
        const r = await fetch(`${UAT.serverUrl}/health`);
        return r.ok;
      } catch {
        return false;
      }
    },
    timeoutMs,
  );
}
