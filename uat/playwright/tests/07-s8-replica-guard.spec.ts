import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';
import { ARTIFACTS, UAT } from './helpers/env';
import { docker, logs, rm } from './helpers/docker';

/**
 * S8 — Replica guard.
 *
 * Documented behaviour: docs/master-key.md § "Replica Guard" — "A second
 * server against the same database fails to start with a message naming the
 * lock file and the escape hatch"; .env.example AGTCRDN_REPLICA_MODE.
 *
 * A second container is started against the same /data volume, exactly the
 * mistake an operator makes when they `docker run` a new server without
 * stopping the old one.
 */
test.describe('S8 replica guard', () => {
  test.afterAll(() => rm(UAT.server2));

  test('a second server on the same data volume exits non-zero and names the lock file', async () => {
    rm(UAT.server2);
    const r = docker(
      [
        'run', '--name', UAT.server2,
        '--network', UAT.network,
        '-v', `${UAT.volume}:/data`,
        '-e', `AGTCRDN_ROOT_USERNAME=${UAT.rootUsername}`,
        '-e', `AGTCRDN_ROOT_PASSWORD=${UAT.rootPassword}`,
        '-e', `AGTCRDN_MASTER_SECRET=${UAT.masterSecret}`,
        UAT.serverImage,
      ],
      { timeout: 180_000 },
    );

    expect(r.code, 'the second server must not start').not.toBe(0);

    const containerLog = logs(UAT.server2);
    // Keep the evidence: run.sh collects logs after the container is gone.
    fs.mkdirSync(ARTIFACTS, { recursive: true });
    fs.writeFileSync(path.join(ARTIFACTS, `${UAT.server2}.log`), containerLog);

    expect(containerLog).toContain('/data/agent-cordon.db.lock');
    expect(containerLog).toMatch(/already running against this database/);
    expect(containerLog).toContain('AGTCRDN_REPLICA_MODE=unsafe-shared');
  });

  test('the first server is untouched and still serving', async () => {
    const r = await fetch(`${UAT.serverUrl}/health`);
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ status: 'ok' });
  });
});
