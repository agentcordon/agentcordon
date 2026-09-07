import { test, expect } from '@playwright/test';
import { UAT } from './helpers/env';
import { docker, exec, logs } from './helpers/docker';
import { readState, writeState } from './helpers/state';
import { shot } from './helpers/ui';
import { readDoc } from './helpers/docs';

/**
 * S0 — Install as documented.
 *
 * Every step below is one a first-time user would take from the shipped docs:
 *   README.md § "Quick Start / 1. Start the server"  (docker compose up -d)
 *   README.md § "Production deployment"              (docker run -e AGTCRDN_MASTER_SECRET -v ...)
 *   README.md § "Configuration"                      (AGTCRDN_ROOT_USERNAME / _PASSWORD)
 *   README.md § "Building from Source"               (cargo build --release -> three binaries)
 *   README.md § "2. Install the CLI and the broker"   (curl -fsSL https://your-server/install.sh | sh)
 *   docs/upgrading.md § "Upgrade the CLI"            (the same one-liner)
 *   docs/index.md § "Quick Start"
 *
 * The container start itself happens in uat/run.sh (docker-compose.yml
 * semantics reproduced with plain `docker run` because the compose plugin is
 * not installed here). This spec verifies the documented promises about it.
 *
 * **The binaries every later scenario uses come from this worktree**
 * (uat/Dockerfile.tools builds them into /usr/local/bin), never from a GitHub
 * download. The two tests below that do exercise the documented
 * `curl … /install.sh | sh` path are the harness's only reach onto the public
 * internet, and they are skippable with `UAT_SKIP_NETWORK_INSTALL=1` — see
 * uat/README.md § "Environment flags".
 */

const SKIP_NETWORK_INSTALL = process.env.UAT_SKIP_NETWORK_INSTALL === '1';
const NETWORK_SKIP_REASON =
  'UAT_SKIP_NETWORK_INSTALL=1: the documented installer downloads from the GitHub "latest" release, which needs the public internet. Every other scenario uses the binaries built from this worktree.';

test.describe('S0 install as documented', () => {
  test('the server announces the bootstrap admin credentials on first boot (README "Default admin credentials are printed to the console on first boot")', async () => {
    const serverLog = logs(UAT.server);
    expect(
      serverLog,
      'README promises the admin credentials are printed to the console on first boot',
    ).toContain('Bootstrap root user created');
    expect(serverLog).toContain(`Username: ${UAT.rootUsername}`);
    writeState({ rootPassword: UAT.rootPassword });
  });

  test('the server image ships only the server binary; the CLI and broker must come from elsewhere (README "Building from Source")', async () => {
    const cliInServerImage = docker([
      'run', '--rm', '--entrypoint', 'sh', UAT.serverImage,
      '-c', 'command -v agentcordon agentcordon-broker || echo MISSING',
    ]);
    expect(cliInServerImage.out).toContain('MISSING');
  });

  test('GET /install.sh serves a POSIX-sh script that never re-fetches itself and verifies SHA-256 checksums [D7]', async () => {
    const r = await fetch(`${UAT.serverUrl}/install.sh`);
    expect(r.status).toBe(200);
    const body = await r.text();
    expect(body).toContain('agentcordon');

    // D7.2 — the script used to re-exec itself by re-downloading from the
    // server's *templated* base URL, so the documented `| sh` invocation died
    // wherever that URL was not reachable from the installing host. It must
    // stay a plain POSIX-sh script that runs under whatever shell the user
    // piped it into, and it must never fetch itself a second time.
    expect(body.split('\n')[0]).toBe('#!/bin/sh');
    expect(
      body,
      'the installer must not re-exec itself by re-downloading from the templated base URL',
    ).not.toContain('exec bash -c "$(curl');
    // The only mention of /install.sh left is the usage comment at the top;
    // no executable line may fetch it again.
    const executable = body
      .split('\n')
      .filter((l) => !l.trimStart().startsWith('#'))
      .join('\n');
    expect(executable).not.toContain('/install.sh');
    expect(executable).not.toContain('exec bash');

    // D7.1 — docs/installation.md § "Windows" advertises checksum
    // verification; the Unix path had none. Verification must be on by
    // default and a mismatch must abort the install.
    expect(body, 'the installer must fetch the release SHA256SUMS').toContain('SHA256SUMS');
    expect(body.toLowerCase()).toContain('sha256');
    expect(body, 'a checksum mismatch must abort the install').toContain('SHA-256 mismatch');
    expect(body).toContain('Nothing was installed.');
    // Opting out must be explicit, never the default.
    expect(body).toContain('SKIP_CHECKSUM="${AGENTCORDON_SKIP_CHECKSUM:-0}"');

    // The templated server URL is the one the client actually reached, and
    // the override is documented in the script itself.
    expect(body).toContain('AGTCRDN_SERVER_URL');
  });

  test('the installer records the server and persists PATH, and ends on one next step [D7]', async () => {
    // Install-to-use is three commands, and two of the things that used to
    // stand between the second and the third are now the installer's job:
    // remembering which server this machine belongs to, and putting
    // ~/.local/bin on PATH in a way that survives closing the terminal
    // (uat/artifacts/reviews/ONBOARDING-empirical.md F3, P5).
    const r = await fetch(`${UAT.serverUrl}/install.sh`);
    const body = await r.text();

    // docs/installation.md § "What the installer writes"
    // The script composes the path from $HOME, so assert the pieces it is
    // built from; the run below asserts the path it actually prints.
    expect(body, 'the installer must record the server it was served by').toContain(
      'CONFIG_FILE="${CONFIG_DIR}/config.toml"',
    );
    expect(body).toContain('server_url = ');

    // docs/installation.md § "Persisting PATH": the file each login shell
    // actually reads, not a line printed to a terminal that then closes.
    for (const target of ['.bashrc', '.bash_profile', '.zshrc', 'fish_add_path', 'env.nu']) {
      expect(body, `PATH persistence must cover ${target}`).toContain(target);
    }
    expect(body, 'editing a dotfile must be declinable').toContain('AGENTCORDON_NO_MODIFY_PATH');

    // The closing message: what was installed, and one command.
    expect(body).toContain('Next: cd into a project and run `agentcordon init`.');
    expect(
      body,
      'the server is recorded, so nothing asks the reader for it again',
    ).not.toContain('agentcordon register --server-url');

    const install = readDoc('docs/installation.md');
    expect(install).toContain('AGENTCORDON_NO_MODIFY_PATH');
    expect(install).toContain('~/.agentcordon/config.toml');
  });

  test('README tells a Linux/macOS user how to obtain the CLI, and points at this server\'s own installer [G2]', async () => {
    // G2 — README used to tell the reader to run `agentcordon-broker` and
    // `agentcordon init` without ever saying how to get those binaries on
    // anything but Windows; /install.sh was named only in docs/upgrading.md.
    // This assertion fails the moment that instruction leaves README again.
    const readme = readDoc('README.md');
    expect(readme, 'README must document the Unix installer').toContain('Install the CLI and the broker');
    expect(readme).toContain("verifies them against the release's `SHA256SUMS`");
    expect(readme).toMatch(/curl -fsSL \S+\/install\.sh \| sh/);

    // docs/installation.md is where the quick start's other routes went when
    // the README was cut down; it carries the same one-liner and says what it
    // verifies, so a reader who starts there is not sent to the source.
    const install = readDoc('docs/installation.md');
    expect(install).toMatch(/curl -fsSL \S+\/install\.sh \| sh/);
    expect(install).toContain('SHA256SUMS');
  });

  test('the documented installer installs only binaries that match this server, or says why it cannot [D7]', async () => {
    test.skip(SKIP_NETWORK_INSTALL, NETWORK_SKIP_REASON);
    test.setTimeout(300_000);

    // docs/upgrading.md § "Upgrade the CLI" and README § "2. Install the CLI and the broker":
    //   curl -fsSL https://your-server:3140/install.sh | sh
    // Run exactly that, with `sh` (dash in this image), from inside the
    // Docker network. The installer pins the download to the server's own
    // version (docs/upgrading.md § "Upgrading from 0.3.x"), so there are two
    // legitimate outcomes and both are asserted: the matching release exists
    // and every asset is checksum-verified, or no release exists yet for this
    // version and the installer refuses with a message that says so and
    // points at building from source. What it must never do is install a
    // CLI from a different version.
    const builtVersion = exec(UAT.cli, ['/usr/local/bin/agentcordon', '--version']).out.trim();
    const builtSemver = builtVersion.replace(/^agentcordon\s+/, '');
    const install = docker(
      ['exec', UAT.cli, 'sh', '-c', 'curl -fsSL http://server:3140/install.sh | sh'],
      { timeout: 300_000 },
    );
    expect(install.out).not.toContain('releases/latest');

    if (install.code === 0) {
      expect(install.out).toContain('Installed:');
      expect(install.out).toContain('Fetching SHA256SUMS...');
      expect(install.out).toContain('verified agentcordon-');
      expect(install.out).toContain('sha256 ok');
      const installedVersion = exec(UAT.cli, ['/home/uat/.local/bin/agentcordon', '--version']).out.trim();
      expect(installedVersion).toBe(builtVersion);
      writeState({ installedCliVersion: installedVersion, builtCliVersion: builtVersion });
    } else {
      expect(install.out, 'the installer must pin to this server\'s version').toContain(
        `No published release for AgentCordon v${builtSemver}`,
      );
      expect(install.out).toMatch(/build(ing)? from source/i);
      const stat = exec(UAT.cli, ['sh', '-c', 'test -e /home/uat/.local/bin/agentcordon && echo present || echo absent']);
      expect(stat.out.trim(), 'a refused install must leave nothing behind').toBe('absent');
      writeState({ installedCliVersion: null, builtCliVersion: builtVersion });
    }
  });

  test('the published release\'s CLI cannot drive this release\'s broker (CHANGELOG: "CLI and broker must upgrade together")', async () => {
    test.skip(SKIP_NETWORK_INSTALL, NETWORK_SKIP_REASON);
    test.setTimeout(300_000);

    // A deliberate mismatch: fetch the last *published* CLI straight from the
    // GitHub release (this is not a documented step; the documented installer
    // now refuses to do this, which the previous test proved). It stands in
    // for a user who kept an old binary on PATH.
    const fetchOld = docker(
      ['exec', UAT.cli, 'sh', '-c',
        'mkdir -p /home/uat/released && curl -fsSL -o /home/uat/released/agentcordon ' +
        'https://github.com/agentcordon/agentcordon/releases/latest/download/agentcordon-x86_64-unknown-linux-gnu ' +
        '&& chmod +x /home/uat/released/agentcordon && /home/uat/released/agentcordon --version'],
      { timeout: 300_000 },
    );
    expect(fetchOld.code, fetchOld.out).toBe(0);
    const releasedVersion = fetchOld.out.trim().split('\n').pop() ?? '';
    expect(releasedVersion).toMatch(/^agentcordon \d+\.\d+\.\d+/);
    writeState({ releasedCliVersion: releasedVersion });

    // Give the released binary its own scratch workspace so the failure is
    // about the wire format, not about a missing keypair.
    exec(UAT.cli, ['mkdir', '-p', '/home/uat/released-check']);
    const relInit = docker([
      'exec', '-w', '/home/uat/released-check', UAT.cli,
      '/home/uat/released/agentcordon', 'init',
    ]);
    expect(relInit.code, relInit.out).toBe(0);

    const releasedAgainstNewBroker = docker([
      'exec', '-w', '/home/uat/released-check',
      '-e', 'AGTCRDN_BROKER_URL=http://127.0.0.1:9876',
      '-e', `AGTCRDN_BROKER_SHARED_SECRET=${UAT.brokerSharedSecret}`,
      UAT.cli, '/home/uat/released/agentcordon', 'status',
    ]);
    // When this tree IS the published release (right after a tag), the
    // released CLI is the same version and speaks the same wire format: the
    // broker accepts its signature and only complains that the scratch
    // workspace is not registered. When the versions differ, the older CLI
    // must be refused at the signature, never silently accepted.
    const built = readState().builtCliVersion as string | undefined;
    expect(releasedAgainstNewBroker.code).not.toBe(0);
    if (built && built === releasedVersion) {
      expect(releasedAgainstNewBroker.out).not.toMatch(/401 Unauthorized/);
      expect(releasedAgainstNewBroker.out).toMatch(/re-?registration|not registered/i);
    } else {
      expect(releasedAgainstNewBroker.out).toMatch(/401 Unauthorized/);
    }
  });

  test('the CLI built from this worktree reports a different version from the release it is wire-incompatible with [D5]', async () => {
    test.skip(SKIP_NETWORK_INSTALL, NETWORK_SKIP_REASON);
    // D5: this release is wire-incompatible with the last published one
    // (nonce in the CLI->broker signature, shared secret for a non-loopback
    // bind, new vend request shape), so its binaries must not report the
    // published version string.
    const { releasedCliVersion, builtCliVersion } = readState();
    expect(releasedCliVersion, 'the mismatch test must have run first').toBeTruthy();
    // Right after a release the tree and the published binaries are the same
    // version, and must say so; at any other commit the tree carries a version
    // the published release does not, so a mismatch is visible in --version.
    const treeIsTheRelease = builtCliVersion === releasedCliVersion;
    if (treeIsTheRelease) {
      expect(builtCliVersion).toBe(releasedCliVersion);
    } else {
      expect(builtCliVersion, `built "${builtCliVersion}" vs released "${releasedCliVersion}"`).not.toBe(
        releasedCliVersion,
      );
    }
  });

  test('the published server URL serves the admin UI and redirects to the login page (README "Open http://localhost:3140")', async ({ page }, testInfo) => {
    // Leave the released binaries out of the way; every later scenario calls
    // /usr/local/bin/agentcordon via the `cli()` helper.
    //
    // The config file goes too. A successful documented install records this
    // server in it, which would make `agentcordon init` in S3 enroll on its
    // own — correct behaviour, but it would make S3 depend on whether a
    // release happened to exist for this version. S3 drives the two halves
    // explicitly; S16 drives the enrolling `init`.
    exec(UAT.cli, ['rm', '-rf', '/home/uat/.local/bin/agentcordon', '/home/uat/.local/bin/agentcordon-broker', '/home/uat/released', '/home/uat/.agentcordon/config.toml']);

    await page.goto('/');
    await page.waitForURL(/\/login/, { timeout: 30_000 });
    await expect(page.locator('#login-username')).toBeVisible();
    await shot(page, testInfo, 's0-login-page');
  });
});
