# Gitea Actions setup

What CI does for this repo, and how to stand the runner back up.

The workflow (`.gitea/workflows/docker-images.yml`) fires on `v*` tag
pushes and on manual dispatch, in two stages:

- **stage 0** — `publish` (test, build, govulncheck, then push the
  server/agent/relay images to the Gitea registry) and
  `windows-binaries` (cross-compile `agent.exe` and the Fyne GUI
  `agent-gui.exe`, upload as an artifact).
- **stage 1** — `release`, tag pushes only: runs `deploy/build.sh` and
  attaches every binary plus `sha256sums.txt` to a Gitea release.

`release` is gated with `needs: publish`, so a tag whose test suite
fails never ships binaries.

## 1. Enable Actions

Actions is off by default on a fresh Gitea. Check both levels:

- **Instance:** `app.ini` needs

  ```ini
  [actions]
  ENABLED = true
  ```

  then restart Gitea.
- **Repo:** Settings → Advanced Settings → tick **Actions**.

## 2. Register the runner

The runner is what was actually lost — the workflow file survived. Run
this on a machine that can reach `https://gitea.mynetbird.uk` and has
Docker:

1. Gitea → repo **Settings → Actions → Runners → Create new runner**,
   copy the registration token. (Site Administration → Actions →
   Runners registers one shared by every repo instead.)
2. Drop the token in place:

   ```sh
   cp deploy/runner.env.example deploy/runner.env
   $EDITOR deploy/runner.env     # paste the token
   ```

3. Start it:

   ```sh
   docker compose -f deploy/docker-compose.runner.yml up -d
   docker compose -f deploy/docker-compose.runner.yml logs -f
   ```

Look for `runner registered successfully`, then confirm the runner shows
**Idle** in the Gitea runners list. The token is single-use: it is
swapped for permanent credentials kept in the `runner-data` volume, so
re-running `up -d` later needs no token.

> The runner mounts `/var/run/docker.sock` so `docker/build-push-action`
> can build images. That is root-equivalent access to the host — only
> run it somewhere you trust with this repo's secrets.

### Naming things correctly

v4 renamed the **binary** from `act_runner` to `gitea-runner`, and the
old `dl.gitea.com/act_runner/...` download paths now redirect to a 404.
The **container image** is still published under the old name, so the
compose file pins `docker.gitea.com/act_runner:4.0.0` — which ships the
`gitea-runner` binary inside. Most guides online get this backwards.

Installing the binary directly instead of using Docker:

```sh
curl -fsSL -o gitea-runner \
  https://dl.gitea.com/gitea-runner/4.0.0/gitea-runner-4.0.0-linux-amd64
chmod +x gitea-runner
```

### Labels

Every job says `runs-on: ubuntu-latest`, so the runner must offer that
label or jobs queue forever with no error:

```
ubuntu-latest:docker://docker.gitea.com/runner-images:ubuntu-latest
```

It is set in both `deploy/runner-config.yml` and the compose
environment. If you registered interactively and accepted the defaults,
re-check it in the Gitea runner list.

## 3. Secrets

Repo → Settings → Actions → Secrets:

| Secret | Needed for | Notes |
| --- | --- | --- |
| `REGISTRY_TOKEN` | pushing images | User → Settings → Applications → generate a token with **write:package**. Username comes from `github.actor` automatically. |
| `RELEASE_TOKEN` | creating releases | Optional. The workflow falls back to the built-in `GITHUB_TOKEN`; add a token with **repo** scope only if release creation 403s. |

## 4. Verify

Manual dispatch first — Actions tab → `docker-images` → **Run workflow**.
That exercises `publish` and `windows-binaries` without cutting a
release. Then a real tag:

```sh
git push origin main v0.9.0
```

Local dry run of the plan, without a server:

```sh
gitea-runner exec --list -W .gitea/workflows/docker-images.yml
```

## Troubleshooting

- **Jobs stay queued / "No runner available"** — label mismatch. The
  runner must advertise `ubuntu-latest`.
- **`Cannot connect to the Docker daemon`** in a build step —
  `privileged: true` missing from `runner-config.yml`, or the socket
  mount is absent.
- **`unauthorized` on image push** — `REGISTRY_TOKEN` lacks
  `write:package`, or `REGISTRY` in the workflow does not match the
  registry host.
- **Fyne/OpenGL step looks hung** — normal cold: the cgo compile of the
  generated GL bindings takes minutes and ~1 GB of gcc RSS. Keep
  `cache.enabled: true` so reruns are cheap, and `capacity: 1` so two
  never run at once.
- **`GHESNotSupportedError` on artifact upload** — the official
  `actions/upload-artifact@v4` refuses to run anywhere but github.com,
  bailing on a hostname check before it ever uses the
  `ACTIONS_RESULTS_URL` the runner exports. Use the community fork
  `christopherhx/gitea-upload-artifact@v4` (and
  `gitea-download-artifact@v4` if you ever need the other half), which
  stubs `isGhes()` to `false` so the v4 protocol the runner does speak
  is used as intended. `actions/upload-artifact@v3` also works if you
  would rather not depend on a fork. Either way tag builds do not rely
  on artifacts: the `release` job attaches the same binaries to the
  Gitea release.
- **`open config file "/config.yml": permission denied`**, looping on
  "Waiting to retry" — SELinux. The bind mounts need the `:z` suffix
  (already set in the compose file); hosts like openSUSE, Fedora and
  RHEL label files `user_home_t`, which containers cannot read.
- **`runner registration token not found`** — the token was already
  used, or it was regenerated in the UI after you copied it. Grab a
  fresh one; `docker compose ... down -v` first if a half-registered
  state is in the volume.
