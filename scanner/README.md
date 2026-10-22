# PHP 2Shell — Version Scanner

## Overview

Automates testing every verified PHP-FPM version against the three RCE attack
chains (A, C, E).  For each version it:

1. Pulls the `php:<tag>-fpm` image.
2. Writes lab files (webroot + configs) inline — no dependency on `setup.sh`.
3. Boots the lab (FPM + nginx) via a single-use Docker network (`php2scan_net`).
4. Runs Chains A, C and E non-interactively, capturing **vulnerable / patched**
   for each chain.
5. Tears down the lab, removes the image and network to free disk space.

Results are written to `scanner/results.json`.

## Architecture

```
scanner/
├── versions.json        # ordered list of verified Docker tags (24 versions)
├── test_runner.py       # orchestrator: pull → start → test → teardown → results
├── to_markdown.py       # convert results.json → human-readable markdown
├── results.json         # generated output (structured)
├── scan-report.md       # generated output (human-readable)
└── README.md            # this file
```

## Usage

### Run the full scan (24 versions)

```bash
cd scanner && python3 test_runner.py --results results.json
```

### Scan a subset of versions

```bash
python3 test_runner.py --versions "8.2.35-fpm,8.5.12-fpm" --results /tmp/test.json
```

### Convert to markdown

```bash
python3 to_markdown.py results.json --out scan-report.md
python3 to_markdown.py results.json   # prints to stdout
```

### Flags

| Flag | Description |
|------|-------------|
| `--versions` | Comma-separated version tags (overrides versions.json) |
| `--results`, `-r` | Output JSON path (default: `results.json`) |
| `--quiet`, `-q` | Suppress verbose stderr output |

## How it works

For each version tag (e.g. `8.2.35-fpm`):

1. **Pull** — `docker pull php:<tag>` + verify with `php -v`
2. **Write** — generate webroot files (index, vuln, app, api, gadget) + php.ini + nginx.conf
3. **Compose** — write a temporary `docker-compose.yml` targeting the specific version, using a fixed network name `php2scan_net`
4. **Wait** — poll `http://127.0.0.1:18080/index.php` up to 90s
5. **Test** — run Chain A (with `--race` for reliability), Chain C, Chain E
6. **Tear down** — `docker compose down` + `docker network rm` + `docker image rm`

## Results

See `results.json` for raw data or `scan-report.md` for the human-readable report.

### Quick summary

| Metric | Value |
|--------|-------|
| Total versions tested | 24 |
| Vulnerable | 23 |
| Patched / Not exploitable | 1 |
| Pull failures | 0 |
| Target unreachable | 0 |

### Key findings

| Range | Chains A | Chains C | Chains E |
|-------|----------|----------|----------|
| 8.0 – 8.5 | ✅ All vulnerable | ✅ All vulnerable | ✅ All vulnerable |
| 7.0 – 7.4 | ✅ All vulnerable | ✅ All vulnerable | ❌ Not exploitable |
| 5.6.40 | ❌ Not exploitable | ❌ Not exploitable | ❌ Not exploitable |

### Versions excluded (unavailable on modern Docker)

These tags were removed from `versions.json` because Docker containerd v2.1+
no longer supports their manifest format:

- `5.4.0-fpm`, `5.4.45-fpm` — manifest v1 (not supported)
- `5.5.0-fpm`, `5.5.38-fpm` — manifest issues / corrupted layers
- `5.6.0-fpm` — tag not found on Docker Hub
- `7.0.0-fpm` — manifest v1 (not supported)

## Exclusions

The following Docker Hub tags were excluded from testing due to incompatibility
with modern Docker (containerd v2.1+):

- **5.4.x** — manifest v1 only, no v2 image
- **5.5.x** — corrupted layers on pull
- **5.6.0** — tag does not exist (only `5.6.40` exists)
- **7.0.0** — manifest v1 only

## Cleanup

Images, containers and the `php2scan_net` network are automatically removed
after each version test. On Ctrl+C, partial results are saved.