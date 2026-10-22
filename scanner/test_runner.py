#!/usr/bin/env python3
"""
PHP 2Shell — Version Scanner (clean rebuild)
============================================
Tests every PHP-FPM version against Chains A, C, E.

For each version:
  1. Pull the image
  2. Start lab (FPM + nginx)
  3. Run Chains A, C, E
  4. Tear down + remove image

Usage:
  python3 test_runner.py [--versions TAG,TAG,...] [--results results.json] [--quiet]
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent  # repo root


# ------------------------------------------------------------------ constants
CHAIN_SCRIPTS = {
    "A": "exploit_chain_a.py",
    "C": "exploit_chain_c.py",
    "E": "exploit_chain_e.py",
}

# Chain A needs race args for reliability
CHAIN_A_ARGS = "--race --race-seconds 8 --race-padding 131072 --race-delay 0.02"


# ------------------------------------------------------------------ helpers
def log(msg, quiet=False):
    if quiet:
        return
    print(msg, file=sys.stderr)


def run(cmd, **kwargs):
    """Run a subprocess; return (ok, stdout_or_None)."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
        return res.returncode == 0, (res.stdout or ""), (res.stderr or "")
    except Exception as exc:
        return False, "", str(exc)


def pull_image(tag):
    """Pull the PHP image. Returns (ok, error)."""
    ok, out, err = run(
        ["docker", "pull", f"php:{tag}"],
        timeout=120,
    )
    if not ok:
        return False, err.strip()
    # Also verify it can run
    ok2, out2, err2 = run(
        ["docker", "run", "--rm", f"php:{tag}", "php", "-v"],
        timeout=30,
    )
    if not ok2:
        return False, err2.strip()
    return True, ""


def write_compose(path, version_tag):
    """Write a docker-compose.yml for a specific PHP version."""
    content = f"""\
services:
  php:
    image: php:{version_tag}
    container_name: php2shell-lab
    ports: ["9000:9000"]
    volumes:
      - ./webroot:/var/www/html
      - ./php.ini:/usr/local/etc/php/php.ini
      - ./php-fpm-pool.conf:/usr/local/etc/php-fpm.d/zz-single-worker.conf
    security_opt: [seccomp:unconfined]
    privileged: true
    command: >
      bash -c "mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions && php-fpm"
  nginx:
    image: nginx:alpine
    container_name: php2shell-nginx
    ports: ["18080:80"]
    volumes:
      - ./webroot:/var/www/html
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
    depends_on: [php]
networks:
  default:
    name: php2scan_net
"""
    path.write_text(content)


def write_webroot(lab_dir):
    """Write the minimal webroot from setup.sh."""
    webroot = lab_dir / "webroot"
    webroot.mkdir(exist_ok=True)
    (webroot / "app").mkdir(exist_ok=True)
    (webroot / "api").mkdir(exist_ok=True)

    # index.php
    (webroot / "index.php").write_text("""<?php
echo "PHP " . PHP_VERSION . "\\n";
echo "SAPI " . php_sapi_name() . "\\n";
echo "upload_progress " . ini_get('session.upload_progress.enabled') . "\\n";
echo "OK\\n";
""")

    # nosession.php
    (webroot / "nosession.php").write_text("""<?php
echo "PHP " . PHP_VERSION . "\\nno session_start\\n";
""")

    # Chain A: LFI
    (webroot / "vuln.php").write_text("""<?php
$page = isset($_GET['page']) ? $_GET['page'] : 'home';
include($page);
""")

    # Chain C: writer (php_serialize)
    (webroot / "app" / ".user.ini").write_text("session.serialize_handler = php_serialize\n")
    (webroot / "app" / "write.php").write_text("""<?php
session_start();
$key = isset($_GET['k']) ? $_GET['k'] : 'x';
$val = isset($_GET['v']) ? $_GET['v'] : '';
if ($val !== '') {
    $_SESSION[$key] = $val;
}
echo "handler " . ini_get('session.serialize_handler') . "\\n";
echo "session_id " . session_id() . "\\n";
echo "stored " . strlen($val) . " bytes\\n";
echo "OK\\n";
""")

    # Chain C: reader (php handler)
    (webroot / "api" / ".user.ini").write_text("session.serialize_handler = php\n")

    (webroot / "api" / "gadget.php").write_text("""<?php
class Evil
{
    public $cmd;
    public function __destruct()
    {
        $marker = "\\x02";
        if (is_string($this->cmd) && $this->cmd !== '') {
            echo $marker;
            system($this->cmd);
            echo $marker;
        }
    }
}
""")

    (webroot / "api" / "endpoint.php").write_text("""<?php
require __DIR__ . '/gadget.php';
session_start();
echo "PHP " . PHP_VERSION . "\\n";
echo "handler " . ini_get('session.serialize_handler') . "\\n";
echo "session_id " . session_id() . "\\n";
echo "OK\\n";
""")

    # Chain E
    (webroot / "api" / "gadget_e.php").write_text("""<?php
class EvilE {
    public $cmd;
    public function __destruct() {
        if (is_string($this->cmd) && $this->cmd !== "") {
            $out = shell_exec($this->cmd . " 2>&1");
            $path = sys_get_temp_dir() . "/e_out_" . md5($this->cmd);
            @file_put_contents($path, (string)$out);
        }
    }
}
""")

    (webroot / "e_shell.php").write_text("""<?php
require __DIR__ . '/api/gadget_e.php';
$GLOBALS['e_cmd'] = isset($_GET['c']) ? $_GET['c'] : '';
session_start();
$path = sys_get_temp_dir() . '/e_out_' . md5(isset($_GET['c']) ? $_GET['c'] : '');
if (is_file($path)) {
    readfile($path);
    unlink($path);
} else {
    echo "no output (gadget did not run)\\n";
}
""")

    # php.ini
    (lab_dir / "php.ini").write_text("""[Session]
session.save_handler = files
session.save_path = /tmp/sessions
session.use_strict_mode = 0
session.use_cookies = 1
session.use_only_cookies = 0
session.upload_progress.enabled = On
session.upload_progress.cleanup = Off
session.upload_progress.prefix = upload_progress_
session.upload_progress.name = PHP_SESSION_UPLOAD_PROGRESS
session.upload_progress.freq = 1%
session.upload_progress.min_freq = 0

[PHP]
display_errors = On
error_reporting = E_ALL
file_uploads = On
memory_limit = 32M
post_max_size = 128M
upload_max_filesize = 128M
""")

    # php-fpm-pool.conf
    (lab_dir / "php-fpm-pool.conf").write_text("""[www]
pm = static
pm.max_children = 1
""")

    # nginx.conf
    (lab_dir / "nginx.conf").write_text("""server {
    listen 80;
    root /var/www/html;
    index index.php;
    client_max_body_size 128m;
    location / { try_files $uri $uri/ /index.php?$query_string; }
    location ~ \\.php$ {
        fastcgi_pass php:9000;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_request_buffering off;
    }
}
""")


def wait_for_lab(url, timeout=60, interval=2):
    """Wait until target responds or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "scan-check"})
            resp = urllib.request.urlopen(req, timeout=5)
            return resp.read().decode("latin-1", "replace")
        except Exception:
            time.sleep(interval)
    return None


def run_chain(version_tag, script_name, cmd_arg, extra_args=""):
    """Run a single exploit chain. Returns dict with results."""
    script = str(PROJECT / "poc" / script_name)
    cmd = [sys.executable, script, "--target", "http://127.0.0.1:18080", "--cmd", cmd_arg, "--timeout", "30"]
    if extra_args:
        cmd.extend(extra_args.split())

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                             cwd=str(PROJECT / "poc"))
    except subprocess.TimeoutExpired:
        return {"vulnerable": False, "details": "exploit timed out", "uid": None, "exit_code": -1}

    output = (res.stdout or "") + (res.stderr or "")

    rce = "RCE confirmed" in output
    uid_match = None
    if rce:
        m = re.search(r"uid=(\d+)", output)
        uid_match = m.group(1) if m else "unknown"

    return {
        "vulnerable": rce,
        "details": output.strip()[:500],
        "uid": uid_match,
        "exit_code": res.returncode,
    }


# ------------------------------------------------------------------ main test logic
def test_version(version_tag, quiet=False):
    """Test one PHP version. Returns result dict."""
    lab_dir = PROJECT / "lab"
    compose_path = lab_dir / "docker-compose.yml"
    results = {
        "php_version": version_tag,
        "chains": {},
        "status": "unknown",
        "php_version_detected": None,
        "error": None,
    }

    # Step 1: Pull
    log(f"  Pulling php:{version_tag}...", quiet)
    ok, err = pull_image(version_tag)
    if not ok:
        results["status"] = "pull_failed"
        results["error"] = err[:300]
        return results

    # Step 2: Write webroot + compose
    log(f"  Writing lab files...", quiet)
    write_webroot(lab_dir)
    write_compose(compose_path, version_tag)

    # Step 3: Start lab
    log(f"  Starting lab...", quiet)
    subprocess.run(["docker", "compose", "down", "--remove-orphans"],
                   capture_output=True, cwd=str(lab_dir))
    ok, out, err = run(
        ["docker", "compose", "up", "-d", "--build"],
        timeout=300, cwd=str(lab_dir),
    )
    if not ok:
        results["status"] = "compose_start_failed"
        results["error"] = (err or out)[:500]
        return results

    # Step 4: Wait for ready (nginx takes time to start)
    log(f"  Waiting for lab (90s max)...", quiet)
    ready_body = wait_for_lab("http://127.0.0.1:18080/index.php", timeout=90, interval=3)
    if not ready_body:
        results["status"] = "target_unreachable"
        results["error"] = "target not reachable after 45s"
        # Cleanup
        subprocess.run(["docker", "compose", "down", "--remove-orphans"],
                       capture_output=True, cwd=str(lab_dir))
        subprocess.run(["docker", "image", "rm", f"php:{version_tag}"],
                       capture_output=True)
        return results

    # Extract detected PHP version
    php_line = ready_body.split("\n")[0].strip()
    results["php_version_detected"] = php_line
    results["status"] = "tested"

    log(f"  Lab ready: {php_line}", quiet)
    time.sleep(2)

    # Step 5: Run chains
    log(f"  Running Chains A, C, E...", quiet)

    for chain_id, chain_name in CHAIN_SCRIPTS.items():
        log(f"    Chain {chain_id}...", quiet)
        extra = CHAIN_A_ARGS if chain_id == "A" else ""
        results["chains"][chain_id] = run_chain(
            version_tag, chain_name, "id", extra
        )

    # Step 6: Cleanup (force remove by known names — more reliable than compose down)
    log(f"  Tearing down...", quiet)
    for cname in ("php2shell-lab", "php2shell-nginx"):
        subprocess.run(["docker", "rm", "-f", cname], capture_output=True)
    subprocess.run(["docker", "network", "rm", "php2scan_net"], capture_output=True)
    subprocess.run(
        ["docker", "image", "rm", "-f", f"php:{version_tag}"],
        capture_output=True,
    )

    return results

    return results


def main():
    ap = argparse.ArgumentParser(description="PHP 2Shell version scanner")
    ap.add_argument("--versions", default=None,
                    help="Comma-separated version tags")
    ap.add_argument("--results", "-r", default=None,
                    help="Output JSON path")
    ap.add_argument("--quiet", "-q", action="store_true",
                    help="Suppress verbose stderr output")
    args = ap.parse_args()

    # Load versions
    if args.versions:
        version_tags = [v.strip() for v in args.versions.split(",") if v.strip()]
    else:
        ver_path = HERE / "versions.json"
        with open(ver_path) as f:
            data = json.load(f)
        version_tags = data["versions"]

    if not version_tags:
        print("[!] No versions to test")
        sys.exit(1)

    print(f"\nPHP 2Shell — Version Scan")
    print(f"{'='*50}")
    print(f"Versions: {len(version_tags)}")
    print(f"Range: {version_tags[0]} → {version_tags[-1]}")
    print(f"{'='*50}\n")

    overall = {
        "scan_metadata": {
            "total_versions": len(version_tags),
            "ordered": "highest_to_lowest",
            "version_list": version_tags,
            "scan_date": time.strftime("%Y-%m-%d %H:%M"),
        },
        "results": [],
        "summary": {
            "total_tested": 0,
            "total_vulnerable": 0,
            "total_patched": 0,
            "total_pull_failed": 0,
            "total_unreachable": 0,
        },
    }

    for i, tag in enumerate(version_tags, 1):
        print(f"[{i:2d}/{len(version_tags)}] {tag}", file=sys.stderr)

        r = test_version(tag, args.quiet)
        overall["results"].append(r)
        overall["summary"]["total_tested"] += 1

        if r["status"] == "pull_failed":
            overall["summary"]["total_pull_failed"] += 1
            print(f"      ✗ PULL FAILED: {r.get('error', '?')[:60]}", file=sys.stderr)
        elif r["status"] == "unreachable":
            overall["summary"]["total_unreachable"] += 1
            print(f"      ✗ UNREACHABLE: {r.get('error', '?')[:60]}", file=sys.stderr)
        else:
            vuln_chains = [c for c, v in r["chains"].items() if v.get("vulnerable")]
            if vuln_chains:
                overall["summary"]["total_vulnerable"] += 1
                print(f"      ⚠ VULNERABLE — chains: {', '.join(vuln_chains)}"
                      f" ({r.get('php_version_detected', '?')})"
                      , file=sys.stderr)
            else:
                overall["summary"]["total_patched"] += 1
                print(f"      ✓ Patched ({r.get('php_version_detected', '?')})"
                      , file=sys.stderr)

    # Save
    out_path = args.results or str(HERE / "results.json")
    with open(out_path, "w") as f:
        json.dump(overall, f, indent=2)

    # Final summary
    s = overall["summary"]
    print(f"\n{'='*50}")
    print(f"SCAN COMPLETE")
    print(f"  Tested:      {s['total_tested']}")
    print(f"  Vulnerable:  {s['total_vulnerable']}")
    print(f"  Patched:     {s['total_patched']}")
    print(f"  Pull failed: {s['total_pull_failed']}")
    print(f"  Unreachable: {s['total_unreachable']}")
    print(f"  Results:     {out_path}")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()