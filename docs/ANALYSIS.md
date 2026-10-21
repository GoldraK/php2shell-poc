# php2shell — Technical Analysis

## CVE-2026-109618 / CVE-2026-109619
**Author:** Qi Deng  **Date:** 2026-10-21

---

## 1. Vulnerability Summary

Weaknesses in PHP's `session.upload_progress` handler and session deserialisation
that enable pre-authentication remote code execution on PHP 5.4.0 through 8.5.x.

| Bug | Root Cause | Impact |
|-----|-----------|--------|
| Session Fixation | `MULTIPART_EVENT_FORMDATA` accepts PHPSESSID from POST body ignoring `use_only_cookies` | Attacker controls session ID and file path |
| Filename Injection | `add_assoc_string_ex(*data->filename)` stores raw filename in session without validation | PHP code / serialized objects injected into session files |
| Serializer Leak | `PS(serializer)` not reset in `php_rshutdown_session_globals()` | Cross-request handler mismatch in FPM |
| `__destruct` on decode failure | `PHP_VAR_UNSERIALIZE_DESTROY` runs destructors even when the decode returns FAILURE, without `BG(serialize_lock)` | Object injection → arbitrary code execution |

## 2. Attack Chains

Only chains that reach a complete RCE are documented here. Each one is
reproducible in the bundled lab and returns an interactive shell.

### Chain A: Session Injection + LFI → RCE

```
Conditions: upload_progress.enabled=On (default) + application has LFI
Complexity: Low | Reliability: 100%

1. POST multipart with PHP code in the filename
2. The rfc1867 handler stores the filename as-is in the session file
3. include(session_file) → execute injected PHP → RCE
```

Verified in the lab: `uid=33(www-data)` on PHP 8.2.35, plus an interactive
shell. If `session.upload_progress.cleanup=On` (the PHP default), the file is
unlinked when the upload request finishes, so the include has to race the
cleanup — `exploit_chain_a.py --race` does exactly that.

### Chain C: Handler Mismatch → `__destruct` → RCE

```
Conditions: two directories with different session.serialize_handler
Complexity: Medium | Reliability: High

1. /app (php_serialize) stores  zz|O:CLASS:N:{PAYLOAD}  in a session variable
2. /api (php handler) reads the same SID
3. The php decoder scans for | → deserializes the object
4. Trailing session data makes the decode FAILURE
5. __destruct fires during PHP_VAR_UNSERIALIZE_DESTROY anyway
6. The gadget runs → RCE
```

**Key insight:** the decode FAILURE does not prevent exploitation, because the
destructor list is walked during cleanup regardless of the return value.

Two constraints found during verification:

- The pipe must be inside a session *value*. A multipart filename is stored
  inside a length-prefixed `php_serialize` value, where the `php` decoder never
  looks for `|`, so it cannot be used as the injection point for this chain.
- The byte lengths in the serialized object must be exact. `s:5:"id;"`
  prevents instantiation; the exploit computes real lengths from the payload.

### Chain E: Session Decode Failure → `__destruct` → RCE

```
Conditions: session_start() endpoint + a session file you can plant
Complexity: Low | Reliability: High

1. Session file contains  x|<serialized object><trailing junk>
2. session_start() deserializes the object, then fails on the trailing data
3. PHP_VAR_UNSERIALIZE_DESTROY runs __destruct() during request startup
4. The gadget runs before the script body executes
```

The output problem: at startup the response body does not exist, so anything
the destructor `echo`es is discarded. The lab gadget writes to a temp file and
the page serves it after `session_start()` returns, which is what makes the
interactive shell possible.

An OOM variant was also reproduced (a 30 MB session file against
`memory_limit=32M` produces `Fatal error: Allowed memory size exhausted` inside
`session_start()` and the worker survives), but the bailout aborts before the
destructor runs, so it does not yield code execution. The decode-failure path
above is the one that works.

## 3. Root Cause Detail

### 3.1 Session Fixation (ext/session/session.c)

```c
// MULTIPART_EVENT_FORMDATA handler — no use_only_cookies check
if (name_len == progress->sname_len &&
    memcmp(data->name, PS(session_name), name_len) == 0) {
    zval_ptr_dtor(&progress->sid);
    ZVAL_STRINGL(&progress->sid, (*data->value), value_len);
    // ← Accepts PHPSESSID from POST body regardless of use_only_cookies!
}
```

Fix: [PR #22113](https://github.com/php/php-src/pull/22113) adds a
`!PS(use_only_cookies) &&` check.

### 3.2 Unvalidated Filename

```c
// FILE_START handler stores raw filename
add_assoc_string_ex(&progress->current_file, "name",
                    sizeof("name") - 1, *data->filename);
// ← No sanitization, no encoding, no length limit
```

The filename can contain arbitrary bytes, including PHP code. It never becomes
a path: PHP writes the upload to its own `mkstemp()` file and only copies the
name into the session array, which is why Chain A needs an LFI rather than a
directory-traversal write.

### 3.3 `__destruct` on Decode Failure

```c
PS_SERIALIZER_DECODE_FUNC(php) {
    while (p < endptr) {
        if (php_var_unserialize(...)) {
            php_set_session_var(name, &rv, &var_hash);  // object stored
        } else {
            retval = FAILURE; goto break_outer_loop;
        }
    }
break_outer_loop:
    PHP_VAR_UNSERIALIZE_DESTROY(var_hash);  // ← __destruct fires HERE
    return retval;  // FAILURE
}
```

Even though the decoder returns FAILURE and `session_start()` calls
`php_session_cancel_decode()` to destroy `$_SESSION`, the object's
`__destruct()` has already fired during `var_hash` cleanup. This is the
primitive behind both Chain C and Chain E.

## 4. Version Matrix

| Version | upload_progress | Vulnerable | Official Fix |
|---------|----------------|------------|-------------|
| < 5.4 | No | No | N/A |
| 5.4 - 5.6 | Yes | Yes | EOL, no fix |
| 7.0 - 7.4 | Yes | Yes | EOL, no fix |
| 8.0 - 8.1 | Yes | Yes | EOL, no fix |
| 8.2.x | Yes | Yes | → 8.2.35 |
| 8.3.x | Yes | Yes | → 8.3.36 |
| 8.4.x | Yes | Yes | → 8.4.27 |
| 8.5.x | Yes | Yes | → 8.5.12 |

## 5. Detection

```bash
# Check PHP version
php -r 'echo PHP_VERSION, PHP_EOL;'

# Check upload_progress setting
php -r 'echo ini_get("session.upload_progress.enabled"), PHP_EOL;'

# Check for handler mismatch across directories
find /var/www -name ".user.ini" -exec grep -l "serialize_handler" {} \;

# Monitor for exploitation attempts
grep -r "PHP_SESSION_UPLOAD_PROGRESS" /var/log/nginx/access.log
```

## 6. Mitigation

```ini
; Primary mitigation
session.upload_progress.enabled = Off

; Additional hardening
session.use_only_cookies = On
session.use_strict_mode = On

; Ensure one handler across directories
session.serialize_handler = php_serialize
```

**Warning:** Chain A and Chain C are request-level bugs. They do not depend on
the memory-corruption fixes, so updating PHP alone does not remove them —
disabling `upload_progress` and enforcing consistent session handling does.

## 7. References

- [PHP Security Advisory](https://www.php.net/archive/2026.php) (pending)
- [PR #22113 — Session fixation fix](https://github.com/php/php-src/pull/22113)
- [dinosn — var_destroy reentry](https://github.com/dinosn/php-8.5.5-var_destroy-uaf)
- [PHP Bug #71101 — Handler mismatch](https://bugs.php.net/bug.php?id=71101)
- [cnpanda — Handler mismatch exploitation](https://www.cnpanda.net/en/sec/580.html)
