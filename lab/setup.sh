#!/bin/bash
# php2shell lab bootstrap.
#
# Builds a single PHP-FPM + nginx target on :18080 and every endpoint the three
# exploit chains need:
#
#   Chain A  upload_progress filename injection -> include() -> RCE
#   Chain C  session handler mismatch -> __destruct -> RCE
#   Chain E  session decode failure -> __destruct -> RCE
#
# Running this script overwrites every lab file, including the Chain C
# endpoints. That is intentional: the lab must be reproducible.
set -e

cd "$(dirname "$0")"

echo "Setting up php2shell lab..."

mkdir -p webroot/app webroot/api webroot/reader

# ---------------------------------------------------------------- basics
cat > webroot/index.php << 'EOF'
<?php
session_start();
echo "PHP " . PHP_VERSION . "\n";
echo "SAPI " . php_sapi_name() . "\n";
echo "upload_progress " . ini_get('session.upload_progress.enabled') . "\n";
echo "OK\n";
EOF

cat > webroot/nosession.php << 'EOF'
<?php
echo "PHP " . PHP_VERSION . "\nno session_start\n";
EOF

# Chain A: LFI sink.
cat > webroot/vuln.php << 'EOF'
<?php
$page = $_GET['page'] ?? 'home';
include($page);
EOF

# ------------------------------------------------- Chain C: writer (php_serialize)
echo "session.serialize_handler = php_serialize" > webroot/app/.user.ini
cp webroot/nosession.php webroot/app/upload.php

cat > webroot/app/write.php << 'EOF'
<?php
/**
 * Chain C lab writer: a plain session write under php_serialize.
 *
 * Storing an attacker-controlled string in $_SESSION is enough. The value is
 * serialized with php_serialize (length-prefixed), so a pipe inside it is just
 * data. A sibling directory configured with session.serialize_handler=php will
 * later split the stored line at the first pipe and deserialize whatever
 * follows as a PHP object -- the handler mismatch.
 */
session_start();

$key = $_GET['k'] ?? 'x';
$val = $_GET['v'] ?? '';
if ($val !== '') {
    $_SESSION[$key] = $val;
}

echo "handler " . ini_get('session.serialize_handler') . "\n";
echo "session_id " . session_id() . "\n";
echo "stored " . strlen($val) . " bytes\n";
echo "OK\n";
EOF

# -------------------------------------------------- Chain C: reader (php handler)
echo "session.serialize_handler = php" > webroot/api/.user.ini

# The gadget class must exist before session_start() decodes the session file,
# mirroring how a real application reaches a POP chain through its autoloader.
cat > webroot/api/gadget.php << 'EOF'
<?php
/**
 * Lab stand-in for an application POP gadget.
 *
 * Chain C only needs *some* class with a useful __destruct() that is already
 * loaded when the mismatched session is decoded. Real applications reach this
 * through their autoloader (Monolog, Guzzle, Laravel, Symfony, ...).
 */
class Evil
{
    public $cmd;

    public function __destruct()
    {
        $marker = "\x02";
        if (is_string($this->cmd) && $this->cmd !== '') {
            echo $marker;
            system($this->cmd);
            echo $marker;
        }
    }
}
EOF

cat > webroot/api/endpoint.php << 'EOF'
<?php
// Gadget must be declared before session_start() decodes the mismatched file.
require __DIR__ . '/gadget.php';

session_start();

echo "PHP " . PHP_VERSION . "\n";
echo "handler " . ini_get('session.serialize_handler') . "\n";
echo "session_id " . session_id() . "\n";
echo "OK\n";
EOF

# ---------------------------------------------------------------- Chain E
# The gadget runs during PHP_VAR_UNSERIALIZE_DESTROY, i.e. before the response
# body exists. It therefore stashes output in a temp file that e_shell.php
# serves once session_start() has returned.
cat > webroot/api/gadget_e.php << 'EOF'
<?php
/**
 * Chain E gadget: runs during PHP_VAR_UNSERIALIZE_DESTROY, before the
 * response body exists. Writes its output to a file for e_shell.php to serve.
 */
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
EOF

cat > webroot/e_shell.php << 'EOF'
<?php
/**
 * Chain E reader-with-command.
 *
 * The session decoder runs __destruct() while session_start() is still
 * starting up. At that point the response body is not writable, so a gadget
 * that echo()es loses its output. Instead the gadget writes to a per-request
 * file and this script serves that file once session_start() has returned.
 */

require __DIR__ . '/api/gadget_e.php';

$GLOBALS['e_cmd'] = $_GET['c'] ?? '';

session_start();

$path = sys_get_temp_dir() . '/e_out_' . md5($_GET['c'] ?? '');
if (is_file($path)) {
    readfile($path);
    unlink($path);
} else {
    echo "no output (gadget did not run)\n";
}
EOF

# ---------------------------------------------------------------- PHP config
cat > php.ini << 'EOF'
[Session]
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
EOF

# A single, fixed worker keeps every request on the same process, so the
# session file written by one request is the one the next request reads.
cat > php-fpm-pool.conf << 'EOF'
; A single, fixed worker keeps the lab deterministic: every request lands on
; the same process, so the session file written by one request is the one the
; next request reads.
[www]
pm = static
pm.max_children = 1
EOF

# ---------------------------------------------------------------- nginx
cat > nginx.conf << 'EOF'
server {
    listen 80;
    root /var/www/html;
    index index.php;
    client_max_body_size 128m;
    location / { try_files $uri $uri/ /index.php?$query_string; }
    location ~ \.php$ {
        fastcgi_pass php:9000;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_request_buffering off;
    }
}
EOF

# ---------------------------------------------------------------- compose
cat > docker-compose.yml << 'EOF'
services:
  php:
    image: php:8.2-fpm
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
EOF

echo "Starting containers..."
docker compose up -d --build

echo ""
echo "Lab ready!  http://127.0.0.1:18080"
echo ""
echo "Run every chain:"
echo "  cd ../poc && ./run_all.sh"
echo ""
echo "Or individually:"
echo "  python3 ../poc/exploit_chain_a.py --target http://127.0.0.1:18080   # -> shell"
echo "  python3 ../poc/exploit_chain_c.py --target http://127.0.0.1:18080   # -> shell"
echo "  python3 ../poc/exploit_chain_e.py --target http://127.0.0.1:18080   # -> shell"
echo "  python3 ../poc/verify_session_injection.py --target http://127.0.0.1:18080"
echo "  python3 ../poc/verify_handler_mismatch.py --target http://127.0.0.1:18080"
