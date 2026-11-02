#!/bin/bash
# Entry point of the passkeys-dev webmail container. See compose.yaml (same dir).
set -euo pipefail

# 1. Copy the Roundcube checkout (read-only at /app) into /work. Excluded: its
#    REAL config (never used here), git metadata, node_modules, temp/ and logs/
#    contents, and plugins/passkeys, which is this folder, bind-mounted live.
rsync -a --delete \
    --exclude '/config/config.inc.php' \
    --exclude '/.git' \
    --exclude '/node_modules' \
    --exclude '/temp/*' \
    --exclude '/logs/*' \
    --exclude '/plugins/passkeys' \
    /app/ /work/

if [ ! -d /work/vendor/lbuchs/webauthn ]; then
    echo 'refusing to start: lbuchs/webauthn is missing from the checkout'"'"'s vendor/' >&2
    exit 1
fi

# 2. Throwaway config: SQLite inside the container, GreenMail for IMAP/SMTP.
cp /dev-config/config.inc.php /work/config/config.inc.php

# Safety net: refuse to start unless the effective config is the dev one.
if ! grep -q 'PASSKEYS-DEV-INSTANCE' /work/config/config.inc.php; then
    echo 'refusing to start: /work/config/config.inc.php is not the passkeys-dev config' >&2
    exit 1
fi

mkdir -p /work/temp /work/logs
chmod 777 /work/temp /work/logs

# 3. Database. The SQLite driver creates Roundcube's own schema when the file is
#    new (every `up` starts empty, the file lives in /work/temp); then add the
#    plugin's tables the way the plugin installer does, plus any migrations.
cd /work
php bin/initdb.sh --dir=plugins/passkeys/SQL
if [ -d plugins/passkeys/SQL/sqlite ]; then
    php bin/updatedb.sh --package=passkeys --dir=plugins/passkeys/SQL
fi

# 4. Serve public_html like the browser tests do (tests/Browser/TestCase.php).
cd /work/public_html
echo 'passkeys-dev: serving on :8000'
exec php -S 0.0.0.0:8000
