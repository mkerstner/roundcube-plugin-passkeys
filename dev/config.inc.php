<?php

// PASSKEYS-DEV-INSTANCE — throwaway config for the local Docker test instance.
// start.sh copies this over the container's copy of config/config.inc.php; the
// checkout's real config is never read. Nothing here is a real secret.

$config = [];

// Database: SQLite inside the container, recreated on every start
$config['db_dsnw'] = 'sqlite:////work/temp/passkeys-dev.db?mode=0646';

// GreenMail (authentication enabled, accounts defined in compose.yaml)
$config['imap_host'] = 'mailhost:3143';
$config['smtp_host'] = 'mailhost:3025';
$config['smtp_user'] = '%u';
$config['smtp_pass'] = '%p';

// 24 characters, dev-only
$config['des_key'] = 'passkeys-dev-only-key-24';

$config['skin'] = getenv('PASSKEYS_DEV_SKIN') ?: 'elastic';
$config['plugins'] = ['passkeys'];

// logs/userlogins: what fail2ban would read
$config['log_logins'] = true;

$config['temp_dir'] = '/work/temp/';
$config['log_dir'] = '/work/logs/';
$config['create_default_folders'] = true;
$config['product_name'] = 'Passkeys dev';
$config['enable_installer'] = false;
