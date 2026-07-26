# Passkeys plugin for Roundcube

Optional **passwordless passkey** (WebAuthn / FIDO2) authentication for Roundcube.

Each user may enrol one or more passkeys and then sign in without typing a
password, using a fingerprint, face, device screen lock, or a hardware
security key. Passkeys are strictly **opt-in per user** and are designed to
coexist with the existing authentication features:

- The standard username/password login form keeps working unchanged.
- Any 2FA plugin keeps working — this plugin does not touch the password
  `authenticate` path.
- A user who never enrols a passkey sees no difference at all.

## How passwordless works here

Roundcube authenticates against IMAP, so it always needs the real IMAP
password to open the mailbox. A passkey cannot supply that password directly.
This plugin therefore stores the IMAP password **encrypted with a key that
only the passkey can derive** (via the WebAuthn PRF / `hmac-secret`
extension). The key never leaves the browser/authenticator, and the server
keeps only ciphertext it cannot decrypt on its own. At login the passkey
unlocks the stored password in the browser, which then completes a normal
Roundcube login.

Because this relies on the PRF extension, passwordless login requires a
reasonably modern browser (Chrome/Edge 116+, Safari 18+, recent Firefox) and
a PRF-capable authenticator. See `passkeys_on_no_prf` in the configuration
for how unsupported devices are handled.

## Requirements

- Roundcube with PHP >= 8.1 (`ext-openssl`, `ext-mbstring`, `ext-sodium`).
- The `lbuchs/webauthn` library (installed automatically via Composer).
- HTTPS — WebAuthn only works over a secure context.

## Installation

### A. Via the Roundcube plugin installer (recommended)

Run from the Roundcube root:

```bash
composer require roundcube/passkeys
```

The `roundcube/plugin-installer` (declared as a dependency) then, driven by the
`extra.roundcube` block in this plugin's `composer.json`:

- installs the plugin into `plugins/passkeys/`,
- pulls in the `lbuchs/webauthn` dependency,
- creates the database table from `SQL/<driver>.initial.sql` (`extra.roundcube.sql-dir`),
- copies `config.inc.php.dist` to `config.inc.php` if no config exists yet,
- adds `passkeys` to the `plugins` list in `config/config.inc.php` (when that
  file is writable and Composer runs on the CLI),
- refuses to install on Roundcube older than `min-version` (1.6.0).

Set the `SKIP_DB_INIT=1` environment variable before `composer require` if you
prefer to create the schema yourself.

### B. Manual installation

1. Drop this directory into `plugins/passkeys/` and run `composer install` at
   the Roundcube root so `lbuchs/webauthn` is available on the autoloader.
2. Create the database table:

   ```bash
   bin/updatedb.sh --dir=plugins/passkeys/SQL --package=passkeys
   ```

3. Add `passkeys` to the `plugins` array in `config/config.inc.php`.
4. (Optional) copy `config.inc.php.dist` to `config.inc.php` and adjust
   `passkeys_rp_id`, `passkeys_require_uv`, etc.

> **Schema versioning note.** The plugin installer seeds the schema with
> `db_init` (a straight run of `*.initial.sql`) and does *not* write a
> `passkeys-version` row into the `system` table. Future schema migrations are
> applied with `bin/updatedb.sh --dir=plugins/passkeys/SQL --package=passkeys`,
> which is also the recommended way to create the table for a manual install so
> the version bookkeeping is in place from the start.

## Configuration

See `config.inc.php.dist` — every option has a safe default, so no
configuration is strictly required beyond enabling the plugin. The most
important option in a multi-hostname setup is `passkeys_rp_id`.

## Status / roadmap

This plugin is being built in phases:

1. **Settings management (done)** — a "Passkeys" tab that lists a user's
   enrolled passkeys and lets them remove one. Database schema and credential
   store in place.
2. **Enrolment (done)** — the WebAuthn registration ceremony from the Settings
   tab: create a discoverable credential, validate the attestation
   server-side, and persist it.
3. **PRF wrapping (done)** — at enrolment the IMAP password is encrypted with a
   key derived from the passkey (WebAuthn PRF/hmac-secret) and stored as
   `wrapped_secret`; the server never holds a key that can decrypt it.
4. **Passwordless login (done)** — a "Sign in with a passkey" button on the
   login page. The assertion is verified server-side (via the `startup` hook,
   since Roundcube short-circuits unauthenticated requests), the wrapped
   password is released, decrypted in the browser, and the standard login form
   is submitted so the normal password/2FA path completes the sign-in.
5. **Hardening (partial)** — signature-counter regression check and last-used
   stamping are in place. Still to do: explicit CSRF token checks on the AJAX
   endpoints, brute-force/lockout integration on the assert path, and a
   re-enrolment prompt when a stored password becomes stale (IMAP password
   changed out-of-band).

## License

GPL-3.0-or-later.
