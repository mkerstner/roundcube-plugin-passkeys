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

When adding a passkey the user types their current password; the server
checks it against the session and the browser encrypts what was typed. The
server never sends the session's password to the browser.

Because this relies on the PRF extension, passwordless login requires a
reasonably modern browser (Chrome/Edge 116+, Safari 18+, recent Firefox) and
a PRF-capable authenticator. Devices without PRF cannot add a passkey (the
user is told so); their password login is unaffected.

## When the password changes

A passkey holds a copy of the password from the time it was added (or last
updated), so it stops working when the password changes:

- **Changed with Roundcube's `password` plugin:** all of the user's passkeys
  are marked "needs update" right away.
- **Changed elsewhere:** the first passkey sign-in fails at the mail server;
  the plugin recognizes that the password came from the passkey, marks it
  "needs update" and explains it on the login page. From then on that passkey
  is not tried again (each attempt would count towards the account lockout);
  it fills in the username so the user only types the new password.

After the next password login the user is asked once to update their
passkeys. *Settings › Passkeys › Update passkey* asks for the current
password and one touch of the passkey, and stores the new password in place
of the old one; there is no need to remove and re-add the passkey.

## Security

- **CSRF:** every plugin request must be a POST carrying the session's
  request token in the `X-Roundcube-Request` header. Core checks this for
  logged-in requests too, but the login-page endpoints run in the `startup`
  hook, before any of core's checks.
- **Brute force:** passkey sign-ins share Roundcube's per-user lockout
  (`login_rate_limit`) with password logins. A failed assertion counts as a
  failed login, a locked account's password is not released, and failures
  are written to the `userlogins` log (`log_logins`) in core's format, so the
  usual fail2ban filter for Roundcube catches them. Wrong passwords typed
  when adding or updating a passkey count as well.
- **Replay and cloning:** each challenge can be used once, and a signature
  counter that goes backwards (a cloned authenticator) is rejected.
  Synced passkeys (iCloud Keychain, Google Password Manager) have no counter,
  so for them the single-use challenge is what stops a replay.

## Skins

The plugin is skin-independent and needs no per-skin files:

- **Styles** are loaded from the plugin root (`passkeys.css`), not from a skin
  folder, so they apply on any skin — including skins that do not inherit from
  `elastic`.
- **The "Sign in with a passkey" button** is added to the login form via the
  core `loginform_content` hook, so it renders — with an "or sign in using
  passkeys" divider — directly below the standard Login button. Because the
  login form (and these extra buttons) are rendered by Roundcube core, not by
  the skin, this placement is identical on every skin with no skin template
  changes. The divider and button are hidden until the client script confirms
  the browser supports WebAuthn (`body.passkeys-available`).

So **nothing extra is required for any skin**. The credential-management page in
Settings uses core templates and needs no skin work either.

## Requirements

- Roundcube 1.6 or newer on PHP >= 8.1 with `ext-openssl`. Tested with
  Roundcube 1.7.5 and 1.7.6 on PHP 8.3 and the PHP 8.6 release candidate.
  `ext-sodium` is only used to verify Ed25519 passkeys when OpenSSL cannot.
- The `lbuchs/webauthn` library (installed automatically via Composer).
- HTTPS — WebAuthn only works over a secure context.

## Installation

### A. Via the Roundcube plugin installer (recommended)

Run from the Roundcube root:

```bash
composer require mkerstner/passkeys
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

1. Drop this directory into `plugins/passkeys/` and make `lbuchs/webauthn`
   available on Roundcube's autoloader, from the Roundcube root:

   ```bash
   composer require lbuchs/webauthn:^2.2
   ```

2. Create the database table:

   ```bash
   bin/initdb.sh --dir=plugins/passkeys/SQL
   ```

3. Add `passkeys` to the `plugins` array in `config/config.inc.php`.
4. (Optional) copy `config.inc.php.dist` to `config.inc.php` and adjust
   `passkeys_rp_id`, `passkeys_require_uv`, etc.

### Upgrading

The plugin installer applies schema changes on `composer update`. For a
manual installation, after replacing the files run:

```bash
bin/updatedb.sh --dir=plugins/passkeys/SQL --package=passkeys
```

Upgrading from 1.0.x adds the `stale` column. 1.0.x did not record a schema
version, so `updatedb.sh` applies every migration once and records the
version from then on.

## Configuration

See `config.inc.php.dist` — every option has a safe default, so no
configuration is strictly required beyond enabling the plugin. The most
important option in a multi-hostname setup is `passkeys_rp_id`.

## Development

`dev/` (not part of releases) holds a Docker instance and an end-to-end test:

```bash
docker compose -f dev/compose.yaml up -d     # http://localhost:8766
node dev/e2e.mjs
```

The instance copies a Roundcube checkout (`ROUNDCUBE_DIR`, default
`../roundcubemail` next to this repository, with `composer install` done and
`lbuchs/webauthn` in its `vendor/`) without its configuration, uses its own
SQLite database and a GreenMail server with real password checks, and mounts
this folder live as `plugins/passkeys`. `PASSKEYS_DEV_SKIN` selects the skin.
The test speaks HTTP like the browser and plays the authenticator with
`dev/soft-authenticator.js` (ES256, PRF emulated), which can also replace
`navigator.credentials` in a page of the dev instance:

```js
await import('/static.php/plugins/passkeys/dev/soft-authenticator.js');  // or a <script> tag
PasskeysSoftAuthenticator.install(window);
```

It does not replace a test with a real browser and authenticator.

## License

GNU General Public License version 3 or any later version
(GPL-3.0-or-later), see [LICENSE](LICENSE).
