<?php

/*
 +-----------------------------------------------------------------------+
 | Passkeys plugin for Roundcube                                         |
 |                                                                       |
 | Optional passwordless passkey (WebAuthn/FIDO2) authentication.        |
 | Passkeys are opt-in per user and never replace or interfere with the  |
 | standard username/password login or any 2FA plugin: a user with no    |
 | enrolled passkey sees the unchanged login experience.                 |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or           |
 | any later version with exceptions for skins & plugins.               |
 +-----------------------------------------------------------------------+
*/

use lbuchs\WebAuthn\WebAuthn;
use lbuchs\WebAuthn\Binary\ByteBuffer;

/**
 * Passwordless passkey authentication plugin.
 *
 * Roundcube needs the real IMAP password, so a passkey cannot stand in for
 * it. At enrolment the browser encrypts the user's password with a key only
 * the passkey can derive (WebAuthn PRF) and the server stores the ciphertext.
 * At sign-in the assertion is verified here, the ciphertext released and
 * decrypted in the browser, and the standard login form submitted, so the
 * normal password/2FA path completes the login.
 *
 * @author Matthias Kerstner
 */
class passkeys extends rcube_plugin
{
    // Active in Settings (enrolment/management) and on the login screen
    // (passwordless sign-in). Not initialized on logout: core then switches to
    // the login page and re-runs init() for task "login". This plugin is
    // AJAX-driven, so it must NOT set $noframe/$noajax (those would make the
    // plugin API skip init() for framed/AJAX requests).
    public $task = '?(?!logout).*';

    /** @var rcmail */
    private $rc;

    /** @var rcube_passkeys_store */
    private $store;

    /** @var array|null The verified passkey sign-in this login request completes */
    private $passkey_login;

    #[\Override]
    public function init()
    {
        $this->rc = rcmail::get_instance();

        $this->load_config();

        // Expose localized strings to the client-side scripts as well.
        $this->add_texts('localization/', true);

        // The credential store is needed by every entry point.
        require_once __DIR__ . '/lib/rcube_passkeys_store.php';
        $this->store = new rcube_passkeys_store($this->rc->get_dbh());

        // Add the passkey button to the login form itself, right below the
        // standard Login button. loginform_content is a core hook and the form
        // is rendered by core, so this works on every skin. Registered for every
        // task: core also renders the login form after a session timeout, from
        // whatever task the request started in.
        $this->add_hook('loginform_content', [$this, 'login_form_content']);

        // The plugin API's task, not $this->rc->task: when core switches to the
        // login page (after logout) it re-runs init() before updating the latter.
        $task = $this->api->task;

        if ($task == 'settings') {
            $this->add_hook('settings_actions', [$this, 'settings_actions']);
            // Fired by the password plugin: every passkey still holds the old password.
            $this->add_hook('password_change', [$this, 'password_change']);

            $this->register_action('plugin.passkeys', [$this, 'settings_page']);
            $this->register_action('plugin.passkeys.reg-challenge', [$this, 'action_reg_challenge']);
            $this->register_action('plugin.passkeys.register', [$this, 'action_register']);
            $this->register_action('plugin.passkeys.update-challenge', [$this, 'action_update_challenge']);
            $this->register_action('plugin.passkeys.update', [$this, 'action_update']);
            $this->register_action('plugin.passkeys.remove', [$this, 'action_remove']);
            $this->register_action('plugin.passkeys.rename', [$this, 'action_rename']);

            $this->include_script('passkeys.js');
            // Skin-independent stylesheet (works on any skin, not just elastic).
            $this->include_stylesheet('passkeys.css');
        } elseif ($task == 'login') {
            // The login page short-circuits to rendering the login template for
            // unauthenticated requests (index.php), so plugin AJAX actions never
            // reach the normal dispatcher. We handle them in the startup hook,
            // which runs before that short-circuit.
            $this->add_hook('startup', [$this, 'login_startup']);
            $this->add_hook('login_failed', [$this, 'login_failed']);
            $this->add_hook('login_after', [$this, 'login_after']);
        }

        // Passkeys holding an old password: ask once, on the first full page
        // after the login screen (and after any 2FA step, which runs there).
        if ($task != 'login' && !empty($_SESSION['passkeys_stale_prompt'])
            && $this->rc->output->type == 'html' && empty($_REQUEST['_framed'])
        ) {
            $this->rc->session->remove('passkeys_stale_prompt');
            $this->include_script('passkeys.js');
            $this->rc->output->set_env('passkeys_stale_prompt', true);
        }
    }

    /**
     * Handle the passwordless-login AJAX endpoints before the unauthenticated
     * request is short-circuited to the login page, and note whether a login
     * form submission completes a passkey sign-in.
     */
    public function login_startup($args)
    {
        if ($args['task'] !== 'login') {
            return $args;
        }

        if ($args['action'] === 'login') {
            // Core empties the session before it tries the password, so this
            // is the last point at which the marker set by action_assert() exists.
            $this->passkey_login = $this->pending_passkey_login();
        } elseif (empty($this->rc->user->ID)) {
            if ($args['action'] === 'plugin.passkeys.auth-challenge') {
                $this->action_auth_challenge();  // sends response and exits
            } elseif ($args['action'] === 'plugin.passkeys.assert') {
                $this->action_assert();          // sends response and exits
            }
        }

        return $args;
    }

    /**
     * Add a divider and the "Sign in with a passkey" button to the login form,
     * immediately below the standard Login button. Core renders the login form
     * (and the buttons added here) the same way for every skin, so no skin
     * template changes are needed. The button stays hidden until the client
     * script confirms WebAuthn support.
     */
    public function login_form_content($content)
    {
        $this->include_script('passkeys.js');
        $this->include_stylesheet('passkeys.css');

        // "──── or sign in using passkeys ────"
        $content['buttons']['passkeys_sep'] = [
            'outterclass' => 'passkeys-separator',
            'content' => html::tag('span', null, rcube::Q($this->gettext('orsigninwithpasskey'))),
        ];

        $content['buttons']['passkeys_login'] = [
            'outterclass' => 'passkeys-login-row',
            'content' => html::tag('button', [
                'type' => 'button',
                'id' => 'passkeys-login-button',
                'class' => 'button passkeys-login',
                'onclick' => 'return rcmail.passkeys_login()',
            ], rcube::Q($this->gettext('loginwithpasskey'))),
        ];

        return $content;
    }

    /**
     * A passkey sign-in whose released password the mail server rejected: the
     * password changed after the passkey was enrolled. Flag the passkey so it
     * is not used again (every attempt would count towards the account
     * lockout) and tell the user how to recover.
     */
    public function login_failed($args)
    {
        // No code: the server rejected the credentials, as opposed to a storage
        // error, the rate limit or an invalid request.
        if ($this->passkey_login && empty($args['code'])) {
            $this->store->mark_stale($this->passkey_login['credential']);
            $this->rc->output->show_message('passkeys.passkeystale', 'warning', null, true, 15);
        }

        return $args;
    }

    /**
     * After a password login, remind the user of passkeys that still hold an
     * old password (the prompt itself is shown by init() on the next page).
     */
    public function login_after($args)
    {
        if (!$this->passkey_login) {
            foreach ($this->store->list_by_user($this->rc->user->ID) as $cred) {
                if (!empty($cred['stale'])) {
                    $_SESSION['passkeys_stale_prompt'] = true;
                    break;
                }
            }
        }

        return $args;
    }

    /**
     * The password plugin changed the user's password: flag all their passkeys
     * for an update.
     */
    public function password_change($args)
    {
        if ($this->store->mark_user_stale($this->rc->user->ID)) {
            $_SESSION['passkeys_stale_prompt'] = true;
        }

        return $args;
    }

    /**
     * Add the "Passkeys" tab to the Settings navigation.
     */
    public function settings_actions($args)
    {
        $args['actions'][] = [
            'action' => 'plugin.passkeys',
            'class' => 'passkeys',
            'label' => 'passkeys',
            'title' => 'passkeys',
            'domain' => 'passkeys',
        ];

        return $args;
    }

    /**
     * Render the passkey management page.
     */
    public function settings_page()
    {
        $this->register_handler('plugin.body', [$this, 'settings_form']);

        $this->rc->output->set_pagetitle($this->gettext('passkeys'));
        $this->rc->output->send('plugin');
    }

    /**
     * Build the management page body: a list of enrolled credentials plus the
     * "Add a passkey" action.
     */
    public function settings_form()
    {
        $user_id = (int) $this->rc->user->ID;
        $credentials = $this->store->list_by_user($user_id);

        $intro = html::p(['class' => 'hint'], rcube::Q($this->gettext('passkeysexplain')));

        // The table is always rendered (with headers) so the client can add and
        // remove rows without having to reconstruct the whole table markup.
        $table = new html_table(['cols' => 4, 'class' => 'records-table passkeys-table', 'id' => 'passkeys-list']);
        $table->add_header('name', rcube::Q($this->gettext('passkeyname')));
        $table->add_header('created', rcube::Q($this->gettext('passkeycreated')));
        $table->add_header('lastused', rcube::Q($this->gettext('passkeylastused')));
        $table->add_header('actions', '');

        if (empty($credentials)) {
            $table->add_row(['class' => 'passkeys-empty-row']);
            $table->add(['colspan' => 4, 'class' => 'passkeys-empty'], rcube::Q($this->gettext('nopasskeys')));
        } else {
            foreach ($credentials as $cred) {
                $this->add_credential_row($table, $cred);
            }
        }

        // "Add a passkey" button
        $add_button = $this->rc->output->button([
            'command' => 'plugin.passkeys.add',
            'type' => 'input',
            'class' => 'button mainaction add',
            'label' => 'passkeys.addpasskey',
        ]);
        $form_buttons = html::p(['class' => 'formbuttons footerleft'], $add_button);

        return html::div(['id' => 'prefs-title', 'class' => 'boxtitle'], rcube::Q($this->gettext('passkeys')))
            . html::div(['class' => 'box formcontainer scroller'],
                html::div(['class' => 'boxcontent formcontent'], $intro . $table->show()) . $form_buttons
            );
    }

    /**
     * Append one credential row to the management table. passkeys_row() in
     * passkeys.js builds the same markup for rows added or updated later.
     */
    private function add_credential_row(html_table $table, array $cred)
    {
        $row = $this->credential_row_data($cred);
        $name = rcube::Q($row['label']);
        $actions = '';

        if ($row['stale']) {
            $name .= ' ' . html::span('passkeys-stale', rcube::Q($this->gettext('passkeyneedsupdate')));
            $actions .= html::a([
                'href' => '#',
                'class' => 'button update',
                'data-passkeys-update' => $row['id'],
            ], rcube::Q($this->gettext('updatepasskey'))) . ' ';
        }

        $actions .= html::a([
            'href' => '#',
            'class' => 'button delete',
            'title' => $this->gettext('removepasskey'),
            'data-passkeys-remove' => $row['id'],
        ], rcube::Q($this->gettext('removepasskey')));

        $table->add_row(['data-credential-id' => $row['id']]);
        $table->add('name', $name);
        $table->add('created', rcube::Q($row['created']));
        $table->add('lastused', rcube::Q($row['lastused']));
        $table->add('actions', $actions);
    }

    /**
     * Normalize a stored credential row into the display fields used by both
     * the server-rendered table and the client-side row insertion.
     *
     * @return array{id: string, label: string, created: string, lastused: string, stale: bool}
     */
    private function credential_row_data(array $cred)
    {
        return [
            'id' => $cred['credential_id'],
            'label' => $cred['label'] ?: $this->gettext('unnamedpasskey'),
            'created' => $this->rc->format_date($cred['created']),
            'lastused' => !empty($cred['last_used'])
                ? $this->rc->format_date($cred['last_used'])
                : $this->gettext('passkeyneverused'),
            'stale' => !empty($cred['stale']) || empty($cred['wrapped_secret']),
        ];
    }

    /**
     * AJAX: check the typed password and issue a WebAuthn registration
     * challenge for the current user.
     */
    public function action_reg_challenge()
    {
        $this->check_request();

        if (!$this->verify_password()) {
            $this->rc->output->send();
        }

        $wa = $this->get_webauthn();
        if (!$wa) {
            $this->rc->output->show_message($this->gettext('libmissing'), 'error');
            $this->rc->output->send();
        }

        $user = $this->rc->user;
        $user_id = (int) $user->ID;
        $username = $user->get_username();
        $displayname = $this->rc->get_user_name() ?: $username;
        $require_uv = (bool) $this->rc->config->get('passkeys_require_uv', true);
        $timeout = (int) $this->rc->config->get('passkeys_timeout', 60);

        // Exclude already-enrolled credentials so the same authenticator is not
        // registered twice.
        $exclude = [];
        foreach ($this->store->list_by_user($user_id) as $cred) {
            $exclude[] = self::b64url_decode($cred['credential_id']);
        }

        try {
            $args = $wa->getCreateArgs(
                (string) $user_id,   // user handle (reversible to the user id on login)
                $username,
                $displayname,
                $timeout,
                true,                // discoverable/resident key (needed for usernameless login)
                $require_uv,
                null,                // allow both platform and cross-platform authenticators
                $exclude
            );
        } catch (Exception $e) {
            rcube::raise_error($e, true, false);
            $this->rc->output->show_message($this->gettext('passkeyadderror'), 'error');
            $this->rc->output->send();
        }

        // Remember the challenge to validate the response against. Stored
        // base64url-encoded so it survives Roundcube's text-based session store.
        $_SESSION['passkeys_reg_challenge'] = self::b64url_encode($wa->getChallenge()->getBinaryString());

        // The client encrypts the password the user just typed with a key
        // derived from the passkey (PRF extension) and sends back only the
        // ciphertext, which the server cannot decrypt.
        $this->rc->output->command('passkeys_create', [
            'args' => $args,
            'prf_salt' => self::b64url_encode($this->prf_salt()),
        ]);
        $this->rc->output->send();
    }

    /**
     * AJAX: validate and store a newly registered passkey.
     */
    public function action_register()
    {
        $this->check_request();

        $wa = $this->get_webauthn();
        $stored_challenge = $_SESSION['passkeys_reg_challenge'] ?? null;
        $this->rc->session->remove('passkeys_reg_challenge');

        if (!$wa || !$stored_challenge) {
            $this->rc->output->show_message($this->gettext('passkeyadderror'), 'error');
            $this->rc->output->send();
        }

        $challenge = self::b64url_decode($stored_challenge);
        $client_data = self::b64url_decode(rcube_utils::get_input_string('_clientDataJSON', rcube_utils::INPUT_POST));
        $attestation = self::b64url_decode(rcube_utils::get_input_string('_attestationObject', rcube_utils::INPUT_POST));
        $label = trim(rcube_utils::get_input_string('_label', rcube_utils::INPUT_POST));
        $transports = rcube_utils::get_input_string('_transports', rcube_utils::INPUT_POST);
        $wrapped_secret = rcube_utils::get_input_string('_wrapped_secret', rcube_utils::INPUT_POST);
        $wrap_iv = rcube_utils::get_input_string('_wrap_iv', rcube_utils::INPUT_POST);
        $require_uv = (bool) $this->rc->config->get('passkeys_require_uv', true);

        // Without the PRF-wrapped password the passkey could never sign in.
        if ($wrapped_secret === '' || $wrap_iv === '') {
            $this->rc->output->show_message($this->gettext('noprf'), 'error');
            $this->rc->output->send();
        }

        try {
            // failIfRootMismatch = false: self-attested / "none" format passkeys
            // have no attestation root to validate against.
            $data = $wa->processCreate($client_data, $attestation, $challenge, $require_uv, true, false);
        } catch (Throwable $e) {
            rcube::raise_error($e, true, false);
            $this->rc->output->show_message($this->gettext('passkeyadderror'), 'error');
            $this->rc->output->send();
        }

        $credential_id = self::b64url_encode(self::bytes($data->credentialId));
        $aaguid = !empty($data->AAGUID) ? bin2hex(self::bytes($data->AAGUID)) : null;

        $ok = $this->store->insert([
            'credential_id' => $credential_id,
            'user_id' => (int) $this->rc->user->ID,
            'public_key' => $data->credentialPublicKey,
            'sign_count' => (int) ($data->signatureCounter ?? 0),
            'aaguid' => $aaguid,
            'label' => $label !== '' ? $label : null,
            'transports' => $transports !== '' ? $transports : null,
            'prf_supported' => 1,
            'wrapped_secret' => $wrapped_secret,
            'wrap_iv' => $wrap_iv,
        ]);

        if (!$ok) {
            $this->rc->output->show_message($this->gettext('passkeyadderror'), 'error');
            $this->rc->output->send();
        }

        $row = $this->credential_row_data([
            'credential_id' => $credential_id,
            'label' => $label,
            'created' => date('Y-m-d H:i:s'),
            'last_used' => null,
            'wrapped_secret' => $wrapped_secret,
        ]);

        $this->rc->output->command('passkeys_add_row', $row);
        $this->rc->output->show_message($this->gettext('passkeyadded'), 'confirmation');
        $this->rc->output->send();
    }

    /**
     * AJAX: start updating a passkey that holds an old password: check the
     * typed password, then ask that passkey for an assertion and PRF output.
     */
    public function action_update_challenge()
    {
        $this->check_request();

        $cred_id = rcube_utils::get_input_string('_credential_id', rcube_utils::INPUT_POST);
        $cred = $cred_id !== '' ? $this->store->get($this->rc->user->ID, $cred_id) : null;
        $wa = $this->get_webauthn();

        if (!$cred || !$wa) {
            $this->rc->output->show_message($this->gettext('passkeyupdateerror'), 'error');
            $this->rc->output->send();
        }

        if (!$this->verify_password()) {
            $this->rc->output->send();
        }

        $require_uv = (bool) $this->rc->config->get('passkeys_require_uv', true);
        $timeout = (int) $this->rc->config->get('passkeys_timeout', 60);

        try {
            $args = $wa->getGetArgs([self::b64url_decode($cred_id)], $timeout, true, true, true, true, true, $require_uv);
        } catch (Throwable $e) {
            rcube::raise_error($e, true, false);
            $this->rc->output->show_message($this->gettext('passkeyupdateerror'), 'error');
            $this->rc->output->send();
        }

        $_SESSION['passkeys_update_challenge'] = [
            'credential' => $cred_id,
            'challenge' => self::b64url_encode($wa->getChallenge()->getBinaryString()),
        ];

        $this->rc->output->command('passkeys_update_auth', [
            'args' => $args,
            'prf_salt' => self::b64url_encode($this->prf_salt()),
        ]);
        $this->rc->output->send();
    }

    /**
     * AJAX: verify the passkey's assertion and store the password it wrapped
     * with its PRF output in place of the old one.
     */
    public function action_update()
    {
        $this->check_request();

        $pending = $_SESSION['passkeys_update_challenge'] ?? null;
        $this->rc->session->remove('passkeys_update_challenge');

        $user_id = (int) $this->rc->user->ID;
        $id = rcube_utils::get_input_string('_id', rcube_utils::INPUT_POST);
        $client_data = self::b64url_decode(rcube_utils::get_input_string('_clientDataJSON', rcube_utils::INPUT_POST));
        $auth_data = self::b64url_decode(rcube_utils::get_input_string('_authenticatorData', rcube_utils::INPUT_POST));
        $signature = self::b64url_decode(rcube_utils::get_input_string('_signature', rcube_utils::INPUT_POST));
        $wrapped_secret = rcube_utils::get_input_string('_wrapped_secret', rcube_utils::INPUT_POST);
        $wrap_iv = rcube_utils::get_input_string('_wrap_iv', rcube_utils::INPUT_POST);
        $require_uv = (bool) $this->rc->config->get('passkeys_require_uv', true);

        $cred = is_array($pending) && $id !== '' && hash_equals($pending['credential'], $id)
            ? $this->store->get($user_id, $id) : null;
        $wa = $this->get_webauthn();

        if (!$cred || !$wa || $wrapped_secret === '' || $wrap_iv === '') {
            $this->rc->output->show_message($this->gettext('passkeyupdateerror'), 'error');
            $this->rc->output->send();
        }

        try {
            $wa->processGet($client_data, $auth_data, $signature, $cred['public_key'],
                self::b64url_decode($pending['challenge']), (int) $cred['sign_count'], $require_uv);
        } catch (Throwable $e) {
            rcube::raise_error($e, true, false);
            $this->rc->output->show_message($this->gettext('passkeyupdateerror'), 'error');
            $this->rc->output->send();
        }

        if (!$this->store->update_secret($user_id, $id, $wrapped_secret, $wrap_iv, self::sign_count($auth_data, $cred))) {
            $this->rc->output->show_message($this->gettext('passkeyupdateerror'), 'error');
            $this->rc->output->send();
        }

        $this->rc->output->command('passkeys_update_row', $this->credential_row_data($this->store->get($user_id, $id)));
        $this->rc->output->show_message($this->gettext('passkeyupdated'), 'confirmation');
        $this->rc->output->send();
    }

    /**
     * AJAX (login page, via startup hook): issue an assertion challenge for a
     * discoverable passkey. No user is known yet — the authenticator returns
     * the user handle.
     */
    public function action_auth_challenge()
    {
        $this->check_request();

        $wa = $this->get_webauthn();
        if (!$wa) {
            $this->login_error('libmissing');
        }

        $require_uv = (bool) $this->rc->config->get('passkeys_require_uv', true);
        $timeout = (int) $this->rc->config->get('passkeys_timeout', 60);

        try {
            // Empty credential id list => usernameless/discoverable login.
            $args = $wa->getGetArgs([], $timeout, true, true, true, true, true, $require_uv);
        } catch (Throwable $e) {
            rcube::raise_error($e, true, false);
            $this->login_error('loginfailed');
        }

        $_SESSION['passkeys_auth_challenge'] = self::b64url_encode($wa->getChallenge()->getBinaryString());

        $this->rc->output->command('passkeys_authenticate', [
            'args' => $args,
            'prf_salt' => self::b64url_encode($this->prf_salt()),
        ]);
        $this->rc->output->send();
    }

    /**
     * AJAX (login page, via startup hook): verify a passkey assertion and, on
     * success, release the wrapped IMAP password so the client can decrypt it
     * and complete a normal login. The assertion is the gate that authorizes
     * releasing the (still PRF-encrypted) secret.
     *
     * Brute force: the owner's account lockout (login_rate_limit) applies as
     * for password logins, failed assertions count towards it, and failures
     * are written to the userlogins log in core's format (fail2ban).
     */
    public function action_assert()
    {
        $this->check_request();

        $wa = $this->get_webauthn();
        $stored = $_SESSION['passkeys_auth_challenge'] ?? null;
        // One attempt per challenge. Not unset(): Roundcube merges the stored
        // session into the new one on write, only remove() deletes a key.
        $this->rc->session->remove('passkeys_auth_challenge');

        if (!$wa || !$stored) {
            $this->login_error('loginfailed');
        }

        $challenge = self::b64url_decode($stored);
        $id = rcube_utils::get_input_string('_id', rcube_utils::INPUT_POST);
        $client_data = self::b64url_decode(rcube_utils::get_input_string('_clientDataJSON', rcube_utils::INPUT_POST));
        $auth_data = self::b64url_decode(rcube_utils::get_input_string('_authenticatorData', rcube_utils::INPUT_POST));
        $signature = self::b64url_decode(rcube_utils::get_input_string('_signature', rcube_utils::INPUT_POST));
        $require_uv = (bool) $this->rc->config->get('passkeys_require_uv', true);

        $cred = $id !== '' ? $this->store->get_by_credential_id($id) : null;
        $user = $cred ? new rcube_user((int) $cred['user_id']) : null;
        $username = $user && $user->ID ? $user->get_username() : null;

        if (!$username) {
            // Unknown passkey, e.g. removed here but still on the device. Only
            // a well-formed id goes into the log (no forged log lines).
            $this->rc->log_login('passkey ' . (preg_match('/^[A-Za-z0-9_-]{1,64}/', $id, $m) ? substr($m[0], 0, 16) : '?'), true);
            $this->login_error('loginfailed');
        }

        if ($user->is_locked()) {
            $this->rc->log_login($username, true, rcmail::ERROR_RATE_LIMIT);
            $this->login_error('accountlocked');
        }

        try {
            $wa->processGet($client_data, $auth_data, $signature, $cred['public_key'],
                $challenge, (int) $cred['sign_count'], $require_uv);
        } catch (Throwable $e) {
            rcube::raise_error($e, true, false);
            $user->failed_login();
            $this->rc->log_login($username, true);
            $this->login_error('loginfailed');
        }

        // Advance the signature counter (cloned-authenticator detection) and
        // stamp last-used.
        $this->store->update_sign_count($id, self::sign_count($auth_data, $cred));

        // The passkey is genuine but its stored password no longer works: send
        // the user to the password form rather than into a failed IMAP login.
        if (!empty($cred['stale']) || empty($cred['wrapped_secret'])) {
            $this->rc->output->command('passkeys_stale', ['username' => $username]);
            $this->rc->output->send();
        }

        // Lets the login request tell a failure of this password apart (see
        // login_startup() and login_failed()).
        $_SESSION['passkeys_login'] = ['credential' => $id, 'user' => $username, 'time' => time()];

        $this->rc->output->command('passkeys_unwrap', [
            'credential' => $id,
            'username' => $username,
            'wrapped_secret' => $cred['wrapped_secret'],
            'wrap_iv' => $cred['wrap_iv'],
        ]);
        $this->rc->output->send();
    }

    /**
     * AJAX: remove one of the current user's passkeys.
     */
    public function action_remove()
    {
        $this->check_request();

        $user_id = (int) $this->rc->user->ID;
        $cred_id = rcube_utils::get_input_string('_credential_id', rcube_utils::INPUT_POST);

        if ($cred_id !== '' && $this->store->remove($user_id, $cred_id)) {
            $this->rc->output->command('passkeys_remove_row', $cred_id);
            $this->rc->output->show_message($this->gettext('passkeyremoved'), 'confirmation');
        } else {
            $this->rc->output->show_message($this->gettext('passkeyremoveerror'), 'error');
        }

        $this->rc->output->send();
    }

    /**
     * AJAX: rename one of the current user's passkeys.
     */
    public function action_rename()
    {
        $this->check_request();

        $user_id = (int) $this->rc->user->ID;
        $cred_id = rcube_utils::get_input_string('_credential_id', rcube_utils::INPUT_POST);
        $label = trim(rcube_utils::get_input_string('_label', rcube_utils::INPUT_POST));

        if ($cred_id !== '' && $label !== '' && $this->store->rename($user_id, $cred_id, $label)) {
            $this->rc->output->command('passkeys_rename_row', ['id' => $cred_id, 'label' => $label]);
            $this->rc->output->show_message($this->gettext('successfullysaved'), 'confirmation');
        } else {
            $this->rc->output->show_message($this->gettext('passkeyrenameerror'), 'error');
        }

        $this->rc->output->send();
    }

    /**
     * CSRF protection for the plugin's AJAX endpoints: a POST carrying the
     * session's request token in the X-Roundcube-Request header, which
     * rcmail.http_post() always sends and a cross-site page cannot set. Core
     * checks the token before authenticated actions too, but the login
     * endpoints run in the startup hook, before any of core's checks.
     */
    private function check_request()
    {
        $token = rcube_utils::request_header('X-Roundcube-Request');

        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !is_string($token)
            || !hash_equals($this->rc->get_request_token(), $token)
        ) {
            rcube::raise_error(['code' => 403, 'message' => 'passkeys: request security check failed'], true, true);
        }
    }

    /**
     * Check the password typed into the add/update dialog against the one this
     * session logged in with. Wrapping the password is done with what the user
     * types, so the server never hands the session's password to the browser
     * (where a hijacked session or an XSS could read it). Wrong guesses count
     * towards the account lockout like failed logins. Shows the error.
     */
    private function verify_password()
    {
        $user = $this->rc->user;
        $charset = $this->rc->config->get('password_charset', 'UTF-8');
        $password = rcube_utils::get_input_string('_password', rcube_utils::INPUT_POST, true, $charset);

        if ($user->is_locked()) {
            $this->rc->output->show_message('accountlocked', 'error');
            return false;
        }

        if ($password === '' || !hash_equals((string) $this->rc->decrypt($_SESSION['password']), $password)) {
            $user->failed_login();
            $this->rc->output->show_message($this->gettext('passwordincorrect'), 'error');
            return false;
        }

        return true;
    }

    /**
     * The verified passkey sign-in a login form submission completes: set by
     * action_assert() in this session, named by the form, for the same user,
     * and recent.
     *
     * @return array{credential: string, user: string, time: int}|null
     */
    private function pending_passkey_login()
    {
        $marker = $_SESSION['passkeys_login'] ?? null;
        $posted = rcube_utils::get_input_string('_passkeys_credential', rcube_utils::INPUT_POST);
        $user = trim(rcube_utils::get_input_string('_user', rcube_utils::INPUT_POST));

        if (is_array($marker) && $posted !== '' && hash_equals($marker['credential'], $posted)
            && $user === $marker['user'] && time() - $marker['time'] < 300
        ) {
            return $marker;
        }

        return null;
    }

    /**
     * Send a login-page error to the client and end the request.
     */
    private function login_error($label)
    {
        $this->rc->output->command('passkeys_login_error', $this->gettext($label));
        $this->rc->output->send();
    }

    /**
     * Build a configured WebAuthn instance, or null when the library is not
     * available.
     *
     * @return WebAuthn|null
     */
    private function get_webauthn()
    {
        if (!class_exists('lbuchs\\WebAuthn\\WebAuthn')) {
            rcube::raise_error('passkeys: lbuchs/webauthn library not installed', true, false);
            return null;
        }

        $formats = (array) $this->rc->config->get('passkeys_formats', ['none', 'packed', 'apple', 'fido-u2f']);

        try {
            // 4th argument enables base64url encoding of the outgoing ByteBuffer
            // values (challenge, ids) so the client can decode them directly.
            return new WebAuthn($this->rp_name(), $this->rp_id(), $formats, true);
        } catch (Throwable $e) {
            rcube::raise_error($e, true, false);
            return null;
        }
    }

    /**
     * Relying Party ID: the registrable domain the users reach Roundcube on.
     *
     * Derived from the Host the browser used (port stripped, subject to
     * trusted_host_patterns), not SERVER_NAME: behind a reverse proxy or with
     * a catch-all vhost SERVER_NAME is often "_", "localhost" or an internal
     * name, and WebAuthn then fails with an origin mismatch.
     */
    private function rp_id()
    {
        $rp_id = $this->rc->config->get('passkeys_rp_id');

        if (empty($rp_id)) {
            $rp_id = rcube_utils::server_name('HTTP_HOST');
        }

        return $rp_id;
    }

    /**
     * Relying Party display name shown in the authenticator prompt.
     */
    private function rp_name()
    {
        return $this->rc->config->get('passkeys_rp_name')
            ?: ($this->rc->config->get('product_name') ?: 'Roundcube Webmail');
    }

    /**
     * Fixed salt for the WebAuthn PRF evaluation.
     *
     * The real entropy of the wrapping key comes from the authenticator's
     * per-credential secret; this salt only has to be stable across enrolment
     * and login, so a constant (optionally overridden per install) is fine.
     *
     * @return string 32 raw bytes
     */
    private function prf_salt()
    {
        $seed = $this->rc->config->get('passkeys_prf_salt', 'roundcube-passkeys-prf-v1');

        return hash('sha256', (string) $seed, true);
    }

    /**
     * The signature counter of a verified assertion (authenticator data bytes
     * 33-36), never below the stored one. Authenticators without a counter
     * always report 0; lbuchs/webauthn already rejects a real regression.
     */
    private static function sign_count($auth_data, array $cred)
    {
        $counter = (int) $cred['sign_count'];

        if (strlen($auth_data) >= 37) {
            $unpacked = unpack('N', substr($auth_data, 33, 4));
            $counter = max($counter, (int) ($unpacked[1] ?? 0));
        }

        return $counter;
    }

    /**
     * Raw bytes of a value that may be a ByteBuffer or already a binary string.
     */
    private static function bytes($value)
    {
        if ($value instanceof ByteBuffer) {
            return $value->getBinaryString();
        }

        return (string) $value;
    }

    /**
     * URL-safe base64 encode without padding.
     */
    private static function b64url_encode($bin)
    {
        return rtrim(strtr(base64_encode((string) $bin), '+/', '-_'), '=');
    }

    /**
     * URL-safe base64 decode (tolerates missing padding).
     */
    private static function b64url_decode($str)
    {
        $str = strtr((string) $str, '-_', '+/');
        $pad = strlen($str) % 4;
        if ($pad) {
            $str .= str_repeat('=', 4 - $pad);
        }

        return base64_decode($str);
    }
}
