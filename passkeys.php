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
 * Phase 2 adds the WebAuthn registration ceremony to the Settings tab: a user
 * can enrol a passkey, which is validated server-side and persisted. Binding
 * the IMAP password to the passkey (PRF wrapping) and the passwordless login
 * path are added in later phases, so an enrolled passkey is not yet usable for
 * sign-in.
 *
 * @author Matthias Kerstner
 */
class passkeys extends rcube_plugin
{
    // Active in Settings (enrolment/management) and on the login screen
    // (passwordless sign-in). Never active on logout. This plugin is
    // AJAX-driven, so it must NOT set $noframe/$noajax (those would make the
    // plugin API skip init() for framed/AJAX requests).
    public $task = '?(?!logout).*';

    /** @var rcmail */
    private $rc;

    /** @var rcube_passkeys_store */
    private $store;

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

        if ($this->rc->task == 'settings') {
            $this->add_hook('settings_actions', [$this, 'settings_actions']);

            $this->register_action('plugin.passkeys', [$this, 'settings_page']);
            $this->register_action('plugin.passkeys.reg-challenge', [$this, 'action_reg_challenge']);
            $this->register_action('plugin.passkeys.register', [$this, 'action_register']);
            $this->register_action('plugin.passkeys.remove', [$this, 'action_remove']);
            $this->register_action('plugin.passkeys.rename', [$this, 'action_rename']);

            $this->include_script('passkeys.js');
            $this->include_stylesheet($this->local_skin_path() . '/passkeys.css');
        } elseif ($this->rc->task == 'login') {
            // The login page short-circuits to rendering the login template for
            // unauthenticated requests (index.php), so plugin AJAX actions never
            // reach the normal dispatcher. We handle them in the startup hook,
            // which runs before that short-circuit.
            $this->add_hook('startup', [$this, 'login_startup']);
            $this->add_hook('template_container', [$this, 'login_container']);

            $this->include_script('passkeys.js');
            $this->include_stylesheet($this->local_skin_path() . '/passkeys.css');
        }
    }

    /**
     * Handle the passwordless-login AJAX endpoints before the unauthenticated
     * request is short-circuited to the login page.
     */
    public function login_startup($args)
    {
        if ($args['task'] === 'login' && empty($this->rc->user->ID)) {
            if ($args['action'] === 'plugin.passkeys.auth-challenge') {
                $this->action_auth_challenge();  // sends response and exits
            } elseif ($args['action'] === 'plugin.passkeys.assert') {
                $this->action_assert();          // sends response and exits
            }
        }

        return $args;
    }

    /**
     * Inject the "Sign in with a passkey" button into the login form footer.
     * The button is hidden until the client script confirms WebAuthn support.
     */
    public function login_container($args)
    {
        if ($args['name'] === 'loginfooter') {
            $button = html::tag('button', [
                'type' => 'button',
                'id' => 'passkeys-login-button',
                'class' => 'btn btn-secondary button passkeys-login',
                'style' => 'display:none',
                'onclick' => 'return rcmail.passkeys_login()',
            ], rcube::Q($this->gettext('loginwithpasskey')));

            $args['content'] = ($args['content'] ?? '') . html::div(['id' => 'passkeys-login'], $button);
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
     * Append one credential row to the management table.
     */
    private function add_credential_row(html_table $table, array $cred)
    {
        $row = $this->credential_row_data($cred);

        $remove = html::a([
            'href' => '#',
            'class' => 'button delete',
            'title' => $this->gettext('removepasskey'),
            'data-passkeys-remove' => $row['id'],
        ], rcube::Q($this->gettext('removepasskey')));

        $table->add_row(['data-credential-id' => $row['id']]);
        $table->add('name', rcube::Q($row['label']));
        $table->add('created', rcube::Q($row['created']));
        $table->add('lastused', rcube::Q($row['lastused']));
        $table->add('actions', $remove);
    }

    /**
     * Normalize a stored credential row into the display fields used by both
     * the server-rendered table and the client-side row insertion.
     *
     * @return array{id: string, label: string, created: string, lastused: string}
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
        ];
    }

    /**
     * AJAX: issue a WebAuthn registration challenge for the current user.
     */
    public function action_reg_challenge()
    {
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

        // The client wraps the current IMAP password with a key derived from the
        // passkey (PRF extension) so it can be recovered at passwordless login.
        // The password only transits to the browser over TLS and is never stored
        // server-side in a form the server can decrypt.
        $this->rc->output->command('passkeys_create', [
            'args' => $args,
            'prf_salt' => self::b64url_encode($this->prf_salt()),
            'password' => $this->rc->decrypt($_SESSION['password']),
            'on_no_prf' => $this->rc->config->get('passkeys_on_no_prf', 'reject'),
        ]);
        $this->rc->output->send();
    }

    /**
     * AJAX: validate and store a newly registered passkey.
     */
    public function action_register()
    {
        $wa = $this->get_webauthn();
        $stored_challenge = $_SESSION['passkeys_reg_challenge'] ?? null;

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
        $prf_supported = (bool) rcube_utils::get_input_value('_prf_supported', rcube_utils::INPUT_POST);
        $require_uv = (bool) $this->rc->config->get('passkeys_require_uv', true);

        try {
            // failIfRootMismatch = false: self-attested / "none" format passkeys
            // have no attestation root to validate against.
            $data = $wa->processCreate($client_data, $attestation, $challenge, $require_uv, true, false);
        } catch (Throwable $e) {
            rcube::raise_error($e, true, false);
            unset($_SESSION['passkeys_reg_challenge']);
            $this->rc->output->show_message($this->gettext('passkeyadderror'), 'error');
            $this->rc->output->send();
        }

        unset($_SESSION['passkeys_reg_challenge']);

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
            'prf_supported' => $prf_supported ? 1 : 0,
            'wrapped_secret' => $wrapped_secret !== '' ? $wrapped_secret : null,
            'wrap_iv' => $wrap_iv !== '' ? $wrap_iv : null,
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
        ]);

        $this->rc->output->command('passkeys_add_row', $row);
        $this->rc->output->show_message($this->gettext('passkeyadded'), 'confirmation');
        $this->rc->output->send();
    }

    /**
     * AJAX (login page, via startup hook): issue an assertion challenge for a
     * discoverable passkey. No user is known yet — the authenticator returns
     * the user handle.
     */
    public function action_auth_challenge()
    {
        $wa = $this->get_webauthn();
        if (!$wa) {
            $this->rc->output->command('passkeys_login_error', $this->gettext('libmissing'));
            $this->rc->output->send();
        }

        $require_uv = (bool) $this->rc->config->get('passkeys_require_uv', true);
        $timeout = (int) $this->rc->config->get('passkeys_timeout', 60);

        try {
            // Empty credential id list => usernameless/discoverable login.
            $args = $wa->getGetArgs([], $timeout, true, true, true, true, true, $require_uv);
        } catch (Throwable $e) {
            rcube::raise_error($e, true, false);
            $this->rc->output->command('passkeys_login_error', $this->gettext('loginfailed'));
            $this->rc->output->send();
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
     */
    public function action_assert()
    {
        $wa = $this->get_webauthn();
        $stored = $_SESSION['passkeys_auth_challenge'] ?? null;

        if (!$wa || !$stored) {
            $this->rc->output->command('passkeys_login_error', $this->gettext('loginfailed'));
            $this->rc->output->send();
        }

        $challenge = self::b64url_decode($stored);
        $id = rcube_utils::get_input_string('_id', rcube_utils::INPUT_POST);
        $client_data = self::b64url_decode(rcube_utils::get_input_string('_clientDataJSON', rcube_utils::INPUT_POST));
        $auth_data = self::b64url_decode(rcube_utils::get_input_string('_authenticatorData', rcube_utils::INPUT_POST));
        $signature = self::b64url_decode(rcube_utils::get_input_string('_signature', rcube_utils::INPUT_POST));
        $require_uv = (bool) $this->rc->config->get('passkeys_require_uv', true);

        $cred = $id !== '' ? $this->store->get_by_credential_id($id) : null;

        // The passkey must exist and carry a wrapped password (i.e. it was
        // enrolled with PRF support); otherwise passwordless login is impossible.
        if (!$cred || empty($cred['wrapped_secret'])) {
            unset($_SESSION['passkeys_auth_challenge']);
            $this->rc->output->command('passkeys_login_error', $this->gettext('loginfailed'));
            $this->rc->output->send();
        }

        try {
            $wa->processGet($client_data, $auth_data, $signature, $cred['public_key'],
                $challenge, (int) $cred['sign_count'], $require_uv);
        } catch (Throwable $e) {
            rcube::raise_error($e, true, false);
            unset($_SESSION['passkeys_auth_challenge']);
            $this->rc->output->command('passkeys_login_error', $this->gettext('loginfailed'));
            $this->rc->output->send();
        }

        unset($_SESSION['passkeys_auth_challenge']);

        // Advance the signature counter (cloned-authenticator detection) and
        // stamp last-used.
        $new_counter = (int) $cred['sign_count'];
        if (strlen($auth_data) >= 37) {
            $unpacked = unpack('N', substr($auth_data, 33, 4));
            $new_counter = max($new_counter, (int) ($unpacked[1] ?? 0));
        }
        $this->store->update_sign_count($id, $new_counter);

        // Resolve the login name for this credential's owner.
        $user = new rcube_user((int) $cred['user_id']);
        $username = $user->ID ? $user->get_username() : null;

        if (!$username) {
            $this->rc->output->command('passkeys_login_error', $this->gettext('loginfailed'));
            $this->rc->output->send();
        }

        $this->rc->output->command('passkeys_unwrap', [
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
     */
    private function rp_id()
    {
        $rp_id = $this->rc->config->get('passkeys_rp_id');

        if (empty($rp_id)) {
            $rp_id = rcube_utils::server_name();
            // strip any port component
            if (($pos = strpos($rp_id, ':')) !== false) {
                $rp_id = substr($rp_id, 0, $pos);
            }
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
