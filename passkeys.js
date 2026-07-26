/**
 * Client script for the Passkeys plugin.
 *
 * Settings task: list/remove passkeys and the WebAuthn registration ceremony,
 * including wrapping the IMAP password with a key derived from the passkey
 * (PRF extension).
 *
 * Login task: the "Sign in with a passkey" ceremony — assert, unwrap the
 * password client-side, then submit the standard login form so the normal
 * password/2FA path completes the sign-in.
 */

if (window.rcmail) {
    rcmail.addEventListener('init', function () {
        var action = rcmail.env.action || '';

        if (rcmail.env.task == 'settings' && /^plugin\.passkeys/.test(action)) {
            rcmail.register_command('plugin.passkeys.add', function () {
                rcmail.passkeys_add();
            }, true);

            // Delegated handler for the per-row remove links (works for both
            // server-rendered and dynamically inserted rows).
            $(document).on('click', 'a[data-passkeys-remove]', function (e) {
                e.preventDefault();
                rcmail.passkeys_remove($(this).attr('data-passkeys-remove'));
            });
        }

        if (rcmail.env.task == 'login') {
            rcmail.passkeys_init_login();
        }
    });
}

/**
 * Whether this browser can do WebAuthn at all.
 */
rcube_webmail.prototype.passkeys_supported = function () {
    return !!(window.PublicKeyCredential && navigator.credentials
        && navigator.credentials.create && navigator.credentials.get
        && window.crypto && window.crypto.subtle);
};

/* ------------------------------------------------------------------ *
 *  Enrolment (Settings)                                               *
 * ------------------------------------------------------------------ */

/**
 * Start enrolling a new passkey: fetch a registration challenge.
 */
rcube_webmail.prototype.passkeys_add = function () {
    if (!this.passkeys_supported()) {
        this.display_message(this.get_label('notsupported', 'passkeys'), 'error');
        return;
    }

    this.http_post('plugin.passkeys.reg-challenge', {}, this.set_busy(true, 'loading'));
};

/**
 * Server callback: run navigator.credentials.create(), derive the PRF secret,
 * wrap the IMAP password with it, and submit everything for storage.
 *
 * @param {object} data {args, prf_salt, password, on_no_prf}
 */
rcube_webmail.prototype.passkeys_create = function (data) {
    var ref = this;
    var args = data.args;
    var salt = this.passkeys_b64url_to_buf(data.prf_salt);
    var password = data.password;
    var on_no_prf = data.on_no_prf || 'reject';

    try {
        args.publicKey.challenge = this.passkeys_b64url_to_buf(args.publicKey.challenge);
        args.publicKey.user.id = this.passkeys_b64url_to_buf(args.publicKey.user.id);
        (args.publicKey.excludeCredentials || []).forEach(function (c) {
            c.id = ref.passkeys_b64url_to_buf(c.id);
        });
        args.publicKey.extensions = args.publicKey.extensions || {};
        args.publicKey.extensions.prf = { eval: { first: salt } };
    } catch (e) {
        this.display_message(this.get_label('weberror', 'passkeys'), 'error');
        return;
    }

    var created;

    navigator.credentials.create(args)
        .then(function (credential) {
            created = credential;
            return ref.passkeys_obtain_prf(credential, salt).catch(function () {
                if (on_no_prf === 'second_factor') {
                    return null;  // enrol without passwordless capability
                }
                throw new Error('no-prf');
            });
        })
        .then(function (prf) {
            var response = created.response;
            var transports = '';
            if (typeof response.getTransports === 'function') {
                try { transports = (response.getTransports() || []).join(','); } catch (e) { /* optional */ }
            }

            var label = window.prompt(ref.get_label('passkeynameprompt', 'passkeys'), '');
            if (label === null) {
                ref.display_message(ref.get_label('passkeyaddcancelled', 'passkeys'), 'notice');
                return;
            }

            var post = {
                _clientDataJSON: ref.passkeys_buf_to_b64url(response.clientDataJSON),
                _attestationObject: ref.passkeys_buf_to_b64url(response.attestationObject),
                _transports: transports,
                _label: label.replace(/^\s+|\s+$/g, '')
            };

            if (!prf) {
                post._prf_supported = 0;
                ref.http_post('plugin.passkeys.register', post, ref.set_busy(true, 'loading'));
                return;
            }

            return ref.passkeys_wrap(prf, password).then(function (wrapped) {
                post._wrapped_secret = wrapped.wrapped_secret;
                post._wrap_iv = wrapped.wrap_iv;
                post._prf_supported = 1;
                ref.http_post('plugin.passkeys.register', post, ref.set_busy(true, 'loading'));
            });
        })
        .catch(function (err) {
            ref.passkeys_report_error(err);
        });
};

/**
 * Ask for confirmation and remove a passkey.
 */
rcube_webmail.prototype.passkeys_remove = function (cred_id) {
    if (!cred_id) {
        return;
    }

    var ref = this;
    this.confirm_dialog(this.get_label('passkeyremoveconfirm', 'passkeys'), 'delete', function () {
        ref.http_post('plugin.passkeys.remove', { _credential_id: cred_id }, ref.set_busy(true, 'loading'));
    });
};

/**
 * Server callback: append a freshly enrolled credential to the table.
 */
rcube_webmail.prototype.passkeys_add_row = function (o) {
    var $table = $('#passkeys-list');

    $table.find('tr.passkeys-empty-row').remove();

    var $remove = $('<a>')
        .attr({ href: '#', 'class': 'button delete', 'data-passkeys-remove': o.id })
        .attr('title', this.get_label('removepasskey', 'passkeys'))
        .text(this.get_label('removepasskey', 'passkeys'));

    var $row = $('<tr>').attr('data-credential-id', o.id);
    $('<td>').addClass('name').text(o.label).appendTo($row);
    $('<td>').addClass('created').text(o.created).appendTo($row);
    $('<td>').addClass('lastused').text(o.lastused).appendTo($row);
    $('<td>').addClass('actions').append($remove).appendTo($row);

    $table.find('tbody').append($row);
};

/**
 * Server callback: drop a removed credential's row from the table.
 */
rcube_webmail.prototype.passkeys_remove_row = function (cred_id) {
    var $table = $('#passkeys-list');

    $table.find('tr[data-credential-id="' + cred_id + '"]').remove();

    if (!$table.find('tbody tr').length) {
        var $cell = $('<td>').attr('colspan', 4).addClass('passkeys-empty')
            .text(this.get_label('nopasskeys', 'passkeys'));
        $table.find('tbody').append($('<tr>').addClass('passkeys-empty-row').append($cell));
    }
};

/* ------------------------------------------------------------------ *
 *  Passwordless login                                                 *
 * ------------------------------------------------------------------ */

/**
 * Reveal the passkey divider and button on the login form. They are rendered
 * (hidden) by the server via the loginform_content hook on every skin; here we
 * only unhide them when the browser actually supports WebAuthn, so the "or sign
 * in using passkeys" divider never shows without a working button.
 */
rcube_webmail.prototype.passkeys_init_login = function () {
    if (this.passkeys_supported()) {
        document.body.className += (document.body.className ? ' ' : '') + 'passkeys-available';
    }
};

/**
 * Kick off the passwordless login ceremony: fetch an assertion challenge.
 */
rcube_webmail.prototype.passkeys_login = function () {
    if (!this.passkeys_supported()) {
        this.display_message(this.get_label('notsupported', 'passkeys'), 'error');
        return false;
    }

    this.http_post('plugin.passkeys.auth-challenge', {}, this.set_busy(true, 'loading'));
    return false;
};

/**
 * Server callback: run navigator.credentials.get() with the PRF extension,
 * keep the PRF output, and submit the assertion for verification.
 *
 * @param {object} data {args, prf_salt}
 */
rcube_webmail.prototype.passkeys_authenticate = function (data) {
    var ref = this;
    var args = data.args;
    var salt = this.passkeys_b64url_to_buf(data.prf_salt);

    try {
        args.publicKey.challenge = this.passkeys_b64url_to_buf(args.publicKey.challenge);
        (args.publicKey.allowCredentials || []).forEach(function (c) {
            c.id = ref.passkeys_b64url_to_buf(c.id);
        });
        args.publicKey.extensions = args.publicKey.extensions || {};
        args.publicKey.extensions.prf = { eval: { first: salt } };
    } catch (e) {
        this.display_message(this.get_label('weberror', 'passkeys'), 'error');
        return;
    }

    navigator.credentials.get(args)
        .then(function (assertion) {
            var r = assertion.response;
            var ext = assertion.getClientExtensionResults();

            if (!ext.prf || !ext.prf.results || !ext.prf.results.first) {
                ref.display_message(ref.get_label('noprf', 'passkeys'), 'error');
                return;
            }

            ref._passkeys_prf = new Uint8Array(ext.prf.results.first);

            ref.http_post('plugin.passkeys.assert', {
                _id: assertion.id,
                _clientDataJSON: ref.passkeys_buf_to_b64url(r.clientDataJSON),
                _authenticatorData: ref.passkeys_buf_to_b64url(r.authenticatorData),
                _signature: ref.passkeys_buf_to_b64url(r.signature),
                _userHandle: r.userHandle ? ref.passkeys_buf_to_b64url(r.userHandle) : ''
            }, ref.set_busy(true, 'loading'));
        })
        .catch(function (err) {
            ref.passkeys_report_error(err);
        });
};

/**
 * Server callback: decrypt the wrapped IMAP password with the PRF output and
 * complete a normal login.
 *
 * @param {object} data {username, wrapped_secret, wrap_iv}
 */
rcube_webmail.prototype.passkeys_unwrap = function (data) {
    var ref = this;
    var prf = this._passkeys_prf;

    if (!prf) {
        this.display_message(this.get_label('weberror', 'passkeys'), 'error');
        return;
    }

    var ct = this.passkeys_b64url_to_buf(data.wrapped_secret);
    var iv = this.passkeys_b64url_to_buf(data.wrap_iv);

    window.crypto.subtle.importKey('raw', prf, { name: 'AES-GCM' }, false, ['decrypt'])
        .then(function (key) {
            return window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
        })
        .then(function (pt) {
            ref._passkeys_prf = null;
            ref.passkeys_submit_login(data.username, new TextDecoder().decode(pt));
        })
        .catch(function () {
            ref._passkeys_prf = null;
            ref.display_message(ref.get_label('weberror', 'passkeys'), 'error');
        });
};

/**
 * Server callback: show a login error.
 */
rcube_webmail.prototype.passkeys_login_error = function (msg) {
    this.display_message(msg || this.get_label('weberror', 'passkeys'), 'error');
};

/**
 * Fill and submit the standard login form so the normal password/2FA login
 * path runs, exactly as if the user had typed their password.
 */
rcube_webmail.prototype.passkeys_submit_login = function (username, password) {
    var form = (this.gui_objects && this.gui_objects.loginform) || document.forms['login-form'];

    if (!form) {
        this.display_message(this.get_label('weberror', 'passkeys'), 'error');
        return;
    }

    $('#rcmloginuser', form).val(username);
    $('#rcmloginpwd', form).val(password);

    form.submit();
};

/* ------------------------------------------------------------------ *
 *  PRF / crypto helpers                                               *
 * ------------------------------------------------------------------ */

/**
 * Obtain the PRF output for a freshly created credential. Prefers the value
 * returned inline by create(); falls back to an extra get() when the platform
 * only reports the extension as enabled.
 *
 * @return {Promise<Uint8Array>}
 */
rcube_webmail.prototype.passkeys_obtain_prf = function (credential, salt) {
    var ext = credential.getClientExtensionResults();

    if (ext.prf && ext.prf.results && ext.prf.results.first) {
        return Promise.resolve(new Uint8Array(ext.prf.results.first));
    }

    if (ext.prf && ext.prf.enabled) {
        return this.passkeys_prf_via_get(credential.rawId, salt);
    }

    return Promise.reject(new Error('no-prf'));
};

/**
 * Fetch a PRF output via an immediate get() against a specific credential.
 * The challenge here is local-only (used solely to evaluate the PRF, not for
 * authentication), so a random value is fine.
 *
 * @return {Promise<Uint8Array>}
 */
rcube_webmail.prototype.passkeys_prf_via_get = function (rawId, salt) {
    return navigator.credentials.get({
        publicKey: {
            challenge: window.crypto.getRandomValues(new Uint8Array(32)),
            allowCredentials: [{ type: 'public-key', id: rawId }],
            userVerification: 'preferred',
            timeout: 60000,
            extensions: { prf: { eval: { first: salt } } }
        }
    }).then(function (assertion) {
        var ext = assertion.getClientExtensionResults();
        if (ext.prf && ext.prf.results && ext.prf.results.first) {
            return new Uint8Array(ext.prf.results.first);
        }
        throw new Error('no-prf');
    });
};

/**
 * AES-GCM encrypt a string under a raw PRF key.
 *
 * @return {Promise<{wrapped_secret: string, wrap_iv: string}>}
 */
rcube_webmail.prototype.passkeys_wrap = function (prf_bytes, plaintext) {
    var ref = this;
    var iv = window.crypto.getRandomValues(new Uint8Array(12));

    return window.crypto.subtle.importKey('raw', prf_bytes, { name: 'AES-GCM' }, false, ['encrypt'])
        .then(function (key) {
            return window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(plaintext));
        })
        .then(function (ct) {
            return {
                wrapped_secret: ref.passkeys_buf_to_b64url(ct),
                wrap_iv: ref.passkeys_buf_to_b64url(iv.buffer)
            };
        });
};

/**
 * Map an exception from a WebAuthn ceremony to a user-facing message.
 */
rcube_webmail.prototype.passkeys_report_error = function (err) {
    if (err && (err.name == 'NotAllowedError' || err.name == 'AbortError')) {
        this.display_message(this.get_label('passkeyaddcancelled', 'passkeys'), 'notice');
    } else if (err && err.message === 'no-prf') {
        this.display_message(this.get_label('noprf', 'passkeys'), 'error');
    } else {
        this.display_message(this.get_label('weberror', 'passkeys'), 'error');
    }
};

/* ------------------------------------------------------------------ *
 *  base64url helpers                                                  *
 * ------------------------------------------------------------------ */

rcube_webmail.prototype.passkeys_b64url_to_buf = function (str) {
    str = String(str).replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) {
        str += '=';
    }

    var bin = window.atob(str), bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
        bytes[i] = bin.charCodeAt(i);
    }

    return bytes.buffer;
};

rcube_webmail.prototype.passkeys_buf_to_b64url = function (buf) {
    var bytes = new Uint8Array(buf), bin = '';
    for (var i = 0; i < bytes.length; i++) {
        bin += String.fromCharCode(bytes[i]);
    }

    return window.btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
