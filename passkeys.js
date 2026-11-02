/**
 * Client script for the Passkeys plugin.
 *
 * Settings task: list/remove passkeys, the WebAuthn registration ceremony,
 * and updating a passkey after a password change. Both wrap the password the
 * user types with a key derived from the passkey (PRF extension).
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

            // Delegated handlers for the per-row links (works for both
            // server-rendered and dynamically inserted rows).
            $(document).on('click', 'a[data-passkeys-remove]', function (e) {
                e.preventDefault();
                rcmail.passkeys_remove($(this).attr('data-passkeys-remove'));
            }).on('click', 'a[data-passkeys-update]', function (e) {
                e.preventDefault();
                rcmail.passkeys_update($(this).attr('data-passkeys-update'));
            });

            // A typed password is kept only until the server answers.
            $.each(['reg-challenge', 'update-challenge'], function (i, name) {
                rcmail.addEventListener('responseafterplugin.passkeys.' + name, function () {
                    rcmail._passkeys_pending = null;
                });
            });
        }

        if (rcmail.env.task == 'login') {
            rcmail.passkeys_init_login();
        }

        if (rcmail.env.passkeys_stale_prompt) {
            rcmail.passkeys_stale_prompt();
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
 *  Enrolment and updates (Settings)                                   *
 * ------------------------------------------------------------------ */

/**
 * Start enrolling a new passkey: ask for a name and the current password,
 * then fetch a registration challenge.
 */
rcube_webmail.prototype.passkeys_add = function () {
    var ref = this;

    if (!this.passkeys_supported()) {
        this.display_message(this.get_label('notsupported', 'passkeys'), 'error');
        return;
    }

    this.passkeys_password_dialog('passkeys.addpasskey', 'passkeyaddhint', true, function (label, password) {
        ref._passkeys_pending = { label: label, password: password };
        ref.http_post('plugin.passkeys.reg-challenge', { _password: password }, ref.set_busy(true, 'loading'));
    });
};

/**
 * Server callback: run navigator.credentials.create(), derive the PRF secret,
 * wrap the typed password with it, and submit everything for storage.
 *
 * @param {object} data {args, prf_salt}
 */
rcube_webmail.prototype.passkeys_create = function (data) {
    var ref = this;
    var pending = this.passkeys_take_pending();
    var salt = this.passkeys_b64url_to_buf(data.prf_salt);
    var args, created;

    try {
        args = this.passkeys_options(data.args, salt);
    } catch (e) {
        pending = null;
    }

    if (!pending) {
        this.display_message(this.get_label('weberror', 'passkeys'), 'error');
        return;
    }

    navigator.credentials.create(args)
        .then(function (credential) {
            created = credential;
            return ref.passkeys_obtain_prf(credential, salt);
        })
        .then(function (prf) {
            return ref.passkeys_wrap(prf, pending.password);
        })
        .then(function (wrapped) {
            var response = created.response;
            var transports = '';
            if (typeof response.getTransports === 'function') {
                try { transports = (response.getTransports() || []).join(','); } catch (e) { /* optional */ }
            }

            ref.http_post('plugin.passkeys.register', {
                _clientDataJSON: ref.passkeys_buf_to_b64url(response.clientDataJSON),
                _attestationObject: ref.passkeys_buf_to_b64url(response.attestationObject),
                _transports: transports,
                _label: pending.label,
                _wrapped_secret: wrapped.wrapped_secret,
                _wrap_iv: wrapped.wrap_iv
            }, ref.set_busy(true, 'loading'));
        })
        .catch(function (err) {
            ref.passkeys_report_error(err);
        });
};

/**
 * Update a passkey that still holds an old password: ask for the current
 * password, then fetch an assertion challenge for that passkey.
 */
rcube_webmail.prototype.passkeys_update = function (cred_id) {
    var ref = this;

    if (!this.passkeys_supported()) {
        this.display_message(this.get_label('notsupported', 'passkeys'), 'error');
        return;
    }

    this.passkeys_password_dialog('passkeys.updatepasskey', 'passkeyupdatehint', false, function (label, password) {
        ref._passkeys_pending = { password: password };
        ref.http_post('plugin.passkeys.update-challenge', { _credential_id: cred_id, _password: password },
            ref.set_busy(true, 'loading'));
    });
};

/**
 * Server callback: get an assertion and the PRF output from the passkey being
 * updated, wrap the typed password with it, and submit both.
 *
 * @param {object} data {args, prf_salt}
 */
rcube_webmail.prototype.passkeys_update_auth = function (data) {
    var ref = this;
    var pending = this.passkeys_take_pending();
    var salt = this.passkeys_b64url_to_buf(data.prf_salt);
    var args, assertion;

    try {
        args = this.passkeys_options(data.args, salt);
    } catch (e) {
        pending = null;
    }

    if (!pending) {
        this.display_message(this.get_label('weberror', 'passkeys'), 'error');
        return;
    }

    navigator.credentials.get(args)
        .then(function (result) {
            assertion = result;
            return ref.passkeys_wrap(ref.passkeys_prf_result(assertion), pending.password);
        })
        .then(function (wrapped) {
            var post = ref.passkeys_assertion_post(assertion);
            post._wrapped_secret = wrapped.wrapped_secret;
            post._wrap_iv = wrapped.wrap_iv;
            ref.http_post('plugin.passkeys.update', post, ref.set_busy(true, 'loading'));
        })
        .catch(function (err) {
            ref.passkeys_report_error(err);
        });
};

/**
 * Ask for the current password (and, when adding, a name for the passkey),
 * then call back with both.
 */
rcube_webmail.prototype.passkeys_password_dialog = function (title, hint, with_name, callback) {
    var id = 'passkeys-dialog-' + new Date().getTime();
    var name = $('<input>').attr({ type: 'text', id: id + '-name', 'class': 'form-control', maxlength: 128, 'data-submit': 1 });
    var password = $('<input>').attr({ type: 'password', id: id + '-pass', 'class': 'form-control',
        autocomplete: 'current-password', 'data-submit': 1 });
    var content = $('<div>').addClass('passkeys-dialog')
        .append($('<p>').addClass('hint').text(this.get_label(hint, 'passkeys')));

    if (with_name) {
        content.append(this.passkeys_dialog_field(name, this.get_label('passkeyname', 'passkeys')));
    }
    content.append(this.passkeys_dialog_field(password, this.get_label('passkeypassword', 'passkeys')));

    this.simple_dialog(content, title, function () {
        if (password.val() === '') {
            password.focus();
            return false;
        }

        callback($.trim(name.val()), password.val());
        return true;
    }, { button: 'continue' });

    (with_name ? name : password).focus();
};

rcube_webmail.prototype.passkeys_dialog_field = function (input, label) {
    return $('<div>').addClass('form-group')
        .append($('<label>').attr('for', input.attr('id')).text(label), input);
};

/**
 * The name and password typed into the dialog, for the ceremony the server
 * just answered; forgotten as soon as they are taken.
 */
rcube_webmail.prototype.passkeys_take_pending = function () {
    var pending = this._passkeys_pending;

    this._passkeys_pending = null;

    return pending;
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
 * Build the table row for a credential: the same markup add_credential_row()
 * in passkeys.php renders.
 *
 * @param {object} o {id, label, created, lastused, stale}
 */
rcube_webmail.prototype.passkeys_row = function (o) {
    var $name = $('<td>').addClass('name').text(o.label);
    var $actions = $('<td>').addClass('actions');

    if (o.stale) {
        $name.append(' ', $('<span>').addClass('passkeys-stale').text(this.get_label('passkeyneedsupdate', 'passkeys')));
        $actions.append($('<a>').attr({ href: '#', 'class': 'button update', 'data-passkeys-update': o.id })
            .text(this.get_label('updatepasskey', 'passkeys')), ' ');
    }

    $actions.append($('<a>')
        .attr({ href: '#', 'class': 'button delete', 'data-passkeys-remove': o.id })
        .attr('title', this.get_label('removepasskey', 'passkeys'))
        .text(this.get_label('removepasskey', 'passkeys')));

    return $('<tr>').attr('data-credential-id', o.id).append(
        $name,
        $('<td>').addClass('created').text(o.created),
        $('<td>').addClass('lastused').text(o.lastused),
        $actions
    );
};

/**
 * Server callback: add a freshly enrolled credential to the top of the table
 * (the list is newest first).
 */
rcube_webmail.prototype.passkeys_add_row = function (o) {
    var $table = $('#passkeys-list');

    $table.find('tr.passkeys-empty-row').remove();
    $table.find('tbody').prepend(this.passkeys_row(o));
};

/**
 * Server callback: redraw an updated credential's row.
 */
rcube_webmail.prototype.passkeys_update_row = function (o) {
    $('#passkeys-list tr[data-credential-id="' + o.id + '"]').replaceWith(this.passkeys_row(o));
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

/**
 * After a password login: offer to update passkeys that hold an old password.
 */
rcube_webmail.prototype.passkeys_stale_prompt = function () {
    var ref = this;

    this.confirm_dialog($('<p>').text(this.get_label('passkeystaleprompt', 'passkeys')), 'passkeys.updatepasskey', function () {
        ref.location_href(ref.url('settings/plugin.passkeys'), window);
    }, { title: this.get_label('passkeys', 'passkeys') });  // options.title is used as is, not as a label name
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
    var args;

    try {
        args = this.passkeys_options(data.args, this.passkeys_b64url_to_buf(data.prf_salt));
    } catch (e) {
        this.display_message(this.get_label('weberror', 'passkeys'), 'error');
        return;
    }

    navigator.credentials.get(args)
        .then(function (assertion) {
            ref._passkeys_prf = ref.passkeys_prf_result(assertion);
            ref.http_post('plugin.passkeys.assert', ref.passkeys_assertion_post(assertion), ref.set_busy(true, 'loading'));
        })
        .catch(function (err) {
            ref.passkeys_report_error(err);
        });
};

/**
 * Server callback: decrypt the wrapped IMAP password with the PRF output and
 * complete a normal login.
 *
 * @param {object} data {credential, username, wrapped_secret, wrap_iv}
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
            ref.passkeys_submit_login(data.username, new TextDecoder().decode(pt), data.credential);
        })
        .catch(function () {
            ref._passkeys_prf = null;
            ref.display_message(ref.get_label('weberror', 'passkeys'), 'error');
        });
};

/**
 * Server callback: the passkey is genuine but holds an old password. Fill in
 * the username so the user only has to type the current password.
 *
 * @param {object} data {username}
 */
rcube_webmail.prototype.passkeys_stale = function (data) {
    this._passkeys_prf = null;

    $('#rcmloginuser').val(data.username);
    $('#rcmloginpwd').val('').focus();

    this.display_message(this.get_label('passkeystale', 'passkeys'), 'warning', 15000);
};

/**
 * Server callback: show a login error.
 */
rcube_webmail.prototype.passkeys_login_error = function (msg) {
    this._passkeys_prf = null;
    this.display_message(msg || this.get_label('weberror', 'passkeys'), 'error');
};

/**
 * Fill and submit the standard login form so the normal password/2FA login
 * path runs, exactly as if the user had typed their password. The credential
 * id lets the server recognize a password the mail server then rejects as the
 * passkey's (an out-of-date copy).
 */
rcube_webmail.prototype.passkeys_submit_login = function (username, password, cred_id) {
    var form = (this.gui_objects && this.gui_objects.loginform) || document.forms['login-form'];

    if (!form) {
        this.display_message(this.get_label('weberror', 'passkeys'), 'error');
        return;
    }

    $('#rcmloginuser', form).val(username);
    $('#rcmloginpwd', form).val(password);
    $('input[name="_passkeys_credential"]', form).remove();
    $('<input>').attr({ type: 'hidden', name: '_passkeys_credential' }).val(cred_id).appendTo(form);

    form.submit();
};

/* ------------------------------------------------------------------ *
 *  WebAuthn / PRF / crypto helpers                                    *
 * ------------------------------------------------------------------ */

/**
 * Decode the base64url fields of WebAuthn options from the server and request
 * the PRF output for the given salt.
 *
 * @return {object} The options, ready for navigator.credentials.create/get()
 */
rcube_webmail.prototype.passkeys_options = function (args, salt) {
    var ref = this;
    var pk = args.publicKey;

    pk.challenge = this.passkeys_b64url_to_buf(pk.challenge);
    if (pk.user) {
        pk.user.id = this.passkeys_b64url_to_buf(pk.user.id);
    }
    (pk.excludeCredentials || []).concat(pk.allowCredentials || []).forEach(function (c) {
        c.id = ref.passkeys_b64url_to_buf(c.id);
    });
    pk.extensions = pk.extensions || {};
    pk.extensions.prf = { eval: { first: salt } };

    return args;
};

/**
 * The POST fields that carry an assertion to the server.
 */
rcube_webmail.prototype.passkeys_assertion_post = function (assertion) {
    var r = assertion.response;

    return {
        _id: assertion.id,
        _clientDataJSON: this.passkeys_buf_to_b64url(r.clientDataJSON),
        _authenticatorData: this.passkeys_buf_to_b64url(r.authenticatorData),
        _signature: this.passkeys_buf_to_b64url(r.signature),
        _userHandle: r.userHandle ? this.passkeys_buf_to_b64url(r.userHandle) : ''
    };
};

/**
 * The PRF output an assertion carries.
 *
 * @return {Uint8Array}
 * @throws {Error} 'no-prf' when the authenticator did not evaluate the PRF
 */
rcube_webmail.prototype.passkeys_prf_result = function (assertion) {
    var ext = assertion.getClientExtensionResults();

    if (!ext.prf || !ext.prf.results || !ext.prf.results.first) {
        throw new Error('no-prf');
    }

    return new Uint8Array(ext.prf.results.first);
};

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
    var ref = this;

    return navigator.credentials.get({
        publicKey: {
            challenge: window.crypto.getRandomValues(new Uint8Array(32)),
            allowCredentials: [{ type: 'public-key', id: rawId }],
            userVerification: 'preferred',
            timeout: 60000,
            extensions: { prf: { eval: { first: salt } } }
        }
    }).then(function (assertion) {
        return ref.passkeys_prf_result(assertion);
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
    this._passkeys_prf = null;

    if (err && (err.name == 'NotAllowedError' || err.name == 'AbortError')) {
        this.display_message(this.get_label('passkeycancelled', 'passkeys'), 'notice');
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
