/**
 * Client script for the Passkeys plugin.
 *
 * Phase 2: Settings management (list + remove) and the WebAuthn registration
 * ceremony ("add a passkey"). The passwordless login ceremony is added in a
 * later phase.
 */

if (window.rcmail) {
    rcmail.addEventListener('init', function () {
        if (rcmail.env.task == 'settings' && /^plugin\.passkeys/.test(rcmail.env.action || '')) {
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
    });
}

/**
 * Whether this browser can do WebAuthn at all.
 */
rcube_webmail.prototype.passkeys_supported = function () {
    return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
};

/**
 * Start enrolling a new passkey: fetch a registration challenge from the
 * server. The ceremony continues in passkeys_create().
 */
rcube_webmail.prototype.passkeys_add = function () {
    if (!this.passkeys_supported()) {
        this.display_message(this.get_label('notsupported', 'passkeys'), 'error');
        return;
    }

    this.http_post('plugin.passkeys.reg-challenge', {}, this.set_busy(true, 'loading'));
};

/**
 * Server callback: run navigator.credentials.create() with the given options
 * and submit the result back for validation and storage.
 *
 * @param {object} args WebAuthn creation options ({publicKey: {...}}) with
 *                      base64url-encoded challenge and ids.
 */
rcube_webmail.prototype.passkeys_create = function (args) {
    var ref = this;

    try {
        args.publicKey.challenge = this.passkeys_b64url_to_buf(args.publicKey.challenge);
        args.publicKey.user.id = this.passkeys_b64url_to_buf(args.publicKey.user.id);

        (args.publicKey.excludeCredentials || []).forEach(function (cred) {
            cred.id = ref.passkeys_b64url_to_buf(cred.id);
        });
    } catch (e) {
        this.display_message(this.get_label('weberror', 'passkeys'), 'error');
        return;
    }

    navigator.credentials.create(args)
        .then(function (credential) {
            var response = credential.response;
            var transports = '';

            if (typeof response.getTransports === 'function') {
                try {
                    transports = (response.getTransports() || []).join(',');
                } catch (e) { /* optional */ }
            }

            var label = window.prompt(ref.get_label('passkeynameprompt', 'passkeys'), '');
            if (label === null) {
                // user cancelled the naming step; the credential was created on
                // the device but we simply do not store it.
                ref.display_message(ref.get_label('passkeyaddcancelled', 'passkeys'), 'notice');
                return;
            }

            ref.http_post('plugin.passkeys.register', {
                _clientDataJSON: ref.passkeys_buf_to_b64url(response.clientDataJSON),
                _attestationObject: ref.passkeys_buf_to_b64url(response.attestationObject),
                _transports: transports,
                _label: label.replace(/^\s+|\s+$/g, '')
            }, ref.set_busy(true, 'loading'));
        })
        .catch(function (err) {
            // NotAllowedError / AbortError means the user cancelled or timed out.
            if (err && (err.name == 'NotAllowedError' || err.name == 'AbortError')) {
                ref.display_message(ref.get_label('passkeyaddcancelled', 'passkeys'), 'notice');
            } else {
                ref.display_message(ref.get_label('weberror', 'passkeys'), 'error');
            }
        });
};

/**
 * Ask for confirmation and remove a passkey.
 *
 * @param {string} cred_id base64url credential id
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
 *
 * @param {object} o {id, label, created, lastused}
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
 *
 * @param {string} cred_id base64url credential id
 */
rcube_webmail.prototype.passkeys_remove_row = function (cred_id) {
    var $table = $('#passkeys-list');

    $table.find('tr[data-credential-id="' + cred_id + '"]').remove();

    // Nothing left: restore the empty-state row.
    if (!$table.find('tbody tr').length) {
        var $cell = $('<td>').attr('colspan', 4).addClass('passkeys-empty')
            .text(this.get_label('nopasskeys', 'passkeys'));
        $table.find('tbody').append($('<tr>').addClass('passkeys-empty-row').append($cell));
    }
};

/**
 * Convert a base64url string to an ArrayBuffer.
 */
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

/**
 * Convert an ArrayBuffer to a base64url string (no padding).
 */
rcube_webmail.prototype.passkeys_buf_to_b64url = function (buf) {
    var bytes = new Uint8Array(buf), bin = '';
    for (var i = 0; i < bytes.length; i++) {
        bin += String.fromCharCode(bytes[i]);
    }

    return window.btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
