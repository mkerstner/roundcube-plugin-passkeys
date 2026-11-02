/**
 * Software WebAuthn authenticator for development tests. NOT for production.
 *
 * ES256 keys, "none" attestation, discoverable credentials, user verification
 * always granted, a signature counter, and the PRF extension (emulated the way
 * browsers map it onto CTAP2 hmac-secret). It uses only WebCrypto, so the same
 * file runs in Node (dev/e2e.mjs) and in a browser page, where install()
 * replaces navigator.credentials.create/get:
 *
 *   PasskeysSoftAuthenticator.install(window)          // credentials kept in localStorage
 *   PasskeysSoftAuthenticator.install(window, {prf: false})   // device without PRF
 *
 * Options: origin, store ({load(), save(list)}), prf (default true),
 * prfAtCreate (default true; false = report only "enabled" at create, like
 * authenticators that need a separate get() for the first PRF output).
 */
(function (root) {
    'use strict';

    var subtle = root.crypto.subtle;
    var FLAG_UP = 0x01, FLAG_UV = 0x04, FLAG_AT = 0x40;

    function concat() {
        var parts = Array.prototype.map.call(arguments, toBytes);
        var out = new Uint8Array(parts.reduce(function (n, p) { return n + p.length; }, 0));
        var off = 0;
        parts.forEach(function (p) { out.set(p, off); off += p.length; });
        return out;
    }

    function toBytes(v) {
        if (v instanceof Uint8Array) {
            return v;
        }
        if (v instanceof ArrayBuffer) {
            return new Uint8Array(v);
        }
        if (ArrayBuffer.isView(v)) {
            return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
        }
        if (Array.isArray(v)) {
            return new Uint8Array(v);
        }
        if (typeof v === 'string') {
            return new TextEncoder().encode(v);
        }
        throw new TypeError('not bytes');
    }

    function buffer(bytes) {
        return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    }

    function u16(n) { return [(n >> 8) & 255, n & 255]; }
    function u32(n) { return [(n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255]; }

    function b64url(bytes) {
        bytes = toBytes(bytes);
        var bin = '';
        for (var i = 0; i < bytes.length; i++) {
            bin += String.fromCharCode(bytes[i]);
        }
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function unb64url(str) {
        str = String(str).replace(/-/g, '+').replace(/_/g, '/');
        while (str.length % 4) {
            str += '=';
        }
        var bin = atob(str), out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) {
            out[i] = bin.charCodeAt(i);
        }
        return out;
    }

    function random(n) {
        return root.crypto.getRandomValues(new Uint8Array(n));
    }

    function sha256(data) {
        return subtle.digest('SHA-256', toBytes(data)).then(function (h) { return new Uint8Array(h); });
    }

    /* Minimal CBOR encoder: integers, byte strings, text, arrays, maps (a Map
       keeps integer keys, a plain object has text keys). */
    function cbor(v) {
        function head(major, n) {
            if (n < 24) {
                return [(major << 5) | n];
            }
            if (n < 256) {
                return [(major << 5) | 24, n];
            }
            if (n < 65536) {
                return [(major << 5) | 25].concat(u16(n));
            }
            return [(major << 5) | 26].concat(u32(n));
        }

        if (typeof v === 'number') {
            return v >= 0 ? new Uint8Array(head(0, v)) : new Uint8Array(head(1, -1 - v));
        }
        if (typeof v === 'string') {
            var t = toBytes(v);
            return concat(head(3, t.length), t);
        }
        if (v instanceof Uint8Array || v instanceof ArrayBuffer) {
            var b = toBytes(v);
            return concat(head(2, b.length), b);
        }
        if (Array.isArray(v)) {
            return concat.apply(null, [head(4, v.length)].concat(v.map(cbor)));
        }
        var entries = v instanceof Map ? Array.from(v.entries()) : Object.keys(v).map(function (k) { return [k, v[k]]; });
        var parts = [head(5, entries.length)];
        entries.forEach(function (e) { parts.push(cbor(e[0]), cbor(e[1])); });
        return concat.apply(null, parts);
    }

    /* WebCrypto ECDSA signatures are r||s; WebAuthn wants ASN.1 DER. */
    function der(raw) {
        function int(b) {
            var i = 0;
            while (i < b.length - 1 && b[i] === 0) {
                i++;
            }
            b = b.slice(i);
            if (b[0] & 0x80) {
                b = concat([0], b);
            }
            return concat([0x02, b.length], b);
        }
        var r = int(raw.slice(0, 32)), s = int(raw.slice(32));
        return concat([0x30, r.length + s.length], r, s);
    }

    /* PRF as browsers implement it on top of hmac-secret:
       HMAC-SHA-256(credential secret, SHA-256("WebAuthn PRF" || 0x00 || salt)). */
    function prf(secret, salt) {
        return Promise.all([
            sha256(concat('WebAuthn PRF', [0], toBytes(salt))),
            subtle.importKey('raw', unb64url(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']),
        ]).then(function (r) {
            return subtle.sign('HMAC', r[1], r[0]);
        });
    }

    function memoryStore() {
        var list = [];
        return { load: function () { return list; }, save: function (l) { list = l; } };
    }

    function localStore(win, key) {
        key = key || 'passkeys-soft-authenticator';
        return {
            load: function () { return JSON.parse(win.localStorage.getItem(key) || '[]'); },
            save: function (l) { win.localStorage.setItem(key, JSON.stringify(l)); },
        };
    }

    function SoftAuthenticator(opts) {
        opts = opts || {};
        this.origin = opts.origin || (root.location && root.location.origin);
        this.store = opts.store || memoryStore();
        this.prf = opts.prf !== false;
        this.prfAtCreate = opts.prfAtCreate !== false;
    }

    SoftAuthenticator.prototype.credentials = function () {
        return this.store.load();
    };

    /* Overwrite a stored credential's fields, e.g. {counter: 0} to fake a
       cloned authenticator. */
    SoftAuthenticator.prototype.patch = function (id, fields) {
        var list = this.store.load();
        list.forEach(function (c) {
            if (c.id === id) {
                Object.assign(c, fields);
            }
        });
        this.store.save(list);
    };

    SoftAuthenticator.prototype.extensions = function (cred, requested, at_create) {
        var ext = requested && requested.prf;
        if (!ext || !this.prf) {
            return Promise.resolve({});
        }
        if ((at_create && !this.prfAtCreate) || !ext.eval || !ext.eval.first) {
            return Promise.resolve(at_create ? { prf: { enabled: true } } : {});
        }
        return prf(cred.prfSecret, ext.eval.first).then(function (first) {
            var out = { prf: { results: { first: first } } };
            if (at_create) {
                out.prf.enabled = true;
            }
            return out;
        });
    };

    SoftAuthenticator.prototype.create = function (options) {
        var self = this, pk = options.publicKey;
        var rpId = (pk.rp && pk.rp.id) || new URL(this.origin).hostname;
        var credId = random(32), cred, keys, ext;

        return subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
            .then(function (k) {
                keys = k;
                return subtle.exportKey('jwk', k.privateKey);
            })
            .then(function (jwk) {
                cred = {
                    id: b64url(credId),
                    rpId: rpId,
                    userHandle: b64url(pk.user.id),
                    jwk: jwk,
                    prfSecret: b64url(random(32)),
                    counter: 0,
                };
                return self.extensions(cred, pk.extensions, true);
            })
            .then(function (e) {
                ext = e;
                var cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, unb64url(cred.jwk.x)], [-3, unb64url(cred.jwk.y)]]);
                return sha256(rpId).then(function (rpHash) {
                    return concat(rpHash, [FLAG_UP | FLAG_UV | FLAG_AT], u32(0), new Uint8Array(16),
                        u16(credId.length), credId, cbor(cose));
                });
            })
            .then(function (authData) {
                var list = self.store.load();
                list.push(cred);
                self.store.save(list);

                var clientData = toBytes(JSON.stringify({
                    type: 'webauthn.create',
                    challenge: b64url(pk.challenge),
                    origin: self.origin,
                    crossOrigin: false,
                }));

                return {
                    id: cred.id,
                    rawId: buffer(credId),
                    type: 'public-key',
                    authenticatorAttachment: 'platform',
                    response: {
                        clientDataJSON: buffer(clientData),
                        attestationObject: buffer(cbor({ fmt: 'none', attStmt: {}, authData: authData })),
                        getTransports: function () { return ['internal']; },
                    },
                    getClientExtensionResults: function () { return ext; },
                };
            });
    };

    SoftAuthenticator.prototype.get = function (options) {
        var self = this, pk = options.publicKey;
        var rpId = pk.rpId || new URL(this.origin).hostname;
        var allow = (pk.allowCredentials || []).map(function (c) { return b64url(c.id); });
        var list = this.store.load();
        var cred = list.filter(function (c) {
            return c.rpId === rpId && (!allow.length || allow.indexOf(c.id) >= 0);
        }).pop();

        if (!cred) {
            var err = new Error('No matching credential');
            err.name = 'NotAllowedError';
            return Promise.reject(err);
        }

        cred.counter++;
        this.store.save(list);

        var clientData = toBytes(JSON.stringify({
            type: 'webauthn.get',
            challenge: b64url(pk.challenge),
            origin: this.origin,
            crossOrigin: false,
        }));
        var authData, ext;

        return sha256(rpId)
            .then(function (rpHash) {
                authData = concat(rpHash, [FLAG_UP | FLAG_UV], u32(cred.counter));
                return Promise.all([
                    sha256(clientData),
                    subtle.importKey('jwk', cred.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']),
                    self.extensions(cred, pk.extensions, false),
                ]);
            })
            .then(function (r) {
                ext = r[2];
                return subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, r[1], concat(authData, r[0]));
            })
            .then(function (sig) {
                return {
                    id: cred.id,
                    rawId: buffer(unb64url(cred.id)),
                    type: 'public-key',
                    authenticatorAttachment: 'platform',
                    response: {
                        clientDataJSON: buffer(clientData),
                        authenticatorData: buffer(authData),
                        signature: buffer(der(new Uint8Array(sig))),
                        userHandle: buffer(unb64url(cred.userHandle)),
                    },
                    getClientExtensionResults: function () { return ext; },
                };
            });
    };

    root.PasskeysSoftAuthenticator = {
        SoftAuthenticator: SoftAuthenticator,
        b64url: b64url,
        unb64url: unb64url,
        install: function (win, opts) {
            var auth = new SoftAuthenticator(Object.assign({ origin: win.location.origin, store: localStore(win) }, opts));
            win.navigator.credentials.create = function (o) { return auth.create(o); };
            win.navigator.credentials.get = function (o) { return auth.get(o); };
            return auth;
        },
    };
})(globalThis);
