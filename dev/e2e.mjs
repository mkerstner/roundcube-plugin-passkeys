/**
 * End-to-end test of the passkeys plugin against the dev instance
 * (dev/compose.yaml), speaking HTTP like the browser does and playing the
 * authenticator with dev/soft-authenticator.js. The client half mirrors
 * passkeys.js: PRF output -> AES-GCM key -> wrap/unwrap the IMAP password.
 *
 *   node dev/e2e.mjs                      (PASSKEYS_DEV_URL, default http://localhost:8766)
 *
 * Exit code 1 when a check fails.
 */
import './soft-authenticator.js';

const { SoftAuthenticator, b64url, unb64url } = globalThis.PasskeysSoftAuthenticator;
const BASE = (process.env.PASSKEYS_DEV_URL || 'http://localhost:8766').replace(/\/$/, '');
const USER = 'alice@example.net';
const PASS = 'alice-pass';

let failures = 0;

function check(ok, label, detail) {
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${!ok && detail !== undefined ? `\n      ${detail}` : ''}`);
    if (!ok) {
        failures++;
    }
    return ok;
}

/** A browser stand-in: cookie jar + the request token Roundcube hands out. */
class Browser {
    constructor() {
        this.cookies = new Map();
        this.token = null;
    }

    async request(query, { form, ajax = false, csrf = true } = {}) {
        const headers = { Cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ') };
        let body;

        if (form) {
            body = new URLSearchParams(ajax ? { _remote: '1', _unlock: '0', ...form } : form);
            headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }
        if (ajax && csrf && this.token) {
            headers['X-Roundcube-Request'] = this.token;
        }

        const res = await fetch(`${BASE}/?${new URLSearchParams(query)}`, {
            method: form ? 'POST' : 'GET', headers, body, redirect: 'manual',
        });

        for (const c of res.headers.getSetCookie()) {
            const [pair] = c.split(';');
            const [k, v] = pair.split('=');
            if (v === '-del-' || v === '') {
                this.cookies.delete(k);
            } else {
                this.cookies.set(k, v);
            }
        }

        const text = await res.text();
        const token = text.match(/"request_token":"([^"]+)"/);
        if (token) {
            this.token = token[1];
        }

        return { status: res.status, location: res.headers.get('location') || '', text };
    }

    /** POST an AJAX action; returns the client commands as [{name, args}]. */
    async ajax(task, action, form = {}, opts = {}) {
        const res = await this.request({ _task: task, _action: action }, { form, ajax: true, ...opts });
        let json = {};
        try {
            json = JSON.parse(res.text);
        } catch {
            return { status: res.status, commands: [], raw: res.text };
        }
        const commands = [...(json.exec || '').matchAll(/this\.(\w+)\((.*)\);\n/g)]
            .map((m) => ({ name: m[1], args: JSON.parse(`[${m[2]}]`) }));
        return { status: res.status, commands, raw: res.text };
    }

    async loginPage() {
        this.cookies.clear();
        this.token = null;
        return this.request({ _task: 'login' });
    }

    async passwordLogin(user, pass) {
        const res = await this.request({ _task: 'login' }, {
            form: { _token: this.token, _task: 'login', _action: 'login', _timezone: 'UTC', _url: '', _user: user, _pass: pass },
        });
        if (res.status === 302) {
            await this.request({ _task: 'mail' });  // pick up the new session's token
        }
        return res;
    }
}

function command(res, name) {
    return res.commands.find((c) => c.name === name);
}

function describe(res) {
    return res.commands.map((c) => `${c.name}(${JSON.stringify(c.args).slice(1, -1).slice(0, 160)})`).join(' ') || `${res.status} ${res.raw.slice(0, 160)}`;
}

/* --- the browser half of passkeys.js ------------------------------------ */

async function aesKey(prf, usage) {
    return crypto.subtle.importKey('raw', prf, { name: 'AES-GCM' }, false, [usage]);
}

async function wrap(prf, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(prf, 'encrypt'), new TextEncoder().encode(plaintext));
    return { wrapped_secret: b64url(ct), wrap_iv: b64url(iv) };
}

async function unwrap(prf, data) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64url(data.wrap_iv) }, await aesKey(prf, 'decrypt'), unb64url(data.wrapped_secret));
    return new TextDecoder().decode(pt);
}

function decodeOptions(args, salt) {
    const pk = structuredClone(args.publicKey);
    pk.challenge = unb64url(pk.challenge);
    if (pk.user) {
        pk.user.id = unb64url(pk.user.id);
    }
    for (const c of [...(pk.excludeCredentials || []), ...(pk.allowCredentials || [])]) {
        c.id = unb64url(c.id);
    }
    pk.extensions = { ...(pk.extensions || {}), prf: { eval: { first: unb64url(salt) } } };
    return { publicKey: pk };
}

/** Settings > Passkeys > Add, as passkeys_add() + passkeys_create() do it. */
async function enrol(browser, auth, label, { password } = {}) {
    const challenge = await browser.ajax('settings', 'plugin.passkeys.reg-challenge');
    const create = command(challenge, 'passkeys_create');
    if (!create) {
        return { challenge };
    }
    const data = create.args[0];
    const cred = await auth.create(decodeOptions(data.args, data.prf_salt));
    const prf = cred.getClientExtensionResults().prf?.results?.first;
    const wrapped = prf ? await wrap(prf, password ?? data.password) : null;
    const register = await browser.ajax('settings', 'plugin.passkeys.register', {
        _clientDataJSON: b64url(cred.response.clientDataJSON),
        _attestationObject: b64url(cred.response.attestationObject),
        _transports: cred.response.getTransports().join(','),
        _label: label,
        ...(wrapped
            ? { _wrapped_secret: wrapped.wrapped_secret, _wrap_iv: wrapped.wrap_iv, _prf_supported: '1' }
            : { _prf_supported: '0' }),
    });
    return { challenge, data, cred, register };
}

/** Login page > Sign in with a passkey, up to (not including) the form submit. */
async function passkeyAssert(browser, auth, { tamper } = {}) {
    const challenge = await browser.ajax('login', 'plugin.passkeys.auth-challenge');
    const authn = command(challenge, 'passkeys_authenticate');
    if (!authn) {
        return { challenge };
    }
    const data = authn.args[0];
    const assertion = await auth.get(decodeOptions(data.args, data.prf_salt));
    const r = assertion.response;
    const post = {
        _id: assertion.id,
        _clientDataJSON: b64url(r.clientDataJSON),
        _authenticatorData: b64url(r.authenticatorData),
        _signature: b64url(r.signature),
        _userHandle: b64url(r.userHandle),
    };
    if (tamper) {
        tamper(post);
    }
    const assert = await browser.ajax('login', 'plugin.passkeys.assert', post);
    return { challenge, data, assertion, post, assert, prf: assertion.getClientExtensionResults().prf?.results?.first };
}

/* --- the run ------------------------------------------------------------- */

const browser = new Browser();
const auth = new SoftAuthenticator({ origin: BASE });

console.log(`passkeys e2e against ${BASE}\n`);

// Login page renders the plugin's button and assets
let page = await browser.loginPage();
check(page.status === 200, 'login page loads');
check(page.text.includes('id="passkeys-login-button"'), 'login form has the passkey button');
check(/plugins\/passkeys\/passkeys\.css/.test(page.text) && /plugins\/passkeys\/passkeys\.js/.test(page.text), 'plugin CSS and JS are included');
const skin = page.text.match(/"skin":"([^"]+)"/)?.[1];
const css = page.text.match(/skins\/([a-z0-9_-]+)\/styles\/styles\.min\.css/)?.[1];
check(skin === css, `skin "${skin}" serves its own stylesheet`, `stylesheet from skins/${css}`);

// Password login, then enrol a passkey
let res = await browser.passwordLogin(USER, PASS);
check(res.status === 302 && res.location.includes('_task=mail'), 'password login works', `${res.status} ${res.location}`);

const enrolled = await enrol(browser, auth, 'e2e key');
check(!!enrolled.data, 'reg-challenge returns creation options', enrolled.challenge && describe(enrolled.challenge));
check(enrolled.data?.args?.publicKey?.authenticatorSelection?.residentKey === 'required', 'discoverable credential requested');
check(!!command(enrolled.register || { commands: [] }, 'passkeys_add_row'), 'register stores the passkey', enrolled.register && describe(enrolled.register));

const settings = await browser.request({ _task: 'settings', _action: 'plugin.passkeys', _framed: '1' });
check(settings.text.includes('e2e key'), 'settings list shows the passkey');

// The login form rendered by other tasks has the button too
const sessauth = browser.cookies.get('roundcube_sessauth');
browser.cookies.set('roundcube_sessauth', 'expired');
page = await browser.request({ _task: 'mail' });
check(page.text.includes('"task":"login"') && page.text.includes('id="passkeys-login-button"'), 'login form after a session timeout has the passkey button');
browser.cookies.set('roundcube_sessauth', sessauth);

// Log out, sign in with the passkey
await browser.passwordLogin(USER, PASS);
page = await browser.request({ _task: 'logout', _token: browser.token });
check(page.text.includes('id="passkeys-login-button"') && /plugins\/passkeys\/passkeys\.js/.test(page.text), 'login form shown on logout has the passkey button');
await browser.loginPage();

const login = await passkeyAssert(browser, auth);
const unwrapCmd = login.assert && command(login.assert, 'passkeys_unwrap');
check(!!unwrapCmd, 'assertion verified, wrapped password released', login.assert ? describe(login.assert) : describe(login.challenge));
if (unwrapCmd) {
    check(unwrapCmd.args[0].username === USER, 'released for the right user', unwrapCmd.args[0].username);
    const password = await unwrap(login.prf, unwrapCmd.args[0]);
    check(password === PASS, 'PRF key decrypts the stored password');
    res = await browser.passwordLogin(unwrapCmd.args[0].username, password);
    check(res.status === 302 && res.location.includes('_task=mail'), 'standard login form completes the sign-in', `${res.status} ${res.location}`);
    const list = await browser.request({ _task: 'settings', _action: 'plugin.passkeys', _framed: '1' });
    const row = list.text.match(new RegExp(`data-credential-id="${login.assertion.id}"[\\s\\S]*?</tr>`))?.[0] || '';
    check(row && !/class="lastused">Never</.test(row), 'last-used is stamped', row);
}

// Replay and cloned-authenticator checks
await browser.request({ _task: 'logout', _token: browser.token });
await browser.loginPage();
const first = await passkeyAssert(browser, auth);
const replay = await browser.ajax('login', 'plugin.passkeys.assert', first.post);
check(!command(replay, 'passkeys_unwrap'), 'replayed assertion is rejected', describe(replay));

auth.patch(enrolled.cred.id, { counter: 0 });   // the next assertion carries counter 1 again
const cloned = await passkeyAssert(browser, auth);
check(!command(cloned.assert, 'passkeys_unwrap'), 'signature-counter regression is rejected', describe(cloned.assert));

const forged = await passkeyAssert(browser, auth, { tamper: (p) => { p._signature = b64url(new Uint8Array(70)); } });
check(!command(forged.assert, 'passkeys_unwrap'), 'bad signature is rejected', describe(forged.assert));

console.log(`\n${failures ? `${failures} check(s) failed` : 'all checks passed'}`);
process.exit(failures ? 1 : 0);
