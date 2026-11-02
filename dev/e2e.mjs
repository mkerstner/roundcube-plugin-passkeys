/**
 * End-to-end test of the passkeys plugin against the dev instance
 * (dev/compose.yaml), speaking HTTP like the browser does and playing the
 * authenticator with dev/soft-authenticator.js. The client half mirrors
 * passkeys.js: PRF output -> AES-GCM key -> wrap/unwrap the IMAP password.
 *
 *   node dev/e2e.mjs                      (PASSKEYS_DEV_URL, default http://localhost:8766)
 *
 * Uses the GreenMail accounts from compose.yaml: alice (main flow), bob (gets
 * locked out for a minute), carol (stale password). A rerun within a minute
 * waits for bob's lockout to expire. Exit code 1 when a check fails.
 */
import './soft-authenticator.js';

const { SoftAuthenticator, b64url, unb64url } = globalThis.PasskeysSoftAuthenticator;
const BASE = (process.env.PASSKEYS_DEV_URL || 'http://localhost:8766').replace(/\/$/, '');
const ALICE = ['alice@example.net', 'alice-pass'];
const BOB = ['bob@example.net', 'bob-pass'];
const CAROL = ['carol@example.net', 'carol-pass'];

let failures = 0;

function check(ok, label, detail) {
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${!ok && detail !== undefined ? `\n      ${detail}` : ''}`);
    if (!ok) {
        failures++;
    }
    return ok;
}

function section(title) {
    console.log(`\n# ${title}`);
}

/** A browser stand-in: cookie jar + the request token Roundcube hands out. */
class Browser {
    constructor() {
        this.cookies = new Map();
        this.token = null;
    }

    /**
     * @param {object} opts form: POST fields; ajax: send as rcmail.http_post();
     *                      token: X-Roundcube-Request value (default: the session's; false: none)
     */
    async request(query, { form, ajax = false, token, method } = {}) {
        const headers = { Cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ') };
        let body;

        if (form) {
            body = new URLSearchParams(ajax ? { _remote: '1', _unlock: '0', ...form } : form);
            headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }
        token = token === undefined ? this.token : token;
        if (ajax && token) {
            headers['X-Roundcube-Request'] = token;
        }

        const res = await fetch(`${BASE}/?${new URLSearchParams(query)}`, {
            method: method || (form ? 'POST' : 'GET'), headers, body, redirect: 'manual',
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
        const found = text.match(/"request_token":"([^"]+)"/);
        if (found) {
            this.token = found[1];
        }

        return { status: res.status, location: res.headers.get('location') || '', text };
    }

    /** POST an AJAX action; returns the client commands as [{name, args}]. */
    async ajax(task, action, form = {}, opts = {}) {
        const res = await this.request({ _task: task, _action: action }, { form, ajax: true, ...opts });
        let json;
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

    async passwordLogin(user, pass, extra = {}) {
        const res = await this.request({ _task: 'login' }, {
            form: { _token: this.token, _task: 'login', _action: 'login', _timezone: 'UTC', _url: '', _user: user, _pass: pass, ...extra },
        });
        if (res.status === 302) {
            res.next = await this.request({ _task: 'mail' });  // the page after login, with the new session's token
        }
        return res;
    }

    /** Fresh login page + password login; waits out a lockout left by a previous run. */
    async signIn([user, pass]) {
        for (let attempt = 0; attempt < 2; attempt++) {
            await this.loginPage();
            const res = await this.passwordLogin(user, pass);
            if (res.status === 302) {
                return res;
            }
            if (attempt === 0 && res.text.includes('Too many failed login attempts')) {
                console.log(`      (${user} is locked out from a previous run, waiting 61 s)`);
                await new Promise((r) => setTimeout(r, 61000));
            }
        }
        throw new Error(`password login failed for ${user}`);
    }

    async logout() {
        return this.request({ _task: 'logout', _token: this.token });
    }

    async settingsList() {
        return this.request({ _task: 'settings', _action: 'plugin.passkeys', _framed: '1' });
    }
}

function command(res, name) {
    return res?.commands?.find((c) => c.name === name);
}

function describe(res) {
    if (!res) {
        return '(no response)';
    }
    return res.commands.map((c) => `${c.name}(${JSON.stringify(c.args).slice(1, -1).slice(0, 160)})`).join(' ')
        || `${res.status} ${res.raw.slice(0, 160)}`;
}

function message(res) {
    return command(res, 'display_message')?.args[0] || command(res, 'passkeys_login_error')?.args[0] || '';
}

/* --- the browser half of passkeys.js ------------------------------------ */

async function aesKey(prf, usage) {
    return crypto.subtle.importKey('raw', prf, { name: 'AES-GCM' }, false, [usage]);
}

async function wrap(prf, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(prf, 'encrypt'), new TextEncoder().encode(plaintext));
    return { _wrapped_secret: b64url(ct), _wrap_iv: b64url(iv) };
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

function assertionPost(assertion) {
    const r = assertion.response;
    return {
        _id: assertion.id,
        _clientDataJSON: b64url(r.clientDataJSON),
        _authenticatorData: b64url(r.authenticatorData),
        _signature: b64url(r.signature),
        _userHandle: b64url(r.userHandle),
    };
}

/**
 * Settings > Passkeys > Add, as passkeys_add() + passkeys_create() do it.
 * `wraps` is what gets encrypted (default: the typed password); a different
 * value stands in for a password that changed after enrolment.
 */
async function enrol(browser, auth, label, typed, { wraps } = {}) {
    const challenge = await browser.ajax('settings', 'plugin.passkeys.reg-challenge', { _password: typed });
    const create = command(challenge, 'passkeys_create');
    if (!create) {
        return { challenge };
    }
    const data = create.args[0];
    const cred = await auth.create(decodeOptions(data.args, data.prf_salt));
    const prf = cred.getClientExtensionResults().prf?.results?.first;
    const register = await browser.ajax('settings', 'plugin.passkeys.register', {
        _clientDataJSON: b64url(cred.response.clientDataJSON),
        _attestationObject: b64url(cred.response.attestationObject),
        _transports: cred.response.getTransports().join(','),
        _label: label,
        ...(prf ? await wrap(prf, wraps ?? typed) : {}),
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
    const post = assertionPost(assertion);
    if (tamper) {
        tamper(post);
    }
    const assert = await browser.ajax('login', 'plugin.passkeys.assert', post);
    return { challenge, data, assertion, post, assert, prf: assertion.getClientExtensionResults().prf?.results?.first };
}

/** The whole passwordless sign-in: assert, unwrap, submit the login form. */
async function passkeySignIn(browser, auth) {
    await browser.loginPage();
    const login = await passkeyAssert(browser, auth);
    const released = command(login.assert, 'passkeys_unwrap')?.args[0];
    if (!released) {
        return { login };
    }
    const password = await unwrap(login.prf, released);
    const res = await browser.passwordLogin(released.username, password, { _passkeys_credential: released.credential });
    return { login, released, password, res };
}

function row(page, id) {
    return page.text.match(new RegExp(`data-credential-id="${id}"[\\s\\S]*?</tr>`))?.[0] || '';
}

/* --- the run ------------------------------------------------------------- */

console.log(`passkeys e2e against ${BASE}`);

const browser = new Browser();
const auth = new SoftAuthenticator({ origin: BASE });

section('Login page');
let page = await browser.loginPage();
check(page.status === 200, 'login page loads');
check(page.text.includes('id="passkeys-login-button"'), 'login form has the passkey button');
check(/plugins\/passkeys\/passkeys\.css/.test(page.text) && /plugins\/passkeys\/passkeys\.js/.test(page.text), 'plugin CSS and JS are included');
const skin = page.text.match(/"skin":"([^"]+)"/)?.[1];
const css = page.text.match(/skins\/([a-z0-9_-]+)\/styles\/styles\.min\.css/)?.[1];
check(skin === css, `skin "${skin}" serves its own stylesheet`, `stylesheet from skins/${css}`);

section('CSRF: login endpoints run before core\'s checks');
let res = await browser.ajax('login', 'plugin.passkeys.auth-challenge', {}, { token: false });
check(res.status === 403 && !command(res, 'passkeys_authenticate'), 'auth-challenge without the request token is refused', describe(res));
res = await browser.ajax('login', 'plugin.passkeys.auth-challenge', {}, { token: 'forged' });
check(res.status === 403, 'auth-challenge with a wrong token is refused', describe(res));
res = await browser.request({ _task: 'login', _action: 'plugin.passkeys.auth-challenge', _remote: '1' }, { ajax: true, method: 'GET' });
check(res.status === 403, 'auth-challenge by GET is refused', `${res.status}`);
res = await browser.ajax('login', 'plugin.passkeys.assert', { _id: 'x' }, { token: false });
check(res.status === 403, 'assert without the request token is refused', describe(res));
res = await browser.ajax('login', 'plugin.passkeys.auth-challenge');
check(!!command(res, 'passkeys_authenticate'), 'auth-challenge with the token works', describe(res));

section('Enrolment needs the typed password');
await browser.signIn(ALICE);
res = await browser.ajax('settings', 'plugin.passkeys.reg-challenge', { _password: ALICE[1] }, { token: 'forged' });
check(res.status === 403, 'reg-challenge with a wrong token is refused', describe(res));
res = await browser.ajax('settings', 'plugin.passkeys.reg-challenge', { _password: 'wrong' });
check(!command(res, 'passkeys_create') && /password is incorrect/.test(message(res)), 'a wrong password gets no challenge', describe(res));
const enrolled = await enrol(browser, auth, 'e2e key', ALICE[1]);
check(!!enrolled.data, 'reg-challenge returns creation options', describe(enrolled.challenge));
check(enrolled.data && !('password' in enrolled.data) && !enrolled.challenge.raw.includes(ALICE[1]), 'the response does not contain the password');
check(enrolled.data?.args?.publicKey?.authenticatorSelection?.residentKey === 'required', 'discoverable credential requested');
check(!!command(enrolled.register, 'passkeys_add_row'), 'register stores the passkey', describe(enrolled.register));
page = await browser.settingsList();
check(page.text.includes('e2e key'), 'settings list shows the passkey');

section('Login form on other pages');
const sessauth = browser.cookies.get('roundcube_sessauth');
browser.cookies.set('roundcube_sessauth', 'expired');
page = await browser.request({ _task: 'mail' });
check(page.text.includes('"task":"login"') && page.text.includes('id="passkeys-login-button"'), 'login form after a session timeout has the passkey button');
browser.cookies.set('roundcube_sessauth', sessauth);
page = await browser.logout();
check(page.text.includes('id="passkeys-login-button"') && /plugins\/passkeys\/passkeys\.js/.test(page.text), 'login form shown on logout has the passkey button');

section('Passwordless sign-in');
let signin = await passkeySignIn(browser, auth);
check(!!signin.released, 'assertion verified, wrapped password released', describe(signin.login.assert || signin.login.challenge));
check(signin.released?.username === ALICE[0], 'released for the right user', signin.released?.username);
check(signin.password === ALICE[1], 'PRF key decrypts the stored password');
check(signin.res?.status === 302 && signin.res.location.includes('_task=mail'), 'standard login form completes the sign-in', `${signin.res?.status} ${signin.res?.location}`);
check(!signin.res?.next.text.includes('"passkeys_stale_prompt":true'), 'no update prompt after a passkey sign-in');
page = await browser.settingsList();
check(!/class="lastused">Never</.test(row(page, enrolled.cred.id)), 'last-used is stamped', row(page, enrolled.cred.id));

section('Replay');
// Synced passkeys (iCloud, Google) have no signature counter, so only the
// single-use challenge stops a replayed assertion.
const synced = new SoftAuthenticator({ origin: BASE, counter: false });
check(!!command((await enrol(browser, synced, 'synced key', ALICE[1])).register, 'passkeys_add_row'), 'a passkey without a signature counter enrols');
await browser.logout();
await browser.loginPage();
const first = await passkeyAssert(browser, synced);
check(!!command(first.assert, 'passkeys_unwrap'), 'and signs in', describe(first.assert));
res = await browser.ajax('login', 'plugin.passkeys.assert', first.post);
check(!command(res, 'passkeys_unwrap'), 'replaying its assertion in the same session is rejected (single-use challenge)', describe(res));

section('Lockout (bob)');
const bobAuth = new SoftAuthenticator({ origin: BASE });
await browser.signIn(BOB);
const bobKey = await enrol(browser, bobAuth, 'bob key', BOB[1]);
check(!!command(bobKey.register, 'passkeys_add_row'), 'bob enrols a passkey', describe(bobKey.register));
await browser.logout();
await browser.loginPage();
let bad = await passkeyAssert(browser, bobAuth);    // first use: the stored counter becomes 1
check(!!command(bad.assert, 'passkeys_unwrap'), 'bob\'s passkey works', describe(bad.assert));
bobAuth.patch(bobKey.cred.id, { counter: 0 });
bad = await passkeyAssert(browser, bobAuth);        // counter 1 again: a cloned authenticator
check(!command(bad.assert, 'passkeys_unwrap'), 'signature-counter regression is rejected', describe(bad.assert));
for (let i = 0; i < 2; i++) {
    bad = await passkeyAssert(browser, bobAuth, { tamper: (p) => { p._signature = b64url(new Uint8Array(70)); } });
    check(!command(bad.assert, 'passkeys_unwrap'), `bad signature ${i + 1} is rejected`, describe(bad.assert));
}
const locked = await passkeyAssert(browser, bobAuth);
check(!command(locked.assert, 'passkeys_unwrap') && /Too many failed login attempts/.test(message(locked.assert)),
    'after 3 failures a valid passkey is refused: account locked', describe(locked.assert));
await browser.loginPage();
res = await browser.passwordLogin(...BOB);
check(res.status !== 302, 'the password login is locked too (same counter)', `${res.status}`);

section('Stale password (carol)');
const carolAuth = new SoftAuthenticator({ origin: BASE });
await browser.signIn(CAROL);
const carolKey = await enrol(browser, carolAuth, 'carol key', CAROL[1], { wraps: 'carol-old-pass' });
check(!!command(carolKey.register, 'passkeys_add_row'), 'carol enrols a passkey (holding a password that is about to be "old")', describe(carolKey.register));
await browser.logout();
signin = await passkeySignIn(browser, carolAuth);
check(signin.password === 'carol-old-pass' && signin.res?.status !== 302, 'the mail server rejects the passkey\'s old password', `${signin.res?.status}`);
check(signin.res?.text.includes('Your password has changed since this passkey was set up'), 'the login page explains it', signin.res?.text.match(/display_message\([^)]*\)/g)?.join(' '));
await browser.loginPage();
const again = await passkeyAssert(browser, carolAuth);
check(!command(again.assert, 'passkeys_unwrap') && command(again.assert, 'passkeys_stale')?.args[0].username === CAROL[0],
    'the stale passkey is no longer released (no second failed IMAP login)', describe(again.assert));

res = await browser.passwordLogin(...CAROL);
check(res.status === 302 && res.next.text.includes('"passkeys_stale_prompt":true'), 'password login: the next page prompts to update', `${res.status}`);
page = await browser.request({ _task: 'mail' });
check(!page.text.includes('"passkeys_stale_prompt":true'), 'the prompt is shown once');
page = await browser.settingsList();
check(/passkeys-stale/.test(row(page, carolKey.cred.id)) && row(page, carolKey.cred.id).includes(`data-passkeys-update="${carolKey.cred.id}"`),
    'settings marks it "needs update" with an Update action', row(page, carolKey.cred.id));

res = await browser.ajax('settings', 'plugin.passkeys.update-challenge', { _credential_id: carolKey.cred.id, _password: CAROL[1] }, { token: false });
check(res.status === 403, 'update-challenge without the request token is refused', `${res.status}`);
res = await browser.ajax('settings', 'plugin.passkeys.update-challenge', { _credential_id: carolKey.cred.id, _password: CAROL[1] });
const updateAuth = command(res, 'passkeys_update_auth');
check(updateAuth?.args[0].args.publicKey.allowCredentials?.[0]?.id === carolKey.cred.id, 'update-challenge asks that passkey for an assertion', describe(res));
if (updateAuth) {
    const data = updateAuth.args[0];
    const assertion = await carolAuth.get(decodeOptions(data.args, data.prf_salt));
    res = await browser.ajax('settings', 'plugin.passkeys.update', {
        ...assertionPost(assertion),
        ...(await wrap(assertion.getClientExtensionResults().prf.results.first, CAROL[1])),
    });
    check(command(res, 'passkeys_update_row')?.args[0].stale === false, 'update stores the new password and clears the flag', describe(res));
}
await browser.logout();
signin = await passkeySignIn(browser, carolAuth);
check(signin.password === CAROL[1] && signin.res?.status === 302, 'the updated passkey signs in again', `${signin.res?.status}`);

console.log(`\n${failures ? `${failures} check(s) failed` : 'all checks passed'}`);
process.exit(failures ? 1 : 0);
