// ============================================================================
// src/checks.js - the production checklist, as code (sections 7, 15)
// ============================================================================
// Each check reads a deployment (a Compose file, the env files it uses, and
// the files around it) and returns findings:
//
//   FAIL   must be fixed before going live
//   WARN   probably wrong - fix it, or be able to explain why not
//
// Some checklist items cannot be read from a file - "everyone has their own
// admin account with MFA", "someone receives the alerts". Those stay on the
// MANUAL list. A tool that pretends to check everything is worse than one
// that is honest about what it cannot see.
//
// One rule for the tool itself: it reads secret values to judge them, but it
// NEVER prints one. Findings name the variable, not its value.
// ============================================================================

const DATABASE_IMAGES = /^(.*\/)?(postgres|mysql|mariadb|mongo|redis|mcr\.microsoft\.com\/mssql\/server)(:|@|$)/;
const PROXY_IMAGES = /^(.*\/)?(caddy|nginx|traefik|haproxy|envoy)(:|@|$)/;
const SECRET_NAME = /(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)$/i;
const DEFAULT_PASSWORDS = new Set(['postgres', 'password', 'admin', 'root', 'changeme', 'change_me', 'secret', 'example', '123456', 'pass']);
const SUPERUSERS = new Set(['postgres', 'root', 'sa', 'admin']);
const TEMPLATE_ENV = /^\.env\.(example|sample|template)$/;

const MANUAL = [
    'Every administrator has an individual account, with MFA (section 9)',
    'Logs and alerts are enabled - and someone actually receives the alerts (Module 8)',
    'Error messages show no stack traces or internal details (Module 3)',
    'The application and its dependencies are patched and scanned (Modules 4-6)',
    'Certificate renewal is automatic, or its expiry date is monitored',
    'Deployment and recovery procedures are written down and tested',
];

// "5432:5432", "127.0.0.1:5432:5432", "80", "8080:80/tcp", or the long form.
function parsePort(entry) {
    if (typeof entry === 'object' && entry !== null) {
        return {
            hostIp: entry.host_ip || null,
            published: entry.published != null ? String(entry.published) : null,
            target: String(entry.target),
        };
    }
    const parts = String(entry).replace(/\/(tcp|udp)$/, '').split(':');
    if (parts.length === 1) return { hostIp: null, published: null, target: parts[0] };
    if (parts.length === 2) return { hostIp: null, published: parts[0], target: parts[1] };
    return { hostIp: parts.slice(0, -2).join(':'), published: parts.at(-2), target: parts.at(-1) };
}

const isPublic = (port) => port.published !== null && (!port.hostIp || port.hostIp === '0.0.0.0' || port.hostIp === '::');
const isLocalOnly = (port) => port.published !== null && ['127.0.0.1', 'localhost', '::1'].includes(port.hostIp);
const isInterpolated = (value) => typeof value === 'string' && value.includes('${');

function environmentOf(service) {
    const env = service.environment || {};
    if (Array.isArray(env)) {
        return Object.fromEntries(env.map((item) => {
            const at = String(item).indexOf('=');
            return at === -1 ? [item, ''] : [item.slice(0, at), item.slice(at + 1)];
        }));
    }
    return Object.fromEntries(Object.entries(env).map(([k, v]) => [k, v == null ? '' : String(v)]));
}

function envFilesOf(service) {
    const value = service.env_file;
    if (!value) return [];
    return (Array.isArray(value) ? value : [value]).map((item) => (typeof item === 'object' ? item.path : item));
}

// deployment = { compose, envFiles: { relPath: {KEY: value} }, files: [relPath], tracking(relPath) }
function runChecks(deployment) {
    const { compose, envFiles, files, tracking } = deployment;
    const services = Object.entries(compose.services || {});
    const findings = [];
    const add = (status, area, message) => findings.push({ status, area, message });

    // Effective environment per service: env_file values, then "environment:" wins.
    const effectiveEnv = Object.fromEntries(services.map(([name, svc]) => {
        const fromFiles = Object.assign({}, ...envFilesOf(svc).map((f) => envFiles[f] || {}));
        return [name, { ...fromFiles, ...environmentOf(svc) }];
    }));

    // --- HTTPS -------------------------------------------------------------
    const published = services.flatMap(([name, svc]) =>
        (svc.ports || []).map(parsePort).filter(isPublic).map((p) => ({ name, svc, ...p })));
    if (!published.some((p) => p.published === '443')) {
        const plain = published.map((p) => `${p.name}:${p.published}`).join(', ') || 'none';
        add('FAIL', 'HTTPS', `No service publishes port 443, so traffic is plain HTTP (published: ${plain})`);
    }
    for (const p of published) {
        const isProxy = PROXY_IMAGES.test(p.svc.image || '') || p.name === 'proxy';
        const isDb = DATABASE_IMAGES.test(p.svc.image || '');
        if (!isProxy && !isDb && !['80', '443'].includes(p.published)) {
            add('WARN', 'Exposure', `${p.name} publishes port ${p.published} directly - route it through the HTTPS proxy instead`);
        }
    }

    // --- Debug -------------------------------------------------------------
    for (const [name, env] of Object.entries(effectiveEnv)) {
        if (env.NODE_ENV !== undefined && !isInterpolated(env.NODE_ENV) && env.NODE_ENV !== 'production') {
            add('FAIL', 'Debug', `${name}: NODE_ENV is "${env.NODE_ENV}", not "production"`);
        }
        if (env.DEBUG !== undefined && /^(1|true|yes|on|\*)$/i.test(env.DEBUG)) {
            add('FAIL', 'Debug', `${name}: DEBUG is switched on`);
        }
    }

    // --- Secrets: files ----------------------------------------------------
    for (const file of files) {
        const base = file.split('/').pop();
        if (!/^\.env(\..+)?$/.test(base) || TEMPLATE_ENV.test(base)) continue;
        const state = tracking(file);
        if (state === 'tracked') {
            add('FAIL', 'Secrets', `${file} is committed to Git - remove it AND rotate every value in it`);
        } else if (state === 'untracked') {
            add('WARN', 'Secrets', `${file} is not git-ignored - one "git add ." away from being committed`);
        }
    }

    // --- Secrets: written into the Compose file ----------------------------
    for (const [name, svc] of services) {
        for (const [key, value] of Object.entries(environmentOf(svc))) {
            if (SECRET_NAME.test(key) && value !== '' && !isInterpolated(value)) {
                add('FAIL', 'Secrets', `${name}: ${key} is written in the Compose file - inject it at deploy time`);
            }
        }
    }

    // --- Default credentials (once per env file, once per service literal) ---
    const defaults = (env) => Object.entries(env)
        .filter(([key, value]) => /PASSWORD$/i.test(key) && DEFAULT_PASSWORDS.has(String(value).toLowerCase()))
        .map(([key]) => key);
    for (const [file, env] of Object.entries(envFiles)) {
        const keys = defaults(env);
        if (keys.length) add('FAIL', 'Credentials', `${file}: ${keys.join(', ')} use a well-known default password`);
    }
    for (const [name, svc] of services) {
        const keys = defaults(environmentOf(svc));
        if (keys.length) add('FAIL', 'Credentials', `${name}: ${keys.join(', ')} use a well-known default password`);
    }

    // --- Database exposure -------------------------------------------------
    for (const [name, svc] of services) {
        if (!DATABASE_IMAGES.test(svc.image || '')) continue;
        for (const port of (svc.ports || []).map(parsePort)) {
            if (isPublic(port)) {
                add('FAIL', 'Database', `${name} publishes port ${port.published} to every network - the database must not face the internet`);
            } else if (isLocalOnly(port)) {
                add('WARN', 'Database', `${name} publishes port ${port.published} on localhost - the application never needs this; remove it`);
            }
        }
    }

    // --- Least privilege: the app's database account ------------------------
    for (const [name, env] of Object.entries(effectiveEnv)) {
        if (DATABASE_IMAGES.test(compose.services[name].image || '')) continue;
        const user = env.DB_USER || env.PGUSER;
        if (user && !isInterpolated(user) && SUPERUSERS.has(user.toLowerCase())) {
            add('WARN', 'Least privilege', `${name} connects to the database as "${user}", a superuser - give it its own limited account`);
        }
    }

    // --- Pinned images ------------------------------------------------------
    for (const [name, svc] of services) {
        if (svc.build) {
            add('WARN', 'Images', `${name} is built on the server - deploy the image your pipeline built and scanned`);
        }
        if (!svc.image) continue;
        const ref = svc.image.split('@')[0];
        const tag = ref.lastIndexOf(':') > ref.lastIndexOf('/') ? ref.slice(ref.lastIndexOf(':') + 1) : null;
        if (!svc.image.includes('@') && (tag === null || tag === 'latest')) {
            add('WARN', 'Images', `${name} uses "${svc.image}" - pin a version so every update is deliberate and scanned`);
        }
    }

    // --- Backups ------------------------------------------------------------
    if (!files.some((f) => /(^|\/)backups?\/.*restore/i.test(f))) {
        add('FAIL', 'Backups', 'No restore test found (expected backup/restore-test.sh) - an untested backup is a hope, not a backup');
    }

    return { findings, manual: MANUAL };
}

module.exports = { runChecks, parsePort, MANUAL };
