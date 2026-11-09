// ============================================================================
// tests/checks.test.js - the checker must catch the scenario's problems,
// pass the hardened version, and never print a secret
// ============================================================================

const path = require('path');
const { runChecks, parsePort } = require('../src/checks');
const { loadDeployment, formatReport } = require('../check-readiness');

const SCENARIO = path.join(__dirname, '..', '..', 'scenario');
const HARDENED = path.join(__dirname, '..', '..', 'hardened');

// Git state is mocked, so the tests give the same answer before and after
// the files are committed.
function load(root, tracking = () => 'tracked') {
    return { ...loadDeployment(root), tracking };
}

const areas = (findings, status) => findings.filter((f) => f.status === status).map((f) => f.area);

describe('the scenario deployment', () => {
    const { findings } = runChecks(load(SCENARIO));
    const fails = areas(findings, 'FAIL');

    it.each(['HTTPS', 'Debug', 'Secrets', 'Credentials', 'Database', 'Backups'])('fails on %s', (area) => {
        expect(fails).toContain(area);
    });

    it('flags both debug settings', () => {
        const debug = findings.filter((f) => f.area === 'Debug').map((f) => f.message);
        expect(debug).toEqual(expect.arrayContaining([
            expect.stringContaining('NODE_ENV is "development"'),
            expect.stringContaining('DEBUG is switched on'),
        ]));
    });

    it('warns about the API port, the superuser account and unpinned images', () => {
        const warns = areas(findings, 'WARN');
        expect(warns).toEqual(expect.arrayContaining(['Exposure', 'Least privilege', 'Images']));
    });
});

describe('the hardened deployment', () => {
    it('has no failures and no warnings', () => {
        const { findings } = runChecks(load(HARDENED));
        expect(findings).toEqual([]);
    });
});

describe('the report itself', () => {
    it('never prints a secret value', () => {
        const deployment = load(SCENARIO);
        const { text } = formatReport('../scenario', deployment.composeName, runChecks(deployment));

        expect(text).toContain('POSTGRES_PASSWORD');
        expect(text).not.toContain('students-prod-jwt-2026');
        expect(text).not.toMatch(/PASSWORD[^\n]*=\s*postgres/);
    });

    it('always lists the checks no file can prove', () => {
        const deployment = load(HARDENED);
        const { text } = formatReport('../hardened', deployment.composeName, runChecks(deployment));
        expect(text).toContain('individual account, with MFA');
    });
});

describe('individual rules', () => {
    const deployment = (services, extra = {}) => ({
        compose: { services },
        envFiles: {},
        files: ['backup/restore-test.sh', ...(extra.files || [])],
        tracking: extra.tracking || (() => 'tracked'),
    });

    it('reads every Compose port syntax', () => {
        expect(parsePort('5432:5432')).toEqual({ hostIp: null, published: '5432', target: '5432' });
        expect(parsePort('127.0.0.1:5432:5432')).toEqual({ hostIp: '127.0.0.1', published: '5432', target: '5432' });
        expect(parsePort('80')).toEqual({ hostIp: null, published: null, target: '80' });
        expect(parsePort('8080:80/tcp')).toEqual({ hostIp: null, published: '8080', target: '80' });
        expect(parsePort({ target: 443, published: 443 })).toEqual({ hostIp: null, published: '443', target: '443' });
    });

    it('accepts secrets injected with ${...} but fails secrets written in the file', () => {
        const { findings } = runChecks(deployment({
            proxy: { image: 'caddy:2.11.7-alpine', ports: ['443:443'] },
            ok: { image: 'api:1.0.0', environment: { DB_PASSWORD: '${DB_PASSWORD}' } },
            bad: { image: 'api:1.0.0', environment: { JWT_SECRET: 'abc123' } },
        }));
        const secrets = findings.filter((f) => f.area === 'Secrets');
        expect(secrets).toHaveLength(1);
        expect(secrets[0].message).toContain('bad: JWT_SECRET');
        expect(secrets[0].message).not.toContain('abc123');
    });

    it('warns - not fails - for a database bound to localhost only', () => {
        const { findings } = runChecks(deployment({
            proxy: { image: 'caddy:2.11.7-alpine', ports: ['443:443'] },
            db: { image: 'postgres:17.11-alpine', ports: ['127.0.0.1:5432:5432'] },
        }));
        expect(findings.filter((f) => f.area === 'Database').map((f) => f.status)).toEqual(['WARN']);
    });

    it('treats an untracked .env as a warning and an ignored one as fine', () => {
        const services = { proxy: { image: 'caddy:2.11.7-alpine', ports: ['443:443'] } };
        const untracked = runChecks(deployment(services, { files: ['.env'], tracking: () => 'untracked' }));
        const ignored = runChecks(deployment(services, { files: ['.env'], tracking: () => 'ignored' }));

        expect(untracked.findings.map((f) => f.status)).toEqual(['WARN']);
        expect(ignored.findings).toEqual([]);
    });

    it('warns when a service is built on the server instead of pulled as a pinned image', () => {
        const { findings } = runChecks(deployment({
            proxy: { image: 'caddy:2.11.7-alpine', ports: ['443:443'] },
            backend: { build: './backend' },
        }));
        expect(findings).toEqual([expect.objectContaining({ status: 'WARN', area: 'Images' })]);
        expect(findings[0].message).toContain('built on the server');
    });

    it('never treats .env.example as a secret file', () => {
        const { findings } = runChecks(deployment(
            { proxy: { image: 'caddy:2.11.7-alpine', ports: ['443:443'] } },
            { files: ['.env.example'] },
        ));
        expect(findings).toEqual([]);
    });
});
