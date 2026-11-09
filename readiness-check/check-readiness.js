// ============================================================================
// check-readiness.js - run the production checklist against a deployment
// ============================================================================
//   npm run check -- ../scenario
//   npm run check -- ../hardened
//   npm run check -- "D:\path\to\your\project"     (any folder with a Compose file)
//
// Exit code 1 when anything FAILS, so the same command can be a pipeline gate
// (Module 6): no green check, no deployment.
// ============================================================================

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const YAML = require('yaml');
const { runChecks } = require('./src/checks');

const COMPOSE_NAMES = ['compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml'];
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'coverage']);

function listFiles(root, dir = '', depth = 0) {
    if (depth > 3) return [];
    return fs.readdirSync(path.join(root, dir), { withFileTypes: true }).flatMap((entry) => {
        const rel = dir ? `${dir}/${entry.name}` : entry.name;
        if (entry.isDirectory()) return SKIP_DIRS.has(entry.name) ? [] : listFiles(root, rel, depth + 1);
        return [rel];
    });
}

// KEY=value lines only. Values are kept in memory for the checks, never printed.
function parseEnvFile(text) {
    const env = {};
    for (const line of text.split(/\r?\n/)) {
        const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
        if (match) env[match[1]] = match[2].replace(/^(['"])(.*)\1$/, '$2');
    }
    return env;
}

function gitTracking(root) {
    return (rel) => {
        const file = path.join(root, rel);
        try {
            execFileSync('git', ['ls-files', '--error-unmatch', file], { cwd: root, stdio: 'ignore' });
            return 'tracked';
        } catch {
            // not tracked - is it ignored?
        }
        try {
            execFileSync('git', ['check-ignore', '-q', file], { cwd: root, stdio: 'ignore' });
            return 'ignored';
        } catch {
            return 'untracked';
        }
    };
}

function loadDeployment(root) {
    const composeName = COMPOSE_NAMES.find((name) => fs.existsSync(path.join(root, name)));
    if (!composeName) throw new Error(`No Compose file found in ${root}`);
    const compose = YAML.parse(fs.readFileSync(path.join(root, composeName), 'utf8')) || {};

    const envFiles = {};
    for (const svc of Object.values(compose.services || {})) {
        const list = svc.env_file ? [].concat(svc.env_file) : [];
        for (const item of list) {
            const rel = typeof item === 'object' ? item.path : item;
            const file = path.join(root, rel);
            if (fs.existsSync(file)) envFiles[rel] = parseEnvFile(fs.readFileSync(file, 'utf8'));
        }
    }

    const files = listFiles(root);
    return { composeName, compose, envFiles, files, tracking: gitTracking(root) };
}

function formatReport(target, composeName, { findings, manual }) {
    const lines = [`Production-readiness check: ${path.join(target, composeName)}`, ''];
    const order = { FAIL: 0, WARN: 1 };
    for (const f of [...findings].sort((a, b) => order[a.status] - order[b.status])) {
        lines.push(`  ${f.status.padEnd(5)} ${f.area.padEnd(16)} ${f.message}`);
    }
    if (findings.length === 0) lines.push('  No automated findings.');
    lines.push('', '  Check by hand - no file can prove these:');
    for (const item of manual) lines.push(`  [ ]   ${item}`);

    const fails = findings.filter((f) => f.status === 'FAIL').length;
    const warns = findings.filter((f) => f.status === 'WARN').length;
    lines.push('', fails
        ? `Result: ${fails} failed, ${warns} warning(s) - NOT ready for production.`
        : `Result: no failures, ${warns} warning(s) - now complete the manual checks.`);
    return { text: lines.join('\n'), fails };
}

function main() {
    const target = process.argv[2];
    if (!target) {
        console.error('Usage: npm run check -- <folder containing a Compose file>');
        process.exit(2);
    }
    const root = path.resolve(target);
    const deployment = loadDeployment(root);
    const { text, fails } = formatReport(target, deployment.composeName, runChecks(deployment));
    console.log(text);
    process.exit(fails ? 1 : 0);
}

if (require.main === module) main();

module.exports = { loadDeployment, parseEnvFile, formatReport };
