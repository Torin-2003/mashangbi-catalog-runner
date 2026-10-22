// Generic maintenance infrastructure only; no business code is loaded or executed.
import { createHash, createSign } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { CODE_PATH, MAX_CODE, REPOSITORY, REPOSITORY_ID, digest, ensure, hash,
  hexKey, openRunner, openTransfer, sealRunner } from './transfer-codec.mjs';
const RUNNER_REPO = 'Torin-2003/mashangbi-catalog-runner';
const API = 'https://api.github.com';
const BASE = `/repos/${REPOSITORY}`;
const sha1 = (bytes) => createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
async function bounded(response, limit) {
  const chunks = []; let size = 0;
  try {
    for await (const chunk of response.body ?? []) {
      size += chunk.length; ensure(size <= limit); chunks.push(Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  } finally { for (const chunk of chunks) chunk.fill(0); }
}
export async function reseal(env, transport = globalThis.fetch, now = Date.now) {
  // Reject local execution, forks, other workflows, refs, enabled runners, stale hash pins and debug logging.
  ensure(env.GITHUB_ACTIONS === 'true' && env.GITHUB_EVENT_NAME === 'workflow_dispatch');
  ensure(env.GITHUB_REPOSITORY === RUNNER_REPO && env.GITHUB_REF === 'refs/heads/main');
  ensure(env.GITHUB_WORKFLOW_REF === `${RUNNER_REPO}/.github/workflows/reseal-runner.yml@refs/heads/main`);
  ensure(env.CATALOG_RUNNER_ENABLED === '0');
  ensure(env.ACTIONS_STEP_DEBUG !== 'true' && env.ACTIONS_RUNNER_DEBUG !== 'true' && env.RUNNER_DEBUG !== '1');
  ensure(env.MAINTENANCE_MODE === 'publish' || env.MAINTENANCE_MODE === 'recover');
  const oldHash = hash(env.EXPECTED_OLD_SHA256), transferHash = hash(env.TRANSFER_SHA256);
  ensure(hash(env.CATALOG_RUNNER_CODE_SHA256) === oldHash);
  ensure(/^\d+$/.test(env.CATALOG_PUBLISHER_APP_ID ?? '') && /^\d+$/.test(env.CATALOG_PUBLISHER_INSTALLATION_ID ?? ''));
  const master = hexKey(env.CATALOG_CHECKPOINT_KEY), transferKey = hexKey(env.CATALOG_RESEAL_TRANSFER_KEY);
  let token, code, oldCode, checkCode, result;
  async function request(path, auth, method = 'GET', body, raw = false) {
    // All callers below use constants or validated SHA values, never response download URLs.
    const response = await transport(`${API}${path}`, { method, redirect: 'error',
      credentials: 'omit', signal: AbortSignal.timeout(30000), headers: {
        authorization: `Bearer ${auth}`, accept: raw ? 'application/vnd.github.raw+json' : 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'MSB-Reseal-Maintenance/1',
        ...(body ? { 'Content-Type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}) });
    if (!response.ok) { await response.body?.cancel(); throw Error('Rejected'); }
    if (response.status === 204) { await response.body?.cancel(); return null; }
    const bytes = await bounded(response, raw ? MAX_CODE + 8192 : 1024 * 1024);
    if (raw) return bytes;
    try { return JSON.parse(bytes.toString('utf8')); } finally { bytes.fill(0); }
  }
  const json = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  try {
    const issued = Math.floor(now() / 1000);
    const body = `${json({ alg: 'RS256', typ: 'JWT' })}.${json({ iat: issued - 60, exp: issued + 540, iss: env.CATALOG_PUBLISHER_APP_ID })}`;
    const jwt = `${body}.${createSign('RSA-SHA256').update(body).sign(env.CATALOG_PUBLISHER_APP_PRIVATE_KEY, 'base64url')}`;
    const installationPath = `/app/installations/${env.CATALOG_PUBLISHER_INSTALLATION_ID}`;
    const installation = await request(installationPath, jwt);
    ensure(String(installation.app_id) === env.CATALOG_PUBLISHER_APP_ID && installation.account?.login === 'Torin-2003' && installation.suspended_at === null);
    const granted = await request(`${installationPath}/access_tokens`, jwt, 'POST', {
      repository_ids: [REPOSITORY_ID], permissions: { contents: 'write' } });
    ensure(typeof granted.token === 'string' && granted.token.length > 0);
    token = granted.token;
    const expires = Date.parse(granted.expires_at);
    ensure(Number.isFinite(expires) && expires > now() + 60000 && expires <= now() + 3660000);
    ensure(granted.permissions?.contents === 'write' && Object.entries(granted.permissions).every(
      ([key, value]) => key === 'contents' || (key === 'metadata' && value === 'read')));
    const access = await request('/installation/repositories?per_page=100', token);
    ensure(access.total_count === 1 && access.repositories?.length === 1);
    const identity = (repo) => ensure(repo.id === REPOSITORY_ID && repo.full_name === REPOSITORY && repo.private === true);
    identity(access.repositories[0]);
    const repo = await request(BASE, token); identity(repo); ensure(repo.default_branch === 'main' && repo.archived === false);
    const branch = await request(`${BASE}/branches/main`, token);
    const revision = branch.commit?.sha; ensure(/^[a-f0-9]{40}$/.test(revision ?? ''));
    async function file(path, revision) {
      const endpoint = `${BASE}/contents/${path}?ref=${revision}`;
      const meta = await request(endpoint, token);
      ensure(meta.type === 'file' && meta.path === path && /^[a-f0-9]{40}$/.test(meta.sha ?? ''));
      ensure(Number.isSafeInteger(meta.size) && meta.size > 0 && meta.size <= MAX_CODE + 8192);
      const bytes = await request(endpoint, token, 'GET', undefined, true);
      ensure(bytes.length === meta.size && sha1(bytes) === meta.sha);
      return { bytes, sha: meta.sha };
    }
    const transfer = await file(`maintenance/transfers/${transferHash}.enc`, revision);
    code = openTransfer(transfer.bytes, transferKey, transferHash, oldHash, now());
    const old = await file(CODE_PATH, revision);
    if (env.MAINTENANCE_MODE === 'recover') {
      // Lost-response recovery is strictly read-only and requires current ciphertext to contain this exact bundle.
      oldCode = openRunner(old.bytes, master); ensure(oldCode.equals(code));
      result = digest(old.bytes);
    } else {
      ensure(digest(old.bytes) === oldHash);
      oldCode = openRunner(old.bytes, master); // Detect wrong checkpoint master BEFORE any write.
      ensure(oldCode.length > 0);
      const sealed = sealRunner(code, master);
      checkCode = openRunner(sealed, master); ensure(checkCode.equals(code));
      const expectedNew = digest(sealed);
      // Exactly one mutation, never blindly retried. GitHub contents SHA precondition is per-file CAS.
      const written = await request(`${BASE}/contents/${CODE_PATH}`, token, 'PUT', {
        message: 'chore: reseal encrypted catalog runner\n\nCo-Authored-By: Claude Code <noreply@anthropic.com>', branch: 'main', sha: old.sha,
        content: sealed.toString('base64') });
      ensure(written.content?.path === CODE_PATH && written.content.sha === sha1(sealed));
      ensure(/^[a-f0-9]{40}$/.test(written.commit?.sha ?? ''));
      const verified = await file(CODE_PATH, written.commit.sha);
      ensure(digest(verified.bytes) === expectedNew);
      // Also detect an immediate competing update at the branch tip; disabled flag remains external gate.
      const current = await file(CODE_PATH, 'main'); ensure(digest(current.bytes) === expectedNew);
      result = expectedNew;
    }
  } finally {
    master.fill(0); transferKey.fill(0); code?.fill(0); oldCode?.fill(0); checkCode?.fill(0);
    // Token revocation attempted on success AND error; if it fails, fail closed without emitting the hash.
    if (token) await request('/installation/token', token, 'DELETE');
  }
  return result;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  reseal(process.env).then((value) => console.log(value)).catch(() => {
    console.error('Maintenance failed; runner remains disabled; inspect private ciphertext before retry.');
    process.exitCode = 1;
  });
}
