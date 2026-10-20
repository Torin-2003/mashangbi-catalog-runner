import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto';
export const REPOSITORY = 'Torin-2003/mashangbi-catalog-state';
export const REPOSITORY_ID = 1425995770;
export const CODE_PATH = 'runner/runner.enc';
export const MAX_CODE = 16 * 1024 * 1024 - 36;
const CODE_MAGIC = Buffer.from('MSBRC1\0\0');
const TRANSFER_MAGIC = Buffer.from('MSBRT1\0\0');
export const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
export function ensure(value) { if (!value) throw Error('Rejected'); }
export function hexKey(value) {
  ensure(typeof value === 'string' && /^[a-fA-F0-9]{64}$/.test(value));
  return Buffer.from(value, 'hex');
}
export function hash(value) { ensure(typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)); return value; }
function encrypt(code, key, aad) {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const body = Buffer.concat([cipher.update(code), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]);
}
function decrypt(body, key, aad) {
  ensure(body.length >= 28);
  const cipher = createDecipheriv('aes-256-gcm', key, body.subarray(0, 12));
  cipher.setAAD(aad); cipher.setAuthTag(body.subarray(12, 28));
  const provisional = cipher.update(body.subarray(28));
  try { return Buffer.concat([provisional, cipher.final()]); }
  finally { provisional.fill(0); }
}
function derived(master) {
  ensure(master.length === 32);
  return Buffer.from(hkdfSync('sha256', master, Buffer.alloc(0), 'mashangbi-runner-code-v1', 32));
}
export function sealRunner(code, master) {
  ensure(code.length > 0 && code.length <= MAX_CODE);
  const key = derived(master);
  try { return Buffer.concat([CODE_MAGIC, encrypt(code, key, CODE_MAGIC)]); }
  finally { key.fill(0); }
}
export function openRunner(bytes, master) {
  ensure(bytes.length <= MAX_CODE + 36 && bytes.subarray(0, 8).equals(CODE_MAGIC));
  const key = derived(master);
  try { return decrypt(bytes.subarray(8), key, CODE_MAGIC); }
  finally { key.fill(0); }
}
export function makeTransfer(code, key, expectedOldSha256, now = Date.now()) {
  ensure(key.length === 32 && code.length > 0 && code.length <= MAX_CODE);
  const metadata = Buffer.from(JSON.stringify({ version: 1, repository: REPOSITORY,
    repositoryId: REPOSITORY_ID, path: CODE_PATH, expectedOldSha256: hash(expectedOldSha256),
    codeSha256: digest(code), createdAt: now, expiresAt: now + 24 * 60 * 60 * 1000 }));
  const length = Buffer.alloc(4); length.writeUInt32BE(metadata.length);
  const aad = Buffer.concat([TRANSFER_MAGIC, length, metadata]);
  return Buffer.concat([aad, encrypt(code, key, aad)]);
}
export function openTransfer(bytes, key, expectedDigest, expectedOldSha256, now = Date.now()) {
  ensure(key.length === 32 && bytes.length >= 40 && bytes.length <= MAX_CODE + 8192);
  ensure(digest(bytes) === hash(expectedDigest) && bytes.subarray(0, 8).equals(TRANSFER_MAGIC));
  const length = bytes.readUInt32BE(8);
  ensure(length > 0 && length <= 4096 && bytes.length > 12 + length + 28);
  const aad = bytes.subarray(0, 12 + length);
  const metadata = JSON.parse(bytes.subarray(12, 12 + length).toString('utf8'));
  ensure(Object.keys(metadata).sort().join(',') === 'codeSha256,createdAt,expectedOldSha256,expiresAt,path,repository,repositoryId,version');
  ensure(metadata.version === 1 && metadata.repository === REPOSITORY && metadata.repositoryId === REPOSITORY_ID && metadata.path === CODE_PATH);
  ensure(metadata.expectedOldSha256 === hash(expectedOldSha256));
  ensure(Number.isSafeInteger(metadata.createdAt) && Number.isSafeInteger(metadata.expiresAt));
  ensure(metadata.createdAt <= now + 60000 && metadata.expiresAt > now && metadata.expiresAt - metadata.createdAt === 86400000);
  const code = decrypt(bytes.subarray(12 + length), key, aad);
  try { ensure(code.length > 0 && code.length <= MAX_CODE && digest(code) === hash(metadata.codeSha256)); return code; }
  catch (error) { code.fill(0); throw error; }
}
