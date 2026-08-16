#!/usr/bin/env node
import { webcrypto } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const password = process.env.ITINERARY_PASSWORD || '';
const extraTerms = (process.env.SENSITIVE_TERMS || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
if (!password) { console.error('Missing GitHub secret: ITINERARY_PASSWORD'); process.exit(2); }

const enc = new TextEncoder();
const dec = new TextDecoder();
const findings = [];

function hexToBytes(hex) { return new Uint8Array(hex.match(/../g).map(b => parseInt(b, 16))); }
function b64ToBytes(b64) { return new Uint8Array(Buffer.from(b64, 'base64')); }
function mask(s) { s = String(s); return s.length <= 6 ? '*'.repeat(s.length) : `${s.slice(0, 2)}***${s.slice(-2)}`; }
function add(source, rule, sample) { findings.push({ source, rule, sample: mask(String(sample).slice(0, 80)) }); }
function luhnOk(digits) {
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) { let n = Number(digits[i]); if (alt) { n *= 2; if (n > 9) n -= 9; } sum += n; alt = !alt; }
  return sum % 10 === 0;
}
async function deriveKey(password, salt, iterations) {
  const baseKey = await webcrypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return webcrypto.subtle.deriveKey({ name: 'PBKDF2', salt: enc.encode(salt), iterations, hash: 'SHA-256' }, baseKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}
async function decryptPayload() {
  const data = JSON.parse(await fs.readFile(path.join(root, 'encrypted-data.json'), 'utf8'));
  if (data.alg !== 'AES-GCM') throw new Error(`Unexpected encryption alg: ${data.alg}`);
  const key = await deriveKey(password, data.salt, data.iterations);
  const cipher = b64ToBytes(data.ciphertext), tag = b64ToBytes(data.tag);
  const combined = new Uint8Array(cipher.length + tag.length);
  combined.set(cipher); combined.set(tag, cipher.length);
  const plaintext = await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: hexToBytes(data.iv), tagLength: data.tagLength || 128 }, key, combined);
  return dec.decode(plaintext);
}
async function walk(dir, out = []) {
  for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    const rel = path.relative(root, full);
    if (entry.isDirectory()) {
      if (['.git', 'node_modules'].includes(entry.name)) continue;
      await walk(full, out);
    } else if (entry.isFile()) {
      if (!/\.(png|jpe?g|gif|webp|ico|pdf|zip)$/i.test(entry.name)) out.push(rel);
    }
  }
  return out;
}

function scanText(source, text, { publicFile = false, decryptedPayload = false } = {}) {
  // Always check exact secrets/deny-list terms in all files and decrypted payload.
  if (text.includes(password)) add(source, 'password literal leaked', password);
  for (const term of extraTerms) if (text.toLowerCase().includes(term.toLowerCase())) add(source, 'SENSITIVE_TERMS match', term);

  // PII pattern scans are only for decrypted website payload, not README/source-code examples.
  if (decryptedPayload) {
    const rules = [
      ['email address', /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/ig],
      ['private google docs/sheets link', /https:\/\/docs\.google\.com\/[^\s"'<>]+/ig],
      ['booking/hotel confirmation context', /(?:booking\s*(?:reference|confirmation|details|number)|confirmation\s*(?:code|number)?|confirm(?:ation)?|reservation\s*(?:number|code)?|order\s*(?:number|id)?|訂位代碼|確認碼|訂單編號|確認編號|\bPNR\b)[\s\S]{0,100}\b[A-Z0-9]{5,14}\b/ig],
      ['ticket number context', /(?:ticket\s*number|e-?ticket|機票號碼)[\s\S]{0,80}\b\d{10,14}\b/ig],
      ['hotel confirmation alnum', /\b[A-Z0-9]{5,6}UC\d{6,8}\b/ig],
      ['passport number context', /(?:passports*(?:no.?|number)|護照號碼)[sS]{0,80}(?=[A-Z0-9]*d)[A-Z0-9]{6,12}/ig],
      ['phone context', /(?:phone|tel|mobile|電話|手機)[\s\S]{0,40}(?:\+?\d[\d\s().-]{8,}\d)/ig],
    ];
    for (const [name, re] of rules) for (const m of text.matchAll(re)) add(source, name, m[0]);
    for (const raw of text.match(/(?:\d[ -]?){13,19}/g) || []) {
      const digits = raw.replace(/\D/g, '');
      if (digits.length >= 13 && digits.length <= 19 && luhnOk(digits)) add(source, 'credit card-like number', raw);
    }
  }

  // Public website assets should not contain plaintext trip details.
  if (publicFile) {
    for (const re of [/AF\s*0005/i, /AF\s*0010/i, /ibis\s+Paris\s+Tour\s+Eiffel/i, /Cambronne/i, /Superior\s+Room/i]) {
      const m = text.match(re); if (m) add(source, 'plaintext trip detail in public file', m[0]);
    }
  }
}

for (const rel of await walk(root)) {
  const text = await fs.readFile(path.join(root, rel), 'utf8').catch(() => '');
  scanText(rel, text, { publicFile: ['index.html', 'style.css', 'README.md'].includes(rel) });
}

let payload;
try { payload = await decryptPayload(); }
catch (err) { console.error(`Failed to decrypt encrypted-data.json with ITINERARY_PASSWORD: ${err.message}`); process.exit(2); }
scanText('decrypted encrypted-data.json payload', payload, { decryptedPayload: true });

if (findings.length) {
  console.error('Sensitive information scan failed:');
  for (const f of findings) console.error(`- ${f.source}: ${f.rule} (${f.sample})`);
  process.exit(1);
}
console.log('Sensitive information scan passed.');
console.log('Encrypted payload decrypted successfully; no configured sensitive patterns found.');
