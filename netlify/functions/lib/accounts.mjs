import { getStore } from "@netlify/blobs";
import { randomBytes, scrypt as _scrypt, timingSafeEqual, createHash } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(_scrypt);

export const accountStore = () => getStore("taiynsha-accounts");

const sha = (s) => createHash("sha256").update(String(s)).digest("hex");
const SESSION_TTL = 90 * 24 * 3600 * 1000;
const MAX_SESSIONS = 20;

export const validId = (id) => /^[A-Za-z0-9]{1,60}$/.test(String(id || ""));

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const key = await scrypt(String(password), salt, 64);
  return { salt: salt.toString("hex"), hash: key.toString("hex") };
}

export async function checkPassword(password, acc) {
  const key = await scrypt(String(password), Buffer.from(acc.salt, "hex"), 64);
  const want = Buffer.from(acc.hash, "hex");
  return key.length === want.length && timingSafeEqual(key, want);
}

export async function readAccount(store, id) {
  if (!validId(id)) return { acc: null, etag: null };
  const res = await store.getWithMetadata(`acc-${id}`, { type: "json", consistency: "strong" });
  return { acc: res?.data || null, etag: res?.etag || null };
}

export async function findIdByUsername(store, username) {
  const rec = await store.get(`un-${username}`, { type: "json", consistency: "strong" });
  return rec?.id || null;
}

// Чтение → изменение → запись с повтором при конфликте.
export async function mutateAccount(store, id, fn) {
  for (let attempt = 0; attempt < 6; attempt++) {
    const { acc, etag } = await readAccount(store, id);
    if (!acc) return { error: "not_found" };
    const out = await fn(acc);
    if (out && out.error && !out.saved) return out;
    const w = await store.setJSON(`acc-${id}`, acc, etag ? { onlyIfMatch: etag } : {});
    if (!w || w.modified !== false) return out && out.error ? { ...out, acc } : { acc, out };
  }
  return { error: "conflict" };
}

export function newSession(acc) {
  const secret = randomBytes(24).toString("hex");
  const now = Date.now();
  acc.sessions = (Array.isArray(acc.sessions) ? acc.sessions : []).filter((s) => now - s.created < SESSION_TTL);
  acc.sessions.push({ h: sha(secret), created: now });
  if (acc.sessions.length > MAX_SESSIONS) acc.sessions = acc.sessions.slice(-MAX_SESSIONS);
  return `${acc.id}.${secret}`;
}

export function hasSession(acc, token) {
  const secret = String(token || "").split(".")[1];
  if (!secret) return false;
  const h = sha(secret);
  const now = Date.now();
  return (acc.sessions || []).some((s) => s.h === h && now - s.created < SESSION_TTL);
}

export async function verifySession(store, token) {
  const id = String(token || "").split(".")[0];
  if (!validId(id)) return null;
  const { acc } = await readAccount(store, id);
  return acc && hasSession(acc, token) ? acc : null;
}

export function publicAccount(acc) {
  return {
    id: acc.id,
    nick: acc.nick,
    username: acc.username,
    bio: acc.bio || "",
    createdAt: acc.createdAt,
    usernameChangedAt: acc.usernameChangedAt || acc.createdAt,
    following: Array.isArray(acc.following) ? acc.following : [],
    captchaVerified: !!acc.captchaVerified,
  };
}

export function dropSession(acc, token) {
  const secret = String(token || "").split(".")[1];
  if (!secret) return;
  const h = sha(secret);
  acc.sessions = (acc.sessions || []).filter((s) => s.h !== h);
}
