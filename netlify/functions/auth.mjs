import { getStore } from "@netlify/blobs";
import { randomBytes } from "node:crypto";
import {
  accountStore, hashPassword, checkPassword, readAccount, findIdByUsername,
  mutateAccount, newSession, hasSession, verifySession, publicAccount, dropSession, validId,
} from "./lib/accounts.mjs";

const LOCK_STEPS = [3600_000, 5 * 3600_000, 24 * 3600_000]; // 1 ч → 5 ч → 24 ч и дальше
const MAX_FAILS = 5;
const DAY = 24 * 3600_000;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" },
  });
}

const USERNAME_RE = /^[a-z0-9_]{5,20}$/;
const NICK_RE = /^[\p{L}\p{N}_ .-]+$/u;

function checkNick(nick) {
  nick = String(nick || "").trim();
  if (nick.length < 5 || nick.length > 20) return "Имя должно содержать от 5 до 20 символов";
  if (!NICK_RE.test(nick)) return "Используй буквы, цифры, пробел, точку, дефис или _";
  return null;
}
const checkUsername = (u) => (USERNAME_RE.test(u) ? null : "Юзернейм: 5–20 символов, латиница, цифры и _");
const checkPassword8 = (p) => (typeof p === "string" && p.length >= 8 && p.length <= 128 ? null : "Пароль должен содержать от 8 до 128 символов");

async function legacyAllowed(id, username) {
  // Перенос старого аккаунта: допускается только если профиль с таким id и юзернеймом уже есть в общей ленте.
  try {
    const feed = await getStore("taiynsha-social").get("shared-feed-v1.json", { type: "json" });
    const p = (feed?.profiles || []).find((x) => x.id === id);
    return !!p && String(p.username || "").toLowerCase() === username;
  } catch { return false; }
}

export default async (request) => {
  if (request.method !== "POST") return json({ error: "method" }, 405);
  let body;
  try {
    const raw = await request.text();
    if (raw.length > 20_000) return json({ error: "too_large" }, 413);
    body = JSON.parse(raw);
  } catch { return json({ error: "bad_json" }, 400); }

  if (!body || typeof body !== 'object' || Array.isArray(body)) return json({ error: "bad_body" }, 400);

  const store = accountStore();
  const op = body.op;

  /* ---------- Регистрация ---------- */
  if (op === "register") {
    const username = String(body.username || "").trim().toLowerCase();
    const nick = String(body.nick || "").trim();
    const bio = String(body.bio || "").trim().slice(0, 180);
    const err = checkUsername(username) || checkNick(nick) || checkPassword8(body.password);
    if (err) return json({ error: "validation", message: err }, 400);

    let id = "u" + Date.now() + randomBytes(3).toString("hex");
    const legacy = String(body.legacyId || "");
    if (legacy && validId(legacy) && !(await readAccount(store, legacy)).acc && (await legacyAllowed(legacy, username))) id = legacy;

    const claim = await store.setJSON(`un-${username}`, { id }, { onlyIfNew: true });
    if (claim && claim.modified === false) return json({ error: "taken", message: "Этот юзернейм уже занят" }, 409);

    const { salt, hash } = await hashPassword(body.password);
    const now = Date.now();
    const acc = {
      id, username, nick, bio, createdAt: Number(body.createdAt) > 0 && id === legacy ? Number(body.createdAt) : now,
      usernameChangedAt: now, salt, hash, following: [], captchaVerified: false,
      fails: 0, lockLevel: 0, lockUntil: 0, sessions: [],
    };
    const session = newSession(acc);
    await store.setJSON(`acc-${id}`, acc);
    return json({ ok: true, session, profile: publicAccount(acc) });
  }

  /* ---------- Вход с блокировкой ---------- */
  if (op === "login") {
    const username = String(body.username || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!USERNAME_RE.test(username) || !password || password.length > 128) {
      return json({ error: "invalid", message: "Неверный юзернейм или пароль" }, 401);
    }
    const id = await findIdByUsername(store, username);
    const { acc } = id ? await readAccount(store, id) : { acc: null };
    if (!acc) {
      await hashPassword(password); // выравниваем время ответа
      return json({ error: "invalid", message: "Неверный юзернейм или пароль" }, 401);
    }
    const now = Date.now();
    if (acc.lockUntil > now) return json({ error: "locked", retryAfter: acc.lockUntil - now }, 429);

    const ok = await checkPassword(password, acc);
    const res = await mutateAccount(store, id, (a) => {
      const t = Date.now();
      if (a.lockUntil > t) return { error: "locked", retryAfter: a.lockUntil - t };
      if (ok) {
        a.fails = 0; a.lockLevel = 0; a.lockUntil = 0;
        return { session: newSession(a) };
      }
      a.fails = (a.fails || 0) + 1;
      if (a.fails >= MAX_FAILS) {
        a.lockLevel = (a.lockLevel || 0) + 1;
        a.fails = 0;
        a.lockUntil = t + LOCK_STEPS[Math.min(a.lockLevel - 1, LOCK_STEPS.length - 1)];
        return { error: "locked", retryAfter: a.lockUntil - t, saved: true };
      }
      return { error: "invalid", attemptsLeft: MAX_FAILS - a.fails, saved: true };
    });
    if (res.error === "locked") return json({ error: "locked", retryAfter: res.retryAfter }, 429);
    if (res.error === "invalid") return json({ error: "invalid", attemptsLeft: res.attemptsLeft, message: "Неверный юзернейм или пароль" }, 401);
    if (res.error === "not_found") return json({ error: "invalid", message: "Неверный юзернейм или пароль" }, 401);
    if (res.error) return json({ error: res.error }, 500);
    return json({ ok: true, session: res.out.session, profile: publicAccount(res.acc) });
  }

  /* ---------- Всё остальное требует сессии ---------- */
  const acc0 = await verifySession(store, body.session);
  if (!acc0) return json({ error: "no_session" }, 401);

  if (op === "me") return json({ ok: true, profile: publicAccount(acc0) });

  if (op === "logout") {
    await mutateAccount(store, acc0.id, (a) => { dropSession(a, body.session); });
    return json({ ok: true });
  }

  if (op === "delete") {
    await store.delete(`acc-${acc0.id}`);
    await store.delete(`un-${acc0.username}`);
    return json({ ok: true });
  }

  if (op === "update") {
    const patch = body.patch && typeof body.patch === "object" ? body.patch : {};
    if (patch.nick !== undefined) { const e = checkNick(patch.nick); if (e) return json({ error: "validation", message: e }, 400); }
    if (patch.password) { const e = checkPassword8(patch.password); if (e) return json({ error: "validation", message: e }, 400); }
    let newUsername = null;
    if (patch.username !== undefined) {
      newUsername = String(patch.username).trim().toLowerCase();
      const e = checkUsername(newUsername);
      if (e) return json({ error: "validation", message: e }, 400);
      if (newUsername !== acc0.username) {
        const left = DAY - (Date.now() - (acc0.usernameChangedAt || 0));
        if (left > 0) return json({ error: "validation", message: `Юзернейм можно будет сменить через ${Math.ceil(left / 3600_000)} ч.` }, 400);
        const claim = await store.setJSON(`un-${newUsername}`, { id: acc0.id }, { onlyIfNew: true });
        if (claim && claim.modified === false) return json({ error: "taken", message: "Этот юзернейм уже занят" }, 409);
      } else newUsername = null;
    }
    const pw = patch.password ? await hashPassword(patch.password) : null;
    const res = await mutateAccount(store, acc0.id, (a) => {
      if (!hasSession(a, body.session)) return { error: "no_session" };
      if (patch.nick !== undefined) a.nick = String(patch.nick).trim();
      if (patch.bio !== undefined) a.bio = String(patch.bio).trim().slice(0, 180);
      if (Array.isArray(patch.following)) a.following = patch.following.filter((x) => validId(x)).slice(0, 500);
      if (patch.captchaVerified === true) a.captchaVerified = true;
      if (newUsername) { a.username = newUsername; a.usernameChangedAt = Date.now(); }
      if (pw) {
        a.salt = pw.salt; a.hash = pw.hash;
        const keep = (a.sessions || []).filter((s) => hasSession({ sessions: [s] }, body.session));
        a.sessions = keep; // остальные устройства придётся авторизовать заново
      }
    });
    if (res.error) return json({ error: res.error }, res.error === "no_session" ? 401 : 500);
    if (newUsername) await store.delete(`un-${acc0.username}`);
    return json({ ok: true, profile: publicAccount(res.acc) });
  }

  return json({ error: "unknown_op" }, 400);
};
