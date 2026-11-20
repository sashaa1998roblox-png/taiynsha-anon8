import { getStore } from "@netlify/blobs";
import { createHash } from "node:crypto";
import { accountStore, verifySession } from "./lib/accounts.mjs";

const STORE = "taiynsha-social";
const KEY = "shared-feed-v1.json";
const MAX_BODY = 900_000;
const MAX_POSTS = 800;
const MAX_PROFILES = 2000;
const MAX_VIEWERS = 20_000;
const POST_LIMIT = 5;
const POST_WINDOW_MS = 30 * 60 * 1000;
const MAX_RATE_ACTORS = 20_000;
const SAFE_ID = /^[A-Za-z0-9_-]{1,80}$/;
function safeId(value, max = 80) { const s = String(value || "").slice(0, max); return SAFE_ID.test(s) ? s : ""; }

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function token(v) {
  return String(v || "").replace(/[^\w.-]/g, "").slice(0, 80);
}

function cleanProfile(p) {
  if (!p || typeof p !== "object") return null;
  const id = safeId(p.id);
  if (!id) return null;
  const photo = typeof p.photo === "string" && (/^data:image\/(png|jpeg|webp|gif);base64,/i.test(p.photo)) && p.photo.length <= 150_000 ? p.photo : "";
  const out = {
    id,
    nick: String(p.nick || "").slice(0, 60),
    username: String(p.username || "").slice(0, 40),
    avatar: String(p.avatar || "").slice(0, 8),
    bio: String(p.bio || "").slice(0, 400),
    createdAt: Number(p.createdAt) || Date.now(),
  };
  if (photo) out.photo = photo;
  return out;
}

function upsertProfile(state, p) {
  const clean = cleanProfile(p);
  if (!clean) return;
  const i = state.profiles.findIndex((x) => x.id === clean.id);
  if (i >= 0) state.profiles[i] = clean;
  else if (state.profiles.length < MAX_PROFILES) state.profiles.push(clean);
}

// Профиль принимается только от владельца аккаунта: данные берём из серверной учётной записи.
async function authedProfile(body) {
  if (!body?.session || !body?.profile) return null;
  const acc = await verifySession(accountStore(), body.session);
  if (!acc || acc.id !== String(body.profile.id || "")) return null;
  return { ...body.profile, id: acc.id, nick: acc.nick, username: acc.username, bio: acc.bio || "", createdAt: acc.createdAt };
}

function cleanPosts(value, existing) {
  if (!Array.isArray(value)) return null;
  if (value.length > MAX_POSTS) return null;
  const old = new Map((existing || []).map((p) => [p.id, p]));
  const output = [];
  for (const item of value) {
    if (!item || typeof item !== "object") continue;
    const id = safeId(item.id);
    const title = String(item.title || "").slice(0, 180);
    const text = String(item.text || "").slice(0, 5000);
    if (!id || (!title && !text)) continue;
    const comments = Array.isArray(item.comments) ? item.comments.slice(-150).map((c) => ({
      ...(c?.id && safeId(c.id, 40) ? { id: safeId(c.id, 40) } : {}),
      ...(c?.replyTo && safeId(c.replyTo, 40) ? { replyTo: safeId(c.replyTo, 40) } : {}),
      text: String(c?.text || "").slice(0, 500),
      date: Number(c?.date) || Date.now(),
      authorId: safeId(c?.authorId),
    })) : [];
    const prev = old.get(id);
    const { liked, likedBy, viewedBy, ...rest } = item;
    output.push({
      ...rest,
      id,
      title,
      text,
      date: Number(item.date) || Date.now(),
      // Счётчики и списки зрителей принадлежат серверу: клиент их не перезаписывает.
      likes: prev ? prev.likes || 0 : Math.max(0, Math.min(1_000_000, Number(item.likes) || 0)),
      views: prev ? prev.views || 0 : Math.max(0, Math.min(10_000_000, Number(item.views) || 0)),
      likedBy: prev ? prev.likedBy || [] : [],
      viewedBy: prev ? prev.viewedBy || [] : [],
      comments,
    });
  }
  return output;
}

function publicPosts(posts, viewer) {
  return posts.map((p) => {
    const { likedBy, viewedBy, ...rest } = p;
    return { ...rest, liked: !!(viewer && Array.isArray(likedBy) && likedBy.includes(viewer)) };
  });
}

async function readState(store) {
  const res = await store.getWithMetadata(KEY, { type: "json", consistency: "strong" });
  const data = res?.data || {};
  return {
    etag: res?.etag || null,
    state: {
      posts: Array.isArray(data.posts) ? data.posts : [],
      profiles: Array.isArray(data.profiles) ? data.profiles : [],
      deletedPostIds: Array.isArray(data.deletedPostIds) ? data.deletedPostIds.slice(-5000) : [],
      deletedCommentIds: Array.isArray(data.deletedCommentIds) ? data.deletedCommentIds.slice(-20000) : [],
      postRateLimits: data.postRateLimits && typeof data.postRateLimits === "object" && !Array.isArray(data.postRateLimits) ? data.postRateLimits : {},
      updatedAt: Number(data.updatedAt) || 0,
    },
  };
}

// Чтение → изменение → запись с повтором, если кто-то записал раньше нас.
async function mutate(store, fn) {
  for (let attempt = 0; attempt < 6; attempt++) {
    const { etag, state } = await readState(store);
    const result = fn(state);
    if (result && result.error) return result;
    state.updatedAt = Date.now();
    const opts = etag ? { onlyIfMatch: etag } : { onlyIfNew: true };
    const w = await store.setJSON(KEY, state, opts);
    if (!w || w.modified !== false) return { state, result };
  }
  return { error: "Conflict", status: 409 };
}

export default async (request) => {
  if (!["GET", "PUT", "POST"].includes(request.method)) {
    return json({ error: "Method not allowed" }, 405);
  }

  const store = getStore(STORE);

  // Личность зрителя: вошедший аккаунт = один зритель на всех устройствах;
  // аноним = токен браузера (он не может начинаться с "u", чтобы не выдать себя за аккаунт).
  async function resolveViewer(rawViewer, session) {
    if (session) {
      const acc = await verifySession(accountStore(), session);
      if (acc) return "u" + acc.id;
    }
    const t = token(rawViewer);
    return t.startsWith("u") ? "x" + t : t;
  }

  if (request.method === "GET") {
    const viewer = await resolveViewer(new URL(request.url).searchParams.get("viewer"), request.headers.get("x-session"));
    const { state } = await readState(store);
    const since = Math.max(0, Number(new URL(request.url).searchParams.get("since")) || 0);
    // Клиент уже знает эту версию: не передаём всю ленту повторно.
    if (since && state.updatedAt <= since) {
      return json({ unchanged: true, updatedAt: state.updatedAt });
    }
    return json({
      posts: publicPosts(state.posts, viewer),
      profiles: state.profiles,
      updatedAt: state.updatedAt,
    });
  }

  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_BODY) return json({ error: "Payload too large" }, 413);

  let body;
  try {
    const raw = await request.text();
    if (raw.length > MAX_BODY) return json({ error: "Payload too large" }, 413);
    body = JSON.parse(raw);
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  if (!body || typeof body !== 'object' || Array.isArray(body)) return json({ error: "Invalid request body" }, 400);
  const viewer = await resolveViewer(body?.viewer, body?.session);
  const verifiedAccount = body?.session ? await verifySession(accountStore(), body.session) : null;
  const clientIp = request.headers.get("x-nf-client-connection-ip") || request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
  const rateIdentity = verifiedAccount
    ? `account:${verifiedAccount.id}`
    : `ip:${createHash("sha256").update(clientIp).digest("hex")}`;
  function consumePostSlots(state, amount, now = Date.now()) {
    state.postRateLimits = state.postRateLimits && typeof state.postRateLimits === "object" && !Array.isArray(state.postRateLimits) ? state.postRateLimits : {};
    const recent = (Array.isArray(state.postRateLimits[rateIdentity]) ? state.postRateLimits[rateIdentity] : []).filter((t) => Number.isFinite(t) && now - t < POST_WINDOW_MS);
    if (recent.length + amount > POST_LIMIT) {
      const retryAfterMs = Math.max(1000, recent[0] + POST_WINDOW_MS - now);
      return { error: "post_limit", status: 429, retryAfterMs, remaining: Math.max(0, POST_LIMIT - recent.length) };
    }
    state.postRateLimits[rateIdentity] = [...recent, ...Array.from({ length: amount }, () => now)];
    for (const [key, times] of Object.entries(state.postRateLimits)) {
      const active = Array.isArray(times) ? times.filter((t) => Number.isFinite(t) && now - t < POST_WINDOW_MS) : [];
      if (active.length) state.postRateLimits[key] = active; else delete state.postRateLimits[key];
    }
    const keys = Object.keys(state.postRateLimits);
    if (keys.length > MAX_RATE_ACTORS) for (const key of keys.slice(0, keys.length - MAX_RATE_ACTORS)) delete state.postRateLimits[key];
    return null;
  }

  if (request.method === "PUT") {
    if (!Array.isArray(body?.posts) || body.posts.length > MAX_POSTS) return json({ error: "Invalid posts data" }, 400);
    const prof = await authedProfile(body);
    const acc = body.session ? await verifySession(accountStore(), body.session) : null;
    const out = await mutate(store, (state) => {
      const incoming = cleanPosts(body.posts, state.posts);
      if (!incoming) return { error: "Invalid posts data", status: 400 };
      const existing = new Map(state.posts.map(p => [p.id, p]));
      const newlyCreated = incoming.filter(p => !existing.has(p.id) && !state.deletedPostIds.includes(p.id));
      if (newlyCreated.length) {
        const limited = consumePostSlots(state, newlyCreated.length);
        if (limited) return limited;
      }
      const merged = [...state.posts];
      for (const next of incoming) {
        const prev = existing.get(next.id);
        if (!prev) {
          // Не позволяем старой вкладке восстановить публикацию после админского удаления.
          if (state.deletedPostIds.includes(next.id)) continue;
          // Only attribute a post when the client explicitly selected profile mode
          // and the supplied author ID matches the verified account. Otherwise keep it anonymous.
          if (acc && String(next.authorId || "") === String(acc.id)) next.authorId = acc.id;
          else delete next.authorId;
          merged.unshift(next);
          continue;
        }
        // Anonymous snapshots cannot replace existing content. Authenticated users may
        // update their own posts; other posts receive only newly submitted comments.
        const isOwner = !!acc && String(prev.authorId || "") === acc.id;
        const incomingComments = Array.isArray(next.comments) ? next.comments : [];
        const oldCommentIds = new Set((prev.comments || []).map(c => c.id).filter(Boolean));
        const isDeletedComment = (commentId) => state.deletedCommentIds.includes(`${prev.id}:${commentId}`);
        const additions = incomingComments.filter(c => c.id && !oldCommentIds.has(c.id) && !isDeletedComment(c.id)).slice(-150).map(c => ({ ...c, authorId: acc ? acc.id : "" }));
        if (isOwner) {
          const safeNext = { ...next, comments: incomingComments.filter(c => !c.id || !isDeletedComment(c.id)), authorId: acc.id, likes: prev.likes || 0, views: prev.views || 0,
            likedBy: prev.likedBy || [], viewedBy: prev.viewedBy || [] };
          const idx = merged.findIndex(p => p.id === prev.id);
          if (idx >= 0) merged[idx] = safeNext;
        } else if (additions.length) {
          const idx = merged.findIndex(p => p.id === prev.id);
          if (idx >= 0) merged[idx] = { ...merged[idx], comments: [...(merged[idx].comments || []), ...additions].slice(-150) };
        }
      }
      state.posts = merged.slice(0, MAX_POSTS);
      if (prof) upsertProfile(state, prof);
    });
    if (out.error) return json({ error: out.error, retryAfterMs: out.retryAfterMs || 0, remaining: out.remaining }, out.status || 400);
    return json({ ok: true, count: out.state.posts.length, updatedAt: out.state.updatedAt });
  }

  // POST: точечные операции — просмотры, лайки, профиль.
  const op = body?.op;
  if (op === "create_post") {
    const raw = body.post && typeof body.post === "object" ? body.post : null;
    if (!raw) return json({ error: "invalid_post" }, 400);
    const id = safeId(raw.id);
    const title = String(raw.title || "").trim().slice(0, 180);
    const text = String(raw.text || "").trim().slice(0, 1800);
    const poll = raw.poll && typeof raw.poll === "object" ? {
      question: String(raw.poll.question || title).trim().slice(0, 180),
      options: Array.isArray(raw.poll.options) ? raw.poll.options.slice(0, 6).map((x) => String(x || "").trim().slice(0, 100)).filter(Boolean) : [],
      votes: {}, voters: {},
    } : null;
    if (!id || (!poll && (!title || !text)) || (poll && (!poll.question || poll.options.length < 2))) {
      return json({ error: "invalid_post" }, 400);
    }
    const newPost = { id, title: poll ? poll.question : title, text: poll ? "" : text, date: Date.now(), likes: 0, views: 0, comments: [] };
    if (poll) newPost.poll = poll;
    if (verifiedAccount && String(raw.authorId || '') === String(verifiedAccount.id)) newPost.authorId = verifiedAccount.id;
    const out = await mutate(store, (state) => {
      if (state.posts.some((p) => p.id === id) || state.deletedPostIds.includes(id)) return { error: "post_exists", status: 409 };
      const limited = consumePostSlots(state, 1);
      if (limited) return limited;
      state.posts.unshift(newPost);
      state.posts = state.posts.slice(0, MAX_POSTS);
    });
    if (out.error) return json({ error: out.error, retryAfterMs: out.retryAfterMs || null, remaining: out.remaining ?? null, limit: POST_LIMIT, windowMs: POST_WINDOW_MS }, out.status || 400);
    return json({ ok: true, post: newPost, remaining: Math.max(0, POST_LIMIT - (out.state.postRateLimits[rateIdentity] || []).length), updatedAt: out.state.updatedAt });
  }

  if (op === "profile") {
    const prof = await authedProfile(body);
    if (!prof) return json({ error: "no_session" }, 401);
    const out = await mutate(store, (state) => { upsertProfile(state, prof); });
    if (out.error) return json({ error: out.error }, out.status || 400);
    return json({ ok: true, updatedAt: out.state.updatedAt });
  }

  if (op === "profile_delete") {
    const acc = await verifySession(accountStore(), body.session);
    if (!acc) return json({ error: "no_session" }, 401);
    const out = await mutate(store, (state) => { state.profiles = state.profiles.filter((x) => x.id !== acc.id); });
    if (out.error) return json({ error: out.error }, out.status || 400);
    return json({ ok: true });
  }

  // Владелец может удалить только собственную публикацию. Удаление и tombstone
  // записываются одной серверной операцией, чтобы PUT со старой вкладки не восстановил пост.
  if (op === "owner_delete_post") {
    const acc = await verifySession(accountStore(), body.session);
    if (!acc) return json({ error: "no_session" }, 401);
    const postId = safeId(body.postId);
    if (!postId) return json({ error: "invalid_post_id" }, 400);
    const out = await mutate(store, (state) => {
      const post = state.posts.find((p) => p.id === postId);
      if (!post) return { error: "post_not_found", status: 404 };
      if (String(post.authorId || "") !== String(acc.id)) {
        return { error: "forbidden", status: 403 };
      }
      state.posts = state.posts.filter((p) => p.id !== postId);
      state.deletedPostIds = Array.isArray(state.deletedPostIds) ? state.deletedPostIds : [];
      if (!state.deletedPostIds.includes(postId)) state.deletedPostIds.push(postId);
      state.deletedPostIds = state.deletedPostIds.slice(-5000);
    });
    if (out.error) return json({ error: out.error }, out.status || 400);
    return json({ ok: true, postId, updatedAt: out.state.updatedAt });
  }

  // Админские удаления выполняются только на сервере после проверки реальной сессии
  // аккаунта с зарезервированным username. Проверка имени в браузере не считается авторизацией.
  if (op === "admin_delete_post" || op === "admin_delete_comment") {
    const admin = await verifySession(accountStore(), body.session);
    if (!admin || String(admin.username || "").toLowerCase() !== "s3anchezz") {
      return json({ error: "forbidden" }, 403);
    }
    const postId = safeId(body.postId);
    if (!postId) return json({ error: "invalid_post_id" }, 400);
    const out = await mutate(store, (state) => {
      const post = state.posts.find((p) => p.id === postId);
      if (!post) return { error: "post_not_found", status: 404 };
      if (op === "admin_delete_post") {
        state.posts = state.posts.filter((p) => p.id !== postId);
        state.deletedPostIds = Array.isArray(state.deletedPostIds) ? state.deletedPostIds : [];
        if (!state.deletedPostIds.includes(postId)) state.deletedPostIds.push(postId);
        state.deletedPostIds = state.deletedPostIds.slice(-5000);
        return;
      }
      const commentId = safeId(body.commentId, 80);
      if (!commentId) return { error: "invalid_comment_id", status: 400 };
      const before = Array.isArray(post.comments) ? post.comments.length : 0;
      post.comments = (Array.isArray(post.comments) ? post.comments : []).filter((c, index) =>
        c.id !== commentId && `legacy_${postId}_${index}` !== commentId
      );
      if (post.comments.length === before) return { error: "comment_not_found", status: 404 };
      state.deletedCommentIds = Array.isArray(state.deletedCommentIds) ? state.deletedCommentIds : [];
      const deletedKey = `${postId}:${commentId}`;
      if (!state.deletedCommentIds.includes(deletedKey)) state.deletedCommentIds.push(deletedKey);
      state.deletedCommentIds = state.deletedCommentIds.slice(-20000);
    });
    if (out.error) return json({ error: out.error }, out.status || 400);
    return json({ ok: true, updatedAt: out.state.updatedAt });
  }

  if (!viewer) return json({ error: "viewer required" }, 400);

  if (op === "view") {
    const ids = Array.isArray(body.ids) ? body.ids.slice(0, 200).map((x) => String(x)) : [];
    const out = await mutate(store, (state) => {
      for (const p of state.posts) {
        if (!ids.includes(p.id)) continue;
        p.viewedBy = Array.isArray(p.viewedBy) ? p.viewedBy : [];
        if (p.viewedBy.includes(viewer)) continue;
        if (p.viewedBy.length < MAX_VIEWERS) p.viewedBy.push(viewer);
        p.views = (Number(p.views) || 0) + 1;
      }
    });
    if (out.error) return json({ error: out.error }, out.status || 400);
    return json({ ok: true, updatedAt: out.state.updatedAt, posts: publicPosts(out.state.posts, viewer).map(({ id, views, likes, liked }) => ({ id, views, likes, liked })) });
  }

  if (op === "like") {
    const id = String(body.id || "");
    const on = !!body.on;
    const out = await mutate(store, (state) => {
      const p = state.posts.find((x) => x.id === id);
      if (!p) return { error: "Post not found", status: 404 };
      p.likedBy = Array.isArray(p.likedBy) ? p.likedBy : [];
      const has = p.likedBy.includes(viewer);
      if (on && !has) { p.likedBy.push(viewer); p.likes = (Number(p.likes) || 0) + 1; }
      if (!on && has) { p.likedBy = p.likedBy.filter((v) => v !== viewer); p.likes = Math.max(0, (Number(p.likes) || 0) - 1); }
    });
    if (out.error) return json({ error: out.error }, out.status || 400);
    return json({ ok: true, updatedAt: out.state.updatedAt, posts: publicPosts(out.state.posts, viewer).map(({ id, views, likes, liked }) => ({ id, views, likes, liked })) });
  }

  return json({ error: "Unknown op" }, 400);
};
