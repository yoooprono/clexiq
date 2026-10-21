'use strict';
/* =====================================================================
   Clexiq — serveur (fonctions Vercel)
   - Connexion des chaînes : YouTube (code dans la description, vérifié
     automatiquement via l'API officielle), TikTok et Instagram (OAuth officiel)
   - Liste des vidéos d'une chaîne, soumission sans copier-coller
   - Synchronisation des vues et des gains (appelée toutes les 30 min)
   Les jetons d'accès sont chiffrés (AES-256-GCM) et ne quittent jamais le serveur.
   ===================================================================== */
const crypto = require('crypto');

const ADMIN_EMAIL = 'yoooprono@gmail.com';
const PLATFORMS = ['TikTok', 'Instagram', 'YouTube'];
const MAX_SUBMIT_PER_DAY = 30;

class HttpError extends Error { constructor(status, code, message) { super(message || code); this.status = status; this.code = code } }
const bad = (code, msg) => new HttpError(400, code, msg);

function createApp({ db, auth, fetch, env, now = () => Date.now(), FieldValue, Timestamp, FieldPath, mailer = null }) {
  const E = k => (env[k] || '').trim();
  const SITE = (E('SITE_URL') || '').replace(/\/+$/, '');
  const API_BASE = (E('API_URL') || SITE).replace(/\/+$/, '');
  const IGV = E('IG_API_VERSION') || 'v23.0';
  const enabled = {
    YouTube: !!E('YOUTUBE_API_KEY'),
    TikTok: !!(E('TIKTOK_CLIENT_KEY') && E('TIKTOK_CLIENT_SECRET')),
    Instagram: !!(E('INSTAGRAM_APP_ID') && E('INSTAGRAM_APP_SECRET'))
  };
  const ts = ms => Timestamp.fromMillis(ms);
  const tms = t => t && t.toMillis ? t.toMillis() : (t ? +new Date(t) : 0);
  const cents = n => Math.round((+n || 0) * 100) / 100;

  /* ---------- chiffrement & signature ---------- */
  function key() {
    const k = Buffer.from(E('TOKEN_KEY'), 'base64');
    if (k.length !== 32) throw new HttpError(500, 'config', 'TOKEN_KEY doit faire 32 octets (base64).');
    return k;
  }
  function seal(obj) {
    const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key(), iv);
    const data = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
    return { iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: data.toString('base64') };
  }
  function open(box) {
    const d = crypto.createDecipheriv('aes-256-gcm', key(), Buffer.from(box.iv, 'base64'));
    d.setAuthTag(Buffer.from(box.tag, 'base64'));
    return JSON.parse(Buffer.concat([d.update(Buffer.from(box.data, 'base64')), d.final()]).toString('utf8'));
  }
  const b64u = b => Buffer.from(b).toString('base64url');
  function signState(payload) {
    const body = b64u(JSON.stringify(payload));
    return body + '.' + crypto.createHmac('sha256', key()).update(body).digest('base64url');
  }
  function readState(s) {
    const [body, sig] = String(s || '').split('.');
    if (!body || !sig) throw bad('state');
    const exp = crypto.createHmac('sha256', key()).update(body).digest('base64url');
    if (exp.length !== sig.length || !crypto.timingSafeEqual(Buffer.from(exp), Buffer.from(sig))) throw bad('state', 'Lien de connexion invalide.');
    const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!(p.exp > now())) throw bad('state_expired', 'Lien de connexion expiré, recommence.');
    return p;
  }
  function newCode() { const a = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789', r = crypto.randomBytes(6); return 'CLX-' + [...r].map(x => a[x % a.length]).join('') }

  /* ---------- utilisateurs ---------- */
  async function requireUser(req) {
    const h = req.headers.authorization || req.headers.Authorization || '';
    const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
    if (!tok) throw new HttpError(401, 'auth', 'Connexion requise.');
    let dec; try { dec = await auth.verifyIdToken(tok, true) } catch (e) { throw new HttpError(401, 'auth', 'Session expirée, reconnecte-toi.') }
    if (!dec.email_verified) throw new HttpError(403, 'unverified', 'Confirme ton adresse email.');
    const isAdmin = (dec.email || '').toLowerCase() === ADMIN_EMAIL;
    const u = await db.collection('users').doc(dec.uid).get();
    if (!u.exists || u.data().status !== 'active') throw new HttpError(403, 'inactive', 'Compte inactif ou suspendu.');
    return { uid: dec.uid, email: (dec.email || '').toLowerCase(), isAdmin, user: u.data() };
  }

  /* ---------- notifications & journal admin ---------- */
  const NOTIF_TYPES = ['clip', 'payment', 'channel', 'warning', 'campaign', 'support', 'system'];
  const str = (v, max) => String(v == null ? '' : v).replace(/\u0000/g, '').trim().slice(0, max);
  async function notify(uid, { type = 'system', title, body = '', vars = {}, link = null }) {
    if (!uid) return null;
    const ref = db.collection('notifications').doc();
    const V = {}; for (const k of Object.keys(vars || {}).slice(0, 8)) V[k] = str(vars[k], 200);
    await ref.set({ userId: uid, type: NOTIF_TYPES.includes(type) ? type : 'system', title: str(title, 160), body: str(body, 600), vars: V, link: link && typeof link === 'object' ? { view: str(link.view, 30), id: str(link.id, 120) } : null, read: false, createdAt: ts(now()) });
    return ref.id;
  }
  async function log(actor, action, targetUid, detail) {
    await db.collection('adminLog').doc().set({ action: str(action, 40), targetUid: str(targetUid, 128), detail: str(detail, 500), by: actor ? actor.email : 'system', byUid: actor ? actor.uid : '', createdAt: ts(now()) });
  }

  /* ---------- appels API ---------- */
  async function getJSON(url, opt = {}) {
    const r = await fetch(url, opt); let j = null;
    try { j = await r.json() } catch (e) { }
    if (!r.ok) { const m = j && (j.error && (j.error.message || j.error.error_user_msg || j.error.code) || j.message); const err = new HttpError(r.status === 429 ? 429 : 502, r.status === 429 ? 'quota' : 'upstream', String(m || 'Erreur ' + r.status)); err.upstream = r.status; throw err }
    return j || {};
  }
  const yt = (path, q) => getJSON(`https://www.googleapis.com/youtube/v3/${path}?${new URLSearchParams({ ...q, key: E('YOUTUBE_API_KEY') })}`);
  const ytDur = d => { const m = String(d || '').match(/PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?/) || []; return (+m[1] || 0) * 3600 + (+m[2] || 0) * 60 + (+m[3] || 0) };

  async function tokenFor(chId, platform) {
    const s = await db.collection('secrets').doc(chId).get();
    if (!s.exists) throw new HttpError(409, 'reconnect', 'Reconnecte ce compte pour autoriser Clexiq.');
    let t = open(s.data().box);
    const soon = now() + 5 * 60e3;
    if (platform === 'TikTok' && t.expiresAt < soon) {
      const j = await getJSON('https://open.tiktokapis.com/v2/oauth/token/', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_key: E('TIKTOK_CLIENT_KEY'), client_secret: E('TIKTOK_CLIENT_SECRET'), grant_type: 'refresh_token', refresh_token: t.refresh }) });
      if (!j.access_token) throw new HttpError(409, 'reconnect', 'Autorisation TikTok expirée : reconnecte ce compte.');
      t = { access: j.access_token, refresh: j.refresh_token || t.refresh, expiresAt: now() + (+j.expires_in || 86400) * 1000 };
      await db.collection('secrets').doc(chId).set({ box: seal(t), updatedAt: ts(now()) }, { merge: true });
    }
    if (platform === 'Instagram' && t.expiresAt < now() + 7 * 864e5 && t.issuedAt < now() - 864e5) {
      try {
        const j = await getJSON(`https://graph.instagram.com/refresh_access_token?${new URLSearchParams({ grant_type: 'ig_refresh_token', access_token: t.access })}`);
        if (j.access_token) { t = { access: j.access_token, expiresAt: now() + (+j.expires_in || 5184000) * 1000, issuedAt: now() }; await db.collection('secrets').doc(chId).set({ box: seal(t), updatedAt: ts(now()) }, { merge: true }) }
      } catch (e) { if (t.expiresAt < now()) throw new HttpError(409, 'reconnect', 'Autorisation Instagram expirée : reconnecte ce compte.') }
    }
    return t.access;
  }

  /* Liste normalisée : {id, url, title, thumb, publishedAt(ms), views, duration, viewsAvailable} */
  async function listVideos(ch) {
    if (!enabled[ch.platform]) throw new HttpError(503, 'disabled', "Cette plateforme n'est pas encore activée sur Clexiq.");
    if (ch.platform === 'YouTube') {
      const cid = ch.channelId || (await ytChannelByHandle(ch.handle)).id;
      const c = await yt('channels', { part: 'contentDetails', id: cid });
      const up = c.items && c.items[0] && c.items[0].contentDetails.relatedPlaylists.uploads;
      if (!up) return [];
      const pl = await yt('playlistItems', { part: 'contentDetails', playlistId: up, maxResults: 50 });
      const ids = (pl.items || []).map(i => i.contentDetails.videoId);
      return (await ytVideos(ids)).filter(v => v.duration <= 180);
    }
    if (ch.platform === 'TikTok') {
      const tok = await tokenFor(ch.id, 'TikTok'), out = [];
      let cursor, more = true, pages = 0;
      while (more && pages < 3) {
        const j = await getJSON('https://open.tiktokapis.com/v2/video/list/?fields=id,title,video_description,create_time,cover_image_url,share_url,view_count,duration', { method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' }, body: JSON.stringify(cursor ? { max_count: 20, cursor } : { max_count: 20 }) });
        const d = j.data || {}; (d.videos || []).forEach(v => out.push(ttNorm(v, ch))); cursor = d.cursor; more = !!d.has_more; pages++;
      }
      return out;
    }
    if (ch.platform === 'Instagram') {
      const tok = await tokenFor(ch.id, 'Instagram');
      const j = await getJSON(`https://graph.instagram.com/${IGV}/me/media?${new URLSearchParams({ fields: 'id,caption,media_type,media_product_type,permalink,thumbnail_url,media_url,timestamp', limit: '30', access_token: tok })}`);
      const vids = (j.data || []).filter(m => m.media_type === 'VIDEO' || m.media_product_type === 'REELS');
      const views = await igViews(vids.map(m => m.id), tok);
      return vids.map(m => ({ id: m.id, url: m.permalink, title: String(m.caption || '').slice(0, 90), thumb: m.thumbnail_url || '', publishedAt: +new Date(m.timestamp), views: views[m.id] ?? null, viewsAvailable: views[m.id] != null }));
    }
    throw bad('platform');
  }
  const ttNorm = (v, ch) => ({ id: String(v.id), url: v.share_url || `https://www.tiktok.com/@${ch.handle}/video/${v.id}`, title: String(v.title || v.video_description || '').slice(0, 90), thumb: v.cover_image_url || '', publishedAt: (+v.create_time || 0) * 1000, views: v.view_count != null ? +v.view_count : null, duration: +v.duration || 0, viewsAvailable: v.view_count != null });
  async function ytVideos(ids) {
    const out = [];
    for (let i = 0; i < ids.length; i += 50) {
      const vs = await yt('videos', { part: 'snippet,statistics,contentDetails,status', id: ids.slice(i, i + 50).join(',') });
      (vs.items || []).forEach(v => { if (v.status && v.status.privacyStatus && v.status.privacyStatus !== 'public') return; const th = v.snippet.thumbnails || {}; out.push({ id: v.id, url: `https://www.youtube.com/shorts/${v.id}`, title: String(v.snippet.title || '').slice(0, 90), thumb: (th.high || th.medium || th.default || {}).url || '', publishedAt: +new Date(v.snippet.publishedAt), views: +((v.statistics || {}).viewCount || 0), duration: ytDur(v.contentDetails.duration), viewsAvailable: true }) });
    }
    return out;
  }
  async function igViews(ids, tok) {
    const out = {};
    for (const id of ids) {
      try { const j = await getJSON(`https://graph.instagram.com/${IGV}/${id}/insights?${new URLSearchParams({ metric: 'views', access_token: tok })}`); const m = (j.data || []).find(x => x.name === 'views'); if (m) out[id] = +((m.values && m.values[0] && m.values[0].value) ?? m.total_value?.value ?? 0) } catch (e) { if (e.code === 'quota') throw e }
    }
    return out;
  }
  async function ytChannelByHandle(handle) {
    const c = await yt('channels', { part: 'snippet', forHandle: '@' + String(handle).replace(/^@/, '') });
    const it = c.items && c.items[0]; if (!it) throw new HttpError(404, 'notfound', 'Chaîne YouTube introuvable. Vérifie le nom (ex : @machaine).');
    return it;
  }

  /* ---------- liaison des chaînes ---------- */
  async function claimChannel(id, data, uid) {
    return db.runTransaction(async tx => {
      const ref = db.collection('channels').doc(id), s = await tx.get(ref);
      if (s.exists && s.data().userId !== uid && s.data().status === 'verified') throw new HttpError(409, 'taken', 'Cette chaîne est déjà reliée à un autre compte Clexiq.');
      const keep = s.exists && s.data().userId === uid ? s.data() : {};
      tx.set(ref, { ...data, createdAt: keep.createdAt || ts(now()) }, { merge: false });
      return { id, ...data };
    });
  }
  async function ytLink(uid, user, handle) {
    if (!enabled.YouTube) throw new HttpError(503, 'disabled', "La connexion YouTube n'est pas encore activée sur Clexiq.");
    const h = String(handle || '').trim().replace(/^@/, '');
    if (!/^[A-Za-z0-9._-]{3,30}$/.test(h)) throw bad('handle', 'Nom de chaîne invalide.');
    const it = await ytChannelByHandle(h), id = 'youtube_' + it.id.toLowerCase();
    const prev = await db.collection('channels').doc(id).get();
    const code = prev.exists && prev.data().userId === uid && prev.data().code ? prev.data().code : newCode();
    return claimChannel(id, { userId: uid, userName: user.name || '', platform: 'YouTube', handle: (it.snippet.customUrl || '@' + h).replace(/^@/, ''), channelId: it.id, title: String(it.snippet.title || '').slice(0, 100), avatar: ((it.snippet.thumbnails || {}).default || {}).url || '', code, method: 'code', status: 'pending', checkedAt: null, reason: '', linkedAt: null, reviewedAt: null }, uid);
  }
  async function ytVerify(uid, id) {
    const ref = db.collection('channels').doc(id), s = await ref.get();
    if (!s.exists || s.data().userId !== uid || s.data().platform !== 'YouTube') throw new HttpError(404, 'notfound', 'Chaîne introuvable.');
    return ytCheck(ref, s.data());
  }
  async function ytCheck(ref, ch) {
    if (ch.status === 'verified') return { status: 'verified' };
    const c = await yt('channels', { part: 'snippet,brandingSettings', id: ch.channelId });
    const it = c.items && c.items[0];
    const text = it ? [it.snippet.description, it.brandingSettings && it.brandingSettings.channel && it.brandingSettings.channel.description].join(' ') : '';
    if (it && text.toUpperCase().includes(ch.code)) {
      await ref.update({ status: 'verified', linkedAt: ts(now()), reviewedAt: ts(now()), checkedAt: ts(now()), reason: '' });
      await notify(ch.userId, { type: 'channel', title: 'Compte vérifié', body: 'Ton compte {p} @{h} est maintenant vérifié.', vars: { p: 'YouTube', h: ch.handle }, link: { view: 'channels' } }).catch(() => { });
      return { status: 'verified' };
    }
    const reason = it ? 'Code introuvable dans la description de la chaîne.' : 'Chaîne YouTube introuvable.';
    await ref.update({ status: 'failed', checkedAt: ts(now()), reason });
    return { status: 'failed', reason };
  }
  async function oauthStart(uid, platform) {
    if (!enabled[platform]) throw new HttpError(503, 'disabled', "Cette plateforme n'est pas encore activée sur Clexiq.");
    const state = signState({ uid, p: platform, exp: now() + 10 * 60e3, n: crypto.randomBytes(8).toString('hex') });
    const redirect = `${API_BASE}/api/oauth/${platform.toLowerCase()}/callback`;
    if (platform === 'TikTok') return `https://www.tiktok.com/v2/auth/authorize/?${new URLSearchParams({ client_key: E('TIKTOK_CLIENT_KEY'), scope: 'user.info.basic,user.info.profile,video.list', response_type: 'code', redirect_uri: redirect, state })}`;
    if (platform === 'Instagram') return `https://www.instagram.com/oauth/authorize?${new URLSearchParams({ client_id: E('INSTAGRAM_APP_ID'), redirect_uri: redirect, response_type: 'code', scope: 'instagram_business_basic,instagram_business_manage_insights', state, enable_fb_login: '0' })}`;
    throw bad('platform');
  }
  async function oauthCallback(platform, q) {
    const st = readState(q.state);
    if (st.p !== platform) throw bad('state');
    if (q.error) throw bad('denied', 'Autorisation refusée.');
    const code = String(q.code || '').replace(/#_$/, '');
    if (!code) throw bad('code');
    const u = await db.collection('users').doc(st.uid).get();
    if (!u.exists || u.data().status !== 'active') throw new HttpError(403, 'inactive');
    const redirect = `${API_BASE}/api/oauth/${platform.toLowerCase()}/callback`;
    let id, data, secret;
    if (platform === 'TikTok') {
      const tk = await getJSON('https://open.tiktokapis.com/v2/oauth/token/', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_key: E('TIKTOK_CLIENT_KEY'), client_secret: E('TIKTOK_CLIENT_SECRET'), code, grant_type: 'authorization_code', redirect_uri: redirect }) });
      if (!tk.access_token) throw new HttpError(502, 'upstream', 'TikTok n\'a pas renvoyé de jeton.');
      if (!String(tk.scope || '').includes('video.list')) throw bad('scope', 'Autorise l\'accès à tes vidéos pour continuer.');
      const me = await getJSON('https://open.tiktokapis.com/v2/user/info/?fields=open_id,username,display_name,avatar_url', { headers: { Authorization: 'Bearer ' + tk.access_token } });
      const p = (me.data && me.data.user) || {};
      if (!p.open_id) throw new HttpError(502, 'upstream', 'Profil TikTok illisible.');
      id = 'tiktok_' + String(p.username || p.open_id).toLowerCase();
      data = { userId: st.uid, userName: u.data().name || '', platform: 'TikTok', handle: p.username || p.display_name || p.open_id, title: String(p.display_name || '').slice(0, 100), avatar: p.avatar_url || '', extId: p.open_id, method: 'oauth', status: 'verified', code: '', linkedAt: ts(now()), reviewedAt: ts(now()), checkedAt: ts(now()), reason: '' };
      secret = { access: tk.access_token, refresh: tk.refresh_token, expiresAt: now() + (+tk.expires_in || 86400) * 1000 };
    } else if (platform === 'Instagram') {
      const sh = await getJSON('https://api.instagram.com/oauth/access_token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: E('INSTAGRAM_APP_ID'), client_secret: E('INSTAGRAM_APP_SECRET'), grant_type: 'authorization_code', redirect_uri: redirect, code }) });
      const short = sh.access_token || (sh.data && sh.data[0] && sh.data[0].access_token);
      if (!short) throw new HttpError(502, 'upstream', 'Instagram n\'a pas renvoyé de jeton.');
      const ll = await getJSON(`https://graph.instagram.com/access_token?${new URLSearchParams({ grant_type: 'ig_exchange_token', client_secret: E('INSTAGRAM_APP_SECRET'), access_token: short })}`);
      const tok = ll.access_token || short;
      const me = await getJSON(`https://graph.instagram.com/${IGV}/me?${new URLSearchParams({ fields: 'user_id,username,name,profile_picture_url,account_type', access_token: tok })}`);
      if (!me.username) throw new HttpError(502, 'upstream', 'Profil Instagram illisible.');
      id = 'instagram_' + me.username.toLowerCase();
      data = { userId: st.uid, userName: u.data().name || '', platform: 'Instagram', handle: me.username, title: String(me.name || '').slice(0, 100), avatar: me.profile_picture_url || '', extId: String(me.user_id || ''), method: 'oauth', status: 'verified', code: '', linkedAt: ts(now()), reviewedAt: ts(now()), checkedAt: ts(now()), reason: '' };
      secret = { access: tok, expiresAt: now() + (+ll.expires_in || 3600) * 1000, issuedAt: now() };
    } else throw bad('platform');
    await claimChannel(id, data, st.uid);
    await db.collection('secrets').doc(id).set({ box: seal(secret), platform, uid: st.uid, updatedAt: ts(now()) });
    await notify(st.uid, { type: 'channel', title: 'Compte vérifié', body: 'Ton compte {p} @{h} est maintenant vérifié.', vars: { p: platform, h: data.handle }, link: { view: 'channels' } }).catch(() => { });
    return { id, platform };
  }
  async function unlink(uid, id, isAdmin) {
    const ref = db.collection('channels').doc(id), s = await ref.get();
    if (!s.exists) return;
    if (s.data().userId !== uid && !isAdmin) throw new HttpError(403, 'forbidden');
    await db.collection('secrets').doc(id).delete();
    await ref.delete();
  }

  /* ---------- gains : un seul endroit, idempotent ---------- */
  /* Écrit la valeur ABSOLUE de vues d'un clip et applique la différence aux totaux.
     Impossible de compter deux fois : on part toujours des valeurs déjà enregistrées. */
  async function applyViews(clipId, newViews, opts = {}) {
    return db.runTransaction(async tx => {
      const cref = db.collection('clips').doc(clipId), cs = await tx.get(cref);
      if (!cs.exists) return null;
      const c = cs.data();
      const kref = db.collection('campaigns').doc(c.campaignId), ks = await tx.get(kref);
      const uref = db.collection('users').doc(c.userId), us = await tx.get(uref);
      const lref = db.collection('leaderboard').doc(c.userId), ls = await tx.get(lref);
      const k = ks.exists ? ks.data() : null, ended = !k || (tms(k.endAt) && tms(k.endAt) < now());
      if (c.final && !opts.force) return { skipped: 'final' };
      if (!us.exists || us.data().status === 'deleted') { if (!c.final) tx.update(cref, { final: true, syncedAt: ts(now()) }); return { skipped: 'user' } }
      const removed = opts.removed === true;
      const prevV = +c.views || 0, prevE = +c.earn || 0;
      let views = removed ? 0 : Math.max(prevV, Math.floor(+newViews || 0));
      const paying = !removed && c.status === 'approved';
      let earn = paying ? cents(views / 1000 * (+c.rate || 0)) : 0;
      if (k && paying) { const room = Math.max(0, (+k.budget || 0) - (+k.spent || 0)); earn = Math.min(earn, cents(prevE + room)) }
      earn = Math.max(0, earn);
      const counted = c.status === 'approved';
      const dV = counted ? views - prevV : 0;
      const dE = cents(earn - prevE);
      const upd = { views, earn, syncedAt: ts(now()), syncError: '' };
      if (removed) Object.assign(upd, { status: 'rejected', reason: opts.reason || 'Vidéo supprimée ou passée en privé avant la fin de la campagne.', reviewedAt: ts(now()) });
      if (ended) upd.final = true;
      tx.update(cref, upd);
      if (dE || dV) {
        if (k) tx.update(kref, { spent: FieldValue.increment(dE), views: FieldValue.increment(dV) });
        if (us.exists && us.data().status !== 'deleted') tx.update(uref, { earned: FieldValue.increment(dE), views: FieldValue.increment(dV), ...(removed && counted ? { approved: FieldValue.increment(-1) } : {}) });
        if (ls.exists && dV) tx.update(lref, { views: FieldValue.increment(dV) });
      }
      return { views, earn, dE, dV };
    });
  }

  /* ---------- soumission ---------- */
  async function submit(uid, user, body) {
    const { campaignId, channelId } = body || {}; const vids = [...new Set((body && body.videoIds) || [])].map(String).slice(0, 20);
    if (!campaignId || !channelId || !vids.length) throw bad('params', 'Sélectionne au moins une vidéo.');
    const [ks, cs] = await Promise.all([db.collection('campaigns').doc(campaignId).get(), db.collection('channels').doc(channelId).get()]);
    if (!ks.exists) throw new HttpError(404, 'notfound', 'Campagne introuvable.');
    const k = ks.data(), ch = { id: cs.id, ...cs.data() };
    if (k.status !== 'active' || (tms(k.endAt) && tms(k.endAt) < now())) throw bad('closed', 'Cette campagne n\'accepte plus de clips.');
    if ((+k.spent || 0) >= (+k.budget || 0)) throw bad('budget', 'Le budget de cette campagne est épuisé.');
    if (!cs.exists || ch.userId !== uid || ch.status !== 'verified') throw new HttpError(403, 'channel', 'Choisis une de tes chaînes vérifiées.');
    if (!(k.platforms || []).includes(ch.platform)) throw bad('platform', 'Cette plateforme n\'est pas acceptée sur cette campagne.');
    const mine = await db.collection('clips').where('userId', '==', uid).get();
    if (mine.docs.filter(d => tms(d.data().createdAt) > now() - 864e5).length + vids.length > MAX_SUBMIT_PER_DAY) throw new HttpError(429, 'limit', 'Limite atteinte : 30 clips maximum par 24 h');
    const list = await listVideos(ch), byId = Object.fromEntries(list.map(v => [v.id, v]));
    const start = tms(k.startAt || k.createdAt), linked = tms(ch.linkedAt || ch.reviewedAt || ch.createdAt);
    // Validation manuelle : chaque vidéo soumise attend l'examen d'un administrateur.
    const results = [];
    for (const vid of vids) {
      const v = byId[vid];
      if (!v) { results.push({ id: vid, ok: false, reason: 'Vidéo introuvable sur cette chaîne (supprimée, privée ou trop ancienne).' }); continue }
      if (v.publishedAt < start) { results.push({ id: vid, ok: false, reason: 'Publiée avant le début de la campagne.' }); continue }
      if (v.publishedAt < linked) { results.push({ id: vid, ok: false, reason: 'Publiée avant l\'association du compte.' }); continue }
      const docId = ch.platform.toLowerCase() + '_' + v.id;
      try {
        await db.runTransaction(async tx => {
          const ref = db.collection('clips').doc(docId);
          if ((await tx.get(ref)).exists) throw new HttpError(409, 'dup', 'Déjà soumise sur Clexiq.');
          tx.set(ref, { userId: uid, campaignId, campaignTitle: k.title, channelId: ch.id, channelHandle: ch.handle, platform: ch.platform, videoId: v.id, url: v.url, title: v.title || '', thumb: /^https:\/\//.test(v.thumb || '') ? v.thumb.slice(0, 1000) : '',
            publishedAt: ts(v.publishedAt), declaredViews: v.views || 0, views: 0, rate: +k.rate, earn: 0, status: 'pending', reason: '', source: 'api', viewsAvailable: v.viewsAvailable !== false,
            createdAt: ts(now()), reviewedAt: null, syncedAt: null, final: false });
        });
        if (v.viewsAvailable !== false) await applyViews(docId, v.views || 0);
        results.push({ id: vid, ok: true, clipId: docId });
      } catch (e) { results.push({ id: vid, ok: false, reason: e.code === 'dup' ? e.message : 'Erreur, réessaie.' }) }
    }
    return { results, autoApproved: false };
  }

  /* ---------- correction demandée → le clipper renvoie le clip pour un nouvel examen ---------- */
  async function resubmit(uid, id) {
    const ref = db.collection('clips').doc(String(id || '')), s = await ref.get();
    if (!s.exists || s.data().userId !== uid) throw new HttpError(404, 'notfound', 'Clip introuvable.');
    const c = s.data();
    if (c.status !== 'needs_fix') throw bad('status', 'Ce clip n\'attend pas de correction.');
    const ks = await db.collection('campaigns').doc(c.campaignId).get(), k = ks.exists ? ks.data() : null;
    if (!k || k.status !== 'active' || (tms(k.endAt) && tms(k.endAt) < now())) throw bad('closed', 'Cette campagne n\'accepte plus de clips.');
    const chs = await db.collection('channels').doc(c.channelId).get();
    if (!chs.exists || chs.data().userId !== uid || chs.data().status !== 'verified') throw new HttpError(403, 'channel', 'Reconnecte la chaîne de ce clip pour le renvoyer.');
    const list = await listVideos({ id: chs.id, ...chs.data() }), v = list.find(x => x.id === c.videoId);
    if (!v) throw bad('gone', 'Vidéo introuvable sur cette chaîne (supprimée, privée ou trop ancienne).');
    await ref.update({ status: 'pending', title: v.title || c.title || '', thumb: /^https:\/\//.test(v.thumb || '') ? v.thumb.slice(0, 1000) : c.thumb || '', url: v.url || c.url, declaredViews: v.views || c.declaredViews || 0, fixNote: c.reason || '', reason: '', resubmittedAt: ts(now()) });
    return { ok: true, status: 'pending' };
  }

  /* ---------- modération manuelle des clips (admin uniquement, vérifié côté serveur) ---------- */
  async function adminClip(actor, body) {
    const id = String((body && body.id) || ''), action = body && body.action;
    if (!/^[\w.-]{1,160}$/.test(id)) throw bad('id', 'Identifiant invalide.');
    const ref = db.collection('clips').doc(id), s = await ref.get();
    if (!s.exists) throw new HttpError(404, 'notfound', 'Clip introuvable.');
    const c = s.data(), title = c.title || 'Clip sans titre', link = { view: 'clips', id };
    const reason = str(body && body.reason, 600);
    if (action === 'approve') {
      if (c.status === 'rejected') throw bad('status', 'Une vidéo rejetée ne peut plus être approuvée : le clipper doit la soumettre à nouveau.');
      if (c.status !== 'approved') {
        // on repart de 0 : les vues d'un clip non approuvé ne sont pas encore comptées dans les totaux
        await db.runTransaction(async tx => {
          const x = await tx.get(ref); if (x.data().status === 'approved') return;
          tx.update(ref, { status: 'approved', reason: '', reviewedAt: ts(now()), reviewedBy: actor.email, views: 0, earn: 0 });
          tx.update(db.collection('users').doc(c.userId), { approved: FieldValue.increment(1) });
        });
        await notify(c.userId, { type: 'clip', title: 'Clip approuvé', body: 'Ton clip « {t} » a été approuvé. Ses vues sont maintenant rémunérées.', vars: { t: title }, link });
        await log(actor, 'clip_approve', c.userId, id + ' · ' + title);
      }
      return applyViews(id, Math.max(+c.views || 0, +c.declaredViews || 0), { force: true });
    }
    if (action === 'fix') {
      if (!['pending', 'needs_fix'].includes(c.status)) throw bad('status', 'Seul un clip en attente peut être renvoyé en correction.');
      if (reason.length < 5) throw bad('reason', 'Explique ce qui doit être corrigé.');
      await ref.update({ status: 'needs_fix', reason, reviewedAt: ts(now()), reviewedBy: actor.email });
      await notify(c.userId, { type: 'clip', title: 'Correction demandée', body: 'Ton clip « {t} » doit être corrigé : {r}', vars: { t: title, r: reason }, link });
      await log(actor, 'clip_fix', c.userId, id + ' · ' + reason);
      return { ok: true };
    }
    if (action === 'reject' || action === 'delete') {
      const why = reason || (action === 'delete' ? 'Supprimé par la modération.' : '');
      if (action === 'reject' && why.length < 3) throw bad('reason', 'Indique le motif du refus.');
      if (c.status !== 'rejected') await applyViews(id, 0, { removed: true, reason: why, force: true });
      else await ref.update({ reason: why });
      if (action === 'reject' && c.status !== 'rejected') { await ref.update({ reviewedBy: actor.email }); await notify(c.userId, { type: 'clip', title: 'Clip refusé', body: 'Ton clip « {t} » a été refusé. Motif : {r}', vars: { t: title, r: why }, link }) }
      else await notify(c.userId, { type: 'clip', title: 'Clip supprimé', body: 'Ton clip « {t} » a été supprimé par la modération. Motif : {r}', vars: { t: title, r: why }, link: { view: 'clips' } });
      await log(actor, 'clip_' + action, c.userId, id + ' · ' + why);
      if (action === 'delete') await ref.delete();
      return { ok: true };
    }
    throw bad('action');
  }

  /* ---------- synchronisation ---------- */
  async function sync({ limitMs = 50e3 } = {}) {
    const t0 = now(), report = { checked: 0, updated: 0, removed: 0, errors: [], channelsVerified: 0 };
    const stop = () => now() - t0 > limitMs;
    // 1) vérification automatique des chaînes YouTube en attente (code dans la description)
    if (enabled.YouTube) {
      const pend = await db.collection('channels').where('status', 'in', ['pending', 'failed']).get();
      for (const d of pend.docs) {
        const ch = d.data(); if (stop()) break;
        if (ch.platform !== 'YouTube' || !ch.code || tms(ch.createdAt) < now() - 7 * 864e5) continue;
        try { const r = await ytCheck(d.ref, ch); if (r.status === 'verified') report.channelsVerified++ } catch (e) { report.errors.push('channel ' + d.id + ': ' + e.message) }
      }
    }
    // 2) vues des clips
    const snap = await db.collection('clips').where('status', 'in', ['approved', 'pending', 'needs_fix']).get();
    const clips = snap.docs.map(d => ({ id: d.id, ...d.data() })).filter(c => !c.final && c.videoId);
    const groups = {}, campCache = {};
    clips.forEach(c => { const g = c.platform === 'YouTube' ? 'YouTube' : c.channelId; (groups[g] = groups[g] || []).push(c) });
    for (const [g, list] of Object.entries(groups)) {
      if (stop()) { report.errors.push('temps écoulé, reprise au prochain passage'); break }
      const platform = list[0].platform;
      if (!enabled[platform]) continue;
      try {
        let found = {};
        if (platform === 'YouTube') { for (const v of await ytVideos(list.map(c => c.videoId))) found[v.id] = v }
        else if (platform === 'TikTok') {
          const tok = await tokenFor(g, 'TikTok');
          for (let i = 0; i < list.length; i += 20) {
            const j = await getJSON('https://open.tiktokapis.com/v2/video/query/?fields=id,view_count,create_time', { method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' }, body: JSON.stringify({ filters: { video_ids: list.slice(i, i + 20).map(c => c.videoId) } }) });
            ((j.data && j.data.videos) || []).forEach(v => found[String(v.id)] = { views: v.view_count != null ? +v.view_count : null });
          }
        } else if (platform === 'Instagram') {
          const tok = await tokenFor(g, 'Instagram'), m = await igViews(list.map(c => c.videoId), tok);
          for (const c of list) {
            if (m[c.videoId] != null) found[c.videoId] = { views: m[c.videoId] };
            else { try { await getJSON(`https://graph.instagram.com/${IGV}/${c.videoId}?${new URLSearchParams({ fields: 'id', access_token: tok })}`); found[c.videoId] = { views: null } } catch (e) { if (e.upstream !== 400 && e.upstream !== 404) throw e } }
          }
        }
        for (const c of list) {
          report.checked++;
          const v = found[c.videoId];
          if (!(c.campaignId in campCache)) { const k = await db.collection('campaigns').doc(c.campaignId).get(); campCache[c.campaignId] = k.exists ? k.data() : null }
          const kd = campCache[c.campaignId];
          const endMs = kd ? tms(kd.endAt) : 0, graceOk = !endMs || now() < endMs - 864e5;
          if (!v) {
            if (graceOk) { await applyViews(c.id, 0, { removed: true }); report.removed++; await notify(c.userId, { type: 'clip', title: 'Clip refusé', body: 'Ton clip « {t} » a été refusé. Motif : {r}', vars: { t: c.title || 'Clip sans titre', r: 'Vidéo supprimée ou passée en privé avant la fin de la campagne.' }, link: { view: 'clips', id: c.id } }).catch(() => { }) }
            else await applyViews(c.id, c.views, {}); continue
          }
          if (v.views == null) { await db.collection('clips').doc(c.id).update({ syncedAt: ts(now()), syncError: 'Vues non disponibles via l\'API.' }); continue }
          const r = await applyViews(c.id, v.views); if (r && (r.dE || r.dV)) report.updated++;
        }
      } catch (e) {
        report.errors.push(`${platform} ${g}: ${e.message}`);
        if (e.code === 'reconnect') for (const c of list) await db.collection('clips').doc(c.id).update({ syncError: 'Compte à reconnecter.' });
        if (e.code === 'quota') break;
      }
    }
    // 3) e-mails des campagnes en attente, puis ménage
    if (!stop()) { try { const m = await processMailJobs({ limitMs: Math.max(3e3, limitMs - (now() - t0)) }); report.mailsSent = m.sent; report.mailsFailed = m.failed } catch (e) { report.errors.push('mail: ' + e.message) } }
    if (!stop()) { try { report.notifsPruned = await pruneNotifications() } catch (e) { report.errors.push('notifications: ' + e.message) } }
    report.durationMs = now() - t0;
    const { errors, ...pub } = report;
    await db.collection('settings').doc('sync').set({ lastRunAt: ts(now()), ok: !errors.length, ...pub, errorCount: errors.length });
    await db.collection('settings').doc('syncLog').set({ at: ts(now()), errors: errors.slice(0, 30) });
    return report;
  }

  /* ---------- avertissements (admin uniquement) ---------- */
  const WARN_LEVELS = ['reminder', 'official', 'final'], WARN_SEV = ['low', 'medium', 'high', 'critical'];
  const WARN_CATS = ['content', 'views', 'spam', 'behavior', 'payment', 'account', 'other'];
  const WARN_TITLE = { reminder: 'Rappel des règles', official: 'Avertissement officiel', final: 'Dernier avertissement' };
  async function adminWarn(actor, b = {}) {
    const uid = str(b.userId, 128), us = /^[\w-]{1,128}$/.test(uid) ? await db.collection('users').doc(uid).get() : null;
    if (!us || !us.exists || us.data().status === 'deleted') throw new HttpError(404, 'notfound', 'Utilisateur introuvable.');
    if ((us.data().email || '').toLowerCase() === ADMIN_EMAIL) throw bad('self', 'Impossible d\'avertir un administrateur.');
    const w = {
      level: WARN_LEVELS.includes(b.level) ? b.level : '', severity: WARN_SEV.includes(b.severity) ? b.severity : '', category: WARN_CATS.includes(b.category) ? b.category : '',
      title: str(b.title, 120), message: str(b.message, 2000), problem: str(b.problem, 2000), rule: str(b.rule, 300), instructions: str(b.instructions, 2000), details: str(b.details, 6000)
    };
    if (!w.level || !w.severity || !w.category) throw bad('params', 'Choisis le niveau, la gravité et le type d\'avertissement.');
    if (w.title.length < 3) throw bad('title', 'Le titre doit faire au moins 3 caractères.');
    if (w.message.length < 10) throw bad('message', 'Le message doit faire au moins 10 caractères.');
    const ref = db.collection('warnings').doc(), u = us.data();
    await ref.set({ ...w, userId: uid, userName: u.pseudo || u.name || '', userEmail: u.email || '', by: actor.email, byUid: actor.uid, createdAt: ts(now()), readAt: null });
    await notify(uid, { type: 'warning', title: WARN_TITLE[w.level], body: w.title, link: { view: 'warning', id: ref.id } });
    await log(actor, 'warn', uid, `${w.level} · ${w.severity} · ${w.title}`);
    return { ok: true, id: ref.id };
  }

  /* ---------- gestion des comptes par l'admin (tracée) ---------- */
  async function adminUser(actor, b = {}) {
    const uid = str(b.id, 128); if (!/^[\w-]{1,128}$/.test(uid)) throw bad('id', 'Identifiant invalide.');
    const ref = db.collection('users').doc(uid), s = await ref.get();
    if (!s || !s.exists || s.data().status === 'deleted') throw new HttpError(404, 'notfound', 'Utilisateur introuvable.');
    const u = s.data(); if ((u.email || '').toLowerCase() === ADMIN_EMAIL) throw bad('self', 'Action impossible sur le compte administrateur.');
    const lb = db.collection('leaderboard').doc(uid);
    if (b.action === 'suspend') {
      await ref.update({ status: 'suspended', suspendedAt: ts(now()), suspendReason: str(b.reason, 300) }); await lb.delete();
      await log(actor, 'suspend', uid, str(b.reason, 300) || 'Sans motif'); return { ok: true };
    }
    if (b.action === 'reactivate') {
      await ref.update({ status: 'active', suspendReason: '' }); if (u.pseudo) await lb.set({ name: u.pseudo, handle: '', photo: u.photo || '', views: +u.views || 0 });
      await log(actor, 'reactivate', uid, ''); return { ok: true };
    }
    if (b.action === 'country') {
      const c = String(b.country || '').trim().toUpperCase();
      if (c && !/^[A-Z]{2}$/.test(c)) throw bad('country', 'Pays invalide.');
      await ref.update({ country: c });
      await log(actor, c ? 'country_set' : 'country_unlock', uid, (u.country || '—') + ' → ' + (c || 'à choisir par l\'utilisateur'));
      if (c) await notify(uid, { type: 'system', title: 'Pays mis à jour', body: 'L\'administration a mis à jour le pays de ton compte.', link: { view: 'account' } });
      return { ok: true };
    }
    throw bad('action');
  }

  /* ---------- assistance (tickets) ---------- */
  const SUP_CATS = ['technical', 'account', 'payment', 'campaign', 'video', 'report', 'other'], SUP_ST = ['open', 'in_progress', 'resolved'];
  function cleanAtt(list) {
    const out = [];
    for (const a of (Array.isArray(list) ? list : []).slice(0, 3)) {
      const data = String((a && a.data) || '');
      if (!/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(data)) throw bad('attachment', 'Pièce jointe invalide : seules les images (JPG, PNG, WEBP) sont acceptées.');
      if (data.length > 300000) throw bad('attachment', 'Image trop lourde, choisis-en une plus légère.');
      out.push({ name: str(a.name, 80) || 'capture.jpg', type: data.slice(5, data.indexOf(';')), data });
    }
    if (out.reduce((n, a) => n + a.data.length, 0) > 750000) throw bad('attachment', 'Pièces jointes trop lourdes.');
    return out;
  }
  async function newRef() {
    const a = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    for (let i = 0; i < 6; i++) { const r = crypto.randomBytes(7), id = 'CLX-' + [...r].map(x => a[x % a.length]).join(''); if (!(await db.collection('tickets').doc(id).get()).exists) return id }
    throw new HttpError(500, 'ref', 'Réessaie.');
  }
  const msgs = id => db.collection('tickets').doc(id).collection('messages');
  async function supportCreate(me, b = {}) {
    const category = SUP_CATS.includes(b.category) ? b.category : '', subject = str(b.subject, 120), text = str(b.message, 4000), att = cleanAtt(b.attachments);
    if (!category) throw bad('category', 'Choisis une catégorie.');
    if (subject.length < 3) throw bad('subject', 'Indique un sujet (3 caractères minimum).');
    if (text.length < 10) throw bad('message', 'Décris le problème (10 caractères minimum).');
    const mine = (await db.collection('tickets').where('userId', '==', me.uid).get()).docs.map(d => d.data());
    if (mine.filter(t => t.status !== 'resolved').length >= 5) throw new HttpError(429, 'limit', 'Tu as déjà 5 demandes ouvertes. Attends une réponse avant d\'en créer une autre.');
    if (mine.filter(t => tms(t.createdAt) > now() - 864e5).length >= 10) throw new HttpError(429, 'limit', 'Limite atteinte : 10 demandes maximum par 24 h.');
    const id = await newRef(), u = me.user;
    await db.collection('tickets').doc(id).set({ ref: id, userId: me.uid, userName: u.pseudo || u.name || '', userEmail: u.email || me.email, category, subject, status: 'open', createdAt: ts(now()), updatedAt: ts(now()), lastBy: 'user', unreadAdmin: true, unreadUser: false, messagesCount: 1, lastMessage: text.slice(0, 140) });
    await msgs(id).doc().set({ from: 'user', authorName: u.pseudo || u.name || '', text, attachments: att, createdAt: ts(now()) });
    return { ok: true, id, ref: id };
  }
  async function ticketFor(me, id) {
    if (!/^CLX-[A-Z0-9]{4,12}$/.test(String(id || ''))) throw new HttpError(404, 'notfound', 'Demande introuvable.');
    const ref = db.collection('tickets').doc(String(id)), s = await ref.get();
    if (!s.exists || (s.data().userId !== me.uid && !me.isAdmin)) throw new HttpError(404, 'notfound', 'Demande introuvable.');
    return { ref, t: s.data() };
  }
  async function supportReply(me, b = {}) {
    const { ref, t } = await ticketFor(me, b.id); if (t.userId !== me.uid) throw new HttpError(403, 'forbidden');
    const text = str(b.message, 4000), att = cleanAtt(b.attachments);
    if (!text && !att.length) throw bad('message', 'Écris un message.');
    const n = (await msgs(ref.id).get()).docs.filter(d => d.data().from === 'user' && tms(d.data().createdAt) > now() - 36e5).length;
    if (n >= 15) throw new HttpError(429, 'limit', 'Trop de messages. Réessaie dans un moment.');
    await msgs(ref.id).doc().set({ from: 'user', authorName: me.user.pseudo || me.user.name || '', text, attachments: att, createdAt: ts(now()) });
    await ref.update({ status: t.status === 'resolved' ? 'open' : t.status, updatedAt: ts(now()), lastBy: 'user', unreadAdmin: true, messagesCount: FieldValue.increment(1), lastMessage: (text || '📎').slice(0, 140) });
    return { ok: true };
  }
  async function supportRead(me, b = {}) {
    const { ref, t } = await ticketFor(me, b.id);
    if (t.userId === me.uid && t.unreadUser) await ref.update({ unreadUser: false });
    else if (me.isAdmin && t.unreadAdmin) await ref.update({ unreadAdmin: false });
    return { ok: true };
  }
  const SUP_NOTE = { in_progress: 'Ta demande {ref} est en cours de traitement.', resolved: 'Ta demande {ref} a été résolue.', open: 'Ta demande {ref} a été rouverte.' };
  async function adminSupport(actor, b = {}) {
    const { ref, t } = await ticketFor(actor, b.id), text = str(b.message, 4000);
    const status = b.status === undefined || b.status === '' ? null : SUP_ST.includes(b.status) ? b.status : 'x';
    if (status === 'x') throw bad('status', 'Statut invalide.');
    if (!text && !status) throw bad('message', 'Écris une réponse ou choisis un statut.');
    const next = status || (t.status === 'open' ? 'in_progress' : t.status), link = { view: 'ticket', id: ref.id };
    if (text) {
      await msgs(ref.id).doc().set({ from: 'admin', authorName: 'Assistance Clexiq', text, attachments: [], createdAt: ts(now()) });
      await ref.update({ status: next, updatedAt: ts(now()), lastBy: 'admin', unreadUser: true, unreadAdmin: false, messagesCount: FieldValue.increment(1), lastMessage: text.slice(0, 140) });
      await notify(t.userId, { type: 'support', title: 'Nouvelle réponse de l\'assistance', body: next !== t.status && next === 'resolved' ? 'Ta demande {ref} a été résolue.' : 'Demande {ref} : {s}', vars: { ref: ref.id, s: t.subject }, link });
    } else {
      if (next === t.status) return { ok: true };
      await ref.update({ status: next, updatedAt: ts(now()), unreadAdmin: false, ...(next === 'resolved' ? { resolvedAt: ts(now()) } : {}) });
    }
    if (next !== t.status && !text) await notify(t.userId, { type: 'support', title: 'Suivi de ta demande', body: SUP_NOTE[next], vars: { ref: ref.id }, link });
    await log(actor, 'support', t.userId, ref.id + (text ? ' · réponse' : '') + (next !== t.status ? ' · ' + next : ''));
    return { ok: true, status: next };
  }

  /* ---------- e-mails des nouvelles campagnes ---------- */
  const MAIL_DAILY = Math.max(1, +E('MAIL_DAILY_LIMIT') || 400);
  const unsubToken = uid => crypto.createHmac('sha256', key()).update('unsub:' + uid).digest('base64url').slice(0, 32);
  const unsubUrl = uid => `${API_BASE}/api/email/unsubscribe?u=${encodeURIComponent(uid)}&t=${unsubToken(uid)}`;
  const H = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const MAILT = {
    fr: { subject: 'Nouvelle campagne : {t}', hi: 'Bonjour {n},', intro: 'Une nouvelle campagne vient d\'être publiée sur Clexiq.', brand: 'Marque', plats: 'Plateformes', rpm: 'Rémunération', rpmv: '{m} pour 1 000 vues vérifiées', budget: 'Budget total', start: 'Début', end: 'Fin', noend: 'Sans date de fin', type: 'Type', rules: 'Conditions de participation', brief: 'Le brief', cta: 'Voir la campagne', why: 'Tu reçois cet e-mail car tu as un compte Clexiq et que les alertes de nouvelles campagnes sont activées.', unsub: 'Ne plus recevoir ces e-mails', clipping: 'Clipping', ugc: 'Ambassadeur UGC' },
    en: { subject: 'New campaign: {t}', hi: 'Hi {n},', intro: 'A new campaign has just been published on Clexiq.', brand: 'Brand', plats: 'Platforms', rpm: 'Pay', rpmv: '{m} per 1,000 verified views', budget: 'Total budget', start: 'Start', end: 'End', noend: 'No end date', type: 'Type', rules: 'How to take part', brief: 'The brief', cta: 'View the campaign', why: 'You are receiving this email because you have a Clexiq account with new campaign alerts turned on.', unsub: 'Stop receiving these emails', clipping: 'Clipping', ugc: 'UGC ambassador' },
    es: { subject: 'Nueva campaña: {t}', hi: 'Hola {n}:', intro: 'Se acaba de publicar una nueva campaña en Clexiq.', brand: 'Marca', plats: 'Plataformas', rpm: 'Pago', rpmv: '{m} por cada 1000 vistas verificadas', budget: 'Presupuesto total', start: 'Inicio', end: 'Fin', noend: 'Sin fecha de fin', type: 'Tipo', rules: 'Condiciones de participación', brief: 'El brief', cta: 'Ver la campaña', why: 'Recibes este correo porque tienes una cuenta de Clexiq con las alertas de nuevas campañas activadas.', unsub: 'Dejar de recibir estos correos', clipping: 'Clipping', ugc: 'Embajador UGC' }
  };
  const LOC = { fr: 'fr-FR', en: 'en-US', es: 'es-ES' };
  function campaignMail(k, campId, u, uid) {
    const L = MAILT[u.lang] ? u.lang : 'fr', T = MAILT[L], f = (s, v) => s.replace(/\{(\w+)\}/g, (_, x) => v[x]);
    const usd = n => '$' + (+n || 0).toLocaleString(LOC[L], { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    const d = x => tms(x) ? new Date(tms(x)).toLocaleDateString(LOC[L], { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' }) : '';
    const url = `${SITE}/?camp=${encodeURIComponent(campId)}`, name = u.pseudo || u.name || '';
    const rules = String(k.rules || '').split('\n').map(x => x.trim()).filter(Boolean).slice(0, 12);
    const plats = (k.platforms || []).map(p => p === 'YouTube' ? 'YouTube Shorts' : p).join(' · ');
    const rows = [[T.brand, k.brand], [T.type, T[(k.type || 'clipping')] || T.clipping], [T.plats, plats], [T.rpm, f(T.rpmv, { m: usd(k.rate) })], [T.budget, usd(k.budget)], [T.start, d(k.startAt || k.createdAt) || '—'], [T.end, d(k.endAt) || T.noend]];
    const desc = String(k.description || '').slice(0, 1200);
    const subject = f(T.subject, { t: k.title });
    const html = `<!doctype html><html lang="${L}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>${H(subject)}</title></head>
<body style="margin:0;padding:0;background:#EEF2F8;font-family:Arial,Helvetica,sans-serif;color:#0B1630">
<div style="display:none;max-height:0;overflow:hidden">${H(k.title)} · ${H(f(T.rpmv, { m: usd(k.rate) }))}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#EEF2F8"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#FFFFFF;border-radius:16px;overflow:hidden">
<tr><td style="background:#060B1A;padding:20px 24px"><span style="font:700 22px Arial,Helvetica,sans-serif;color:#F4F8FF">Cle<span style="color:#19E3B5">X</span>iq</span></td></tr>
<tr><td style="padding:24px 24px 8px"><p style="margin:0 0 6px;font-size:15px">${H(f(T.hi, { n: name }))}</p><p style="margin:0 0 18px;font-size:15px;color:#43506B">${H(T.intro)}</p>
<h1 style="margin:0 0 16px;font-size:22px;line-height:1.25;color:#0B1630">${H(k.title)}</h1>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #E1E7F0;border-radius:12px">${rows.map(([a, b], i) => `<tr><td style="padding:10px 14px;font-size:13px;color:#6B7690;${i ? 'border-top:1px solid #E1E7F0;' : ''}width:42%">${H(a)}</td><td style="padding:10px 14px;font-size:14px;font-weight:bold;${i ? 'border-top:1px solid #E1E7F0;' : ''}">${H(b)}</td></tr>`).join('')}</table>
${desc ? `<h2 style="margin:22px 0 8px;font-size:16px">${H(T.brief)}</h2><p style="margin:0;font-size:14px;line-height:1.6;color:#2B3650;white-space:pre-line">${H(desc)}${(k.description || '').length > 1200 ? '…' : ''}</p>` : ''}
${rules.length ? `<h2 style="margin:22px 0 8px;font-size:16px">${H(T.rules)}</h2><ul style="margin:0;padding-left:20px;font-size:14px;line-height:1.7;color:#2B3650">${rules.map(r => `<li>${H(r)}</li>`).join('')}</ul>` : ''}
<table role="presentation" cellpadding="0" cellspacing="0" style="margin:26px 0 8px"><tr><td style="border-radius:12px;background:#19E3B5"><a href="${H(url)}" style="display:inline-block;padding:14px 26px;font:bold 15px Arial,Helvetica,sans-serif;color:#04121F;text-decoration:none">${H(T.cta)}</a></td></tr></table>
</td></tr>
<tr><td style="padding:18px 24px 24px;border-top:1px solid #E1E7F0;font-size:12px;line-height:1.6;color:#6B7690">${H(T.why)}<br><a href="${H(unsubUrl(uid))}" style="color:#6B7690">${H(T.unsub)}</a></td></tr>
</table></td></tr></table></body></html>`;
    const text = [f(T.hi, { n: name }), '', T.intro, '', k.title, ...rows.map(([a, b]) => `${a} : ${b}`), '', desc ? T.brief + ' :\n' + desc : '', rules.length ? T.rules + ' :\n' + rules.map(r => '- ' + r).join('\n') : '', '', T.cta + ' : ' + url, '', T.why, T.unsub + ' : ' + unsubUrl(uid)].filter(x => x !== undefined).join('\n');
    return { subject, html, text, headers: { 'List-Unsubscribe': `<${unsubUrl(uid)}>`, 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' } };
  }
  const mailReady = () => !!(mailer && mailer.configured);
  const isEligible = (u, k) => u.status === 'active' && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(u.email || '') && (u.email || '').toLowerCase() !== ADMIN_EMAIL && (!u.work || u.work === 'both' || u.work === (k.type || 'clipping'));
  async function announce(actor, b = {}) {
    const id = str(b.id, 128), ks = id ? await db.collection('campaigns').doc(id).get() : null;
    if (!ks || !ks.exists) throw new HttpError(404, 'notfound', 'Campagne introuvable.');
    const k = ks.data();
    if (k.status !== 'active' || (tms(k.endAt) && tms(k.endAt) < now())) throw bad('closed', 'La campagne doit être active pour être annoncée.');
    const jref = db.collection('mailJobs').doc(id), js = await jref.get();
    if (!js.exists) {
      await jref.set({ campaignId: id, title: k.title, status: 'running', done: false, phase: 'scan', cursor: '', sent: 0, failed: 0, skipped: 0, notified: 0, createdAt: ts(now()), updatedAt: ts(now()), by: actor.email, lastError: '' });
      await log(actor, 'campaign_announce', '', id + ' · ' + k.title);
    }
    await processMailJobs({ limitMs: 40e3, only: id });
    const out = (await jref.get()).data();
    return { ok: true, job: { ...out, createdAt: tms(out.createdAt), updatedAt: tms(out.updatedAt), finishedAt: tms(out.finishedAt) || null }, emailConfigured: mailReady() };
  }
  async function quotaLeft() {
    const day = new Date(now()).toISOString().slice(0, 10), s = await db.collection('settings').doc('mailQuota').get();
    return s.exists && s.data().day === day ? Math.max(0, MAIL_DAILY - (+s.data().count || 0)) : MAIL_DAILY;
  }
  async function useQuota(n) {
    const day = new Date(now()).toISOString().slice(0, 10), ref = db.collection('settings').doc('mailQuota'), s = await ref.get();
    await ref.set({ day, count: (s.exists && s.data().day === day ? +s.data().count || 0 : 0) + n });
  }
  async function sendOne(job, k, uid, u, lref, prev) {
    if (!mailReady()) return { mail: 'pending' };
    if (!(await quotaLeft())) return { mail: 'pending', quota: true };
    const m = campaignMail(k, job.campaignId, u, uid);
    try { await mailer.send({ to: u.email, ...m }); await useQuota(1); return { mail: 'sent' } }
    catch (e) { await useQuota(1); return { mail: 'failed', error: str(e && (e.response || e.message) || e, 300), attempts: ((prev && prev.attempts) || 0) + 1 } }
  }
  async function processMailJobs({ limitMs = 20e3, only } = {}) {
    const t0 = now(), stop = () => now() - t0 > limitMs, report = { jobs: 0, sent: 0, failed: 0 };
    const canSend = () => limitMs - (now() - t0) > 15e3; // jamais d'envoi SMTP sans marge de temps
    const jobs = (await db.collection('mailJobs').where('done', '==', false).get()).docs.filter(d => !only || d.id === only);
    for (const jd of jobs) {
      if (stop()) break;
      report.jobs++;
      const job = jd.data(), jref = jd.ref, ks = await db.collection('campaigns').doc(job.campaignId).get();
      if (!ks.exists) { await jref.update({ done: true, status: 'cancelled', updatedAt: ts(now()), lastError: 'Campagne supprimée.' }); continue }
      const k = ks.data(), logs = jref.collection('log');
      if (k.status !== 'active' || (tms(k.endAt) && tms(k.endAt) < now())) { await jref.update({ done: true, status: 'cancelled', updatedAt: ts(now()), lastError: 'Campagne en pause ou terminée.' }); continue }
      const c = { sent: 0, failed: 0, skipped: 0, notified: 0 }; let cursor = job.cursor || '', phase = job.phase || 'scan', quota = false, lastError = job.lastError || '';
      const handle = async (uid, u, prev) => {
        const lref = logs.doc(uid), base = prev || {};
        let notif = base.notif === true;
        if (!notif) { await notify(uid, { type: 'campaign', title: 'Nouvelle campagne', body: '« {t} » · {m} pour 1 000 vues', vars: { t: k.title, m: '$' + (+k.rate || 0).toFixed(2) }, link: { view: 'campaign', id: job.campaignId } }); notif = true; c.notified++ }
        let r;
        if (u.emailPrefs && u.emailPrefs.campaigns === false) r = { mail: 'skipped', error: 'Alertes e-mail désactivées par l\'utilisateur.' };
        else if (quota || !canSend()) r = { mail: 'pending', quota };
        else r = await sendOne(job, k, uid, u, lref, prev);
        if (r.quota) quota = true;
        if (r.mail === 'sent') c.sent++; else if (r.mail === 'failed') { c.failed++; lastError = r.error || lastError } else if (r.mail === 'skipped') c.skipped++;
        await lref.set({ notif, mail: r.mail, error: r.error || '', attempts: r.attempts || base.attempts || 0, email: u.email, at: ts(now()) });
      };
      // 1) premier passage sur tous les utilisateurs (par ordre d'identifiant, reprise possible)
      while (phase === 'scan' && !stop()) {
        let q = db.collection('users').orderBy(FieldPath ? FieldPath.documentId() : '__name__');
        if (cursor) q = q.startAfter(cursor);
        const page = await q.limit(50).get();
        if (!page.docs.length) { phase = 'retry'; break }
        for (const d of page.docs) {
          if (stop()) break;
          const u = d.data(); cursor = d.id;
          if (!isEligible(u, k)) continue;
          // réservation atomique : si deux passages tournent en même temps, un seul traite ce destinataire
          try { await logs.doc(d.id).create({ notif: false, mail: 'sending', attempts: 0, email: u.email, at: ts(now()) }) } catch (e) { continue }
          await handle(d.id, u, null);
        }
        await jref.update({ cursor, phase, updatedAt: ts(now()) });
      }
      // 2) nouvelles tentatives (e-mails en attente de configuration ou échoués, 3 essais maximum)
      if (phase === 'retry' && mailReady()) {
        const todo = (await logs.where('mail', 'in', ['pending', 'failed', 'sending']).get()).docs.filter(d => (d.data().attempts || 0) < 3 && (d.data().mail !== 'sending' || tms(d.data().at) < now() - 15 * 60e3));
        for (const d of todo) {
          if (stop() || quota || !canSend()) break;
          const us = await db.collection('users').doc(d.id).get();
          if (!us.exists || !isEligible(us.data(), k)) { await d.ref.update({ mail: 'skipped', error: 'Compte inactif.' }); c.skipped++; continue }
          await handle(d.id, us.data(), d.data());
        }
      }
      const left = phase === 'retry' ? (await logs.where('mail', 'in', ['pending', 'failed', 'sending']).get()).docs.filter(d => mailReady() ? (d.data().attempts || 0) < 3 : true).length : 1;
      const done = phase === 'retry' && left === 0;
      const status = done ? 'done' : !mailReady() ? 'not_configured' : quota ? 'waiting_quota' : 'running';
      await jref.update({ phase, cursor, status, done, sent: FieldValue.increment(c.sent), failed: FieldValue.increment(c.failed), skipped: FieldValue.increment(c.skipped), notified: FieldValue.increment(c.notified), lastError, updatedAt: ts(now()), ...(done ? { finishedAt: ts(now()) } : {}) });
      report.sent += c.sent; report.failed += c.failed;
    }
    return report;
  }
  async function unsubscribe(q) {
    const uid = str(q.u, 128), tok = String(q.t || '');
    if (!/^[\w-]{1,128}$/.test(uid) || !/^[A-Za-z0-9_-]{32}$/.test(tok) || !crypto.timingSafeEqual(Buffer.from(tok), Buffer.from(unsubToken(uid)))) return false;
    if (q.check) return true;
    const ref = db.collection('users').doc(uid), s = await ref.get();
    if (s.exists) await ref.set({ emailPrefs: { campaigns: false } }, { merge: true });
    return true;
  }

  /* ---------- nettoyage des notifications de plus de 120 jours ---------- */
  async function pruneNotifications() {
    const old = await db.collection('notifications').where('createdAt', '<', ts(now() - 120 * 864e5)).limit(300).get();
    let n = 0; for (const d of old.docs) { await d.ref.delete(); n++ }
    return n;
  }

  /* ---------- routeur ---------- */
  async function route(req, res) {
    const path = String((req.query && req.query.path) || '').replace(/^\/+|\/+$/g, '');
    const m = req.method;
    const send = (st, j) => res.status(st).json(j);
    if (path === 'config' && m === 'GET') return send(200, { platforms: enabled, autoSync: true, email: mailReady(), manualReview: true });
    if (path === 'email/unsubscribe' && (m === 'GET' || m === 'POST')) {
      // GET : simple page de confirmation (les antivirus de messagerie ouvrent les liens) ; POST : désinscription réelle
      const q0 = req.query || {}, confirm = m === 'GET';
      const ok = await unsubscribe({ u: q0.u, t: q0.t, check: confirm });
      const L = /\ben\b/i.test(String(req.headers['accept-language'] || '').slice(0, 2)) ? 'en' : /\bes\b/i.test(String(req.headers['accept-language'] || '').slice(0, 2)) ? 'es' : 'fr';
      if (confirm && ok) {
        const lbl = { fr: ['Se désinscrire des e-mails de campagnes ?', 'Tu ne recevras plus d\'e-mails quand une nouvelle campagne est publiée.', 'Confirmer la désinscription'], en: ['Unsubscribe from campaign emails?', 'You will no longer receive an email when a new campaign is published.', 'Confirm'], es: ['¿Darte de baja de los correos de campañas?', 'Ya no recibirás un correo cuando se publique una nueva campaña.', 'Confirmar'] }[L];
        res.status(200); res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.end(`<!doctype html><html lang="${L}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Clexiq</title></head><body style="margin:0;font-family:Arial,Helvetica,sans-serif;background:#060B1A;color:#EAF1FB;display:grid;place-items:center;min-height:100vh;padding:20px"><form method="post" action="${H(API_BASE + '/api/email/unsubscribe?u=' + encodeURIComponent(q0.u) + '&t=' + encodeURIComponent(q0.t))}" style="max-width:420px;background:#0C1428;border:1px solid #1D2A4A;border-radius:16px;padding:28px;text-align:center"><p style="font:700 22px Arial;margin:0 0 14px">Cle<span style="color:#19E3B5">X</span>iq</p><h1 style="font-size:20px;margin:0 0 10px">${H(lbl[0])}</h1><p style="color:#8796B5;line-height:1.6;margin:0 0 18px">${H(lbl[1])}</p><button type="submit" style="background:#19E3B5;color:#04121F;padding:12px 20px;border:0;border-radius:10px;font-weight:bold;font-size:15px;cursor:pointer">${H(lbl[2])}</button></form></body></html>`);
      }
      const msg = { fr: ok ? ['Désinscription confirmée', 'Tu ne recevras plus d\'e-mails pour les nouvelles campagnes. Tu peux les réactiver à tout moment dans Clexiq : Plus → Notifications.'] : ['Lien invalide', 'Ce lien de désinscription est invalide ou incomplet.'],
        en: ok ? ['Unsubscribed', 'You will no longer receive new campaign emails. You can turn them back on anytime in Clexiq: More → Notifications.'] : ['Invalid link', 'This unsubscribe link is invalid or incomplete.'],
        es: ok ? ['Baja confirmada', 'Ya no recibirás correos de nuevas campañas. Puedes reactivarlos cuando quieras en Clexiq: Más → Notificaciones.'] : ['Enlace no válido', 'Este enlace para darte de baja no es válido o está incompleto.'] }[L];
      res.status(ok ? 200 : 400); res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.end(`<!doctype html><html lang="${L}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Clexiq</title></head><body style="margin:0;font-family:Arial,Helvetica,sans-serif;background:#060B1A;color:#EAF1FB;display:grid;place-items:center;min-height:100vh;padding:20px"><div style="max-width:420px;background:#0C1428;border:1px solid #1D2A4A;border-radius:16px;padding:28px;text-align:center"><p style="font:700 22px Arial;margin:0 0 14px">Cle<span style="color:#19E3B5">X</span>iq</p><h1 style="font-size:20px;margin:0 0 10px">${H(msg[0])}</h1><p style="color:#8796B5;line-height:1.6;margin:0 0 18px">${H(msg[1])}</p><a href="${H(SITE || '/')}" style="display:inline-block;background:#19E3B5;color:#04121F;padding:12px 20px;border-radius:10px;font-weight:bold;text-decoration:none">Clexiq</a></div></body></html>`);
    }
    if (path === 'sync' && (m === 'POST' || m === 'GET')) {
      const secret = E('CRON_SECRET'), hdr = (req.headers.authorization || '').replace(/^Bearer /, '');
      let ok = secret && hdr && hdr.length === secret.length && crypto.timingSafeEqual(Buffer.from(hdr), Buffer.from(secret));
      if (!ok) { const u = await requireUser(req).catch(() => null); ok = !!(u && u.isAdmin) }
      if (!ok) throw new HttpError(401, 'auth');
      return send(200, await sync());
    }
    const cb = path.match(/^oauth\/(tiktok|instagram)\/callback$/);
    if (cb && m === 'GET') {
      const platform = cb[1] === 'tiktok' ? 'TikTok' : 'Instagram';
      try { await oauthCallback(platform, req.query); res.status(302).setHeader('Location', `${SITE}/?linked=${cb[1]}`); return res.end() }
      catch (e) { res.status(302).setHeader('Location', `${SITE}/?linkError=${encodeURIComponent(e.message || 'Erreur')}`); return res.end() }
    }
    const me = await requireUser(req);
    if (path === 'oauth/start' && m === 'POST') { const p = (req.body || {}).platform; if (!['TikTok', 'Instagram'].includes(p)) throw bad('platform'); return send(200, { url: await oauthStart(me.uid, p) }) }
    if (path === 'channels/youtube' && m === 'POST') return send(200, await ytLink(me.uid, me.user, (req.body || {}).handle));
    if (path === 'channels/youtube/verify' && m === 'POST') return send(200, await ytVerify(me.uid, String((req.body || {}).id || '')));
    if (path === 'channels/unlink' && m === 'POST') { await unlink(me.uid, String((req.body || {}).id || ''), me.isAdmin); return send(200, { ok: true }) }
    if (path === 'videos' && m === 'GET') {
      const s = await db.collection('channels').doc(String(req.query.channel || '')).get();
      if (!s.exists || (s.data().userId !== me.uid && !me.isAdmin)) throw new HttpError(404, 'notfound', 'Chaîne introuvable.');
      if (s.data().status !== 'verified') throw new HttpError(403, 'channel', 'Cette chaîne n\'est pas encore vérifiée.');
      const list = await listVideos({ id: s.id, ...s.data() });
      return send(200, { videos: list.slice(0, 60), fetchedAt: now() });
    }
    if (path === 'submit' && m === 'POST') return send(200, await submit(me.uid, me.user, req.body));
    if (path === 'clips/resubmit' && m === 'POST') return send(200, await resubmit(me.uid, (req.body || {}).id));
    if (path === 'support/create' && m === 'POST') return send(200, await supportCreate(me, req.body));
    if (path === 'support/reply' && m === 'POST') return send(200, await supportReply(me, req.body));
    if (path === 'support/read' && m === 'POST') return send(200, await supportRead(me, req.body));
    if (path.startsWith('admin/') && !me.isAdmin) throw new HttpError(403, 'forbidden', 'Action réservée aux administrateurs.');
    if (path === 'admin/warn' && m === 'POST') return send(200, await adminWarn(me, req.body));
    if (path === 'admin/user' && m === 'POST') return send(200, await adminUser(me, req.body));
    if (path === 'admin/support' && m === 'POST') return send(200, await adminSupport(me, req.body));
    if (path === 'admin/campaign/announce' && m === 'POST') return send(200, await announce(me, req.body));
    if (path === 'admin/clip' && m === 'POST') { if (!me.isAdmin) throw new HttpError(403, 'forbidden'); return send(200, await adminClip(me, req.body) || { ok: true }) }
    throw new HttpError(404, 'route', 'Route inconnue.');
  }
  return { route, sync, adminClip, applyViews, submit, resubmit, listVideos, ytLink, ytVerify, oauthStart, oauthCallback, unlink, seal, open, signState, readState, enabled, notify, adminWarn, adminUser, supportCreate, supportReply, adminSupport, announce, processMailJobs, campaignMail, unsubToken };
}

module.exports = { createApp, HttpError };
