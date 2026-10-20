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

function createApp({ db, auth, fetch, env, now = () => Date.now(), FieldValue, Timestamp }) {
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
    return { uid: dec.uid, isAdmin, user: u.data() };
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
    const [ks, cs, settings] = await Promise.all([db.collection('campaigns').doc(campaignId).get(), db.collection('channels').doc(channelId).get(), db.collection('settings').doc('main').get()]);
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
    const auto = !settings.exists || settings.data().autoApprove !== false;
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
            publishedAt: ts(v.publishedAt), declaredViews: v.views || 0, views: 0, rate: +k.rate, earn: 0, status: auto ? 'approved' : 'pending', reason: '', source: 'api', viewsAvailable: v.viewsAvailable !== false,
            createdAt: ts(now()), reviewedAt: auto ? ts(now()) : null, syncedAt: null, final: false });
          if (auto) tx.update(db.collection('users').doc(uid), { approved: FieldValue.increment(1) });
        });
        if (v.viewsAvailable !== false) await applyViews(docId, v.views || 0);
        results.push({ id: vid, ok: true, clipId: docId });
      } catch (e) { results.push({ id: vid, ok: false, reason: e.code === 'dup' ? e.message : 'Erreur, réessaie.' }) }
    }
    return { results, autoApproved: auto };
  }

  /* ---------- modération admin (facultative : l'approbation est automatique par défaut) ---------- */
  async function adminClip(body) {
    const id = String((body && body.id) || ''), action = body && body.action;
    const ref = db.collection('clips').doc(id), s = await ref.get();
    if (!s.exists) throw new HttpError(404, 'notfound', 'Clip introuvable.');
    const c = s.data();
    if (action === 'approve') {
      if (c.status !== 'approved') {
        // on repart de 0 : les vues d'un clip non approuvé ne sont pas encore comptées dans les totaux
        await db.runTransaction(async tx => {
          const x = await tx.get(ref); if (x.data().status === 'approved') return;
          tx.update(ref, { status: 'approved', reason: '', reviewedAt: ts(now()), views: 0, earn: 0 });
          tx.update(db.collection('users').doc(c.userId), { approved: FieldValue.increment(1) });
        });
      }
      return applyViews(id, Math.max(+c.views || 0, +c.declaredViews || 0), { force: true });
    }
    if (action === 'reject' || action === 'delete') {
      const reason = String((body && body.reason) || 'Refusé par la modération.').slice(0, 300);
      if (c.status !== 'rejected') await applyViews(id, 0, { removed: true, reason, force: true });
      else await ref.update({ reason });
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
    const snap = await db.collection('clips').where('status', 'in', ['approved', 'pending']).get();
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
          if (!v) { if (graceOk) { await applyViews(c.id, 0, { removed: true }); report.removed++ } else await applyViews(c.id, c.views, {}); continue }
          if (v.views == null) { await db.collection('clips').doc(c.id).update({ syncedAt: ts(now()), syncError: 'Vues non disponibles via l\'API.' }); continue }
          const r = await applyViews(c.id, v.views); if (r && (r.dE || r.dV)) report.updated++;
        }
      } catch (e) {
        report.errors.push(`${platform} ${g}: ${e.message}`);
        if (e.code === 'reconnect') for (const c of list) await db.collection('clips').doc(c.id).update({ syncError: 'Compte à reconnecter.' });
        if (e.code === 'quota') break;
      }
    }
    report.durationMs = now() - t0;
    const { errors, ...pub } = report;
    await db.collection('settings').doc('sync').set({ lastRunAt: ts(now()), ok: !errors.length, ...pub, errorCount: errors.length });
    await db.collection('settings').doc('syncLog').set({ at: ts(now()), errors: errors.slice(0, 30) });
    return report;
  }

  /* ---------- routeur ---------- */
  async function route(req, res) {
    const path = String((req.query && req.query.path) || '').replace(/^\/+|\/+$/g, '');
    const m = req.method;
    const send = (st, j) => res.status(st).json(j);
    if (path === 'config' && m === 'GET') return send(200, { platforms: enabled, autoSync: true });
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
    if (path === 'admin/clip' && m === 'POST') { if (!me.isAdmin) throw new HttpError(403, 'forbidden'); return send(200, await adminClip(req.body) || { ok: true }) }
    throw new HttpError(404, 'route', 'Route inconnue.');
  }
  return { route, sync, adminClip, applyViews, submit, listVideos, ytLink, ytVerify, oauthStart, oauthCallback, unlink, seal, open, signState, readState, enabled };
}

module.exports = { createApp, HttpError };
