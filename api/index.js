'use strict';
// Point d'entrée unique des fonctions Vercel : /api/* → /api/index?path=*
const { initializeApp, cert, getApps } = require('firebase-admin/app');
const { getFirestore, FieldValue, Timestamp, FieldPath } = require('firebase-admin/firestore');
const { getAuth } = require('firebase-admin/auth');
const { createApp, HttpError } = require('../server/core');

let app;
// Lit la clé Firebase même si le copier-coller depuis un téléphone l'a abîmée
// (retours à la ligne, guillemets typographiques, \n doublés...).
function pem(t) {
  const D = '[-\u2010-\u2015\u2212\uFE58\uFE63\uFF0D]';
  const m = String(t).match(new RegExp(D + '+\\s*BEGIN\\s+PRIVATE\\s+KEY\\s*' + D + '+([\\s\\S]*?)' + D + '+\\s*END\\s+PRIVATE\\s+KEY\\s*' + D + '+', 'i'));
  let body = m ? m[1] : '';
  if (!body) { const b = String(t).match(/MII[A-Za-z0-9+\/=\s\\]{1000,}/); body = b ? b[0] : '' }
  body = body.replace(/\\+[nr]|\s|\\/g, '').replace(/[^A-Za-z0-9+\/=]/g, '');
  return body.length > 1000 ? '-----BEGIN PRIVATE KEY-----\n' + body.match(/.{1,64}/g).join('\n') + '\n-----END PRIVATE KEY-----\n' : '';
}
function hint(t) {
  const keys = [...new Set((String(t).match(/[a-z_]{4,20}(?=["\u201C\u201D\u201E]?\s*:)/g) || []))].slice(0, 12).join(', ');
  return 'champs vus : ' + (keys || 'aucun') + ' ; BEGIN : ' + (/BEGIN/i.test(t) ? 'oui' : 'non') + ' ; MII : ' + (/MII/.test(t) ? 'oui' : 'non');
}
function readServiceAccount(raw) {
  const txt = String(raw).trim();
  try {
    const j = JSON.parse(txt);
    if (j.private_key && j.client_email) { const k = pem(j.private_key); if (k) { j.private_key = k; return j } }
  } catch (_) { }
  const Q = '["\u201C\u201D\u201E]';
  const field = k => { const m = txt.match(new RegExp(Q + k + Q + '\\s*:\\s*' + Q + '([^"\u201C\u201D\u201E]+)' + Q)); return m ? m[1].trim() : '' };
  const sa = {
    project_id: field('project_id'),
    client_email: field('client_email'),
    private_key: pem(txt)
  };
  if (!sa.private_key) throw new HttpError(500, 'config', 'FIREBASE_SERVICE_ACCOUNT invalide : clé privée introuvable (' + txt.length + ' caractères reçus ; ' + hint(txt) + ').');
  if (!sa.client_email) throw new HttpError(500, 'config', 'FIREBASE_SERVICE_ACCOUNT invalide : client_email introuvable.');
  if (!sa.project_id) sa.project_id = (sa.client_email.split('@')[1] || '').split('.')[0];
  return sa;
}
// Envoi d'e-mails par SMTP (Gmail avec un mot de passe d'application, ou tout autre serveur SMTP).
// Le module n'est chargé qu'au moment d'envoyer : s'il manque, seul l'envoi d'e-mails échoue.
function makeMailer(env) {
  const user = (env.SMTP_USER || '').trim(), pass = (env.SMTP_PASS || '').replace(/\s+/g, '');
  const host = (env.SMTP_HOST || 'smtp.gmail.com').trim(), port = +(env.SMTP_PORT || 465);
  const from = (env.MAIL_FROM || (user ? `Clexiq <${user}>` : '')).trim();
  let tr = null;
  return {
    configured: !!(user && pass && from),
    async send({ to, subject, html, text, headers }) {
      if (!tr) { const nm = require('nodemailer'); tr = nm.createTransport({ host, port, secure: port === 465, auth: { user, pass }, connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 15000 }) }
      return tr.sendMail({ from, to, subject, html, text, headers });
    }
  };
}
function boot() {
  if (app) return app;
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!raw) throw new HttpError(500, 'config', 'FIREBASE_SERVICE_ACCOUNT manquant.');
  const sa = readServiceAccount(raw);
  try { if (!getApps().length) initializeApp({ credential: cert(sa), projectId: sa.project_id }) }
  catch (e) { throw new HttpError(500, 'config', 'Clé Firebase refusée : ' + e.message) }
  app = createApp({ db: getFirestore(), auth: getAuth(), fetch: globalThis.fetch, env: process.env, FieldValue, Timestamp, FieldPath, mailer: makeMailer(process.env) });
  return app;
}

module.exports = async (req, res) => {
  const site = (process.env.SITE_URL || '').replace(/\/+$/, '');
  const origin = req.headers.origin;
  if (origin && origin === site) { res.setHeader('Access-Control-Allow-Origin', origin); res.setHeader('Vary', 'Origin'); res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type'); res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS') }
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method === 'OPTIONS') return res.status(204).end();
  // Chemin réel (/api/a/b) en secours si la réécriture ne fournit pas ?path=
  try { const u = new URL(req.url, 'http://x'); req.query = req.query || {}; if (!req.query.path && /^\/api\/(?!index)/.test(u.pathname)) req.query.path = u.pathname.slice(5); if (Array.isArray(req.query.path)) req.query.path = req.query.path.join('/') } catch (_) { }
  if (typeof req.body === 'string') { try { req.body = JSON.parse(req.body) } catch (_) { req.body = {} } }
  try { await boot().route(req, res) }
  catch (e) {
    const st = e.status || 500;
    if (st >= 500) console.error(e);
    res.status(st).json({ error: e.code || 'error', message: st >= 500 && !e.code ? 'Erreur serveur.' : (e.message || 'Erreur') });
  }
};
