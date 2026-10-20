'use strict';
// Point d'entrée unique des fonctions Vercel : /api/* → /api/index?path=*
const { initializeApp, cert, getApps } = require('firebase-admin/app');
const { getFirestore, FieldValue, Timestamp } = require('firebase-admin/firestore');
const { getAuth } = require('firebase-admin/auth');
const { createApp, HttpError } = require('../server/core');

let app;
function boot() {
  if (app) return app;
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!raw) throw new HttpError(500, 'config', 'FIREBASE_SERVICE_ACCOUNT manquant.');
  const sa = JSON.parse(raw);
  if (!getApps().length) initializeApp({ credential: cert(sa), projectId: sa.project_id });
  app = createApp({ db: getFirestore(), auth: getAuth(), fetch: globalThis.fetch, env: process.env, FieldValue, Timestamp });
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
  try { const u = new URL(req.url, 'http://x'); req.query = req.query || {}; if (!req.query.path && /^\/api\/(?!index)/.test(u.pathname)) req.query.path = u.pathname.slice(5); if (Array.isArray(req.query.path)) req.query.path = req.query.path.join('/') } catch (_) {}
  if (typeof req.body === 'string') { try { req.body = JSON.parse(req.body) } catch (_) { req.body = {} } }
  try { await boot().route(req, res) }
  catch (e) {
    const st = e.status || 500;
    if (st >= 500) console.error(e);
    res.status(st).json({ error: e.code || 'error', message: st >= 500 && !e.code ? 'Erreur serveur.' : (e.message || 'Erreur') });
  }
};
