// Service worker del sitio protegido: sirve la app descifrando al vuelo cada archivo.
// Los archivos viven cifrados (AES-256-GCM) en e/<hash>.bin; la clave se guarda en este
// dispositivo (IndexedDB) y nunca sale de él.
const SCOPE = new URL(self.registration.scope).pathname;       // /ti-xxxx/
const APP = SCOPE + 'app/';
const ENC = 'ti-enc-v1', SHELL = 'ti-shell-v1', LLAVE = 'ti-llave-v1';
const RUTA_LLAVE = '/__llave__';
const VERSION = 'sw-8-llave-por-cache';   // para saber en el informe qué versión corre
const MIME = {
  html: 'text/html;charset=utf-8', js: 'text/javascript;charset=utf-8', mjs: 'text/javascript;charset=utf-8',
  css: 'text/css;charset=utf-8', json: 'application/json;charset=utf-8',
  webmanifest: 'application/manifest+json', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg',
  svg: 'image/svg+xml', mp3: 'audio/mpeg', m4a: 'audio/mp4', wav: 'audio/wav', txt: 'text/plain;charset=utf-8',
  md: 'text/plain;charset=utf-8', ico: 'image/x-icon', woff2: 'font/woff2', woff: 'font/woff',
};
const mime = (p) => MIME[(p.split('.').pop() || '').toLowerCase()] || 'application/octet-stream';

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

function idb() {
  return new Promise((ok, no) => {
    const r = indexedDB.open('ti_llave', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('k');
    r.onsuccess = () => ok(r.result);
    r.onerror = () => no(r.error);
  });
}
let KEY = null;
let esperando = null;          // a quién avisar cuando llegue la clave pedida

/** Pide la clave a las ventanas abiertas: ellas sí la leen del almacén. */
async function pedirLlaveAlaPagina() {
  const cs = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  if (!cs.length) return null;
  const llega = new Promise((ok) => {
    esperando = ok;
    setTimeout(() => { if (esperando) { esperando = null; ok(null); } }, 2500);
  });
  cs.forEach((c) => c.postMessage({ tipo: 'dameLlave' }));
  return llega;
}

// La clave también llega por mensaje: en Safari el servicio no ve lo que la
// página guardó en el almacén, así que hay que pasársela en mano.
self.addEventListener('message', (e) => {
  const d = e.data || {};
  if (d.tipo === 'llave' && d.key) {
    KEY = d.key;
    if (esperando) { esperando(d.key); esperando = null; }
    if (e.ports && e.ports[0]) e.ports[0].postMessage({ ok: true });   // acuse de recibo
  }
  // Prueba desde revisar.html: ¿puede este servicio leer el almacén del
  // navegador? En algunos Safari no, y por eso no encuentra la clave.
  if (d.tipo === 'diagnostico' && e.ports && e.ports[0]) {
    (async () => {
      const r = { version: VERSION, enMemoria: !!KEY, idb: 'no probado', llaveEnAlmacen: false };
      try {
        const db = await idb();
        r.idb = 'ok';
        r.llaveEnAlmacen = !!(await new Promise((ok) => {
          const g = db.transaction('k').objectStore('k').get('llave');
          g.onsuccess = () => ok(g.result || null);
          g.onerror = () => ok(null);
        }));
        db.close();
      } catch (err) { r.idb = 'falla: ' + (err && err.message || err); }
      try { r.llaveEnCache = !!(await llaveDeCache()); } catch (err) { r.llaveEnCache = false; }
      // Probar el camino nuevo de verdad: pedirle la clave a la página.
      try { r.trasPedir = !!(await llave()); } catch (err) { r.trasPedir = 'error: ' + (err && err.message || err); }
      e.ports[0].postMessage(r);
    })();
  }
});
async function llave() {
  if (KEY) return KEY;
  try {
    const db = await idb();
    KEY = await new Promise((ok) => {
      const g = db.transaction('k').objectStore('k').get('llave');
      g.onsuccess = () => ok(g.result || null);
      g.onerror = () => ok(null);
    });
  } catch { KEY = null; }
  if (!KEY) KEY = await llaveDeCache();          // el almacén del servicio va aparte
  if (!KEY) KEY = await pedirLlaveAlaPagina();   // último recurso: preguntar a la página
  return KEY;
}

/**
 * En Safari el almacén (IndexedDB) del servicio y el de la página van por
 * separado, así que la clave guardada ahí le es invisible. La caché, en cambio,
 * SÍ la comparten: se nota en que la página ve las cachés que crea el servicio.
 * Así que la página deja ahí los bytes de la clave y aquí se recomponen.
 */
async function llaveDeCache() {
  try {
    const c = await caches.open(LLAVE);
    const r = await c.match(RUTA_LLAVE);
    if (!r) return null;
    const bytes = new Uint8Array(await r.arrayBuffer());
    if (bytes.length !== 32) return null;
    return await crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['decrypt']);
  } catch (e) { return null; }
}
async function nombre(path) {
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(path));
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

async function servirApp(path) {
  const key = await llave();
  if (!key) return Response.redirect(SCOPE, 302);               // sin clave: pantalla de candado
  const url = SCOPE + 'e/' + (await nombre(path)) + '.bin';
  const cache = await caches.open(ENC);
  let res = null;
  try {
    res = await fetch(url, { cache: 'reload' });                 // lo más nuevo primero
    if (res.ok) cache.put(url, res.clone()); else res = null;
  } catch { res = null; }
  if (!res) res = await cache.match(url);                        // sin internet: lo guardado
  if (!res) return new Response('No encontrado', { status: 404 });
  const buf = new Uint8Array(await res.arrayBuffer());
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, key, buf.slice(12));
    return new Response(pt, { headers: { 'Content-Type': mime(path), 'Cache-Control': 'no-store' } });
  } catch {
    return new Response('Clave no válida', { status: 403 });
  }
}

async function redConRespaldo(request) {
  const cache = await caches.open(SHELL);
  try {
    const r = await fetch(request, { cache: 'reload' });
    if (r.ok) cache.put(request, r.clone());
    return r;
  } catch {
    return (await cache.match(request, { ignoreSearch: true })) || (await cache.match(SCOPE)) || Response.error();
  }
}

self.addEventListener('fetch', (e) => {
  const { request } = e;
  if (request.method !== 'GET') return;
  const u = new URL(request.url);
  if (u.origin !== location.origin || !u.pathname.startsWith(SCOPE)) return;
  if (u.pathname.startsWith(APP)) {
    let path = decodeURIComponent(u.pathname.slice(APP.length));
    if (path === '' || path.endsWith('/')) path += 'index.html';
    return e.respondWith(servirApp(path));
  }
  if (u.pathname.startsWith(SCOPE + 'e/')) return;              // los bloques los pide servirApp
  e.respondWith(redConRespaldo(request));
});
