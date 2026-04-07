const http = require('http');
const https = require('https');
const url = require('url');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CLIENT_ID = process.env.PARQET_CLIENT_ID || '019d6826-4b3a-724a-8644-44fa63ce23ae';
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const REDIRECT_URI = `${BASE_URL}/callback`;
const ISSUER = 'https://connect.parqet.com';

// PKCE helpers
function base64url(buf) {
  return buf.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
function randomPKCECodeVerifier() { return base64url(crypto.randomBytes(32)); }
function calculatePKCECodeChallenge(v) { return base64url(crypto.createHash('sha256').update(v).digest()); }
function randomState() { return base64url(crypto.randomBytes(16)); }

// Simple session store
const sessions = new Map();
function getSession(req) {
  const cookies = parseCookies(req.headers.cookie || '');
  const sid = cookies['sid'];
  if (sid && sessions.has(sid)) return sessions.get(sid);
  return null;
}
function createSession() {
  const sid = base64url(crypto.randomBytes(16));
  sessions.set(sid, {});
  return sid;
}
function parseCookies(str) {
  const out = {};
  str.split(';').forEach(p => {
    const [k, ...v] = p.trim().split('=');
    if (k) out[k.trim()] = v.join('=').trim();
  });
  return out;
}

// HTTP helpers
function httpsRequest(method, urlStr, token, body, extraHeaders) {
  return new Promise((resolve) => {
    const parsed = new URL(urlStr);
    const bodyStr = body || '';
    const headers = {
      'Accept': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      ...(body ? {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(bodyStr)
      } : {}),
      ...extraHeaders,
    };
    const req = https.request({
      hostname: parsed.hostname,
      path: parsed.pathname + (parsed.search || ''),
      method,
      headers,
    }, res => {
      let raw = '';
      res.on('data', d => raw += d);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
        catch { resolve({ status: res.statusCode, body: raw }); }
      });
    });
    req.on('error', err => resolve({ status: 0, body: err.message }));
    req.setTimeout(10000, () => { req.destroy(); resolve({ status: 0, body: 'timeout' }); });
    if (body) req.write(bodyStr);
    req.end();
  });
}

function fetchProtectedResource(token, endpoint) {
  return httpsRequest('GET', `${ISSUER}${endpoint}`, token);
}

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  // Serve main HTML
  if (parsed.pathname === '/' || parsed.pathname === '/index.html') {
    try {
      const file = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(file);
    } catch(e) { res.writeHead(500); res.end('index.html nicht gefunden: ' + e.message); }
    return;
  }

  // Login
  if (parsed.pathname === '/login') {
    const sid = createSession();
    const verifier = randomPKCECodeVerifier();
    const challenge = calculatePKCECodeChallenge(verifier);
    const state = randomState();
    sessions.set(sid, { verifier, state });

    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: 'code',
      scope: 'portfolio:read',
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });

    res.writeHead(302, {
      Location: `${ISSUER}/oauth2/authorize?${params.toString()}`,
      'Set-Cookie': `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`,
    });
    res.end();
    return;
  }

  // OAuth Callback
  if (parsed.pathname === '/callback') {
    const { code, state, error } = parsed.query;
    const cookies = parseCookies(req.headers.cookie || '');
    const sid = cookies['sid'];
    const session = sessions.get(sid);

    if (error || !code || !session || session.state !== state) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<h2>Fehler beim Login</h2><p>${error || 'Ungültige Session'}</p><a href="/login">Nochmal versuchen</a>`);
      return;
    }

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: session.verifier,
    }).toString();

    const tokenRes = await httpsRequest('POST', `${ISSUER}/oauth2/token`, null, body);

    if (tokenRes.status === 200 && tokenRes.body.access_token) {
      session.access_token = tokenRes.body.access_token;
      session.verifier = null;
      session.state = null;
      res.writeHead(302, { Location: '/' });
      res.end();
    } else {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<h2>Token-Fehler (${tokenRes.status})</h2><pre>${JSON.stringify(tokenRes.body,null,2)}</pre><a href="/login">Nochmal</a>`);
    }
    return;
  }

  // API Status
  if (parsed.pathname === '/api/status') {
    const session = getSession(req);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ authenticated: !!(session && session.access_token) }));
    return;
  }

  // API Holdings — fetch from connect.parqet.com
  if (parsed.pathname === '/api/holdings') {
    const session = getSession(req);
    if (!session || !session.access_token) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Nicht eingeloggt' }));
      return;
    }

    try {
      // Get portfolios from Connect API
      const portfoliosRes = await fetchProtectedResource(session.access_token, '/portfolios');
      const items = portfoliosRes.body?.items || [];

      // For each portfolio, we have the metadata
      // The sync endpoint gives us actual holding values
      // We use the connect API data we have
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        portfolios: items,
        // Holdings come from the portfolio data
        holdings: items[0]?.holdings || [],
        portfolio: items[0] || {},
      }));
    } catch(e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  // Proxy to rebalancing.app sync endpoint (with session cookie)
  if (parsed.pathname === '/api/sync') {
    const session = getSession(req);
    if (!session || !session.access_token) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Nicht eingeloggt' }));
      return;
    }

    const portfolioId = parsed.query.portfolioId;
    if (!portfolioId) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'portfolioId fehlt' }));
      return;
    }

    // Forward request to rebalancing.app with the browser cookie
    const incomingCookie = req.headers.cookie || '';
    const r = await httpsRequest('GET',
      `https://rebalancing.app/api/parqet/sync?portfolioId=${portfolioId}`,
      null, null,
      {
        'Cookie': incomingCookie,
        'Referer': 'https://rebalancing.app/',
        'User-Agent': 'Mozilla/5.0',
      }
    );

    res.writeHead(r.status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(r.body));
    return;
  }

  // Logout
  if (parsed.pathname === '/logout') {
    const cookies = parseCookies(req.headers.cookie || '');
    if (cookies['sid']) sessions.delete(cookies['sid']);
    res.writeHead(302, {
      Location: '/',
      'Set-Cookie': 'sid=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    });
    res.end();
    return;
  }

  res.writeHead(404); res.end('Nicht gefunden');
});

server.listen(PORT, () => {
  console.log(`\n✅ Parqet Rebalancer läuft`);
  console.log(`   → ${BASE_URL}\n`);
});
