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
const PORTFOLIO_ID = '672b29d1a8de8fc0af3368e1';

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
function randomVerifier() { return base64url(crypto.randomBytes(32)); }
function challenge(v) { return base64url(crypto.createHash('sha256').update(v).digest()); }
function randomState() { return base64url(crypto.randomBytes(16)); }

const sessions = new Map();

function getSession(req) {
  const sid = parseCookies(req.headers.cookie||'')['sid'];
  return sid && sessions.has(sid) ? sessions.get(sid) : null;
}
function parseCookies(str) {
  const out = {};
  str.split(';').forEach(p => {
    const [k,...v] = p.trim().split('=');
    if(k) out[k.trim()] = v.join('=').trim();
  });
  return out;
}

function get(urlStr, headers={}) {
  return new Promise(resolve => {
    const p = new URL(urlStr);
    const req = https.request({
      hostname: p.hostname,
      path: p.pathname+(p.search||''),
      method: 'GET',
      headers: { 'Accept':'application/json', 'User-Agent':'Mozilla/5.0', ...headers }
    }, res => {
      let raw='';
      res.on('data',d=>raw+=d);
      res.on('end',()=>{ try{resolve({status:res.statusCode,body:JSON.parse(raw)})}catch{resolve({status:res.statusCode,body:raw})} });
    });
    req.on('error',e=>resolve({status:0,body:e.message}));
    req.setTimeout(15000,()=>{req.destroy();resolve({status:0,body:'timeout'});});
    req.end();
  });
}

function post(urlStr, body, headers={}) {
  return new Promise(resolve => {
    const p = new URL(urlStr);
    const req = https.request({
      hostname: p.hostname,
      path: p.pathname,
      method: 'POST',
      headers: { 'Content-Type':'application/x-www-form-urlencoded', 'Content-Length':Buffer.byteLength(body), ...headers }
    }, res => {
      let raw='';
      res.on('data',d=>raw+=d);
      res.on('end',()=>{ try{resolve({status:res.statusCode,body:JSON.parse(raw)})}catch{resolve({status:res.statusCode,body:raw})} });
    });
    req.on('error',e=>resolve({status:0,body:e.message}));
    req.write(body);
    req.end();
  });
}

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);

  res.setHeader('Access-Control-Allow-Origin','*');
  if(req.method==='OPTIONS'){res.writeHead(200);res.end();return;}

  // HTML
  if(parsed.pathname==='/'||parsed.pathname==='/index.html'){
    try{
      const file = fs.readFileSync(path.join(__dirname,'index.html'),'utf8');
      res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});
      res.end(file);
    }catch(e){res.writeHead(500);res.end('index.html nicht gefunden: '+e.message);}
    return;
  }

  // Login
  if(parsed.pathname==='/login'){
    const sid = base64url(crypto.randomBytes(16));
    const v = randomVerifier();
    const s = randomState();
    sessions.set(sid, {verifier:v, state:s});
    const params = new URLSearchParams({
      client_id:CLIENT_ID, redirect_uri:REDIRECT_URI,
      response_type:'code', scope:'portfolio:read',
      state:s, code_challenge:challenge(v), code_challenge_method:'S256'
    });
    res.writeHead(302,{
      Location:`${ISSUER}/oauth2/authorize?${params}`,
      'Set-Cookie':`sid=${sid}; Path=/; HttpOnly; SameSite=Lax`
    });
    res.end();
    return;
  }

  // Callback
  if(parsed.pathname==='/callback'){
    const {code,state,error} = parsed.query;
    const sid = parseCookies(req.headers.cookie||'')['sid'];
    const session = sessions.get(sid);
    if(error||!code||!session||session.state!==state){
      res.writeHead(200,{'Content-Type':'text/html'});
      res.end(`<h2>Login Fehler: ${error||'ungültige session'}</h2><a href="/login">Nochmal</a>`);
      return;
    }
    const body = new URLSearchParams({
      grant_type:'authorization_code', code,
      redirect_uri:REDIRECT_URI, client_id:CLIENT_ID,
      code_verifier:session.verifier
    }).toString();
    const r = await post(`${ISSUER}/oauth2/token`, body);
    if(r.status===200&&r.body.access_token){
      session.token = r.body.access_token;
      session.verifier = null; session.state = null;
      res.writeHead(302,{Location:'/'});
    } else {
      res.writeHead(200,{'Content-Type':'text/html'});
      res.end(`<h2>Token Fehler (${r.status})</h2><pre>${JSON.stringify(r.body,null,2)}</pre><a href="/login">Nochmal</a>`);
    }
    res.end();
    return;
  }

  // Status
  if(parsed.pathname==='/api/status'){
    const s = getSession(req);
    res.writeHead(200,{'Content-Type':'application/json'});
    res.end(JSON.stringify({authenticated:!!(s&&s.token)}));
    return;
  }

  // Holdings — try multiple strategies
  if(parsed.pathname==='/api/sync'){
    const s = getSession(req);
    if(!s||!s.token){
      res.writeHead(401,{'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'nicht eingeloggt'}));
      return;
    }

    try {
      // Strategy 1: Connect API with bearer token
      let r = await get(`${ISSUER}/portfolios/${PORTFOLIO_ID}`, {
        Authorization: `Bearer ${s.token}`
      });
      console.log('Connect API:', r.status, typeof r.body==='object'?Object.keys(r.body):r.body);

      // Strategy 2: Try with token as query param
      if(r.status!==200) {
        r = await get(`https://api.parqet.com/v1/portfolios/${PORTFOLIO_ID}?access_token=${s.token}`);
        console.log('Public API with token:', r.status);
      }

      // Strategy 3: Public API (needs public portfolio)
      if(r.status!==200) {
        r = await get(`https://api.parqet.com/v1/portfolios/${PORTFOLIO_ID}?timeframe=today`);
        console.log('Public API:', r.status, typeof r.body==='object'?Object.keys(r.body):r.body);
      }

      const portfolio = r.body?.portfolio || r.body || {};
      const rawHoldings = portfolio.holdings || portfolio.positions || portfolio.shares || [];

      console.log('Holdings count:', rawHoldings.length);

      // If no holdings from portfolio endpoint, try activities
      if(rawHoldings.length===0) {
        // Return portfolio value at least
        res.writeHead(200,{'Content-Type':'application/json'});
        res.end(JSON.stringify({
          holdings: [],
          portfolio: portfolio,
          debug: {status: r.status, keys: typeof r.body==='object'?Object.keys(r.body):String(r.body)}
        }));
        return;
      }

      const holdings = rawHoldings.map(h=>({
        name: h.name||h.securityName||'',
        value: h.value||h.currentValue||h.marketValue||0,
        assetType: h.assetType||'security',
        assetIsin: h.isin||h.security?.isin||h.asset?.isin||h.assetIsin||'',
        percentageGain: h.percentageGain||h.gainPercent||null,
      }));

      res.writeHead(200,{'Content-Type':'application/json'});
      res.end(JSON.stringify({holdings, portfolio}));
    } catch(e) {
      console.error(e.message);
      res.writeHead(500,{'Content-Type':'application/json'});
      res.end(JSON.stringify({error:e.message}));
    }
    return;
  }

  // Logout
  if(parsed.pathname==='/logout'){
    const sid = parseCookies(req.headers.cookie||'')['sid'];
    if(sid) sessions.delete(sid);
    res.writeHead(302,{
      Location:'/',
      'Set-Cookie':'sid=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
    });
    res.end();
    return;
  }

  res.writeHead(404); res.end('nicht gefunden');
});

server.listen(PORT, ()=>{
  console.log(`✅ Parqet Rebalancer → ${BASE_URL}`);
});
