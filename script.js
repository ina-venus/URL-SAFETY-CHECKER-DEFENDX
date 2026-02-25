// ══════════════════════════════════════════════
//  DEFENDX — CORE ENGINE
// ══════════════════════════════════════════════

class DefendXEngine {
  constructor() {
    this.knownBrands = [
      'paypal','google','facebook','apple','amazon','microsoft','netflix',
      'instagram','twitter','linkedin','dropbox','github','gmail','yahoo',
      'bank','chase','wellsfargo','citibank','barclays','hsbc','irs','ebay',
      'whatsapp','telegram','binance','coinbase','metamask','trustwallet'
    ];
    this.suspiciousKeywords = [
      'login','secure','verify','update','account','confirm','suspend',
      'urgent','alert','click','free','winner','prize','claim','limited',
      'signin','password','credential','wallet','auth','banking','payment'
    ];
    this.homographMap = {
      'a':'а','e':'е','o':'о','p':'р','c':'с','i':'і','x':'х','y':'у',
      '0':'o','1':'l','l':'1','rn':'m','vv':'w'
    };
    this.knownTLDs = ['com','org','net','edu','gov','io','co','app'];
    this.scanHistory = JSON.parse(localStorage.getItem('dx_history') || '[]');
    this.scanCount = parseInt(localStorage.getItem('dx_scans') || '0');
    this.threatCount = parseInt(localStorage.getItem('dx_threats') || '0');
  }

  analyze(rawURL) {
    let url = rawURL.trim();
    if (!url.startsWith('http')) url = 'https://' + url;

    let parsed;
    try { parsed = new URL(url); }
    catch { return { error: 'Invalid URL format. Please include a valid URL.' }; }

    const checks = [];
    let score = 0;

    const hostname = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname.toLowerCase();
    const fullURL = url.toLowerCase();
    const tld = hostname.split('.').pop();
    const domain = hostname.replace('www.','');
    const path = pathname + parsed.search;

    // 1. URL Length
    if (url.length > 100) { const pts = Math.min(15, Math.floor((url.length-100)/10)*3); score+=pts; checks.push({flag:true,icon:'📏',name:'Excessive URL Length',detail:`URL is ${url.length} chars. Legitimate sites rarely exceed 100.`}); }
    else checks.push({flag:false,icon:'📏',name:'URL Length',detail:`Length ${url.length} chars — within normal range.`});

    // 2. @ symbol
    if (url.includes('@')) { score+=20; checks.push({flag:true,icon:'@',name:'@ Symbol in URL',detail:'@ in URL is a classic phishing trick to confuse browsers about the real domain.'}); }
    else checks.push({flag:false,icon:'@',name:'No @ Symbol',detail:'URL does not contain deceptive @ character.'});

    // 3. IP address as host
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) { score+=25; checks.push({flag:true,icon:'🔢',name:'IP Address Host',detail:`Direct IP (${hostname}) instead of domain name — major phishing indicator.`}); }
    else checks.push({flag:false,icon:'🌐',name:'Domain-Based Host',detail:'Using a proper domain name, not a raw IP.'});

    // 4. Subdomain depth
    const subdomains = hostname.split('.').length - 2;
    if (subdomains > 3) { score+=12; checks.push({flag:true,icon:'🌿',name:'Deep Subdomain Structure',detail:`${subdomains} subdomains. Attackers use deep subdomains to bury fake brand names.`}); }
    else if (subdomains > 1) { score+=5; checks.push({flag:true,icon:'🌿',name:'Multiple Subdomains',detail:`${subdomains} subdomains. Slightly elevated.`}); }
    else checks.push({flag:false,icon:'🌿',name:'Normal Subdomain Depth',detail:'Subdomain structure is typical.'});

    // 5. Brand impersonation
    let impersonated = null;
    for (const brand of this.knownBrands) {
      if (domain.includes(brand) && !domain.endsWith('.com') && !domain === brand+'.com' && !domain === brand+'.org') {
        if (domain !== brand+'.com' && domain !== brand+'.net' && domain !== brand+'.org') {
          impersonated = brand;
          break;
        }
      }
      // Legit match — skip
      if (hostname === brand+'.com' || hostname === 'www.'+brand+'.com') break;
    }
    // Better check: brand in subdomain or weird TLD
    impersonated = null;
    for (const brand of this.knownBrands) {
      const exactOK = [brand+'.com',brand+'.org',brand+'.net','www.'+brand+'.com'];
      if (hostname.includes(brand) && !exactOK.includes(hostname)) {
        impersonated = brand;
        break;
      }
    }
    if (impersonated) { score+=30; checks.push({flag:true,icon:'🎭',name:'Brand Impersonation',detail:`"${impersonated}" appears in a non-official domain. This is a common phishing tactic.`}); }
    else checks.push({flag:false,icon:'🎭',name:'No Brand Impersonation',detail:'No known brand names found in suspicious context.'});

    // 6. Suspicious keywords
    const foundKw = this.suspiciousKeywords.filter(k => fullURL.includes(k));
    if (foundKw.length >= 3) { score+=15; checks.push({flag:true,icon:'🔑',name:'Multiple Suspicious Keywords',detail:`Found: ${foundKw.slice(0,5).join(', ')}. Phishing URLs frequently include urgency/action words.`}); }
    else if (foundKw.length > 0) { score+=5; checks.push({flag:true,icon:'🔑',name:'Suspicious Keywords',detail:`Found: ${foundKw.join(', ')}.`}); }
    else checks.push({flag:false,icon:'🔑',name:'No Suspicious Keywords',detail:'No phishing-associated keywords detected.'});

    // 7. HTTPS
    if (parsed.protocol === 'http:') { score+=15; checks.push({flag:true,icon:'🔓',name:'No HTTPS',detail:'Plain HTTP — data transmitted unencrypted. Never enter credentials here.'}); }
    else checks.push({flag:false,icon:'🔒',name:'HTTPS Enabled',detail:'Connection uses TLS encryption.'});

    // 8. Domain age heuristic (by TLD patterns)
    if (['xyz','top','club','gq','tk','ml','ga','cf'].includes(tld)) { score+=12; checks.push({flag:true,icon:'🆕',name:'Suspicious TLD',detail:`.${tld} domains are frequently used in phishing campaigns due to low cost or free registration.`}); }
    else checks.push({flag:false,icon:'🌐',name:'Standard TLD',detail:`.${tld} is a common, trusted top-level domain.`});

    // 9. Excessive dashes
    const dashes = (hostname.match(/-/g)||[]).length;
    if (dashes >= 3) { score+=10; checks.push({flag:true,icon:'➖',name:'Excessive Hyphens',detail:`${dashes} hyphens in domain. Legitimate domains rarely use more than one.`}); }
    else checks.push({flag:false,icon:'➖',name:'Normal Hyphen Use',detail:'Hyphen count within normal range.'});

    // 10. Path depth
    const pathDepth = pathname.split('/').filter(Boolean).length;
    if (pathDepth > 5) { score+=8; checks.push({flag:true,icon:'🗂️',name:'Deep URL Path',detail:`Path has ${pathDepth} levels. Deep paths can hide phishing destinations.`}); }
    else checks.push({flag:false,icon:'🗂️',name:'Normal Path Depth',detail:`Path depth of ${pathDepth} is typical.`});

    // 11. URL encoding abuse
    const encodedCount = (url.match(/%[0-9a-fA-F]{2}/g)||[]).length;
    if (encodedCount > 5) { score+=10; checks.push({flag:true,icon:'🔡',name:'URL Encoding Abuse',detail:`${encodedCount} encoded characters detected. Often used to obfuscate malicious URLs.`}); }
    else checks.push({flag:false,icon:'🔡',name:'Minimal Encoding',detail:'URL uses minimal percent-encoding.'});

    // 12. Homograph attack
    const homographSuspect = /[а-яёА-ЯЁ\u0400-\u04FF\u0370-\u03FF]/u.test(hostname);
    if (homographSuspect) { score+=35; checks.push({flag:true,icon:'👁️',name:'Homograph Attack Detected',detail:'Non-ASCII characters in domain that look like Latin letters. This is a sophisticated spoofing technique.'}); }
    else checks.push({flag:false,icon:'👁️',name:'No Homograph Attack',detail:'Domain uses standard ASCII characters only.'});

    // 13. Multiple redirects heuristic
    if (fullURL.includes('redirect') || fullURL.includes('redir') || fullURL.includes('url=http') || fullURL.includes('goto=') || fullURL.includes('return=http')) {
      score+=15; checks.push({flag:true,icon:'↪️',name:'Open Redirect Indicator',detail:'URL contains redirect parameters that can chain users to malicious sites.'});
    } else checks.push({flag:false,icon:'↪️',name:'No Redirect Patterns',detail:'No suspicious redirect parameters detected.'});

    // 14. Query string length
    if (parsed.search.length > 200) { score+=8; checks.push({flag:true,icon:'❓',name:'Excessive Query String',detail:`Query string is ${parsed.search.length} chars — may contain obfuscated data.`}); }
    else checks.push({flag:false,icon:'❓',name:'Normal Query Length',detail:'Query string length is acceptable.'});

    // 15. Punycode
    if (hostname.includes('xn--')) { score+=20; checks.push({flag:true,icon:'🌏',name:'Punycode Domain',detail:'Punycode (xn--) domains are often used in internationalized domain name (IDN) homograph attacks.'}); }
    else checks.push({flag:false,icon:'🌏',name:'No Punycode',detail:'Domain uses standard encoding.'});

    // 16. Double slash in path
    if (pathname.includes('//')) { score+=6; checks.push({flag:true,icon:'⚡',name:'Double Slash in Path',detail:'Double slashes in paths are unusual and may indicate URL manipulation attempts.'}); }
    else checks.push({flag:false,icon:'⚡',name:'Clean Path Slashes',detail:'No double slash anomalies.'});

    // 17. Numeric domain
    if (/^\d+\.\d+\.\d+\.\d+$/.test(domain) || /^\d{4,}\./.test(domain)) {
      score+=10; checks.push({flag:true,icon:'🔢',name:'Numeric Domain Pattern',detail:'Domains with many numbers are often generated by malware or phishing kits.'});
    } else checks.push({flag:false,icon:'🔢',name:'Normal Domain Pattern',detail:'Domain does not exhibit numeric anomalies.'});

    // 18. Fake login indicators
    if (['login','signin','account','secure','verify','confirm'].some(k => pathname.includes(k))) {
      score+=10; checks.push({flag:true,icon:'🔐',name:'Login/Auth Path Detected',detail:'Path contains authentication keywords. Verify the domain is legitimate before entering any credentials.'});
    } else checks.push({flag:false,icon:'🔐',name:'No Auth Path Indicators',detail:'Path does not contain login/auth keywords.'});

    // 19. Dots count in hostname
    const dotCount = (hostname.match(/\./g)||[]).length;
    if (dotCount > 4) { score+=8; checks.push({flag:true,icon:'💠',name:'Excessive Domain Dots',detail:`${dotCount} dots in hostname — unusually complex domain structure.`}); }
    else checks.push({flag:false,icon:'💠',name:'Normal Domain Structure',detail:`${dotCount} dots in hostname — normal.`});

    // 20. Shortened URL
    const shorteners = ['bit.ly','goo.gl','tinyurl.com','t.co','ow.ly','buff.ly','short.link','rb.gy','cutt.ly','clck.ru'];
    if (shorteners.some(s => hostname.includes(s))) { score+=18; checks.push({flag:true,icon:'🔗',name:'URL Shortener Detected',detail:'URL shorteners mask the true destination. Malicious links frequently use them.'}); }
    else checks.push({flag:false,icon:'🔗',name:'No URL Shortener',detail:'Full, transparent URL — no shortener service detected.'});

    score = Math.min(100, score);
    const level = score >= 60 ? 'danger' : score >= 25 ? 'warning' : 'safe';

    const deepInfo = this.deepAnalysis(hostname, url, parsed);

    return { url, hostname, score, level, checks, deepInfo, timestamp: Date.now() };
  }

  deepAnalysis(hostname, url, parsed) {
    const tld = hostname.split('.').pop();
    const domainParts = hostname.split('.');
    const baseDomain = domainParts.slice(-2).join('.');

    // Estimate domain age category
    const suspiciousTLDs = ['xyz','top','club','gq','tk','ml','ga','cf','pw','ws','online','site','click'];
    const ageLikelihood = suspiciousTLDs.includes(tld) ? 'High risk (recently registered domains common with this TLD)' : 'Cannot determine without WHOIS — use manual verification';

    return {
      'Base Domain': baseDomain,
      'Full Hostname': hostname,
      'Protocol': parsed.protocol.replace(':',''),
      'Port': parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
      'TLD Risk': suspiciousTLDs.includes(tld) ? 'HIGH' : 'LOW',
      'Has Subdomains': domainParts.length > 2 ? `Yes (${domainParts.length-2})` : 'No',
      'Domain Age Estimate': ageLikelihood,
      'URL Chars': url.length,
      'Query Params': parsed.searchParams.size || 0,
    };
  }

  getVerdict(level, score) {
    if (level === 'danger') return `CRITICAL THREAT — ${score}/100 Risk Score`;
    if (level === 'warning') return `SUSPICIOUS — ${score}/100 Risk Score`;
    return `APPEARS SAFE — ${score}/100 Risk Score`;
  }

  getRecommendation(level, score) {
    if (level === 'danger') return {text:'⛔ DO NOT VISIT this URL. It exhibits multiple high-confidence phishing/malware indicators. Report it via PhishTank or your security team.', cls:'danger'};
    if (level === 'warning') return {text:'⚠️ PROCEED WITH CAUTION. Some suspicious indicators detected. Verify the domain owner through official channels before entering any data.', cls:'warning'};
    return {text:'✅ URL appears safe based on heuristic analysis. Maintain standard security hygiene — no tool offers 100% certainty.', cls:'safe'};
  }

  getEduTip(checks) {
    const flagged = checks.filter(c => c.flag);
    if (flagged.length === 0) return {title:'STAY VIGILANT', text:'Even "safe" URLs can host social engineering content. Look for grammar errors, urgent language, and pressure tactics on any page you visit.'};
    const top = flagged[0];
    const tips = {
      'Brand Impersonation': 'Attackers register domains like "paypal-secure.com" or "amazon-login.net" — always check the base domain directly.',
      'Homograph Attack Detected': 'Unicode spoofing uses Cyrillic or Greek letters that look identical to Latin ones. Your browser bar can be deceived.',
      'URL Shortener Detected': 'Expand shortened URLs using services like checkshorturl.com before clicking them.',
      '@ Symbol in URL': 'In a URL like "https://paypal.com@evil.com", the real destination is evil.com — everything before @ is ignored.',
      'No HTTPS': 'Never submit forms on HTTP pages. Your data travels as plain text, readable by anyone on the network.',
    };
    return {title: top.name.toUpperCase(), text: tips[top.name] || `This check flagged: ${top.detail}`};
  }
}

// ══════════════════════════════════════════════
//  DUPLICATE / ORIGINAL LINK DETECTOR
// ══════════════════════════════════════════════

class DuplicateDetector {
  constructor() {}

  normalize(urlStr) {
    try {
      let u = urlStr.trim();
      if (!u.startsWith('http')) u = 'https://' + u;
      const p = new URL(u);
      // Remove trailing slash, lowercase, remove www, sort params
      let hostname = p.hostname.replace(/^www\./, '');
      let path = p.pathname.replace(/\/+$/, '') || '/';
      const params = Array.from(p.searchParams.entries()).sort((a,b)=>a[0].localeCompare(b[0]));
      const queryStr = params.map(([k,v])=>`${k}=${v}`).join('&');
      return { normalized: `${hostname}${path}${queryStr?'?'+queryStr:''}`, hostname, tld: hostname.split('.').pop(), baseDomain: hostname.split('.').slice(-2).join('.'), original: urlStr };
    } catch { return null; }
  }

  extractBrand(hostname) {
    const brands = ['paypal','google','facebook','apple','amazon','microsoft','netflix','instagram','twitter','linkedin','dropbox','github','gmail','yahoo','chase','wellsfargo','citibank','barclays','hsbc','irs','ebay','binance','coinbase'];
    for (const b of brands) {
      if (hostname.includes(b)) return b;
    }
    return null;
  }

  levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({length:m+1},(_,i)=>Array.from({length:n+1},(_,j)=>i===0?j:j===0?i:0));
    for(let i=1;i<=m;i++) for(let j=1;j<=n;j++) dp[i][j]=a[i-1]===b[j-1]?dp[i-1][j-1]:1+Math.min(dp[i-1][j],dp[i][j-1],dp[i-1][j-1]);
    return dp[m][n];
  }

  analyze(urls) {
    const parsed = urls.map(u => this.normalize(u)).filter(Boolean);
    if (parsed.length === 0) return [];

    const results = [];
    const seen = new Map(); // normalized -> index in results

    for (const p of parsed) {
      // Check exact duplicate
      if (seen.has(p.normalized)) {
        const orig = results[seen.get(p.normalized)];
        orig.count++;
        results.push({ ...p, type: 'duplicate', reason: 'Exact duplicate URL', refersTo: orig.original });
        continue;
      }

      // Check brand impersonation vs known originals
      const brand = this.extractBrand(p.hostname);
      let impersonating = null;
      if (brand) {
        const officialDomains = [`${brand}.com`, `www.${brand}.com`, `${brand}.org`, `${brand}.net`];
        if (!officialDomains.includes(p.hostname)) {
          impersonating = brand;
        }
      }

      // Check visual similarity to already-seen domains
      let similarTo = null;
      for (const [norm, idx] of seen.entries()) {
        const existingHostname = results[idx]?.hostname || '';
        if (!existingHostname) continue;
        const dist = this.levenshtein(p.hostname, existingHostname);
        const similarity = 1 - dist / Math.max(p.hostname.length, existingHostname.length);
        if (similarity > 0.75 && p.hostname !== existingHostname) {
          similarTo = existingHostname;
          break;
        }
      }

      if (impersonating) {
        results.push({ ...p, type: 'suspicious-dupe', count: 1, reason: `Impersonating "${impersonating}" brand`, refersTo: null });
      } else if (similarTo) {
        results.push({ ...p, type: 'suspicious-dupe', count: 1, reason: `Visually similar to "${similarTo}"`, refersTo: similarTo });
      } else {
        results.push({ ...p, type: 'original', count: 1, reason: 'Unique, original URL', refersTo: null });
      }

      seen.set(p.normalized, results.length - 1);
    }

    return results;
  }
}

// ══════════════════════════════════════════════
//  TOAST NOTIFICATIONS
// ══════════════════════════════════════════════

function showToast(type, title, message, duration=5000) {
  const icons = { danger:'🚨', warning:'⚠️', safe:'✅', info:'🔔' };
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${icons[type]||'🔔'}</span>
    <div class="toast-content">
      <div class="toast-title">${title}</div>
      <div>${message}</div>
    </div>
    <button class="toast-close" onclick="dismissToast(this.closest('.toast'))">×</button>
    <div class="toast-progress"></div>
  `;
  toast.addEventListener('click', (e) => { if (!e.target.classList.contains('toast-close')) dismissToast(toast); });
  container.appendChild(toast);

  setTimeout(() => dismissToast(toast), duration);
  return toast;
}

function dismissToast(toast) {
  if (!toast || !toast.parentNode) return;
  toast.style.animation = 'toastOut 0.3s ease forwards';
  setTimeout(() => toast.remove(), 300);
}

// ══════════════════════════════════════════════
//  UI CONTROLLER
// ══════════════════════════════════════════════

const engine = new DefendXEngine();
const dupeDetector = new DuplicateDetector();

function updateStats(threats) {
  engine.scanCount++;
  if (threats) engine.threatCount++;
  localStorage.setItem('dx_scans', engine.scanCount);
  localStorage.setItem('dx_threats', engine.threatCount);
  document.getElementById('scan-count-pill').textContent = engine.scanCount + ' SCANS';
  document.getElementById('threat-count-pill').textContent = engine.threatCount + ' THREATS';
}

function getRiskColor(level) {
  return level === 'danger' ? '#FF3A1A' : level === 'warning' ? '#FFD700' : '#39FF14';
}

function renderResult(data, container) {
  if (data.error) {
    container.innerHTML += `<div class="result-card"><div class="result-header warning" style="padding:20px 28px"><div class="result-verdict warning">⚠️ ${data.error}</div></div></div>`;
    return;
  }

  const { url, score, level, checks, deepInfo, verdict, recommendation, eduTip } = data;
  const rverdict = engine.getVerdict(level, score);
  const rrec = engine.getRecommendation(level, score);
  const retip = engine.getEduTip(checks);
  const flagged = checks.filter(c => c.flag);
  const color = getRiskColor(level);

  const checksHTML = checks.map(c => `
    <div class="check-item ${c.flag ? 'flagged' : 'ok'}">
      <span class="check-icon">${c.icon}</span>
      <div class="check-text">
        <strong>${c.name}</strong>
        ${c.detail}
      </div>
    </div>
  `).join('');

  const deepHTML = Object.entries(deepInfo).map(([k,v]) => {
    let cls = '';
    if (v === 'HIGH') cls = 'bad';
    else if (v === 'LOW') cls = 'good';
    return `<div class="ti-row"><span class="ti-key">${k}</span><span class="ti-val ${cls}">${v}</span></div>`;
  }).join('');

  const card = document.createElement('div');
  card.className = 'result-card';
  card.innerHTML = `
    <div class="result-header ${level}">
      <div class="risk-badge ${level}">${score}</div>
      <div class="result-meta">
        <div class="result-url" title="${url}">${url}</div>
        <div class="result-verdict ${level}">${rverdict}</div>
      </div>
      ${level === 'danger' ? '<span style="font-size:28px">🚨</span>' : level === 'warning' ? '<span style="font-size:28px">⚠️</span>' : '<span style="font-size:28px">✅</span>'}
    </div>
    <div class="result-body">
      <div class="risk-meter-label">
        <span>RISK SCORE</span><span>${score}/100</span>
      </div>
      <div class="risk-meter-track">
        <div class="risk-meter-fill" style="width:0%;background:${color}" data-target="${score}"></div>
      </div>
      <div class="ti-panel">
        <div class="ti-title">// Domain Intelligence</div>
        ${deepHTML}
      </div>
      <div style="font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--text-dim);letter-spacing:0.15em;text-transform:uppercase;margin-bottom:10px;">// Heuristic Checks (${flagged.length} flagged of ${checks.length})</div>
      <div class="checks-grid">${checksHTML}</div>
      <div class="recommendation ${rrec.cls}">${rrec.text}</div>
      <div class="edu-tip">
        <strong>💡 SECURITY INSIGHT: ${retip.title}</strong>
        ${retip.text}
      </div>
    </div>
  `;
  container.appendChild(card);

  // Animate meter
  setTimeout(() => {
    card.querySelector('.risk-meter-fill').style.width = score + '%';
  }, 100);
}

function addToHistory(data) {
  if (data.error) return;
  const item = { url: data.url, score: data.score, level: data.level, ts: Date.now() };
  engine.scanHistory.unshift(item);
  if (engine.scanHistory.length > 20) engine.scanHistory.pop();
  localStorage.setItem('dx_history', JSON.stringify(engine.scanHistory));
  renderHistory();
}

function renderHistory() {
  const hist = engine.scanHistory;
  const section = document.getElementById('history-section');
  const list = document.getElementById('history-list');
  if (hist.length === 0) { section.style.display = 'none'; return; }
  section.style.display = 'block';
  list.innerHTML = hist.map((item, i) => {
    const age = Math.floor((Date.now() - item.ts) / 1000);
    const ageStr = age < 60 ? `${age}s ago` : age < 3600 ? `${Math.floor(age/60)}m ago` : `${Math.floor(age/3600)}h ago`;
    return `<div class="history-item" onclick="reScan('${item.url.replace(/'/g,"\\'")}')" title="Click to re-scan">
      <div class="history-dot ${item.level}"></div>
      <div class="history-url">${item.url}</div>
      <div class="history-score">${item.score}/100</div>
      <div class="history-time">${ageStr}</div>
    </div>`;
  }).join('');
}

function reScan(url) {
  document.getElementById('url-input').value = url;
  scanURL();
}

function clearHistory() {
  engine.scanHistory = [];
  localStorage.setItem('dx_history', '[]');
  renderHistory();
}

const scanMessages = [
  'PARSING URL STRUCTURE...', 'RUNNING HEURISTIC ENGINE...', 'CHECKING BRAND PATTERNS...',
  'ANALYZING DOMAIN FINGERPRINT...', 'SCANNING FOR HOMOGRAPH ATTACKS...',
  'CROSS-REFERENCING THREAT PATTERNS...', 'COMPUTING RISK SCORE...', 'COMPILING REPORT...'
];

async function simulateScan(duration=1800) {
  const textEl = document.getElementById('scan-status-text');
  for (let i = 0; i < scanMessages.length; i++) {
    textEl.textContent = scanMessages[i];
    await new Promise(r => setTimeout(r, duration / scanMessages.length));
  }
}

async function scanURL() {
  const input = document.getElementById('url-input').value.trim();
  if (!input) { showToast('warning','Input Required','Please enter a URL to scan.'); return; }

  const btn = document.getElementById('scan-btn');
  btn.classList.add('scanning');
  btn.textContent = '⏳ SCANNING...';

  const loading = document.getElementById('loading');
  const results = document.getElementById('results');
  const banner = document.getElementById('global-warning-banner');

  loading.classList.add('show');
  results.classList.remove('show');
  results.innerHTML = '';
  banner.classList.remove('show');

  await simulateScan();

  const data = engine.analyze(input);
  loading.classList.remove('show');

  results.classList.add('show');
  renderResult(data, results);
  addToHistory(data);
  updateStats(!data.error && data.level === 'danger');

  // Show warning banner for danger
  if (!data.error && data.level === 'danger') {
    banner.classList.add('show');
    document.getElementById('warning-banner-detail').textContent =
      `Risk Score: ${data.score}/100. ${data.checks.filter(c=>c.flag).length} threat indicators detected. Do NOT visit this URL.`;

    showToast('danger', '🚨 CRITICAL THREAT DETECTED', `${input.substring(0,50)}... scored ${data.score}/100`, 8000);
  } else if (!data.error && data.level === 'warning') {
    showToast('warning', '⚠️ SUSPICIOUS URL', `${data.checks.filter(c=>c.flag).length} warning indicators found. Proceed with caution.`, 6000);
  } else if (!data.error) {
    showToast('safe', '✅ URL APPEARS SAFE', `Risk score: ${data.score}/100. Stay alert for social engineering.`, 4000);
  }

  btn.classList.remove('scanning');
  btn.textContent = '⚡ SCAN';
  window.scrollTo({ top: 300, behavior: 'smooth' });
}

async function bulkScan() {
  const raw = document.getElementById('bulk-input').value.trim();
  if (!raw) { showToast('warning','Input Required','Please enter URLs (one per line).'); return; }

  const urls = raw.split('\n').map(u => u.trim()).filter(Boolean);
  if (urls.length === 0) return;
  if (urls.length > 50) { showToast('warning','Limit Exceeded','Maximum 50 URLs per bulk scan.'); return; }

  // Duplicate detection
  const dupeResults = dupeDetector.analyze(urls);
  renderDupePanel(dupeResults);

  // Toast for dupes
  const dupes = dupeResults.filter(r => r.type !== 'original');
  if (dupes.length > 0) {
    showToast('warning', `🔗 ${dupes.length} Duplicate/Imposter URL(s)`, `${dupeResults.filter(r=>r.type==='suspicious-dupe').length} suspected imposters detected.`, 7000);
  }

  // Scan all
  const results = document.getElementById('results');
  const loading = document.getElementById('loading');
  loading.classList.add('show');
  results.classList.remove('show');
  results.innerHTML = '';

  await simulateScan(1200);
  loading.classList.remove('show');
  results.classList.add('show');

  let threatCount = 0;
  for (const url of urls) {
    const data = engine.analyze(url);
    renderResult(data, results);
    if (!data.error && data.level === 'danger') threatCount++;
    addToHistory(data);
    updateStats(!data.error && data.level === 'danger');
  }

  if (threatCount > 0) {
    showToast('danger', `🚨 ${threatCount} HIGH-RISK URL(s) Found`, `Out of ${urls.length} scanned URLs, ${threatCount} are critical threats.`, 8000);
  }
}

function renderDupePanel(results) {
  const panel = document.getElementById('dupe-panel');
  const list = document.getElementById('dupe-list');
  panel.style.display = 'block';

  const originals = results.filter(r => r.type === 'original');
  const dupes = results.filter(r => r.type === 'duplicate');
  const suspicious = results.filter(r => r.type === 'suspicious-dupe');

  document.getElementById('stat-total').textContent = results.length;
  document.getElementById('stat-original').textContent = originals.length;
  document.getElementById('stat-dupes').textContent = dupes.length + suspicious.length;

  list.innerHTML = results.map(r => {
    const badgeClass = r.type === 'original' ? 'orig' : r.type === 'duplicate' ? 'dupe' : 'sus';
    const badgeText = r.type === 'original' ? 'ORIGINAL' : r.type === 'duplicate' ? 'DUPLICATE' : '⚠ IMPOSTER';
    const itemClass = r.type === 'original' ? 'original' : r.type === 'duplicate' ? 'duplicate' : 'suspicious-dupe';
    return `
      <div class="dupe-item ${itemClass}">
        <span class="dupe-badge ${badgeClass}">${badgeText}</span>
        <div style="flex:1;min-width:0">
          <div class="dupe-url">${r.original}</div>
          ${r.reason !== 'Unique, original URL' ? `<div class="dupe-reason">⚠ ${r.reason}</div>` : ''}
        </div>
      </div>
    `;
  }).join('');
}

function toggleBulk() {
  const area = document.getElementById('bulk-area');
  area.classList.toggle('show');
}

// Keyboard shortcut
document.getElementById('url-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') scanURL();
});

// Init
renderHistory();

// Welcome toast
setTimeout(() => {
  showToast('info', '⚡ DefendX Online', 'URL Threat Intelligence Platform ready. Enter a URL to begin analysis.', 4000);
}, 800);
