const { request } = require('https');
const { writeFileSync } = require('fs');
const axios = require('axios');
const cheerio = require('cheerio');
const dns = require('dns');
const whois = require('whois-json');
const net = require('net');
const urlModule = require('url');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');

const dnsLookup = promisify(dns.lookup);
const SECURITY_HEADERS = [
  'content-security-policy',
  'x-content-type-options',
  'x-frame-options',
  'strict-transport-security',
  'referrer-policy',
  'permissions-policy',
  'x-xss-protection',
  'x-permitted-cross-domain-policies',
  'expect-ct',
  'cache-control',
  'pragma',
  'x-download-options',
  'x-dns-prefetch-control'
];


const SENSITIVE_PATHS = [
  '/.env',
  '/.git/config',
  '/wp-config.php',
  '/phpinfo.php',
  '/admin/config.yml',
  '/.htaccess',
  '/.bash_history',
  '/.ssh/authorized_keys',
  '/.aws/credentials',
  '/config/database.yml',
  '/config/secrets.yml',
  '/logs/access.log',
  '/logs/error.log',
  '/backup.sql',
  '/database.sql',
  '/config.php',
  '/secret.key',
  '/id_rsa',
  '/id_rsa.pub',
  '/.npmrc',
  '/composer.json',
  '/composer.lock',
  '/docker-compose.yml',
  '/nginx.conf',
  '/robots.txt'
];


const COMMON_PORTS = Array.from({ length: 1024 }, (_, i) => i); // Scan all ports from 0 to 1023

axios.defaults.timeout = 5000; // Timeout pour les requêtes HTTP

async function checkHeaders(url) {
  return new Promise((resolve) => {
    const req = request(url, { method: 'HEAD' }, (res) => {
      resolve({
        status: res.statusCode,
        headers: res.headers,
        missing: SECURITY_HEADERS.filter(h => !res.headers[h.toLowerCase()])
      });
    });

    req.on('error', () => resolve(null));
    req.end();
  });
}

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

async function performDNSLookup(domain) {
  try {
    const addresses = await dnsLookup(domain, { all: true });
    return addresses;
  } catch (error) {
    return [];
  }
}

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

async function checkCookies(url) {
  const insecureCookies = new Set();
  try {
    const res = await axios.get(url);
    const cookies = res.headers['set-cookie'] || [];

    cookies.forEach(cookie => {
      if (!cookie.includes('Secure') || !cookie.includes('HttpOnly')) {
        insecureCookies.add(cookie);
      }
      if (!cookie.includes('SameSite') || (cookie.includes('SameSite=None') && !cookie.includes('Secure'))) {
        insecureCookies.add(cookie);
      }
    });

    return Array.from(insecureCookies);
  } catch (error) {
    console.error(`Erreur lors de la récupération des cookies : ${error.message}`);
    return Array.from(insecureCookies);
  }
}



async function checkXSS(target) {
  const payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)' />", 
    "<svg/onload=alert(1)>", 
    "<a href='javascript:alert(1)'>click me</a>", 
    "<body onload=alert('XSS')>", 
    "<iframe src='javascript:alert(1)'></iframe>" 
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
    catch (error) {}
  }
  return results.length > 0 ? results : ['✅ Aucune vulnérabilité détectée'];
}

async function sqli(target) {
  const payloads = [
    "1' OR '1'='1",
    "1' --",
    "1' /*",
    '1" OR "1"="1',
    "1' UNION SELECT NULL, NULL, NULL --",
    "1' OR SLEEP(5) --",
    "1' AND IF(1=1, SLEEP(5), 0) --"
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
    "../../../../../../../../../../../var/www/html/index.php%00"
  ];

  let results = [];

  for (let payload of payloads) {
    const testParam = `${target}?q=${encodeURIComponent(payload)}`;
    try {
      const response = await axios.get(testParam);
      if (response.data.includes("root:x:0:0:root:/root:/bin/bash") || response.data.includes("etc/passwd") || response.data.includes("bash_history")) {
        results.push(`⚠️  LFI détecté avec le payload: ${payload}`);
      }
    } catch (error) {
    }
  }

  return results.length > 0 ? results : ['✅ Aucune vulnérabilité détectée'];
}

async function JWT(target) {
  const payloads = [
    { user: 'admin', role: 'admin' },
    { user: 'attacker', role: 'user' },
    { exp: Math.floor(Date.now() / 1000) - 60 }, 
    { exp: Math.floor(Date.now() / 1000) + 60 * 60 }, 
    { foo: 'bar' }, 
  ];

  let results = [];

  const tokenWithNoSignature = jwt.sign(payloads[0], '', { algorithm: 'none' });
  const tokenWithExpiredExp = jwt.sign({ exp: Math.floor(Date.now() / 1000) - 3600 }, 'fake-secret-key', { algorithm: 'HS256' });


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

  const algorithmsToTest = ['HS256', 'HS384', 'HS512', 'RS256'];

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

  return results.length > 0 ? results : ['✅ Pas de vulnérabilité JWT détectée'];
}

async function detectGraphQLVulnerabilities(target) {
  const introspectionQuery = `{
    __schema {
      types {
        name
      }
    }
  }`;

  const maliciousQueries = [
    `{ user(id: "1") { password } }`, 
    `{ users { id name email password } }`,
    `{ query: invalidQuery }`, 
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
  for (let query of maliciousQueries) {
    try {
      const response = await axios.post(target, {
        query: query
      });
      if (response.data.errors || response.data.data) {
        results.push(`⚠️ Requête malveillante acceptée : ${query}`);
      }
    } catch (error) {
    }
  }
  try {
    const response = await axios.post(target, {
      query: '{ invalidField }'
    });
    if (response.data.errors) {
      results.push('⚠️ Exposition d\'informations sensibles via les erreurs');
    }
  } catch (error) {
  }
  return results.length > 0 ? results : ['✅ Aucune vulnérabilité détectée'];
}


const COMMON_DIRECTORIES = [
  '/admin', '/hidden', '/backup', '/uploads', '/private', '/config', '/secure', '/data', '/files', '/logs', '/temp',
  '/management', '/assets', '/api', '/static', '/wp-admin', '/admin_panel', '/dashboard', '/cms', '/db_backup', '/test', '/public'
];

async function attackBrutForce(baseUrl) {
  const results = [];

  const timeout = 5000; 
  const headers = {
    'User-Agent': 'Mozilla/5.0 (compatible; bruteforce-scanner/1.0)',
  };

  for (const path of COMMON_DIRECTORIES) {
    const targetUrl = `${baseUrl}${path}`;
    try {
      const response = await axios.head(targetUrl, { timeout, headers });

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
    const dnsInfo = await performDNSLookup(hostname);
    const openPorts = await performPortScan(hostname);
    const insecureCookies = await checkCookies(target);
    const xssResults = await checkXSS(target);
    const hasSQLiVulnerability = await sqli(target);
    const hasLFIVulnerability = await lfi(target);
    const jwtResults = await JWT(target);
    const graphqlResults = await detectGraphQLVulnerabilities(target);
    const bruteforceResults = await attackBrutForce(target);

    console.log('\n=== Rapport de sécurité ===');
    console.log(`Cible: ${target}`);

    // En-têtes de sécurité
    console.log('\n[En-têtes de sécurité]:');
    security.missing.length > 0 
      ? security.missing.forEach(h => console.log(`❌ ${h}`))
      : console.log('✅ Tous les en-têtes sont présents');

    // Fichiers sensibles
    console.log('\n[Fichiers sensibles]:');
    sensitiveFiles.length > 0 
      ? sensitiveFiles.forEach(p => console.log(`⚠️  ${p}`))
      : console.log('✅ Aucun fichier exposé détecté');

    // Technologies
    console.log('\n[Technologies]:');
    console.log(`Serveur: ${techInfo.server}`);
    console.log(`Générateur: ${techInfo.generator}`);

    // DNS
    console.log('\n[Informations DNS]:');
    dnsInfo.forEach(info => console.log(`Adresse IP: ${info.address} (IPv${info.family})`));

    // Ports ouverts
    console.log('\n[Ports ouverts]:');
    openPorts.length > 0 
      ? openPorts.forEach(port => console.log(`⚠️  Port ${port} ouvert`))
      : console.log('✅ Aucun port ouvert détecté sur la plage vérifiée');

    // Cookies non sécurisés
console.log('\n[Cookies non sécurisés]:');
if (insecureCookies.length > 0) {
  insecureCookies.forEach(cookie => console.log(`⚠️ Cookie non sécurisé détecté: ${cookie}`));
} else {
  console.log('✅ Tous les cookies sont sécurisés');
}


    // Vulnérabilité XSS
    console.log('\n[Vulnérabilité XSS]:');
    if (xssResults && xssResults.length > 0) {
      xssResults.forEach(result => console.log(result));
    } else {
      console.log('✅ Pas de XSS détecté');
    }

    // Vulnérabilité SQLi
    console.log('\n[Vulnérabilité SQLi]:');
    if (hasSQLiVulnerability&& hasSQLiVulnerability.length > 0) {
      hasSQLiVulnerability.forEach(result => console.log(result));
    } else {
      console.log('✅ Pas de SQLi détecté');
    }

    // Vulnérabilité LFI
    console.log('\n[Vulnérabilité LFI]:');
    if (hasLFIVulnerability && hasLFIVulnerability.length > 0) {
      hasLFIVulnerability.forEach(result => console.log(result));
    } else {
      console.log('✅ Pas de LFI détecté');
    }

    // Vulnérabilité JWT
    console.log('\n[Vulnérabilité JWT]:');
    if (jwtResults && jwtResults.length > 0) {
      jwtResults.forEach(result => console.log(result));
    } else {
      console.log('✅ Pas de vulnérabilité JWT détectée');
    }

    // Vulnérabilités GraphQL
    console.log('\n[Vulnérabilités GraphQL]:');
    if (graphqlResults && graphqlResults.length > 0) {
      graphqlResults.forEach(result => console.log(result));
    } else {
      console.log('✅ Aucune vulnérabilité GraphQL détectée');
    }

    // Attaque par force brute
    console.log('\n[Attaque par force brute]:');
    if (bruteforceResults && bruteforceResults.length > 0) {
      bruteforceResults.forEach(result => console.log(result));
    } else {
      console.log('✅ Aucun répertoire sensible détecté');
    }

    // Générer un rapport JSON
    const timestamp = new Date().toISOString();
    const report = {
      timestamp,
      target,
      headers: { missing: security.missing },
      technologies: techInfo,
      sensitiveFiles,
      dnsInfo,
      openPorts,
      insecureCookies,
      xssResults,
      hasSQLiVulnerability,
      hasLFIVulnerability,
      jwtResults,
      graphqlResults,
      bruteforceResults,
    };

    writeFileSync(reportFileName, JSON.stringify(report, null, 2));
    console.log(`Rapport sauvegardé sous ${reportFileName}`);
  } catch (error) {
    console.log('Erreur:', error.message);
  }
}

// Utilisation
const target = process.argv[2];

if (!target) {
  console.log('Usage: node scanner.js <url> [output_filename.json]');
  process.exit(1);
}

generateReport(target);