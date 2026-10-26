import test from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { createHttpRedirectServer, createPortMultiplexer, ensureControllerTls } from '../dist/index.js';

test('createHttpRedirectServer redirects plaintext HTTP to HTTPS on port 2966', async (t) => {
  const targetPort = 2966;
  const redirectServer = createHttpRedirectServer(targetPort);

  await new Promise((resolve) => redirectServer.listen(0, '127.0.0.1', resolve));
  const assignedPort = redirectServer.address().port;

  t.after(() => {
    if (typeof redirectServer.closeAllConnections === 'function') {
      redirectServer.closeAllConnections();
    }
    redirectServer.close();
  });

  // Test 1: Standard GET request
  const res = await new Promise((resolve, reject) => {
    const req = http.get(
      {
        hostname: '127.0.0.1',
        port: assignedPort,
        path: '/firewall/rules?iface=wan',
        headers: { host: '10.80.0.114:2966', connection: 'close' },
        agent: false,
      },
      resolve
    );
    req.on('error', reject);
  });

  assert.equal(res.statusCode, 301, 'Should respond with 301 Moved Permanently');
  assert.equal(
    res.headers.location,
    'https://10.80.0.114:2966/firewall/rules?iface=wan',
    'Location header should target https on port 2966'
  );
  assert.ok(
    res.headers['strict-transport-security'],
    'Should include Strict-Transport-Security header'
  );

  let body = '';
  res.on('data', (chunk) => (body += chunk));
  await new Promise((resolve) => res.on('end', resolve));
  assert.ok(body.includes('https://10.80.0.114:2966/firewall/rules?iface=wan'));
});

test('createPortMultiplexer routes both TLS and plaintext HTTP on the exact same port', async (t) => {
  const certKeyPath = '/tmp/axon_test_key.pem';
  const certPath = '/tmp/axon_test_cert.pem';

  execSync(
    `openssl req -x509 -newkey rsa:2048 -keyout ${certKeyPath} -out ${certPath} -days 1 -nodes -subj "/CN=localhost"`
  );

  const cert = fs.readFileSync(certPath);
  const key = fs.readFileSync(certKeyPath);

  const httpsServer = https.createServer({ cert, key }, (req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ secure: true, path: req.url }));
  });

  const redirectServer = createHttpRedirectServer(2966);
  const multiplexer = createPortMultiplexer(httpsServer, redirectServer);

  await new Promise((resolve) => multiplexer.listen(0, '127.0.0.1', resolve));
  const multiplexerPort = multiplexer.address().port;

  t.after(() => {
    if (typeof httpsServer.closeAllConnections === 'function') {
      httpsServer.closeAllConnections();
    }
    if (typeof redirectServer.closeAllConnections === 'function') {
      redirectServer.closeAllConnections();
    }
    multiplexer.close();
    httpsServer.close();
    redirectServer.close();
    try {
      fs.unlinkSync(certPath);
      fs.unlinkSync(certKeyPath);
    } catch {}
  });

  // 1. Send plaintext HTTP request to the multiplexer port
  const httpRes = await new Promise((resolve, reject) => {
    const req = http.get(
      {
        hostname: '127.0.0.1',
        port: multiplexerPort,
        path: '/routing',
        headers: { host: '10.80.0.114:2966', connection: 'close' },
        agent: false,
      },
      resolve
    );
    req.on('error', reject);
  });

  assert.equal(httpRes.statusCode, 301, 'Plaintext HTTP must be redirected with 301');
  assert.equal(
    httpRes.headers.location,
    'https://10.80.0.114:2966/routing',
    'Plaintext HTTP must be upgraded to https on port 2966'
  );

  // 2. Send TLS/HTTPS request to the SAME multiplexer port
  const httpsRes = await new Promise((resolve, reject) => {
    const req = https.get(
      {
        hostname: '127.0.0.1',
        port: multiplexerPort,
        path: '/routing',
        rejectUnauthorized: false,
        headers: { connection: 'close' },
        agent: false,
      },
      resolve
    );
    req.on('error', reject);
  });

  assert.equal(httpsRes.statusCode, 200, 'HTTPS request must succeed');
  let secureBody = '';
  httpsRes.on('data', (chunk) => (secureBody += chunk));
  await new Promise((resolve) => httpsRes.on('end', resolve));

  const json = JSON.parse(secureBody);
  assert.equal(json.secure, true);
  assert.equal(json.path, '/routing');
});

test('createHttpRedirectServer sanitizes malicious Host headers and escapes XSS payloads', async (t) => {
  const targetPort = 2966;
  const redirectServer = createHttpRedirectServer(targetPort);

  await new Promise((resolve) => redirectServer.listen(0, '127.0.0.1', resolve));
  const assignedPort = redirectServer.address().port;

  t.after(() => {
    if (typeof redirectServer.closeAllConnections === 'function') {
      redirectServer.closeAllConnections();
    }
    redirectServer.close();
  });

  // Test: Malicious Host header with port injection and XSS script tag in URL
  const res = await new Promise((resolve, reject) => {
    const req = http.get(
      {
        hostname: '127.0.0.1',
        port: assignedPort,
        path: '///attacker.com/</script><script>alert(1)</script>',
        headers: { host: 'evil.com:443', connection: 'close' },
        agent: false,
      },
      resolve
    );
    req.on('error', reject);
  });

  assert.equal(res.statusCode, 301);
  // Host header port 443 must be stripped and replaced with controller's targetPort 2966
  // Protocol-relative triple slashes must collapse to single leading slash
  assert.equal(
    res.headers.location,
    'https://evil.com:2966/attacker.com/</script><script>alert(1)</script>'
  );

  let body = '';
  res.on('data', (chunk) => (body += chunk));
  await new Promise((resolve) => res.on('end', resolve));

  // Verify raw </script> is NOT unescaped inside HTML or script
  assert.ok(
    !body.includes('href="https://evil.com:2966/attacker.com/</script>'),
    'HTML attribute must be entity-escaped'
  );
  assert.ok(
    body.includes('&lt;/script&gt;'),
    'HTML body must contain XML/HTML entity-escaped script tag'
  );
  assert.ok(
    body.includes('\\u003c/script\\u003e'),
    'JavaScript redirect must contain escaped unicode tag'
  );
});

test('ensureControllerTls auto-generates certificates when missing, preventing plaintext HTTP fallback', async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axon_tls_test_'));
  const testCertPath = path.join(tmpDir, 'test_hub.crt');
  const testKeyPath = path.join(tmpDir, 'test_hub.key');

  t.after(() => {
    try {
      if (fs.existsSync(testCertPath)) fs.unlinkSync(testCertPath);
      if (fs.existsSync(testKeyPath)) fs.unlinkSync(testKeyPath);
      fs.rmdirSync(tmpDir);
    } catch {}
  });

  // Verify files do not exist initially
  assert.equal(fs.existsSync(testCertPath), false);
  assert.equal(fs.existsSync(testKeyPath), false);

  // ensureControllerTls should detect missing files and generate valid TLS credentials
  const tlsConfig = ensureControllerTls(testCertPath, testKeyPath);
  assert.ok(tlsConfig, 'ensureControllerTls must return a valid TLS configuration');
  assert.ok(tlsConfig.cert, 'TLS config must include cert');
  assert.ok(tlsConfig.key, 'TLS config must include key');

  // Verify the cert and key were written to disk and are non-empty
  assert.equal(fs.existsSync(testCertPath), true);
  assert.equal(fs.existsSync(testKeyPath), true);
  assert.ok(fs.statSync(testCertPath).size > 100);
  assert.ok(fs.statSync(testKeyPath).size > 100);

  // Verify that an https.Server initializes and successfully performs a TLS handshake with these credentials
  const httpsServer = https.createServer({ cert: tlsConfig.cert, key: tlsConfig.key }, (req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('HTTPS_OK');
  });

  await new Promise((resolve) => httpsServer.listen(0, '127.0.0.1', resolve));
  const serverPort = httpsServer.address().port;

  t.after(() => {
    if (typeof httpsServer.closeAllConnections === 'function') {
      httpsServer.closeAllConnections();
    }
    httpsServer.close();
  });

  const httpsRes = await new Promise((resolve, reject) => {
    const req = https.get(
      {
        hostname: '127.0.0.1',
        port: serverPort,
        path: '/login',
        rejectUnauthorized: false,
        headers: { connection: 'close' },
        agent: false,
      },
      resolve
    );
    req.on('error', reject);
  });

  assert.equal(httpsRes.statusCode, 200);
  let respBody = '';
  httpsRes.on('data', (chunk) => (respBody += chunk));
  await new Promise((resolve) => httpsRes.on('end', resolve));
  assert.equal(respBody, 'HTTPS_OK');
});

test('controller port multiplexer end-to-end: plaintext HTTP /login is redirected with 301 and HTTPS /login never errors', async (t) => {
  // Simulate the appliance scenario: missing certs auto-provisioned, port 2966 multiplexed
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axon_mpx_test_'));
  const testCertPath = path.join(tmpDir, 'hub.crt');
  const testKeyPath = path.join(tmpDir, 'hub.key');

  t.after(() => {
    try {
      if (fs.existsSync(testCertPath)) fs.unlinkSync(testCertPath);
      if (fs.existsSync(testKeyPath)) fs.unlinkSync(testKeyPath);
      fs.rmdirSync(tmpDir);
    } catch {}
  });

  const tlsConfig = ensureControllerTls(testCertPath, testKeyPath);
  assert.ok(tlsConfig, 'Must auto-provision TLS config when certs missing');

  // Upstream UI handler simulating Next.js on port 3000
  const mockUiHandler = (req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!DOCTYPE html><html><body>Next.js Web Console Login</body></html>');
  };

  const httpsServer = https.createServer(
    { cert: tlsConfig.cert, key: tlsConfig.key, rejectUnauthorized: false },
    mockUiHandler
  );
  const redirectServer = createHttpRedirectServer(2966);
  const multiplexer = createPortMultiplexer(httpsServer, redirectServer);

  await new Promise((resolve) => multiplexer.listen(0, '127.0.0.1', resolve));
  const assignedPort = multiplexer.address().port;

  t.after(() => {
    if (typeof httpsServer.closeAllConnections === 'function') {
      httpsServer.closeAllConnections();
    }
    if (typeof redirectServer.closeAllConnections === 'function') {
      redirectServer.closeAllConnections();
    }
    multiplexer.close();
    httpsServer.close();
    redirectServer.close();
  });

  // 1. Client connects via plaintext HTTP: http://127.0.0.1:<port>/login
  // MUST NEVER return the login page over HTTP; MUST return 301 Location: https://...:2966/login
  const httpRes = await new Promise((resolve, reject) => {
    const req = http.get(
      {
        hostname: '127.0.0.1',
        port: assignedPort,
        path: '/login',
        headers: { host: `10.80.0.104:2966`, connection: 'close' },
        agent: false,
      },
      resolve
    );
    req.on('error', reject);
  });

  assert.equal(httpRes.statusCode, 301, 'Plaintext HTTP to /login must receive 301 redirect');
  assert.equal(
    httpRes.headers.location,
    'https://10.80.0.104:2966/login',
    'Plaintext HTTP must be redirected to HTTPS on port 2966'
  );

  let redirectHtml = '';
  httpRes.on('data', (chunk) => (redirectHtml += chunk));
  await new Promise((resolve) => httpRes.on('end', resolve));
  assert.ok(
    !redirectHtml.includes('Next.js Web Console Login'),
    'Plaintext HTTP response must NEVER expose the upstream UI page directly'
  );

  // 2. Client connects via HTTPS: https://127.0.0.1:<port>/login
  // MUST succeed with valid TLS handshake and proxy upstream response without ERR_SSL_PROTOCOL_ERROR
  const httpsRes = await new Promise((resolve, reject) => {
    const req = https.get(
      {
        hostname: '127.0.0.1',
        port: assignedPort,
        path: '/login',
        rejectUnauthorized: false,
        headers: { host: `10.80.0.104:2966`, connection: 'close' },
        agent: false,
      },
      resolve
    );
    req.on('error', reject);
  });

  assert.equal(httpsRes.statusCode, 200, 'HTTPS request to /login must succeed with 200 OK');
  let secureHtml = '';
  httpsRes.on('data', (chunk) => (secureHtml += chunk));
  await new Promise((resolve) => httpsRes.on('end', resolve));
  assert.ok(
    secureHtml.includes('Next.js Web Console Login'),
    'HTTPS request must receive the upstream Next.js login page'
  );
});
