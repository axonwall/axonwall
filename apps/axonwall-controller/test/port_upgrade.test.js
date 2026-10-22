import test from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import { createHttpRedirectServer, createPortMultiplexer } from '../dist/index.js';

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
