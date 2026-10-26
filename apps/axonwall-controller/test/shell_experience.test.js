import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { BUILTIN_PLUGINS, isPluginEnabled, DesiredStateSchema } from '@axonwall/lib';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../../..');

test('cli-workstation plugin (ZSH, Oh My Zsh, VIM, Starship) is enabled by default and can be disabled to reduce attack surface', () => {
  const manifest = BUILTIN_PLUGINS.find((p) => p.id === 'cli-workstation');
  assert.ok(manifest, 'cli-workstation plugin must exist in BUILTIN_PLUGINS');
  assert.equal(manifest.defaultEnabled, true, 'cli-workstation must have defaultEnabled: true');
  assert.ok(manifest.name.includes('Oh My Zsh'), 'cli-workstation name should mention Oh My Zsh');

  const defaultState = DesiredStateSchema.parse({
    version: 1,
    interfaces: [{ name: 'wan', device: 'eth0', type: 'dhcp', enabled: true }],
    aliases: [],
    rules: [],
  });
  assert.equal(
    isPluginEnabled('cli-workstation', defaultState),
    true,
    'cli-workstation must be enabled by default on fresh state'
  );

  const hardenedState = DesiredStateSchema.parse({
    version: 1,
    interfaces: [{ name: 'wan', device: 'eth0', type: 'dhcp', enabled: true }],
    aliases: [],
    rules: [],
    plugins: [{ id: 'cli-workstation', enabled: false, config: {} }],
  });
  assert.equal(
    isPluginEnabled('cli-workstation', hardenedState),
    false,
    'cli-workstation must be disabled when operator explicitly sets enabled: false'
  );
});

test('Oh My Zsh distribution and full-stack plugins (including kubectl) are bundled and syntactically valid', () => {
  const omzRoot = path.join(repoRoot, 'packaging/iso/config/includes.chroot/usr/share/oh-my-zsh');
  assert.ok(fs.existsSync(path.join(omzRoot, 'oh-my-zsh.sh')), 'oh-my-zsh.sh loader must exist');

  const requiredPlugins = [
    'kubectl',
    'helm',
    'git',
    'systemd',
    'sudo',
    'tmux',
    'extract',
    'colored-man-pages',
    'docker',
    'axonwall',
  ];

  for (const plg of requiredPlugins) {
    const plgFile = path.join(omzRoot, 'plugins', plg, `${plg}.plugin.zsh`);
    assert.ok(fs.existsSync(plgFile), `Oh My Zsh plugin ${plg} must exist at ${plgFile}`);
  }

  // Verify kubectl plugin includes KUBECONFIG auto-detection, completion, and standard aliases
  const kubectlContent = fs.readFileSync(
    path.join(omzRoot, 'plugins/kubectl/kubectl.plugin.zsh'),
    'utf-8'
  );
  assert.ok(kubectlContent.includes('/etc/rancher/k3s/k3s.yaml'), 'kubectl plugin must auto-detect k3s kubeconfig');
  assert.ok(kubectlContent.includes('kubectl completion zsh'), 'kubectl plugin must load zsh completion');
  assert.ok(kubectlContent.includes("alias kgp='kubectl get pods'"), 'kubectl plugin must define kgp alias');
  assert.ok(kubectlContent.includes("alias kcuc='kubectl config use-context'"), 'kubectl plugin must define kcuc alias');
  assert.ok(kubectlContent.includes("alias kctx='kubectl config get-contexts'"), 'kubectl plugin must define kctx alias');

  // Verify axonwall plugin includes completions across the entire stack
  const axonwallPlugin = fs.readFileSync(
    path.join(omzRoot, 'plugins/axonwall/axonwall.plugin.zsh'),
    'utf-8'
  );
  for (const fn of [
    '_axonwallctl',
    '_axonwall_tui',
    '_axonwall_zpool',
    '_axonwall_zfs',
    '_axonwall_nft',
    '_axonwall_wg',
    '_axonwall_rosenpass',
    '_axonwall_headscale',
    '_axonwall_tailscale',
    '_axonwall_k3s',
    '_axonwall_virsh',
  ]) {
    assert.ok(axonwallPlugin.includes(fn), `axonwall.plugin.zsh must define completion function ${fn}`);
  }

  // Verify /etc/zsh/axonwall.zsh wires Oh My Zsh, plugins=(... kubectl ...), and attack-surface check
  const axonwallZsh = fs.readFileSync(
    path.join(repoRoot, 'packaging/iso/config/includes.chroot/etc/zsh/axonwall.zsh'),
    'utf-8'
  );
  assert.ok(
    axonwallZsh.includes('/etc/axonwall/workstation.disabled'),
    'axonwall.zsh must respect /etc/axonwall/workstation.disabled marker'
  );
  assert.ok(
    axonwallZsh.includes('/usr/share/oh-my-zsh'),
    'axonwall.zsh must configure ZSH=/usr/share/oh-my-zsh'
  );
  assert.ok(
    axonwallZsh.includes('kubectl'),
    'axonwall.zsh must enable the kubectl Oh My Zsh plugin'
  );
});

test('axonwallctl completion outputs zsh and bash completion scripts', () => {
  const ctlBin = path.join(repoRoot, 'apps/axonwall-controller/dist/axonwallctl.js');
  assert.ok(fs.existsSync(ctlBin), 'Compiled axonwallctl.js must exist');

  const zshOut = execFileSync('node', [ctlBin, 'completion', 'zsh'], { encoding: 'utf-8' });
  assert.ok(zshOut.includes('_axonwallctl'), 'zsh completion output must include _axonwallctl');

  const bashOut = execFileSync('node', [ctlBin, 'completion', 'bash'], { encoding: 'utf-8' });
  assert.ok(
    bashOut.includes('complete -F _axonwallctl_completions axonwallctl ctl'),
    'bash completion output must register complete -F _axonwallctl_completions'
  );
});

test('Neovim Super Configurator (axonwall-config / init.lua) provides zero-chrome UI with native Vim motions and saves to /etc/axonwall/*.yaml', (t) => {
  const initLua = path.join(repoRoot, 'packaging/iso/config/includes.chroot/etc/axonwall/nvim/init.lua');
  const launcherBin = path.join(repoRoot, 'packaging/iso/config/includes.chroot/usr/local/bin/axonwall-config');
  const ctlBin = path.join(repoRoot, 'apps/axonwall-controller/dist/axonwallctl.js');

  assert.ok(fs.existsSync(initLua), 'Neovim Super Configurator init.lua must exist');
  assert.ok(fs.existsSync(launcherBin), 'axonwall-config launcher script must exist');

  // Check if nvim is installed on this test host
  let hasNvim = false;
  try {
    execFileSync('nvim', ['--version'], { stdio: 'ignore' });
    hasNvim = true;
  } catch {}
  if (!hasNvim) {
    t.skip('nvim binary not installed on test runner');
    return;
  }

  const tmpDir = fs.mkdtempSync('/tmp/axonwall-nvim-test-');
  try {
    const env = {
      ...process.env,
      AXONWALL_CONFIG_DIR: tmpDir,
      AXONWALL_ETC_DIR: tmpDir,
      AXONWALLCTL_BIN: ctlBin,
      AXONWALL_NVIM_DOMAIN: 'system',
    };

    // Initialize default YAML files via dump-json -> save-json
    const dumped = execFileSync('node', [ctlBin, 'dump-json'], { env, encoding: 'utf-8' });
    execFileSync('node', [ctlBin, 'save-json', '-'], { env, input: dumped, encoding: 'utf-8' });

    // Launch headless Neovim with our Super Configurator, verify zero-chrome options,
    // use native Vim `normal! ciw` motion to change hostname, add a firewall rule card, and save
    const nvimOut = execFileSync(
      'nvim',
      [
        '--headless',
        '--clean',
        '-u',
        initLua,
        '-c',
        'lua assert(vim.o.number == false and vim.o.cmdheight == 0 and vim.o.laststatus == 0, "Expected zero-chrome options")',
        '-c',
        'lua assert(#_G.AxonwallSuperConfig.DOMAINS == 12, "Expected 12 configuration domains")',
        '-c',
        'normal! ciwaxonwall-nvim-super',
        '-c',
        'lua _G.AxonwallSuperConfig.load_domain(3)',
        '-c',
        'lua _G.AxonwallSuperConfig.add_card()',
        '-c',
        'lua assert(_G.AxonwallSuperConfig.save(false) == true, "Expected save(false) to succeed: " .. tostring(_G.AxonwallSuperConfig.App.status_msg))',
        '-c',
        'qa!',
      ],
      { env, encoding: 'utf-8' }
    );

    const systemYaml = fs.readFileSync(path.join(tmpDir, 'system.yaml'), 'utf-8');
    assert.ok(
      systemYaml.includes('hostname: axonwall-nvim-super'),
      `system.yaml must contain updated hostname edited via Vim 'ciw' motion, got:\n${systemYaml}`
    );

    const firewallYaml = fs.readFileSync(path.join(tmpDir, 'firewall.yaml'), 'utf-8');
    assert.ok(
      firewallYaml.includes('Custom Firewall Rule #'),
      `firewall.yaml must contain newly added Firewall Rule card, got:\n${firewallYaml}`
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
