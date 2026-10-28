import { describe, expect, it } from 'vitest';
import {
  BUILTIN_PLUGINS,
  DesiredStateSchema,
  HOST_MALWARE_SCANNERS,
  analyzeBpfHelperAndTrampolineUsage,
  analyzePmuLbrBranchStack,
  compileBpfLsmGuardC,
  compileDrgnProgIdrAuditScript,
  compileEbpfRootkitHuntScript,
  compileHostDefenseBundle,
  compileIoUringHuntScript,
  compileKernelHardeningSysctl,
  compileYaraGhostInTheRingRules,
  diffKcoreProgIdrAgainstSysBpf,
  disablePluginWithDependents,
  enablePluginWithDependencies,
  isPluginEnabled,
  parseIoUringFdInfo,
  serializeDesiredStateToYamlFiles,
  validateYamlConfigFiles,
} from '../../index.js';

describe('Host Malware, Rootkit & Ghost-in-the-Ring Kernel Defense Suite', () => {
  it('registers host-malware-rootkit plugin in BUILTIN_PLUGINS as enabled by default', () => {
    const manifest = BUILTIN_PLUGINS.find((p) => p.id === 'host-malware-rootkit');
    expect(manifest).toBeDefined();
    expect(manifest?.defaultEnabled).toBe(true);
    expect(manifest?.packages?.debian).toEqual(
      expect.arrayContaining([
        'rkhunter',
        'chkrootkit',
        'clamav',
        'lynis',
        'aide',
        'yara',
        'unhide',
        'debsums',
        'bpftool',
        'bpftrace',
        'python3-drgn',
        'linux-perf',
      ])
    );
    expect(isPluginEnabled('host-malware-rootkit', undefined)).toBe(true);
    expect(isPluginEnabled('host-malware-rootkit', {})).toBe(true);

    const base = DesiredStateSchema.parse({});
    const disabled = disablePluginWithDependents('host-malware-rootkit', base);
    expect(isPluginEnabled('host-malware-rootkit', disabled.state)).toBe(false);

    const reenabled = enablePluginWithDependencies('host-malware-rootkit', disabled.state);
    expect(isPluginEnabled('host-malware-rootkit', reenabled.state)).toBe(true);
    expect(reenabled.state.hostDefense?.enabled).toBe(true);
  });

  it('catalogs all 12 classic scanners and Ghost-in-the-Ring Ring-0 detectors', () => {
    expect(HOST_MALWARE_SCANNERS.length).toBe(12);
    const ids = HOST_MALWARE_SCANNERS.map((s) => s.id);
    expect(ids).toEqual(
      expect.arrayContaining([
        'rkhunter',
        'chkrootkit',
        'clamav',
        'aide',
        'lynis',
        'yara',
        'unhide',
        'debsums',
        'io-uring-ring-hunter',
        'drgn-kcore-prog-idr',
        'pmu-lbr-trampoline-auditor',
        'bpf-lsm-lockdown',
      ])
    );
  });

  it('compiles sysctl, BPF_LSM C policy, drgn prog_idr auditor, io_uring & eBPF hunt scripts, and YARA rules', () => {
    const state = DesiredStateSchema.parse({
      hostDefense: {
        enabled: true,
        ioUringDisabledMode: '2',
        ioUringAllowedGid: 994,
        blockIoUringSqpoll: true,
        unprivilegedBpfDisabled: true,
        kernelLockdownMode: 'confidentiality',
      },
    });

    const sysctl = compileKernelHardeningSysctl(state);
    expect(sysctl).toContain('kernel.io_uring_disabled = 2');
    expect(sysctl).toContain('kernel.io_uring_group = 994');
    expect(sysctl).toContain('kernel.unprivileged_bpf_disabled = 1');

    const lsmC = compileBpfLsmGuardC(state);
    expect(lsmC).toContain('SEC("lsm/bpf")');
    expect(lsmC).toContain('SEC("lsm/uring_sqpoll")');
    expect(lsmC).toContain('trusted_bpf_loaders');
    expect(lsmC).toContain('return -EPERM;');

    const drgnPy = compileDrgnProgIdrAuditScript();
    expect(drgnPy).toContain('idr_for_each(prog["prog_idr"].address_of_())');
    expect(drgnPy).toContain('CRITICAL: HIDDEN FROM SYS_BPF (ROOTKIT)');

    const ioUringSh = compileIoUringHuntScript();
    expect(ioUringSh).toContain('anon_inode:[io_uring]');
    expect(ioUringSh).toContain('SqThread|SqThreadCpu|SqHead|SqTail|CqHead|CqTail|UserFiles');

    const ebpfSh = compileEbpfRootkitHuntScript();
    expect(ebpfSh).toContain('bpf_probe_write_user|bpf_override_return');
    expect(ebpfSh).toContain('perf record -e branches:k -j any,k');

    const yara = compileYaraGhostInTheRingRules();
    expect(yara).toContain('rule Linux_eBPF_Rootkit_TripleCross_Boopkit');
    expect(yara).toContain('rule Linux_IoUring_Implant_Curing_RingReaper');

    const bundle = compileHostDefenseBundle(state);
    expect(Object.keys(bundle.files)).toContain('/etc/sysctl.d/99-axonwall-ghost-in-the-ring.conf');
    expect(Object.keys(bundle.files)).toContain('/usr/local/bin/audit_hidden_bpf_prog_idr.py');
    expect(Object.keys(bundle.files)).toContain('/usr/local/bin/axonwall-hunt-rootkits');
  });

  it('detects io_uring IORING_SETUP_SQPOLL and IOSQE_FIXED_FILE implants from /proc/[pid]/fdinfo', () => {
    const fdInfo = [
      'pos:\t0',
      'flags:\t02000002',
      'SqMask:\t0x3f',
      'SqHead:\t1204',
      'SqTail:\t1204',
      'CqHead:\t1204',
      'CqTail:\t1204',
      'SqThread:\t4193',
      'SqThreadCpu:\t2',
      'UserFiles:\t4',
    ].join('\n');

    const report = parseIoUringFdInfo(4192, 'kworker_u16', 5, fdInfo);
    expect(report.sqPollActive).toBe(true);
    expect(report.fixedFilesActive).toBe(true);
    expect(report.sqThread).toBe(4193);
    expect(report.userFiles).toBe(4);
    expect(report.severity).toBe('CRITICAL');
    expect(report.reasons[0]).toContain('IORING_SETUP_SQPOLL');
  });

  it('detects self-hiding eBPF rootkits by diffing /proc/kcore prog_idr against sys_bpf()', () => {
    const kcore = [
      { id: 12, type: 'BPF_PROG_TYPE_CGROUP_SKB', name: 'sd_devices' },
      { id: 84, type: 'BPF_PROG_TYPE_XDP', name: 'kworker_net' },
      { id: 85, type: 'BPF_PROG_TYPE_TRACING', name: 'hide_getdents' },
    ];
    const userspace = [12];

    const diff = diffKcoreProgIdrAgainstSysBpf(kcore, userspace);
    expect(diff.compromised).toBe(true);
    expect(diff.severity).toBe('CRITICAL');
    expect(diff.hiddenIds).toEqual([84, 85]);
    expect(diff.summary).toContain('84, 85');
  });

  it('detects offensive BPF helpers (#36 / #58) and Silicon PMU LBR trampoline jumps', () => {
    const findings = analyzeBpfHelperAndTrampolineUsage(
      '85: (85) call bpf_probe_write_user#36\n89: (85) call bpf_override_return#58',
      '__x64_sys_getdents64 (1) R I ->tramp: 0xffffffffc02a1000 (bpf_trampoline_6442450944_0+0x0/0x1000)'
    );
    expect(findings.length).toBe(3);
    expect(findings.some((f) => f.helperOrHook.includes('Helper #36'))).toBe(true);
    expect(findings.some((f) => f.helperOrHook.includes('Helper #58'))).toBe(true);

    const pmuHits = analyzePmuLbrBranchStack(
      'ps 5012 __x64_sys_getdents64+0x5/bpf_trampoline_6442450944_0+0x0 bpf_trampoline_6442450944_0+0x42/bpf_prog_a8f91c2b3d4e5f60_hide_getdents+0x0'
    );
    expect(pmuHits.length).toBe(2);
    expect(pmuHits[0].severity).toBe('CRITICAL');
    expect(pmuHits[0].toSymbol).toContain('bpf_trampoline');
  });

  it('round-trips hostDefense in security.yaml', () => {
    const state = DesiredStateSchema.parse({
      hostDefense: {
        enabled: true,
        rkhunterEnabled: true,
        chkrootkitEnabled: true,
        ioUringDisabledMode: '2',
        kernelLockdownMode: 'confidentiality',
      },
    });
    const files = serializeDesiredStateToYamlFiles(state);
    expect(files['security.yaml']).toContain('hostDefense:');
    expect(files['security.yaml']).toContain('ioUringDisabledMode: "2"');

    const validated = validateYamlConfigFiles(files);
    expect(validated.valid).toBe(true);
    expect(validated.state?.hostDefense?.ioUringDisabledMode).toBe('2');
  });
});
