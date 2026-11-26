import type { Interface, TrafficShaperConfig, TrafficShaperInterface } from '../../schemas/index.js';

export interface CompiledTrafficShaper {
  commands: string[];
  shScript: string;
}

function crc16Hex(input: string): string {
  let crc = 0xffff;
  for (let i = 0; i < input.length; i++) {
    crc ^= input.charCodeAt(i);
    for (let j = 0; j < 8; j++) {
      crc = (crc & 1) !== 0 ? (crc >>> 1) ^ 0xa001 : crc >>> 1;
    }
  }
  return crc.toString(16).padStart(4, '0');
}

function buildIfbDeviceName(dev: string): string {
  const clean = dev.replace(/[^a-zA-Z0-9_-]/g, '');
  const candidate = `ifb-${clean}`;
  if (candidate.length <= 15) {
    return candidate;
  }
  // Fit strictly within Linux IFNAMSIZ (15 chars + NUL) while avoiding prefix collisions
  return `ifb-${clean.slice(0, 6)}-${crc16Hex(dev)}`;
}

/**
 * Compiles a TrafficShaperConfig into Linux tc (Traffic Control) commands.
 * Supports CAKE (with diffserv and ack-filter), FQ_CoDel, and HTB with sub-classes.
 * For ingress download shaping, automatically uses IFB (Intermediate Functional Block) redirection.
 */
export function compileTrafficShaper(
  config?: TrafficShaperConfig,
  interfaces: Interface[] = [],
): CompiledTrafficShaper {
  if (!config || !config.enabled || !config.interfaces || config.interfaces.length === 0) {
    return {
      commands: ['# Traffic shaper is disabled or has no interfaces configured'],
      shScript: '#!/bin/bash\n# Traffic shaper is disabled\nexit 0\n',
    };
  }

  const ifDeviceMap = new Map<string, string>();
  for (const iface of interfaces) {
    if (iface.name && iface.device) {
      ifDeviceMap.set(iface.name, iface.device);
    }
  }

  const commands: string[] = ['#!/bin/bash', 'set -e', ''];

  for (const iface of config.interfaces) {
    if (!iface.enabled) continue;
    compileInterfaceShaper(iface, commands, ifDeviceMap);
  }

  return {
    commands,
    shScript: commands.join('\n') + '\n',
  };
}

function compileInterfaceShaper(
  iface: TrafficShaperInterface,
  commands: string[],
  ifDeviceMap: Map<string, string>,
) {
  const resolved = ifDeviceMap.get(iface.interface) || iface.interface;
  const dev = resolved.replace(/[^a-zA-Z0-9_.:-]/g, '');
  if (!dev) return;
  const ifbDev = buildIfbDeviceName(dev);

  commands.push(`### Traffic Shaper for Interface: ${dev} ###`);

  // --- Egress (Upload) Shaping ---
  if (iface.uploadBandwidthMbps > 0) {
    commands.push(`# Egress (Upload) on ${dev} @ ${iface.uploadBandwidthMbps} Mbps`);
    commands.push(`tc qdisc del dev ${dev} root 2>/dev/null || true`);

    if (iface.scheduler === 'cake') {
      const allowedDiffserv = ['diffserv4', 'diffserv3', 'besteffort'];
      const diffserv = allowedDiffserv.includes(iface.cakeDiffserv || '') ? iface.cakeDiffserv : 'diffserv4';
      const ackFilter = iface.cakeAckFilter ? 'ack-filter' : '';
      commands.push(
        `tc qdisc add dev ${dev} root cake bandwidth ${iface.uploadBandwidthMbps}mbit ${diffserv} ${ackFilter}`.trim()
      );
    } else if (iface.scheduler === 'fq_codel') {
      // Simple TBF rate limiter parent with fq_codel leaf
      commands.push(
        `tc qdisc add dev ${dev} root handle 1: tbf rate ${iface.uploadBandwidthMbps}mbit burst 32k latency 50ms`
      );
      commands.push(`tc qdisc add dev ${dev} parent 1:1 handle 10: fq_codel`);
    } else if (iface.scheduler === 'htb') {
      commands.push(`tc qdisc add dev ${dev} root handle 1: htb default 99`);
      commands.push(
        `tc class add dev ${dev} parent 1: classid 1:1 htb rate ${iface.uploadBandwidthMbps}mbit ceil ${iface.uploadBandwidthMbps}mbit`
      );

      if (iface.queues && iface.queues.length > 0) {
        let classIndex = 10;
        const usedPct = iface.queues.reduce((sum, q) => sum + (Number(q.bandwidthPercent) || 0), 0);
        const defaultPct = Math.max(10, 100 - usedPct);
        const defaultRateMbps = Math.max(
          1,
          Math.min(iface.uploadBandwidthMbps, Math.round((iface.uploadBandwidthMbps * defaultPct) / 100)),
        );
        for (const q of iface.queues) {
          const rateMbps = Math.max(1, Math.round((iface.uploadBandwidthMbps * q.bandwidthPercent) / 100));
          const prio = Math.max(1, Math.min(7, Math.trunc(Number(q.priority) || 3)));
          commands.push(
            `tc class add dev ${dev} parent 1:1 classid 1:${classIndex} htb rate ${rateMbps}mbit ceil ${iface.uploadBandwidthMbps}mbit prio ${prio}`
          );
          if (q.codel) {
            commands.push(`tc qdisc add dev ${dev} parent 1:${classIndex} handle ${classIndex}0: fq_codel`);
          }
          commands.push(
            `tc filter add dev ${dev} parent 1: protocol all prio ${prio} handle ${classIndex} fw flowid 1:${classIndex}`
          );
          classIndex += 10;
        }
        // Always ensure default fallback class 1:99 exists when HTB qdisc uses `default 99`
        commands.push(
          `tc class add dev ${dev} parent 1:1 classid 1:99 htb rate ${defaultRateMbps}mbit ceil ${iface.uploadBandwidthMbps}mbit prio 5`
        );
        commands.push(`tc qdisc add dev ${dev} parent 1:99 handle 990: fq_codel`);
      } else {
        // Default catch-all class
        commands.push(
          `tc class add dev ${dev} parent 1:1 classid 1:99 htb rate ${iface.uploadBandwidthMbps}mbit ceil ${iface.uploadBandwidthMbps}mbit prio 5`
        );
        commands.push(`tc qdisc add dev ${dev} parent 1:99 handle 990: fq_codel`);
      }
    }
  }

  // --- Ingress (Download) Shaping via IFB device ---
  if (iface.downloadBandwidthMbps > 0) {
    commands.push('');
    commands.push(`# Ingress (Download) on ${dev} @ ${iface.downloadBandwidthMbps} Mbps via ${ifbDev}`);
    commands.push(`ip link add name ${ifbDev} type ifb 2>/dev/null || true`);
    commands.push(`ip link set dev ${ifbDev} up`);

    // Ingress qdisc on real dev redirects packets to IFB
    commands.push(`tc qdisc del dev ${dev} ingress 2>/dev/null || true`);
    commands.push(`tc qdisc add dev ${dev} handle ffff: ingress`);
    commands.push(
      `tc filter add dev ${dev} parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev ${ifbDev}`
    );

    // Shape on the IFB device
    commands.push(`tc qdisc del dev ${ifbDev} root 2>/dev/null || true`);
    if (iface.scheduler === 'cake') {
      const allowedDiffserv = ['diffserv4', 'diffserv3', 'besteffort'];
      const diffserv = allowedDiffserv.includes(iface.cakeDiffserv || '') ? iface.cakeDiffserv : 'diffserv4';
      commands.push(`tc qdisc add dev ${ifbDev} root cake bandwidth ${iface.downloadBandwidthMbps}mbit ${diffserv}`);
    } else {
      commands.push(
        `tc qdisc add dev ${ifbDev} root handle 1: tbf rate ${iface.downloadBandwidthMbps}mbit burst 32k latency 50ms`
      );
      commands.push(`tc qdisc add dev ${ifbDev} parent 1:1 handle 10: fq_codel`);
    }
  }

  commands.push('');
}
