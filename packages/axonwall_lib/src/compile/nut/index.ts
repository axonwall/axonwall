import type { NutUpsConfig } from '../../schemas/index.js';

export interface NutUpsCompilationOutput {
  upsConf: string;
  nutConf: string;
}

/**
 * Compiles Network UPS Tools (NUT) configuration files (/etc/nut/ups.conf and /etc/nut/nut.conf).
 */
export function compileNutUps(config: NutUpsConfig): NutUpsCompilationOutput {
  const safeName = config.name.split(/[\r\n\]]/)[0].trim().replace(/[^a-zA-Z0-9_-]/g, '') || 'ups';
  const safeDriver = config.driver.split(/[\r\n]/)[0].trim().replace(/[^a-zA-Z0-9_.-]/g, '') || 'usbhid-ups';
  const safePort = config.port.split(/[\r\n]/)[0].trim().replace(/[\r\n\s]+/g, '') || 'auto';
  const safeShutdownBatteryPct = Math.max(1, Math.min(100, Number(config.shutdownBatteryPct) || 20));
  const safeLowBatteryRuntimeSec = Math.max(0, Math.min(86400, Number(config.lowBatteryRuntimeSec) || 300));

  const upsLines: string[] = [];
  upsLines.push('# /etc/nut/ups.conf - Managed by Axonwall UPS');
  upsLines.push('maxretry = 3');
  upsLines.push('');
  upsLines.push(`[${safeName}]`);
  upsLines.push(`    driver = ${safeDriver}`);
  upsLines.push(`    port = ${safePort}`);
  upsLines.push('    desc = "Axonwall Protected Battery Backup"');
  upsLines.push(`    override.battery.charge.low = ${safeShutdownBatteryPct}`);
  upsLines.push(`    override.battery.runtime.low = ${safeLowBatteryRuntimeSec}`);
  upsLines.push('');

  const nutLines: string[] = [];
  nutLines.push('# /etc/nut/nut.conf - Managed by Axonwall UPS');
  nutLines.push('MODE=standalone');
  nutLines.push('');

  return {
    upsConf: upsLines.join('\n'),
    nutConf: nutLines.join('\n'),
  };
}
