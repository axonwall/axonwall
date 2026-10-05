import type { NutUpsConfig } from '../../schemas/index.js';

export interface NutUpsCompilationOutput {
  upsConf: string;
  nutConf: string;
}

/**
 * Compiles Network UPS Tools (NUT) configuration files (/etc/nut/ups.conf and /etc/nut/nut.conf).
 */
export function compileNutUps(config: NutUpsConfig): NutUpsCompilationOutput {
  const upsLines: string[] = [];
  upsLines.push('# /etc/nut/ups.conf - Managed by Axonwall UPS');
  upsLines.push('maxretry = 3');
  upsLines.push('');
  upsLines.push(`[${config.name}]`);
  upsLines.push(`    driver = ${config.driver}`);
  upsLines.push(`    port = ${config.port}`);
  upsLines.push(`    desc = "Axonwall Protected Battery Backup"`);
  upsLines.push(`    override.battery.charge.low = ${config.shutdownBatteryPct}`);
  upsLines.push(`    override.battery.runtime.low = ${config.lowBatteryRuntimeSec}`);
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
