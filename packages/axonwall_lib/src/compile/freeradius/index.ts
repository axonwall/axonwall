import type { FreeRadiusPluginConfig } from '../../schemas/index.js';

/**
 * Compiles FreeRADIUS clients configuration (/etc/freeradius/3.0/clients.conf).
 */
export function compileFreeRadiusClients(config: FreeRadiusPluginConfig): string {
  const lines: string[] = [];

  lines.push('# clients.conf - FreeRADIUS client configuration (Axonwall Managed)');
  lines.push('');

  // Default localhost client for internal testing / PAM
  lines.push('client localhost {');
  lines.push('    ipaddr = 127.0.0.1');
  lines.push('    proto = *');
  lines.push('    secret = testing123');
  lines.push('    require_message_authenticator = no');
  lines.push('    nas_type = other');
  lines.push('    limit {');
  lines.push('        max_connections = 16');
  lines.push('        lifetime = 0');
  lines.push('        idle_timeout = 30');
  lines.push('    }');
  lines.push('}');
  lines.push('');

  for (const client of config.clients) {
    lines.push(`client ${client.name} {`);
    lines.push(`    ipaddr = ${client.ipAddress}`);
    lines.push(`    secret = "${client.secret}"`);
    lines.push('    require_message_authenticator = auto');
    lines.push('    nas_type = other');
    lines.push('    limit {');
    lines.push('        max_connections = 64');
    lines.push('        lifetime = 3600');
    lines.push('        idle_timeout = 60');
    lines.push('    }');
    lines.push('}');
    lines.push('');
  }

  return lines.join('\n');
}
