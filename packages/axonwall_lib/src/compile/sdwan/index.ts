import type { DesiredState, Gateway, GatewayGroup } from '../../schemas/index.js';

export interface SdwanConfig {
  enabled: boolean;
  gateways: Gateway[];
  gatewayGroups: GatewayGroup[];
}

export function compileSdwanConfig(state: DesiredState): string {
  const activeGateways = state.gateways.filter((g) => g.enabled);
  if (activeGateways.length === 0) {
    return JSON.stringify({ enabled: false, gateways: [], gatewayGroups: [] }, null, 2);
  }

  const config: SdwanConfig = {
    enabled: true,
    gateways: activeGateways,
    gatewayGroups: state.gatewayGroups || [],
  };

  return JSON.stringify(config, null, 2);
}
