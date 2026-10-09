import { describe, it, expect } from 'vitest';
import { compileSdwanConfig } from './index.js';
import type { DesiredState } from '../../schemas/index.js';

describe('SD-WAN Compiler', () => {
  it('should compile sdwan config to json', () => {
    const mockState = {
      gateways: [
        {
          id: 'gw-1',
          name: 'WAN1',
          interface: 'wan',
          gatewayIp: '192.168.1.1',
          monitorIp: '8.8.8.8',
          weight: 1,
          isDefault: true,
          enabled: true,
        },
        {
          id: 'gw-2',
          name: 'WAN2',
          interface: 'wan2',
          gatewayIp: '10.0.0.1',
          monitorIp: '1.1.1.1',
          weight: 2,
          isDefault: false,
          enabled: true,
        }
      ],
      gatewayGroups: [
        {
          id: 'group-1',
          name: 'Failover',
          trigger: 'down' as const,
          members: [
            { gatewayName: 'WAN1', tier: 1, weight: 1 },
            { gatewayName: 'WAN2', tier: 2, weight: 1 }
          ]
        }
      ]
    } as unknown as DesiredState;

    const result = compileSdwanConfig(mockState);
    const parsed = JSON.parse(result);

    expect(parsed.enabled).toBe(true);
    expect(parsed.gateways).toHaveLength(2);
    expect(parsed.gatewayGroups).toHaveLength(1);
    expect(parsed.gatewayGroups[0].members[0].gatewayName).toBe('WAN1');
  });

  it('should return disabled if no gateways exist', () => {
    const mockState = {
      gateways: [],
      gatewayGroups: []
    } as unknown as DesiredState;

    const result = compileSdwanConfig(mockState);
    const parsed = JSON.parse(result);

    expect(parsed.enabled).toBe(false);
    expect(parsed.gateways).toHaveLength(0);
  });
});
