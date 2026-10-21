import React from 'react';
import { Box, Text } from 'ink';
import type { NmapRun } from 'nastymap';

export interface HeaderProps {
  scan: NmapRun;
  activeScanLabel: string;
}

export function Header({ scan, activeScanLabel }: HeaderProps) {
  const upHosts = scan.hosts.filter((h) => h.status.state === 'up').length;
  const totalOpenPorts = scan.hosts.reduce(
    (acc, h) => acc + h.ports.filter((p) => p.state === 'open').length,
    0
  );

  return (
    <Box flexDirection="column" borderStyle="round" borderColor="cyan" paddingX={1} marginBottom={1}>
      <Box justifyContent="space-between">
        <Box gap={1}>
          <Text bold color="cyan">
            NASTYMAP CLI
          </Text>
          <Text color="gray">|</Text>
          <Text color="white" bold>
            {activeScanLabel}
          </Text>
        </Box>
        <Box gap={1}>
          <Text color="green" bold>
            ● {upHosts}/{scan.hosts.length} Hosts Online
          </Text>
          <Text color="gray">|</Text>
          <Text color="yellow" bold>
            {totalOpenPorts} Ports
          </Text>
          <Text color="gray">|</Text>
          <Text color="gray">Nmap v{scan.version}</Text>
        </Box>
      </Box>
      <Box marginTop={0}>
        <Text color="gray" dimColor>
          Command: {scan.args} ({scan.startstr})
        </Text>
      </Box>
    </Box>
  );
}
