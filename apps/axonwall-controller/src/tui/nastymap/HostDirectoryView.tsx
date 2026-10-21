import React, { useState } from 'react';
import { Box, Text, useInput } from 'ink';
import type { NmapHost, NmapRun } from 'nastymap';

export interface HostDirectoryViewProps {
  scan: NmapRun;
  onSelectHost: (host: NmapHost) => void;
}

export function HostDirectoryView({ scan, onSelectHost }: HostDirectoryViewProps) {
  const hosts = scan.hosts;
  const [selectedIndex, setSelectedIndex] = useState(0);

  useInput((input, key) => {
    if (key.downArrow) {
      setSelectedIndex((prev) => (prev + 1) % hosts.length);
    } else if (key.upArrow) {
      setSelectedIndex((prev) => (prev - 1 + hosts.length) % hosts.length);
    } else if (key.return) {
      const selected = hosts[selectedIndex];
      if (selected) {
        onSelectHost(selected);
      }
    }
  });

  return (
    <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1}>
      <Box justifyContent="space-between" marginBottom={1}>
        <Text bold color="cyan">
          📋 Discovered Host Directory & Service Catalog
        </Text>
        <Text color="gray" dimColor>
          Use ↑/↓ arrow keys · Press Enter to inspect
        </Text>
      </Box>

      {/* Table Header */}
      <Box borderBottom={true} borderColor="gray" paddingBottom={0} marginBottom={1}>
        <Box width={18}>
          <Text bold color="white">IP Address</Text>
        </Box>
        <Box width={12}>
          <Text bold color="white">Status</Text>
        </Box>
        <Box width={28}>
          <Text bold color="white">Hostname</Text>
        </Box>
        <Box width={26}>
          <Text bold color="white">Operating System</Text>
        </Box>
        <Box>
          <Text bold color="white">Open Ports</Text>
        </Box>
      </Box>

      {/* Table Rows */}
      {hosts.map((host: NmapHost, idx: number) => {
        const isSelected = selectedIndex === idx;
        const openPorts = host.ports.filter((p) => p.state === 'open');
        const openPortsStr =
          openPorts.length > 0
            ? openPorts.map((p) => `${p.portid}/${p.protocol}`).slice(0, 4).join(', ') + (openPorts.length > 4 ? ` +${openPorts.length - 4}` : '')
            : '-';

        return (
          <Box key={host.id}>
            <Box width={18}>
              <Text bold color={isSelected ? 'black' : 'white'} backgroundColor={isSelected ? 'cyan' : undefined}>
                {isSelected ? '► ' : '  '}{host.ipv4 || host.id}
              </Text>
            </Box>
            <Box width={12}>
              <Text color={host.status.state === 'up' ? 'green' : 'red'}>
                {host.status.state.toUpperCase()}
              </Text>
            </Box>
            <Box width={28}>
              <Text color="white">
                {host.primaryHostname || '-'}
              </Text>
            </Box>
            <Box width={26}>
              <Text color="yellow">
                {host.primaryOs || host.osFamily || 'Unknown'}
              </Text>
            </Box>
            <Box>
              <Text color="cyan">
                {openPortsStr}
              </Text>
            </Box>
          </Box>
        );
      })}
    </Box>
  );
}
