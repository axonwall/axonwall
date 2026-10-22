import React from 'react';
import { Box, Text } from 'ink';
import type { NmapRun } from 'nastymap';

export interface StatsViewProps {
  scan: NmapRun;
}

export function StatsView({ scan }: StatsViewProps) {
  const totalHosts = scan.hosts.length;
  const upHosts = scan.hosts.filter((h) => h.status.state === 'up').length;

  let openPortsCount = 0;
  let closedPortsCount = 0;
  let filteredPortsCount = 0;
  const serviceCounts = new Map<string, number>();
  const osCounts = new Map<string, number>();

  for (const host of scan.hosts) {
    const osFam = host.osFamily || 'Unknown';
    osCounts.set(osFam, (osCounts.get(osFam) || 0) + 1);

    for (const p of host.ports) {
      if (p.state === 'open') {
        openPortsCount++;
        const sName = p.service?.name || `Port ${p.portid}`;
        serviceCounts.set(sName, (serviceCounts.get(sName) || 0) + 1);
      } else if (p.state === 'closed') {
        closedPortsCount++;
      } else if (p.state === 'filtered') {
        filteredPortsCount++;
      }
    }
  }

  const topServices = Array.from(serviceCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const topOs = Array.from(osCounts.entries()).sort((a, b) => b[1] - a[1]);

  return (
    <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1}>
      <Box justifyContent="space-between" marginBottom={1}>
        <Text bold color="cyan">
          📊 Security Analytics & Threat Distribution
        </Text>
      </Box>

      {/* Summary Row */}
      <Box gap={2} marginBottom={1}>
        <Box borderStyle="round" borderColor="cyan" paddingX={1} flexDirection="column">
          <Text color="gray">Targets Scanned</Text>
          <Text bold color="white">{totalHosts} Hosts ({upHosts} Up)</Text>
        </Box>

        <Box borderStyle="round" borderColor="green" paddingX={1} flexDirection="column">
          <Text color="gray">Open Ports</Text>
          <Text bold color="green">{openPortsCount} Active Services</Text>
        </Box>

        <Box borderStyle="round" borderColor="yellow" paddingX={1} flexDirection="column">
          <Text color="gray">Filtered Ports</Text>
          <Text bold color="yellow">{filteredPortsCount}</Text>
        </Box>

        <Box borderStyle="round" borderColor="magenta" paddingX={1} flexDirection="column">
          <Text color="gray">Scan Duration</Text>
          <Text bold color="magenta">{scan.runstats?.finished.elapsed ? `${scan.runstats.finished.elapsed}s` : 'Completed'}</Text>
        </Box>
      </Box>

      {/* Operating Systems Breakdown */}
      <Box flexDirection="column" marginBottom={1}>
        <Text bold color="white" underline>
          Operating System Distribution:
        </Text>
        {topOs.map(([osName, count]) => {
          const barLength = Math.max(1, Math.round((count / totalHosts) * 20));
          const bar = '█'.repeat(barLength);
          return (
            <Box key={osName} paddingLeft={2} gap={1}>
              <Box width={18}>
                <Text color="yellow">{osName}</Text>
              </Box>
              <Text color="magenta">{bar}</Text>
              <Text color="white">({count})</Text>
            </Box>
          );
        })}
      </Box>

      {/* Top Discovered Services Breakdown */}
      <Box flexDirection="column">
        <Text bold color="white" underline>
          Top Identified Network Services:
        </Text>
        {topServices.map(([sName, count]) => {
          const barLength = Math.max(1, Math.round((count / (openPortsCount || 1)) * 20));
          const bar = '█'.repeat(barLength);
          return (
            <Box key={sName} paddingLeft={2} gap={1}>
              <Box width={18}>
                <Text color="cyan">{sName.toUpperCase()}</Text>
              </Box>
              <Text color="green">{bar}</Text>
              <Text color="white">({count})</Text>
            </Box>
          );
        })}
      </Box>
    </Box>
  );
}
