import React, { useState } from 'react';
import { Box, Text, useInput } from 'ink';
import type { NmapHost, NmapRun, TopologyGraph, TopologyNode } from 'nastymap';
import { generateTopology } from 'nastymap';

export interface TopologyViewProps {
  scan: NmapRun;
  onSelectHost: (host: NmapHost) => void;
}

function getOsBadgeColor(osFamily: string): string {
  const fam = (osFamily || '').toLowerCase();
  if (fam.includes('linux') || fam.includes('ubuntu') || fam.includes('debian')) return 'green';
  if (fam.includes('windows') || fam.includes('microsoft')) return 'blue';
  if (fam.includes('cisco') || fam.includes('router') || fam.includes('switch')) return 'yellow';
  if (fam.includes('mac') || fam.includes('apple') || fam.includes('ios')) return 'magenta';
  if (fam.includes('bsd') || fam.includes('freebsd')) return 'red';
  return 'gray';
}

export function TopologyView({ scan, onSelectHost }: TopologyViewProps) {
  const graph: TopologyGraph = React.useMemo(() => {
    return generateTopology(scan, { layout: 'traceroute' });
  }, [scan]);

  const targetNodes = graph.nodes.filter((n) => n.nodeType !== 'scanner');
  const [selectedIndex, setSelectedIndex] = useState(0);

  useInput((input, key) => {
    if (key.downArrow) {
      setSelectedIndex((prev) => (prev + 1) % targetNodes.length);
    } else if (key.upArrow) {
      setSelectedIndex((prev) => (prev - 1 + targetNodes.length) % targetNodes.length);
    } else if (key.return) {
      const selected = targetNodes[selectedIndex];
      if (selected && selected.hostRef) {
        onSelectHost(selected.hostRef);
      }
    }
  });

  return (
    <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1}>
      <Box justifyContent="space-between" marginBottom={1}>
        <Text bold color="cyan">
          ◈ Network Topology & Traceroute Hierarchy Tree
        </Text>
        <Text color="gray" dimColor>
          Use ↑/↓ arrow keys to navigate · Press Enter to inspect host
        </Text>
      </Box>

      {/* Scanner Root Gateway */}
      <Box marginBottom={1}>
        <Text color="magenta" bold>
          [⬡ SCANNER ORIGIN]
        </Text>
        <Text color="gray"> 127.0.0.1 (Local Scanner Host)</Text>
      </Box>

      {/* Target Nodes Tree */}
      <Box flexDirection="column">
        {targetNodes.map((node, idx) => {
          const isSelected = selectedIndex === idx;
          const isLast = idx === targetNodes.length - 1;
          const prefix = isLast ? ' └─' : ' ├─';
          const osColor = getOsBadgeColor(node.osFamily);
          const openPortsStr =
            node.openPorts.length > 0
              ? `[Ports: ${node.openPorts.slice(0, 5).join(', ')}${node.openPorts.length > 5 ? '...' : ''}]`
              : '[No open ports]';

          const hopStr = node.hopsAway > 0 ? `──(${node.hopsAway} hop${node.hopsAway > 1 ? 's' : ''}${node.latencyMs ? ` ${node.latencyMs}ms` : ''})──>` : '──>';

          return (
            <Box key={node.id} gap={1}>
              <Text color="cyan">{prefix}</Text>
              <Text color="gray">{hopStr}</Text>

              <Text bold color={node.status === 'up' ? 'green' : 'red'} inverse={isSelected}>
                {isSelected ? '► ' : ''}{node.ip}
              </Text>

              {node.hostname && (
                <Text color="white">
                  ({node.hostname})
                </Text>
              )}

              <Text color={osColor as any}>
                [{node.osFamily}]
              </Text>

              <Text color="yellow" dimColor>
                {openPortsStr}
              </Text>

              <Text color="gray" dimColor>
                {node.deviceType}
              </Text>

              {isSelected && (
                <Text color="cyan" bold>
                  ◄ [ENTER TO INSPECT]
                </Text>
              )}
            </Box>
          );
        })}
      </Box>
    </Box>
  );
}
