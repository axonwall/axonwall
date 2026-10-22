import React, { useState } from 'react';
import { Box, Text, useInput } from 'ink';
import type { NmapHost, NmapRun } from 'nastymap';
import { geocodeIp } from 'nastymap';

export interface WorldMapViewProps {
  scan: NmapRun;
  onSelectHost: (host: NmapHost) => void;
}

// Compact ASCII World Map representation
const ASCII_WORLD_MAP = [
  '  . _..----.._    _             ______                   .-.            ',
  ' /"          "-./ "-.          /      "-.._    _.-.    _/ /             ',
  ':  NORTH         "-._)        :  EUROPE    "/\'    " -/  /   ASIA       ',
  '|  AMERICA           |         \\_           /       /  /                ',
  '|                    |           "-._    _.-"       |  |                ',
  ' \\                  /                / /            |  |                ',
  '  "-._            _."               / /   AFRICA    |  |                ',
  '      "-..____..-"                 / /              /  /                ',
  '           / /                    (_/              /  /   AUSTRALIA     ',
  '    SOUTH / /                                     (__/                  ',
  '   AMERICA_/                                                            ',
];

export function WorldMapView({ scan, onSelectHost }: WorldMapViewProps) {
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
          🌐 Global IP Geolocation & Threat Map
        </Text>
        <Text color="gray" dimColor>
          Use ↑/↓ arrow keys · Press Enter to inspect host
        </Text>
      </Box>

      {/* ASCII World Map Banner */}
      <Box flexDirection="column" marginBottom={1} paddingX={1} borderStyle="round" borderColor="blue">
        {ASCII_WORLD_MAP.map((line, idx) => (
          <Text key={idx} color="cyan" dimColor>
            {line}
          </Text>
        ))}
      </Box>

      {/* Geocoded Hosts Table */}
      <Box flexDirection="column">
        <Box borderBottom={true} borderColor="gray" paddingBottom={0} marginBottom={1}>
          <Box width={18}><Text bold color="white">IP Address</Text></Box>
          <Box width={16}><Text bold color="white">Country</Text></Box>
          <Box width={18}><Text bold color="white">City / Region</Text></Box>
          <Box width={26}><Text bold color="white">Organization / ASN</Text></Box>
          <Box><Text bold color="white">Latency</Text></Box>
        </Box>

        {hosts.map((host: NmapHost, idx: number) => {
          const isSelected = selectedIndex === idx;
          const geo = host.geolocation || geocodeIp(host.ipv4 || host.id);
          const ip = host.ipv4 || host.id;

          return (
            <Box key={host.id}>
              <Box width={18}>
                <Text bold color={isSelected ? 'black' : 'green'} backgroundColor={isSelected ? 'cyan' : undefined}>
                  {isSelected ? '► ' : '  '}{ip}
                </Text>
              </Box>
              <Box width={16}>
                <Text color="yellow">
                  {geo.country || 'Unknown'} [{geo.countryCode || 'UN'}]
                </Text>
              </Box>
              <Box width={18}>
                <Text color="white">
                  {geo.city || 'Internal Subnet'}
                </Text>
              </Box>
              <Box width={26}>
                <Text color="gray">
                  {geo.org || geo.isp || 'Enterprise LAN'}
                </Text>
              </Box>
              <Box>
                <Text color={host.latencyMs && host.latencyMs > 100 ? 'red' : 'green'}>
                  {host.latencyMs !== undefined ? `${host.latencyMs} ms` : '-'}
                </Text>
              </Box>
            </Box>
          );
        })}
      </Box>
    </Box>
  );
}
