import React from 'react';
import { Box, Text } from 'ink';

export type TabId = 'topology' | 'geo' | 'diff' | 'hosts' | 'stats' | 'live';

export interface TabBarProps {
  activeTab: TabId;
}

const TABS: Array<{ id: TabId; keyNum: string; label: string }> = [
  { id: 'topology', keyNum: '1', label: 'Topology Tree' },
  { id: 'geo', keyNum: '2', label: 'World Geo Map' },
  { id: 'diff', keyNum: '3', label: 'Scan Diff' },
  { id: 'hosts', keyNum: '4', label: 'Host Directory' },
  { id: 'stats', keyNum: '5', label: 'Security Stats' },
  { id: 'live', keyNum: '6', label: 'Live Scanner' },
];

export function TabBar({ activeTab }: TabBarProps) {
  return (
    <Box gap={1} marginBottom={1} flexWrap="wrap">
      {TABS.map((tab) => {
        const isActive = activeTab === tab.id;
        return (
          <Box
            key={tab.id}
            borderStyle={isActive ? 'bold' : 'single'}
            borderColor={isActive ? 'cyan' : 'gray'}
            paddingX={1}
          >
            <Text color={isActive ? 'cyan' : 'white'} bold={isActive}>
              [{tab.keyNum}] {tab.label}
            </Text>
          </Box>
        );
      })}
      <Box borderStyle="single" borderColor="gray" paddingX={1}>
        <Text color="gray">[q] Quit</Text>
      </Box>
    </Box>
  );
}
