import React from 'react';
import { Box, Text } from 'ink';

export type TabId = 'topology' | 'geo' | 'diff' | 'hosts' | 'stats' | 'live';

export interface TabBarProps {
  activeTab: TabId;
  embedded?: boolean;
}

const TABS: Array<{ id: TabId; keyNum: string; embeddedKey: string; label: string }> = [
  { id: 'topology', keyNum: '1', embeddedKey: '!', label: 'Topology Tree' },
  { id: 'geo', keyNum: '2', embeddedKey: '@', label: 'World Geo Map' },
  { id: 'diff', keyNum: '3', embeddedKey: '#', label: 'Scan Diff' },
  { id: 'hosts', keyNum: '4', embeddedKey: '$', label: 'Host Directory' },
  { id: 'stats', keyNum: '5', embeddedKey: '%', label: 'Security Stats' },
  { id: 'live', keyNum: '6', embeddedKey: 'n', label: 'Live Scanner' },
];

export function TabBar({ activeTab, embedded = false }: TabBarProps) {
  return (
    <Box gap={1} marginBottom={1} flexWrap="wrap">
      {TABS.map((tab) => {
        const isActive = activeTab === tab.id;
        const k = embedded ? tab.embeddedKey : tab.keyNum;
        return (
          <Text
            key={tab.id}
            color={isActive ? 'black' : 'white'}
            backgroundColor={isActive ? 'cyan' : undefined}
            bold={isActive}
          >
            {isActive ? ` ▸ [${k}] ${tab.label} ` : `[${k}] ${tab.label}`}
          </Text>
        );
      })}
      <Text color="gray">{embedded ? '[v] Cycle View' : '[q] Quit'}</Text>
    </Box>
  );
}
