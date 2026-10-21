import React, { useState } from 'react';
import { Box, Text, useApp, useInput } from 'ink';
import type { NmapHost, NmapRun } from 'nastymap';
import { parseNmapXml, updateHostInScan, SAMPLE_SCANS } from 'nastymap';
import { Header } from './Header';
import { TabBar, TabId } from './TabBar';
import { TopologyView } from './TopologyView';
import { WorldMapView } from './WorldMapView';
import { DiffView } from './DiffView';
import { HostDirectoryView } from './HostDirectoryView';
import { StatsView } from './StatsView';
import { LiveSimulatorView } from './LiveSimulatorView';
import { HostInspector } from './HostInspector';

export interface AppProps {
  initialScan?: NmapRun;
  initialScanLabel?: string;
  initialTab?: TabId;
  diffScanA?: NmapRun;
  diffScanB?: NmapRun;
  embedded?: boolean;
  detectedSubnets?: Array<{ role: string; cidr: string; device: string }>;
}

const SUB_TABS: TabId[] = ['topology', 'geo', 'diff', 'hosts', 'stats', 'live'];

export function App({
  initialScan,
  initialScanLabel = 'Enterprise Multi-Subnet',
  initialTab = 'topology',
  diffScanA,
  diffScanB,
  embedded = false,
  detectedSubnets = [],
}: AppProps) {
  const { exit } = useApp();
  const [currentScan, setCurrentScan] = useState<NmapRun>(() => {
    return initialScan || parseNmapXml(SAMPLE_SCANS.enterprise.xml);
  });
  const [baselineScan, setBaselineScan] = useState<NmapRun>(() => {
    return diffScanA || parseNmapXml(SAMPLE_SCANS.enterprise.xml);
  });
  const [activeScanLabel, setActiveScanLabel] = useState<string>(initialScanLabel);
  const [activeTab, setActiveTab] = useState<TabId>(initialTab);
  const [selectedHost, setSelectedHost] = useState<NmapHost | null>(null);

  const handleUpdateHost = (hostId: string, updater: (prev: NmapHost) => NmapHost | Partial<NmapHost>) => {
    setCurrentScan((prev) => {
      const updated = updateHostInScan(prev, hostId, updater);
      setSelectedHost((curr) => {
        if (!curr) return null;
        const matching = updated.hosts.find((h) => h.id === curr.id || h.ipv4 === curr.ipv4);
        return matching || curr;
      });
      return updated;
    });
  };

  useInput((input, key) => {
    if (!embedded && input === 'q' && !selectedHost) {
      exit();
      return;
    }
    if (input === 'v' && !selectedHost) {
      const idx = SUB_TABS.indexOf(activeTab);
      setActiveTab(SUB_TABS[(idx + 1) % SUB_TABS.length]!);
      return;
    }
    if (!embedded) {
      if (input === '1') {
        setActiveTab('topology');
        setSelectedHost(null);
      } else if (input === '2') {
        setActiveTab('geo');
        setSelectedHost(null);
      } else if (input === '3') {
        setActiveTab('diff');
        setSelectedHost(null);
      } else if (input === '4') {
        setActiveTab('hosts');
        setSelectedHost(null);
      } else if (input === '5') {
        setActiveTab('stats');
        setSelectedHost(null);
      } else if (input === '6') {
        setActiveTab('live');
        setSelectedHost(null);
      }
    } else {
      // When embedded in Axonwall TUI, [!]-[^] or [v] switches NastyMap sub-tabs so [1]-[7] stay global
      if (input === '!') {
        setActiveTab('topology');
        setSelectedHost(null);
      } else if (input === '@') {
        setActiveTab('geo');
        setSelectedHost(null);
      } else if (input === '#') {
        setActiveTab('diff');
        setSelectedHost(null);
      } else if (input === '$') {
        setActiveTab('hosts');
        setSelectedHost(null);
      } else if (input === '%') {
        setActiveTab('stats');
        setSelectedHost(null);
      } else if (input === '^' || input === 'n') {
        setActiveTab('live');
        setSelectedHost(null);
      }
    }
    if (input === 's' && !selectedHost) {
      if (activeScanLabel.includes('Enterprise')) {
        setBaselineScan(currentScan);
        setCurrentScan(parseNmapXml(SAMPLE_SCANS.global.xml));
        setActiveScanLabel('Global Cloud Perimeter');
      } else {
        setBaselineScan(currentScan);
        setCurrentScan(parseNmapXml(SAMPLE_SCANS.enterprise.xml));
        setActiveScanLabel('Enterprise Multi-Subnet');
      }
    }
  });

  return (
    <Box flexDirection="column" padding={embedded ? 0 : 1}>
      {/* Header Banner */}
      <Header scan={currentScan} activeScanLabel={activeScanLabel} />

      {/* Tabs */}
      <TabBar activeTab={activeTab} />

      {/* View Content */}
      {selectedHost ? (
        <HostInspector
          host={selectedHost}
          onBack={() => setSelectedHost(null)}
          onUpdateHost={handleUpdateHost}
        />
      ) : (
        <>
          {activeTab === 'topology' && (
            <TopologyView scan={currentScan} onSelectHost={(host) => setSelectedHost(host)} />
          )}

          {activeTab === 'geo' && (
            <WorldMapView scan={currentScan} onSelectHost={(host) => setSelectedHost(host)} />
          )}

          {activeTab === 'diff' && <DiffView scanA={baselineScan} scanB={diffScanB || currentScan} />}

          {activeTab === 'hosts' && (
            <HostDirectoryView scan={currentScan} onSelectHost={(host) => setSelectedHost(host)} />
          )}

          {activeTab === 'stats' && <StatsView scan={currentScan} />}

          {activeTab === 'live' && (
            <LiveSimulatorView
              detectedSubnets={detectedSubnets}
              onScanCompleted={(newScan, label) => {
                setBaselineScan(currentScan);
                setCurrentScan(newScan);
                setActiveScanLabel(label || 'Live Discovered Scan');
                setActiveTab('topology');
              }}
            />
          )}
        </>
      )}

      {/* Bottom Footer Info */}
      <Box marginTop={1} justifyContent="space-between">
        <Text color="gray" dimColor>
          {embedded
            ? 'NastyMap Sub-views: [v] Cycle View · [n] Live Nmap Scanner · [s] Switch Sample · [Enter] Inspect Host'
            : 'Press [1-6] for tabs · [v] cycle view · [s] switch sample · [q] quit'}
        </Text>
        <Text color="cyan" dimColor>
          NastyMap Engine v1.0.2
        </Text>
      </Box>
    </Box>
  );
}
