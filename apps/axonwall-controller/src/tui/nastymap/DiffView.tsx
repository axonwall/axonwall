import React from 'react';
import { Box, Text } from 'ink';
import type { NmapRun, NmapScanDiff } from 'nastymap';
import { compareNmapScans, parseNmapXml, SAMPLE_SCANS } from 'nastymap';

export interface DiffViewProps {
  scanA?: NmapRun;
  scanB?: NmapRun;
}

export function DiffView({ scanA: propScanA, scanB: propScanB }: DiffViewProps) {
  const scanA = React.useMemo(() => {
    return propScanA || parseNmapXml(SAMPLE_SCANS.breachDiff.xmlA);
  }, [propScanA]);

  const scanB = React.useMemo(() => {
    return propScanB || parseNmapXml(SAMPLE_SCANS.breachDiff.xmlB);
  }, [propScanB]);

  const diffResult: NmapScanDiff = React.useMemo(() => {
    return compareNmapScans(scanA, scanB);
  }, [scanA, scanB]);

  const { summary, addedHosts, removedHosts, modifiedHosts } = diffResult;

  return (
    <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1}>
      <Box justifyContent="space-between" marginBottom={1}>
        <Text bold color="cyan">
          ⚖ Security Incident Scan Diff & Changelog
        </Text>
        <Text color="gray" dimColor>
          Comparing Baseline Scan vs Post-Incident Scan
        </Text>
      </Box>

      {/* Summary Badges */}
      <Box gap={2} marginBottom={1}>
        <Box borderStyle="single" borderColor="green" paddingX={1}>
          <Text color="green" bold>
            +{summary.hostsAdded} Hosts Added
          </Text>
        </Box>
        <Box borderStyle="single" borderColor="red" paddingX={1}>
          <Text color="red" bold>
            -{summary.hostsRemoved} Hosts Removed
          </Text>
        </Box>
        <Box borderStyle="single" borderColor="yellow" paddingX={1}>
          <Text color="yellow" bold>
            ~{summary.hostsModified} Hosts Modified
          </Text>
        </Box>
        <Box borderStyle="single" borderColor="cyan" paddingX={1}>
          <Text color="cyan" bold>
            +{summary.portsAdded} / -{summary.portsRemoved} Ports
          </Text>
        </Box>
      </Box>

      {/* Added Hosts */}
      {addedHosts.length > 0 && (
        <Box flexDirection="column" marginBottom={1}>
          <Text color="green" bold>
            ▶ NEW HOSTS DISCOVERED:
          </Text>
          {addedHosts.map((h) => (
            <Box key={h.ip} paddingLeft={2} gap={1}>
              <Text color="green" bold>
                + {h.ip}
              </Text>
              {h.hostname && <Text color="white">({h.hostname})</Text>}
              {h.newOs && <Text color="gray">[{h.newOs}]</Text>}
              {h.portDiffs.length > 0 && (
                <Text color="yellow">
                  Ports: {h.portDiffs.map((p) => `+${p.portid}/${p.protocol}`).join(', ')}
                </Text>
              )}
            </Box>
          ))}
        </Box>
      )}

      {/* Removed Hosts */}
      {removedHosts.length > 0 && (
        <Box flexDirection="column" marginBottom={1}>
          <Text color="red" bold>
            ▶ UNRESPONSIVE / REMOVED HOSTS:
          </Text>
          {removedHosts.map((h) => (
            <Box key={h.ip} paddingLeft={2} gap={1}>
              <Text color="red" bold>
                - {h.ip}
              </Text>
              {h.hostname && <Text color="white">({h.hostname})</Text>}
              <Text color="gray">[Missing in current scan]</Text>
            </Box>
          ))}
        </Box>
      )}

      {/* Modified Hosts */}
      {modifiedHosts.length > 0 && (
        <Box flexDirection="column" marginBottom={1}>
          <Text color="yellow" bold>
            ▶ MODIFIED TARGETS & BACKDOORS:
          </Text>
          {modifiedHosts.map((h) => (
            <Box key={h.ip} flexDirection="column" paddingLeft={2} marginBottom={1}>
              <Box gap={1}>
                <Text color="yellow" bold>
                  ~ {h.ip}
                </Text>
                {h.hostname && <Text color="white">({h.hostname})</Text>}
              </Box>
              {h.portDiffs
                .filter((p) => p.changeType !== 'unchanged')
                .map((p) => (
                  <Box key={p.portid} paddingLeft={4} gap={1}>
                    <Text color={p.changeType === 'added' ? 'green' : p.changeType === 'removed' ? 'red' : 'yellow'}>
                      {p.changeType === 'added' ? '● [NEW PORT]' : p.changeType === 'removed' ? '● [CLOSED PORT]' : '● [MODIFIED PORT]'}
                    </Text>
                    <Text bold color="white">
                      {p.portid}/{p.protocol}
                    </Text>
                    <Text color="cyan">
                      {p.newPort?.service?.name || p.oldPort?.service?.name}
                    </Text>
                    {(p.newPort?.service?.extrainfo || p.oldPort?.service?.extrainfo) && (
                      <Text color="red" bold>
                        ALERT: {p.newPort?.service?.extrainfo || p.oldPort?.service?.extrainfo}
                      </Text>
                    )}
                  </Box>
                ))}
            </Box>
          ))}
        </Box>
      )}
    </Box>
  );
}
