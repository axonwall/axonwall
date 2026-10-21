import { useState, useCallback, useMemo } from 'react';
import type { NmapHost, NmapRun, TopologyGraph, TopologyLayoutType } from '../types/nmap';
import { parseNmapXml } from '../parser/nmap-xml-parser';
import { SAMPLE_SCANS } from '../data/sample-scans';
import { generateTopology } from '../topology/topology-engine';
import {
  updateHostInScan,
  mergeScanResults,
  addHostToScan,
  removeHostFromScan,
} from '../mutation/scan-mutator';

export interface UseNmapScanOptions {
  initialXml?: string;
  initialSample?: keyof typeof SAMPLE_SCANS;
  layout?: TopologyLayoutType;
}

export function useNmapScan(options: UseNmapScanOptions = {}) {
  const [scan, setScan] = useState<NmapRun>(() => {
    if (options.initialXml) {
      return parseNmapXml(options.initialXml);
    }
    const sample = options.initialSample ? SAMPLE_SCANS[options.initialSample] : SAMPLE_SCANS.enterprise;
    return parseNmapXml(sample.xml || SAMPLE_SCANS.enterprise.xml);
  });

  const [error, setError] = useState<string | null>(null);
  const [selectedHostId, setSelectedHostId] = useState<string | null>(null);

  const loadXml = useCallback((xmlString: string) => {
    try {
      setError(null);
      const parsed = parseNmapXml(xmlString);
      setScan(parsed);
      setSelectedHostId(null);
      return parsed;
    } catch (err: any) {
      setError(err.message);
      throw err;
    }
  }, []);

  const loadSample = useCallback((sampleKey: keyof typeof SAMPLE_SCANS) => {
    const s = SAMPLE_SCANS[sampleKey];
    if (s && s.xml) {
      return loadXml(s.xml);
    }
  }, [loadXml]);

  const updateHost = useCallback(
    (hostIdOrIp: string, updater: (prev: NmapHost) => NmapHost | Partial<NmapHost>) => {
      setScan((prevScan) => updateHostInScan(prevScan, hostIdOrIp, updater));
    },
    []
  );

  const mergeScan = useCallback((newScanOrXml: NmapRun | string) => {
    const newScan = typeof newScanOrXml === 'string' ? parseNmapXml(newScanOrXml) : newScanOrXml;
    setScan((prevScan) => mergeScanResults(prevScan, newScan));
  }, []);

  const addHost = useCallback((host: NmapHost) => {
    setScan((prevScan) => addHostToScan(prevScan, host));
  }, []);

  const removeHost = useCallback((hostIdOrIp: string) => {
    setScan((prevScan) => removeHostFromScan(prevScan, hostIdOrIp));
  }, []);

  const selectedHost: NmapHost | undefined = useMemo(() => {
    if (!selectedHostId) return undefined;
    return scan.hosts.find((h) => (h.ipv4 || h.ipv6 || h.id) === selectedHostId);
  }, [scan.hosts, selectedHostId]);

  const graph: TopologyGraph = useMemo(() => {
    return generateTopology(scan, { layout: options.layout || 'force' });
  }, [scan, options.layout]);

  return {
    scan,
    setScan,
    graph,
    error,
    selectedHostId,
    selectedHost,
    setSelectedHostId,
    loadXml,
    loadSample,
    updateHost,
    mergeScan,
    addHost,
    removeHost,
  };
}
