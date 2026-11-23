import { useCallback, useEffect, useRef, useState } from 'react';
import {
  getFabricTopologyAction,
  getLocalTopologyProbeAction,
  type TopologyFabricSnapshot,
} from '@/server/agent';

/**
 * Adaptive polling hook: fast local/K3s probe at `localIntervalSec` (default 5s)
 * and full multi-host + LibreNMS/NetBox fabric probe at `peerIntervalSec` (default 10s),
 * automatically pausing when the browser tab is hidden.
 */
export function useFabricTelemetry(options: {
  localIntervalSec?: number;
  peerIntervalSec?: number;
  pauseWhenHidden?: boolean;
}) {
  const localMs = Math.max(2000, (options.localIntervalSec ?? 5) * 1000);
  const peerMs = Math.max(5000, (options.peerIntervalSec ?? 10) * 1000);
  const pauseHidden = options.pauseWhenHidden !== false;

  const [fabric, setFabric] = useState<TopologyFabricSnapshot | null>(null);
  const [probing, setProbing] = useState(false);
  const [paused, setPaused] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string>('');
  const [probeError, setProbeError] = useState<string | null>(null);
  const inFlightRef = useRef(false);

  const probeFullFabric = useCallback(async () => {
    if (inFlightRef.current) return;
    inFlightRef.current = true;
    setProbing(true);
    try {
      const snap = await getFabricTopologyAction();
      setFabric(snap);
      setLastUpdated(snap.timestamp || new Date().toISOString());
      setProbeError(snap.daemonDown ? snap.error || 'Daemon unreachable' : null);
    } catch (err) {
      setProbeError(err instanceof Error ? err.message : 'Fabric probe failed');
    } finally {
      inFlightRef.current = false;
      setProbing(false);
    }
  }, []);

  const probeLocalFast = useCallback(async () => {
    if (inFlightRef.current) return;
    try {
      const localSnap = await getLocalTopologyProbeAction();
      setFabric((prev) =>
        prev
          ? { ...prev, timestamp: localSnap.timestamp, local: localSnap }
          : { timestamp: localSnap.timestamp, local: localSnap, peers: [] },
      );
      setLastUpdated(localSnap.timestamp || new Date().toISOString());
    } catch {}
  }, []);

  useEffect(() => {
    void probeFullFabric();
  }, [probeFullFabric]);

  useEffect(() => {
    if (paused) return;
    const checkHidden = () => pauseHidden && typeof document !== 'undefined' && document.visibilityState === 'hidden';

    const localTimer = setInterval(() => {
      if (!checkHidden()) void probeLocalFast();
    }, localMs);

    const peerTimer = setInterval(() => {
      if (!checkHidden()) void probeFullFabric();
    }, peerMs);

    const onVisChange = () => {
      if (!checkHidden()) {
        void probeFullFabric();
      }
    };
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', onVisChange);
    }
    return () => {
      clearInterval(localTimer);
      clearInterval(peerTimer);
      if (typeof document !== 'undefined') {
        document.removeEventListener('visibilitychange', onVisChange);
      }
    };
  }, [paused, pauseHidden, localMs, peerMs, probeLocalFast, probeFullFabric]);

  return {
    fabric,
    probing,
    paused,
    setPaused,
    lastUpdated,
    probeError,
    probeNow: probeFullFabric,
  };
}
