import { useCallback, useRef, useState } from 'react';
import type { TopologyCableEdge, TopologyCanvasNode } from '@axonwall/lib/schemas';

export interface GraphSnapshot {
  nodes: TopologyCanvasNode[];
  cables: TopologyCableEdge[];
}

const MAX_HISTORY = 40;

/**
 * Undo/Redo snapshot history modeled on Eluvix's RoutingEditor `useGraphHistory`.
 */
export function useGraphHistory() {
  const pastRef = useRef<GraphSnapshot[]>([]);
  const futureRef = useRef<GraphSnapshot[]>([]);
  const [, setVersion] = useState(0);

  const pushSnapshot = useCallback((snap: GraphSnapshot) => {
    pastRef.current.push(structuredClone(snap));
    if (pastRef.current.length > MAX_HISTORY) {
      pastRef.current.shift();
    }
    futureRef.current = [];
    setVersion((v) => v + 1);
  }, []);

  const undo = useCallback((current: GraphSnapshot): GraphSnapshot | null => {
    const prev = pastRef.current.pop();
    if (!prev) return null;
    futureRef.current.push(structuredClone(current));
    setVersion((v) => v + 1);
    return prev;
  }, []);

  const redo = useCallback((current: GraphSnapshot): GraphSnapshot | null => {
    const next = futureRef.current.pop();
    if (!next) return null;
    pastRef.current.push(structuredClone(current));
    setVersion((v) => v + 1);
    return next;
  }, []);

  const clearHistory = useCallback(() => {
    pastRef.current = [];
    futureRef.current = [];
    setVersion((v) => v + 1);
  }, []);

  return {
    pushSnapshot,
    undo,
    redo,
    clearHistory,
    canUndo: pastRef.current.length > 0,
    canRedo: futureRef.current.length > 0,
  };
}
