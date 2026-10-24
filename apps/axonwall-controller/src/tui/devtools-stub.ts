// No-op stub for ink's optional react-devtools-core import so esbuild can
// bundle axonwall-tui.js as a self-contained ESM bundle without emitting a
// top-level external import for 'react-devtools-core'.
export default {
  connectToDevTools() {},
  initialize() {},
};
