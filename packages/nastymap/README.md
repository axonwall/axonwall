# nastymap

> High-performance interactive React visualization and parsing library for Nmap XML scan outputs, network topology graphs, GeoIP world mapping, and security scan diffing.

[![npm version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://npmjs.org/package/nastymap)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Robust Nmap XML Parser**: Full support for `<nmaprun>`, `<host>`, `<ports>`, `<os>`, `<distance>`, `<trace>`, `<uptime>`, `<times>`, `<hostscript>`, and `<runstats>`. Gracefully handles minimal host discovery scans (`-sn`) as well as deep vulnerability audits (`-A`).
- **Interactive Multi-Layout Topology**:
  - **Force-Directed (2D dynamic physics)**
  - **Traceroute Route Tree (Hop hierarchy)**
  - **Radial Concentric Rings (Gateway at center)**
  - **Subnet Grid (Grouped by CIDR /24)**
  - **Circular Layout**
- **Geographic IP World Map (`<NmapGeoMap />`)**: Geocodes public & intranet IP addresses onto a high-performance vector world map with curved traceroute flight arcs, animated packets, and city clustering.
- **Security Scan Diff (`<NmapDiffView />` & `compareNmapScans`)**: Detect newly discovered hosts (`+`), removed/unresponsive hosts (`-`), opened backdoors, modified services, and latency shifts between two scans.
- **Exporting & Reports**: Download vector SVG, high-resolution PNG, and self-contained standalone HTML vulnerability reports.
- **Live Search & Filtering**: Instant search by IP, hostname, OS family, open port number, service name, or latency threshold.
- **Host Inspector Drawer (`<HostDetailDrawer />`)**: Deep dive into open ports, CPEs, SSL certificates, Nmap NSE scripts, OS detection accuracy, traceroute hop timeline, and user comments/tags.

## Installation

```bash
npm install nastymap lucide-react
# or
pnpm add nastymap lucide-react
# or
yarn add nastymap lucide-react
```

## Quick Start

### 1. Interactive Network Topology

```tsx
import React from 'react';
import { NmapTopologyView, parseNmapXml } from 'nastymap';

export function NetworkDashboard({ xmlString }: { xmlString: string }) {
  const scan = parseNmapXml(xmlString);

  return (
    <div className="w-full h-[700px] bg-zinc-950">
      <NmapTopologyView
        scan={scan}
        initialLayout="force"
        onSelectHost={(host) => console.log('Selected Host:', host)}
      />
    </div>
  );
}
```

### 2. Geographic Threat Map

```tsx
import React from 'react';
import { NmapGeoMap, parseNmapXml } from 'nastymap';

export function GeoThreatMap({ xmlString }: { xmlString: string }) {
  const scan = parseNmapXml(xmlString);

  return (
    <NmapGeoMap
      scan={scan}
      onSelectHost={(host) => console.log('Inspecting Geo Host:', host.ipv4)}
    />
  );
}
```

### 3. Scan Comparison & Diff

```tsx
import React from 'react';
import { NmapDiffView, parseNmapXml } from 'nastymap';

export function IncidentDiff({ baselineXml, currentXml }) {
  const scanA = parseNmapXml(baselineXml);
  const scanB = parseNmapXml(currentXml);

  return <NmapDiffView scanA={scanA} scanB={scanB} />;
}
```

### 4. Custom React Hook

```tsx
import { useNmapScan } from 'nastymap';

export function CustomScanViewer() {
  const { scan, graph, loadXml, loadSample, selectedHost } = useNmapScan({
    initialSample: 'enterprise',
  });

  return (
    <div>
      <h2>{scan.args}</h2>
      <button onClick={() => loadSample('global')}>Load Global Scan</button>
    </div>
  );
}
```

## Exports

| Export | Type | Description |
|---|---|---|
| `parseNmapXml` | Function | Parses raw Nmap XML string into typed `NmapRun` |
| `compareNmapScans` | Function | Produces structured diff between two scans |
| `generateTopology` | Function | Builds node/edge graph from Nmap scan |
| `geocodeIp` | Function | Resolves IP to lat/lng, city, country, and ASN |
| `exportSvgElement` | Function | Downloads DOM SVG element as `.svg` file |
| `exportToPng` | Function | Rasterizes SVG/Canvas to high-res `.png` |
| `generateHtmlReport` | Function | Generates self-contained HTML report string |
| `<NmapTopologyView />` | Component | Interactive canvas/SVG network topology |
| `<NmapGeoMap />` | Component | Interactive vector GeoIP world map |
| `<NmapDiffView />` | Component | Visual before-and-after scan comparator |
| `<NmapStats />` | Component | Summary metrics and port/OS distribution |
| `<HostTable />` | Component | Searchable, sortable host directory table |
| `<HostDetailDrawer />` | Component | Slide-out host inspector |
| `<NmapCommandViewer />` | Component | Command-line viewer with flag explanations |
| `<ScanUploader />` | Component | Drag-and-drop file uploader & sample loader |

## License

MIT © NastyMap Team
