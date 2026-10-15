import React from 'react';
import Link from 'next/link';
import {
  Palette,
  Sparkles,
  Upload,
  Globe,
  Download,
  FolderGit2,
  CheckCircle2,
  Layers,
  Code2,
  Sliders,
  ExternalLink,
} from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Theme Customization & Repositories | Axonwall Documentation',
  description:
    'Comprehensive guide for authoring custom themes, hosting multi-theme Git repositories, and importing color palettes in Axonwall and Winnegans.',
};

export default function ThemesDocumentationPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Theming & Ecosystem
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Theme Customization & Repository Ecosystem
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Axonwall features an extensible, token-driven theming architecture supporting over 20 curated palettes—including canonical Solarized, Gruvbox, Catppuccin, and pure OLED black. Learn how to create custom palettes, publish multi-theme Git repositories, and import community themes with 1-click.
        </p>
      </div>

      {/* Architecture & Engine */}
      <section id="architecture" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Palette className="w-6 h-6 text-emerald-400" /> Token-Based Theme Engine
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          The Axonwall theme engine dynamically computes and injects standard CSS custom properties into <code className="text-slate-200 font-mono">document.documentElement</code> and the body element. This allows instantaneous theme switching with zero page reload and zero layout shift.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-emerald-400">Zero-Flash Hydration</span>
            <p className="text-slate-400">An early inline hydration script reads the user&apos;s stored preference from <code className="text-slate-300">localStorage</code> before paint, eliminating white-flash transients.</p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-sky-400">Winnegans Cross-Compatibility</span>
            <p className="text-slate-400">Dual-emits both Axonwall tokens (<code className="text-slate-300">--theme-*</code>) and Winnegans reading tokens (<code className="text-slate-300">--wf-*</code>) for interoperability across web apps.</p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-purple-400">Dynamic Live Tuner</span>
            <p className="text-slate-400">Users can tweak hex values in real time through the in-app Theme Switcher and save them as persistent custom palettes.</p>
          </div>
        </div>

        {/* Tokens Reference Table */}
        <div className="pt-2">
          <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider mb-3">Core Theme Color Tokens</h3>
          <div className="overflow-x-auto rounded-xl border border-slate-800">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-4">Token Name</th>
                  <th className="py-2.5 px-4">CSS Custom Property</th>
                  <th className="py-2.5 px-4">UI Role & Usage</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                <tr>
                  <td className="py-2.5 px-4 text-emerald-400">colors.bg</td>
                  <td className="py-2.5 px-4 text-slate-400">--theme-bg, --wf-bg</td>
                  <td className="py-2.5 px-4 font-sans text-slate-400">Primary page viewport background</td>
                </tr>
                <tr>
                  <td className="py-2.5 px-4 text-emerald-400">colors.cardBg</td>
                  <td className="py-2.5 px-4 text-slate-400">--theme-card, --wf-card-bg</td>
                  <td className="py-2.5 px-4 font-sans text-slate-400">Surface layer, card container, sidebar, and modals</td>
                </tr>
                <tr>
                  <td className="py-2.5 px-4 text-emerald-400">colors.border</td>
                  <td className="py-2.5 px-4 text-slate-400">--theme-border, --wf-border</td>
                  <td className="py-2.5 px-4 font-sans text-slate-400">Dividers, card outlines, table borders, and inputs</td>
                </tr>
                <tr>
                  <td className="py-2.5 px-4 text-emerald-400">colors.text</td>
                  <td className="py-2.5 px-4 text-slate-400">--theme-text, --wf-text</td>
                  <td className="py-2.5 px-4 font-sans text-slate-400">Primary headline and body typography</td>
                </tr>
                <tr>
                  <td className="py-2.5 px-4 text-emerald-400">colors.textMuted</td>
                  <td className="py-2.5 px-4 text-slate-400">--theme-text-muted</td>
                  <td className="py-2.5 px-4 font-sans text-slate-400">Secondary labels, metadata, and timestamps</td>
                </tr>
                <tr>
                  <td className="py-2.5 px-4 text-emerald-400">colors.accent</td>
                  <td className="py-2.5 px-4 text-slate-400">--theme-accent, --wf-accent</td>
                  <td className="py-2.5 px-4 font-sans text-slate-400">Action buttons, primary links, active badges, and highlights</td>
                </tr>
                <tr>
                  <td className="py-2.5 px-4 text-emerald-400">colors.ring</td>
                  <td className="py-2.5 px-4 text-slate-400">--theme-ring, --wf-ring</td>
                  <td className="py-2.5 px-4 font-sans text-slate-400">Focus indicators and neon ambient glow effects</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Creating Custom Themes */}
      <section id="creating-themes" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Code2 className="w-6 h-6 text-emerald-400" /> Authoring a Custom Theme
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          A custom theme is a standalone JSON file adhering to the <code className="text-slate-200 font-mono">AxonwallTheme</code> specification. You can create a file from scratch, modify an existing preset, or export directly from the in-app Theme Switcher.
        </p>

        <div className="space-y-2">
          <span className="text-xs font-mono text-slate-400 uppercase">Example: tactical-nord.json</span>
          <CodeBlock
            code={`{
  "$schema": "https://axonwall.com/schemas/theme.json",
  "id": "tactical-nord",
  "name": "Tactical Nord",
  "description": "Arctic polar night palette with aurora teal and frost blue accents",
  "category": "dark-ambient",
  "isDark": true,
  "author": "Axonwall Community",
  "version": "1.0.0",
  "colors": {
    "bg": "#2e3440",
    "text": "#eceff4",
    "textMuted": "#d8dee9",
    "cardBg": "#3b4252",
    "border": "#4c566a",
    "accent": "#88c0d0",
    "accentHover": "#81a1c1",
    "ring": "#88c0d0",
    "readerBg": "#2e3440",
    "readerText": "#eceff4",
    "readerCoord": "#81a1c1",
    "selectionBg": "#434c5e",
    "selectionText": "#eceff4"
  }
}`}
            language="json"
          />
        </div>

        <Callout type="tip" title="Testing Your Theme Locally">
          Open the in-app <strong>Theme Switcher</strong> in the top navigation bar, navigate to the <strong>Import Repo / File</strong> tab, and click <strong>Select .json Theme File</strong>. Your theme will be validated, applied instantly, and stored in your browser&apos;s local storage.
        </Callout>
      </section>

      {/* Building a Theme Repository */}
      <section id="theme-repositories" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <FolderGit2 className="w-6 h-6 text-emerald-400" /> Building a Multi-Theme Repository
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          You can publish a collection of themes in a standard Git repository (such as GitHub, GitLab, or any public Git host). When users paste your repository URL into the Theme Switcher, Axonwall fetches your catalog index and imports all themes in one click.
        </p>

        <div className="space-y-2">
          <span className="text-xs font-mono text-slate-400 uppercase">Recommended Repository Structure</span>
          <CodeBlock
            code={`my-theme-pack/
├── themes.json             # Root catalog manifest (Required for 1-click import)
├── README.md               # Theme descriptions, screenshots, and instructions
├── previews/               # Optional PNG/SVG palette swatch previews
│   ├── tactical-nord.png
│   └── tokyo-night.png
└── themes/                 # Optional individual theme files
    ├── tactical-nord.json
    └── tokyo-night.json`}
            language="bash"
          />
        </div>

        <div className="space-y-2">
          <span className="text-xs font-mono text-slate-400 uppercase">Catalog Manifest Specification (themes.json)</span>
          <CodeBlock
            code={`{
  "$schema": "https://axonwall.com/schemas/theme-manifest.json",
  "name": "Nordic Security Themes",
  "version": "1.0.0",
  "description": "High-visibility Arctic and nocturnal security themes for Axonwall",
  "homepage": "https://github.com/my-org/my-theme-pack",
  "author": "Security Ops Team",
  "themes": [
    {
      "id": "tactical-nord",
      "name": "Tactical Nord",
      "description": "Arctic polar night palette with frost teal accents",
      "category": "dark-ambient",
      "isDark": true,
      "colors": {
        "bg": "#2e3440",
        "text": "#eceff4",
        "textMuted": "#d8dee9",
        "cardBg": "#3b4252",
        "border": "#4c566a",
        "accent": "#88c0d0",
        "accentHover": "#81a1c1",
        "ring": "#88c0d0",
        "selectionBg": "#434c5e",
        "selectionText": "#eceff4"
      }
    },
    {
      "id": "aurora-green",
      "name": "Aurora Borealis",
      "description": "Deep spruce black with radiant polar aurora emerald",
      "category": "cyber",
      "isDark": true,
      "colors": {
        "bg": "#0a1410",
        "text": "#e6fffa",
        "textMuted": "#68d391",
        "cardBg": "#122820",
        "border": "#1c3d31",
        "accent": "#38a169",
        "accentHover": "#48bb78",
        "ring": "#38a169",
        "selectionBg": "#1c4532",
        "selectionText": "#f0fff4"
      }
    }
  ]
}`}
            language="json"
          />
        </div>

        <Callout type="info" title="Automatic GitHub Resolution">
          When a user pastes a GitHub repository URL (such as <code className="text-slate-200">https://github.com/my-org/my-theme-pack</code>), Axonwall automatically resolves the URL to raw GitHub content at <code className="text-slate-200">main/themes.json</code> (falling back to <code className="text-slate-200">main/theme.json</code> if a single theme is hosted).
        </Callout>
      </section>

      {/* Importing Themes */}
      <section id="importing" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Download className="w-6 h-6 text-emerald-400" /> Importing & Managing Themes
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Both the Axonwall documentation website and the Web Console application embed the identical Theme Switcher. Users have three seamless ways to manage their palettes:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-xs text-slate-300">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="flex items-center gap-2 text-white font-bold text-sm">
              <Upload className="w-4 h-4 text-emerald-400" />
              1. Local JSON Upload
            </div>
            <p className="text-slate-400 leading-relaxed">
              Click <strong>Select .json Theme File</strong> in the Theme Switcher. Drop any theme or manifest file to import instantly into browser memory.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="flex items-center gap-2 text-white font-bold text-sm">
              <Globe className="w-4 h-4 text-sky-400" />
              2. Remote Repo URL
            </div>
            <p className="text-slate-400 leading-relaxed">
              Paste any GitHub repository or raw CDN URL into the remote field. The client validates the schema and loads the entire palette collection.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="flex items-center gap-2 text-white font-bold text-sm">
              <Sliders className="w-4 h-4 text-purple-400" />
              3. In-App Color Tuner
            </div>
            <p className="text-slate-400 leading-relaxed">
              Adjust background, card, border, text, and accent colors in the <strong>Color Tuner</strong> tab, give your new palette a name, and save it as a custom theme.
            </p>
          </div>
        </div>
      </section>

      {/* WinnegansFake Compatibility */}
      <section id="winnegans-compatibility" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Sparkles className="w-6 h-6 text-emerald-400" /> WinnegansFake Cross-Ecosystem Compatibility
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall shares its underlying theme specification with the <a href="https://github.com/winnegansFake/winnegansFake" target="_blank" rel="noopener noreferrer" className="text-emerald-400 hover:underline inline-flex items-center gap-1 font-semibold">Winnegans Research Project <ExternalLink className="w-3 h-3" /></a>. Themes authored for Winnegans automatically work in Axonwall, and vice versa.
        </p>

        <Callout type="tip" title="Access All 19 Winnegans Palettes">
          All 19 official Winnegans themes—including <strong>Ethan Schoonover&apos;s Solarized Dark and Light</strong>, <strong>Pavel Pertsev&apos;s Gruvbox</strong>, <strong>Catppuccin (Mocha, Macchiato, Frappé, Latte)</strong>, <strong>Obsidian OLED</strong>, and <strong>Crimson Midnight</strong>—are built directly into Axonwall out-of-the-box.
        </Callout>
      </section>
    </div>
  );
}
