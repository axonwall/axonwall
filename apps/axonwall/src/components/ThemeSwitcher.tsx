'use client';

import React, { useState, useEffect, useRef } from 'react';
import {
  Palette,
  Check,
  Upload,
  Download,
  Globe,
  Trash2,
  RefreshCw,
  X,
  Plus,
  Sparkles,
  ExternalLink,
  Sliders,
  Sun,
  Moon,
} from 'lucide-react';
import {
  BUILTIN_THEMES,
  AxonwallTheme,
  ThemeCategory,
  applyTheme,
  getStoredThemeId,
  getStoredCustomThemes,
  saveCustomTheme,
  deleteCustomTheme,
  importThemeFromJSON,
  fetchThemesFromRemote,
  exportThemeToJSON,
  getThemeById,
  DEFAULT_THEME_ID,
} from '../lib/themes';

interface ThemeSwitcherProps {
  className?: string;
  variant?: 'button' | 'dropdown' | 'compact';
}

export const ThemeSwitcher: React.FC<ThemeSwitcherProps> = ({
  className = '',
  variant = 'button',
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<'presets' | 'custom' | 'import'>('presets');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [activeThemeId, setActiveThemeId] = useState<string>(DEFAULT_THEME_ID);
  const [customThemes, setCustomThemes] = useState<AxonwallTheme[]>([]);
  const [remoteUrl, setRemoteUrl] = useState('');
  const [remoteLoading, setRemoteLoading] = useState(false);
  const [feedbackMessage, setFeedbackMessage] = useState<{ text: string; type: 'success' | 'error' } | null>(null);
  
  // Custom color tuning state
  const [tunedColors, setTunedColors] = useState<{
    bg: string;
    text: string;
    cardBg: string;
    border: string;
    accent: string;
  }>({
    bg: '#080c14',
    text: '#f1f5f9',
    cardBg: '#0e1526',
    border: '#1e293b',
    accent: '#10b981',
  });
  const [customThemeName, setCustomThemeName] = useState('');

  const modalRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Initialize theme on mount
  useEffect(() => {
    const storedId = getStoredThemeId();
    const storedCustoms = getStoredCustomThemes();
    setActiveThemeId(storedId);
    setCustomThemes(storedCustoms);

    const theme = getThemeById(storedId, storedCustoms);
    applyTheme(theme);

    setTunedColors({
      bg: theme.colors.bg,
      text: theme.colors.text,
      cardBg: theme.colors.cardBg,
      border: theme.colors.border,
      accent: theme.colors.accent,
    });
  }, []);

  // Close on outside click
  useEffect(() => {
    const handleOutsideClick = (e: MouseEvent) => {
      if (modalRef.current && !modalRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    if (isOpen) {
      document.addEventListener('mousedown', handleOutsideClick);
    }
    return () => document.removeEventListener('mousedown', handleOutsideClick);
  }, [isOpen]);

  const activeTheme = getThemeById(activeThemeId, customThemes);

  const handleSelectTheme = (theme: AxonwallTheme) => {
    setActiveThemeId(theme.id);
    applyTheme(theme);
    setTunedColors({
      bg: theme.colors.bg,
      text: theme.colors.text,
      cardBg: theme.colors.cardBg,
      border: theme.colors.border,
      accent: theme.colors.accent,
    });
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const content = event.target?.result as string;
        const imported = importThemeFromJSON(content);
        const importedList = Array.isArray(imported) ? imported : [imported];

        let updatedList = [...customThemes];
        for (const t of importedList) {
          updatedList = saveCustomTheme(t);
        }
        setCustomThemes(updatedList);

        if (importedList.length > 0) {
          handleSelectTheme(importedList[0]);
          setFeedbackMessage({
            text: `Successfully imported ${importedList.length} theme(s): ${importedList.map((t) => t.name).join(', ')}`,
            type: 'success',
          });
        }
      } catch (err: any) {
        setFeedbackMessage({
          text: err?.message || 'Failed to import theme JSON file.',
          type: 'error',
        });
      }
      if (fileInputRef.current) fileInputRef.current.value = '';
    };
    reader.readAsText(file);
  };

  const handleFetchRemote = async () => {
    if (!remoteUrl.trim()) {
      setFeedbackMessage({ text: 'Please enter a URL or GitHub repository.', type: 'error' });
      return;
    }
    setRemoteLoading(true);
    setFeedbackMessage(null);
    try {
      const themes = await fetchThemesFromRemote(remoteUrl);
      let updatedList = [...customThemes];
      for (const t of themes) {
        updatedList = saveCustomTheme(t);
      }
      setCustomThemes(updatedList);
      if (themes.length > 0) {
        handleSelectTheme(themes[0]);
        setFeedbackMessage({
          text: `Imported ${themes.length} theme(s) from remote source!`,
          type: 'success',
        });
        setRemoteUrl('');
      }
    } catch (err: any) {
      setFeedbackMessage({
        text: err?.message || 'Failed to fetch themes from URL.',
        type: 'error',
      });
    } finally {
      setRemoteLoading(false);
    }
  };

  const handleSaveTunedTheme = () => {
    const name = customThemeName.trim() || `Custom ${activeTheme.name}`;
    const id = `custom-${Date.now()}`;
    const newTheme: AxonwallTheme = {
      id,
      name,
      description: 'User-customized color palette',
      category: 'custom',
      isDark: activeTheme.isDark,
      colors: {
        ...activeTheme.colors,
        bg: tunedColors.bg,
        text: tunedColors.text,
        cardBg: tunedColors.cardBg,
        border: tunedColors.border,
        accent: tunedColors.accent,
        accentHover: tunedColors.accent,
        ring: tunedColors.accent,
      },
    };
    const updated = saveCustomTheme(newTheme);
    setCustomThemes(updated);
    handleSelectTheme(newTheme);
    setCustomThemeName('');
    setFeedbackMessage({ text: `Saved custom theme "${name}"!`, type: 'success' });
  };

  const handleDeleteCustom = (themeId: string) => {
    const updated = deleteCustomTheme(themeId);
    setCustomThemes(updated);
    if (activeThemeId === themeId) {
      handleSelectTheme(BUILTIN_THEMES[0]);
    }
    setFeedbackMessage({ text: 'Custom theme deleted.', type: 'success' });
  };

  const handleExportJSON = () => {
    const jsonStr = exportThemeToJSON(activeTheme);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeTheme.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const categories = [
    { id: 'all', label: 'All Themes' },
    { id: 'axonwall', label: 'Axonwall' },
    { id: 'solarized', label: 'Solarized' },
    { id: 'gruvbox', label: 'Gruvbox' },
    { id: 'catppuccin', label: 'Catppuccin' },
    { id: 'oled', label: 'OLED / Pure Black' },
    { id: 'dark-ambient', label: 'Dark Ambient' },
    { id: 'dark-red', label: 'Night Red' },
    { id: 'light', label: 'Light' },
  ];

  const allThemes = [...BUILTIN_THEMES, ...customThemes];
  const filteredThemes = allThemes.filter((t) => {
    if (selectedCategory === 'all') return true;
    if (selectedCategory === 'oled') return t.category === 'oled';
    return t.category === selectedCategory;
  });

  return (
    <div className={`relative inline-block ${className}`}>
      {/* Trigger Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800/80 hover:bg-slate-700/80 text-slate-200 border border-slate-700/80 hover:border-emerald-500/50 transition cursor-pointer shadow-sm"
        title="Switch theme or customize colors"
      >
        <Palette className="w-3.5 h-3.5 text-emerald-400" />
        <span className="hidden sm:inline font-mono">{activeTheme.name}</span>
        {/* Tiny color swatch dots */}
        <div className="flex items-center -space-x-1">
          <span
            className="w-2.5 h-2.5 rounded-full border border-black/40"
            style={{ backgroundColor: activeTheme.colors.bg }}
          />
          <span
            className="w-2.5 h-2.5 rounded-full border border-black/40"
            style={{ backgroundColor: activeTheme.colors.accent }}
          />
        </div>
      </button>

      {/* Theme Switcher Modal / Dropdown */}
      {isOpen && (
        <div
          ref={modalRef}
          className="absolute right-0 mt-2 w-[340px] sm:w-[480px] max-h-[85vh] rounded-2xl bg-slate-900 border border-slate-700/80 shadow-2xl p-4 sm:p-5 z-50 overflow-hidden flex flex-col text-slate-100 backdrop-blur-xl animate-in fade-in zoom-in-95 duration-150"
        >
          {/* Header */}
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                <Palette className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-1.5">
                  Theme Customizer
                  <span className="text-[10px] font-mono font-normal text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">
                    20+ Palettes
                  </span>
                </h3>
              </div>
            </div>
            <button
              onClick={() => setIsOpen(false)}
              className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Feedback banner */}
          {feedbackMessage && (
            <div
              className={`my-2 p-2 rounded-lg text-xs flex items-center justify-between ${
                feedbackMessage.type === 'success'
                  ? 'bg-emerald-950/60 border border-emerald-500/40 text-emerald-300'
                  : 'bg-rose-950/60 border border-rose-500/40 text-rose-300'
              }`}
            >
              <span>{feedbackMessage.text}</span>
              <button
                onClick={() => setFeedbackMessage(null)}
                className="text-slate-400 hover:text-white ml-2 text-xs"
              >
                ✕
              </button>
            </div>
          )}

          {/* Nav Tabs */}
          <div className="flex items-center gap-2 my-3 border-b border-slate-800 pb-2">
            <button
              onClick={() => setActiveTab('presets')}
              className={`px-3 py-1 rounded-lg text-xs font-semibold transition ${
                activeTab === 'presets'
                  ? 'bg-emerald-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              Presets & Curated
            </button>
            <button
              onClick={() => setActiveTab('import')}
              className={`px-3 py-1 rounded-lg text-xs font-semibold transition flex items-center gap-1 ${
                activeTab === 'import'
                  ? 'bg-emerald-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Globe className="w-3 h-3" /> Import Repo / File
            </button>
            <button
              onClick={() => setActiveTab('custom')}
              className={`px-3 py-1 rounded-lg text-xs font-semibold transition flex items-center gap-1 ${
                activeTab === 'custom'
                  ? 'bg-emerald-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Sliders className="w-3 h-3" /> Color Tuner
            </button>
          </div>

          {/* Tab 1: Presets & Builtin Palettes */}
          {activeTab === 'presets' && (
            <div className="flex-1 overflow-y-auto space-y-3 pr-1">
              {/* Category Pills */}
              <div className="flex flex-wrap gap-1 pb-1">
                {categories.map((cat) => (
                  <button
                    key={cat.id}
                    onClick={() => setSelectedCategory(cat.id)}
                    className={`px-2 py-0.5 rounded-md text-[11px] font-mono transition ${
                      selectedCategory === cat.id
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        : 'bg-slate-950 text-slate-400 border border-slate-800 hover:text-slate-200'
                    }`}
                  >
                    {cat.label}
                  </button>
                ))}
              </div>

              {/* Theme Grid */}
              <div className="space-y-1.5 max-h-[300px] overflow-y-auto pr-1">
                {filteredThemes.map((theme) => {
                  const isSelected = theme.id === activeThemeId;
                  return (
                    <button
                      key={theme.id}
                      onClick={() => handleSelectTheme(theme)}
                      className={`w-full flex items-center justify-between p-2.5 rounded-xl border text-left transition ${
                        isSelected
                          ? 'bg-slate-800 border-emerald-500 shadow-sm ring-1 ring-emerald-500/50'
                          : 'bg-slate-950/80 border-slate-800 hover:bg-slate-800/60 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        {/* 4-Swatch Palette Block */}
                        <div
                          className="w-8 h-8 rounded-lg border flex flex-wrap overflow-hidden shrink-0 shadow-inner"
                          style={{ borderColor: theme.colors.border }}
                        >
                          <div className="w-4 h-4" style={{ backgroundColor: theme.colors.bg }} />
                          <div className="w-4 h-4" style={{ backgroundColor: theme.colors.cardBg }} />
                          <div className="w-4 h-4" style={{ backgroundColor: theme.colors.accent }} />
                          <div className="w-4 h-4" style={{ backgroundColor: theme.colors.text }} />
                        </div>

                        <div>
                          <div className="flex items-center gap-1.5">
                            <span className="text-xs font-semibold text-white">{theme.name}</span>
                            {theme.category === 'axonwall' && (
                              <span className="px-1.5 py-0.2 rounded bg-emerald-500/10 text-[9px] font-mono text-emerald-400 border border-emerald-500/30">
                                Default
                              </span>
                            )}
                            {theme.category === 'oled' && (
                              <span className="px-1.5 py-0.2 rounded bg-black text-[9px] font-mono text-emerald-400 border border-emerald-500/30">
                                OLED
                              </span>
                            )}
                            {theme.category === 'custom' && (
                              <span className="px-1.5 py-0.2 rounded bg-purple-500/10 text-[9px] font-mono text-purple-300 border border-purple-500/30">
                                Custom
                              </span>
                            )}
                          </div>
                          <p className="text-[11px] text-slate-400 line-clamp-1">{theme.description}</p>
                        </div>
                      </div>

                      {isSelected && <Check className="w-4 h-4 text-emerald-400 shrink-0 ml-2" />}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Tab 2: Remote Importer & File Upload */}
          {activeTab === 'import' && (
            <div className="flex-1 overflow-y-auto space-y-4 pr-1 text-xs">
              {/* Remote Git Repo / URL Box */}
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white flex items-center gap-1.5">
                    <Globe className="w-3.5 h-3.5 text-emerald-400" />
                    Point to a Theme Repo or URL
                  </span>
                  <a
                    href="/docs/themes"
                    target="_blank"
                    className="text-[10px] text-emerald-400 hover:underline flex items-center gap-0.5"
                  >
                    Format Docs <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                </div>
                <p className="text-[11px] text-slate-400">
                  Enter any GitHub repository (e.g. <code className="text-slate-300">https://github.com/winnegansFake/winnegansFake</code>) or a direct URL to a <code className="text-slate-300">themes.json</code> manifest.
                </p>
                <div className="flex gap-2">
                  <input
                    type="url"
                    value={remoteUrl}
                    onChange={(e) => setRemoteUrl(e.target.value)}
                    placeholder="https://github.com/user/theme-repo or raw JSON URL"
                    className="flex-1 bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                  />
                  <button
                    onClick={handleFetchRemote}
                    disabled={remoteLoading}
                    className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-semibold rounded-lg transition shrink-0 flex items-center gap-1"
                  >
                    {remoteLoading ? (
                      <RefreshCw className="w-3 h-3 animate-spin" />
                    ) : (
                      <Download className="w-3 h-3" />
                    )}
                    Import
                  </button>
                </div>
              </div>

              {/* Local File Upload Box */}
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5">
                <span className="font-bold text-white flex items-center gap-1.5">
                  <Upload className="w-3.5 h-3.5 text-sky-400" />
                  Upload Theme JSON File
                </span>
                <p className="text-[11px] text-slate-400">
                  Select a single theme JSON file or a multi-theme manifest from your device.
                </p>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".json,application/json"
                  onChange={handleFileUpload}
                  className="hidden"
                />
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="w-full py-2 bg-slate-900 hover:bg-slate-850 border border-dashed border-slate-700 hover:border-emerald-500 rounded-xl text-center text-slate-300 hover:text-white font-medium transition cursor-pointer flex items-center justify-center gap-2"
                >
                  <Upload className="w-3.5 h-3.5 text-emerald-400" />
                  Select .json Theme File
                </button>
              </div>

              {/* Custom Themes List */}
              {customThemes.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                    My Custom Themes ({customThemes.length})
                  </span>
                  <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                    {customThemes.map((ct) => (
                      <div
                        key={ct.id}
                        className="flex items-center justify-between p-2 rounded-lg bg-slate-950 border border-slate-800 text-xs"
                      >
                        <div className="flex items-center gap-2">
                          <span
                            className="w-3 h-3 rounded-full border border-black/40 shrink-0"
                            style={{ backgroundColor: ct.colors.accent }}
                          />
                          <span className="font-semibold text-white">{ct.name}</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <button
                            onClick={() => handleSelectTheme(ct)}
                            className="px-2 py-0.5 rounded bg-emerald-600/80 hover:bg-emerald-500 text-[10px] text-white font-medium"
                          >
                            Apply
                          </button>
                          <button
                            onClick={() => handleDeleteCustom(ct.id)}
                            className="p-1 text-slate-400 hover:text-rose-400 transition"
                            title="Delete custom theme"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Tab 3: Color Tuner */}
          {activeTab === 'custom' && (
            <div className="flex-1 overflow-y-auto space-y-4 pr-1 text-xs">
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                <span className="font-bold text-white block">Tweak Current Theme Colors</span>
                
                {/* Color Inputs */}
                <div className="grid grid-cols-2 gap-2.5">
                  <div className="space-y-1">
                    <span className="text-[10px] text-slate-400 font-mono">Background</span>
                    <div className="flex items-center gap-2 bg-slate-900 p-1.5 rounded-lg border border-slate-800">
                      <input
                        type="color"
                        value={tunedColors.bg}
                        onChange={(e) => setTunedColors({ ...tunedColors, bg: e.target.value })}
                        className="w-6 h-6 rounded cursor-pointer bg-transparent border-0"
                      />
                      <span className="font-mono text-[10px] text-slate-300">{tunedColors.bg}</span>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[10px] text-slate-400 font-mono">Accent Brand</span>
                    <div className="flex items-center gap-2 bg-slate-900 p-1.5 rounded-lg border border-slate-800">
                      <input
                        type="color"
                        value={tunedColors.accent}
                        onChange={(e) => setTunedColors({ ...tunedColors, accent: e.target.value })}
                        className="w-6 h-6 rounded cursor-pointer bg-transparent border-0"
                      />
                      <span className="font-mono text-[10px] text-slate-300">{tunedColors.accent}</span>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[10px] text-slate-400 font-mono">Card Surface</span>
                    <div className="flex items-center gap-2 bg-slate-900 p-1.5 rounded-lg border border-slate-800">
                      <input
                        type="color"
                        value={tunedColors.cardBg}
                        onChange={(e) => setTunedColors({ ...tunedColors, cardBg: e.target.value })}
                        className="w-6 h-6 rounded cursor-pointer bg-transparent border-0"
                      />
                      <span className="font-mono text-[10px] text-slate-300">{tunedColors.cardBg}</span>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[10px] text-slate-400 font-mono">Primary Text</span>
                    <div className="flex items-center gap-2 bg-slate-900 p-1.5 rounded-lg border border-slate-800">
                      <input
                        type="color"
                        value={tunedColors.text}
                        onChange={(e) => setTunedColors({ ...tunedColors, text: e.target.value })}
                        className="w-6 h-6 rounded cursor-pointer bg-transparent border-0"
                      />
                      <span className="font-mono text-[10px] text-slate-300">{tunedColors.text}</span>
                    </div>
                  </div>
                </div>

                {/* Name & Save */}
                <div className="pt-2 border-t border-slate-800 flex gap-2">
                  <input
                    type="text"
                    value={customThemeName}
                    onChange={(e) => setCustomThemeName(e.target.value)}
                    placeholder={`Name for custom theme...`}
                    className="flex-1 bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                  />
                  <button
                    onClick={handleSaveTunedTheme}
                    className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-lg transition shrink-0"
                  >
                    Save Theme
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Footer Bar: Export & Reset */}
          <div className="mt-3 pt-2.5 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <button
              onClick={handleExportJSON}
              className="flex items-center gap-1 hover:text-white transition"
              title="Download active theme JSON"
            >
              <Download className="w-3 h-3 text-emerald-400" />
              <span>Export {activeTheme.name} (.json)</span>
            </button>

            <button
              onClick={() => handleSelectTheme(BUILTIN_THEMES[0])}
              className="hover:text-emerald-400 transition"
            >
              Reset to Emerald Default
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
