/**
 * Axonwall & Winnegans Universal Theme Engine
 * Comprehensive theme tokens, builtin palettes, import/export, and DOM variable injection.
 */

export type ThemeCategory =
  | 'axonwall'
  | 'solarized'
  | 'gruvbox'
  | 'catppuccin'
  | 'dark-ambient'
  | 'dark-red'
  | 'oled'
  | 'light'
  | 'cyber'
  | 'custom';

export interface ThemeColors {
  /** Page primary background */
  bg: string;
  /** Primary text color */
  text: string;
  /** Secondary / muted text color */
  textMuted: string;
  /** Card / container / surface background */
  cardBg: string;
  /** Border / divider color */
  border: string;
  /** Primary accent / brand / button color */
  accent: string;
  /** Hover / secondary accent */
  accentHover: string;
  /** Focus ring or glow effect */
  ring: string;
  /** Reader / editor viewport background */
  readerBg?: string;
  /** Reader / editor primary text */
  readerText?: string;
  /** Reader line coordinate or secondary meta */
  readerCoord?: string;
  /** Selection highlight background */
  selectionBg: string;
  /** Selection highlight text */
  selectionText: string;
}

export interface AxonwallTheme {
  id: string;
  name: string;
  description: string;
  category: ThemeCategory;
  isDark: boolean;
  colors: ThemeColors;
  author?: string;
  homepage?: string;
  version?: string;
}

export interface ThemeManifest {
  $schema?: string;
  name: string;
  version?: string;
  description?: string;
  homepage?: string;
  author?: string;
  themes: AxonwallTheme[];
}

export const BUILTIN_THEMES: AxonwallTheme[] = [
  // 1. Original Axonwall Theme (Default)
  {
    id: 'axonwall-emerald',
    name: 'Axonwall Cyber Emerald',
    description: 'Original Axonwall cyber defense aesthetic with deep navy background and radiant emerald/cyan synapses.',
    category: 'axonwall',
    isDark: true,
    colors: {
      bg: '#080c14',
      text: '#f1f5f9',
      textMuted: '#94a3b8',
      cardBg: '#0e1526',
      border: '#1e293b',
      accent: '#10b981',
      accentHover: '#34d399',
      ring: '#06b6d4',
      readerBg: '#080c14',
      readerText: '#f1f5f9',
      readerCoord: '#10b981',
      selectionBg: '#064e3b',
      selectionText: '#a7f3d0',
    },
  },

  // 2. Slate Midnight
  {
    id: 'slate-midnight',
    name: 'Slate Midnight',
    description: 'Deep balanced navy slate with sky blue accents for focused day and night monitoring.',
    category: 'dark-ambient',
    isDark: true,
    colors: {
      bg: '#0f172a',
      text: '#e2e8f0',
      textMuted: '#94a3b8',
      cardBg: '#1e293b',
      border: '#334155',
      accent: '#38bdf8',
      accentHover: '#0ea5e9',
      ring: '#0284c7',
      readerBg: '#0f172a',
      readerText: '#f8fafc',
      readerCoord: '#64748b',
      selectionBg: '#0369a1',
      selectionText: '#f0f9ff',
    },
  },

  // 3. Solarized Dark (Ethan Schoonover)
  {
    id: 'solarized-dark',
    name: 'Solarized Dark',
    description: 'Ethan Schoonover’s canonical Solarized Dark: precise LAB color space palette with base03 (#002b36) and base0 (#839496).',
    category: 'solarized',
    isDark: true,
    colors: {
      bg: '#002b36',
      text: '#839496',
      textMuted: '#586e75',
      cardBg: '#073642',
      border: '#073642',
      accent: '#2aa198',
      accentHover: '#268bd2',
      ring: '#b58900',
      readerBg: '#002b36',
      readerText: '#93a1a1',
      readerCoord: '#586e75',
      selectionBg: '#073642',
      selectionText: '#93a1a1',
    },
  },

  // 4. Solarized Light (Ethan Schoonover)
  {
    id: 'solarized-light',
    name: 'Solarized Light',
    description: 'Ethan Schoonover’s canonical Solarized Light: warm base3 (#fdf6e3) background with base00 (#657b83) text.',
    category: 'solarized',
    isDark: false,
    colors: {
      bg: '#fdf6e3',
      text: '#657b83',
      textMuted: '#93a1a1',
      cardBg: '#eee8d5',
      border: '#eee8d5',
      accent: '#268bd2',
      accentHover: '#2aa198',
      ring: '#b58900',
      readerBg: '#fdf6e3',
      readerText: '#586e75',
      readerCoord: '#93a1a1',
      selectionBg: '#eee8d5',
      selectionText: '#073642',
    },
  },

  // 5. Dublin Amber
  {
    id: 'solarized-amber',
    name: 'Dublin Amber',
    description: 'Muted warm solarized dark background with incandescent honey and amber highlights.',
    category: 'dark-ambient',
    isDark: true,
    colors: {
      bg: '#14120e',
      text: '#fef3c7',
      textMuted: '#fcd34d',
      cardBg: '#211d17',
      border: '#453a29',
      accent: '#f59e0b',
      accentHover: '#fbbf24',
      ring: '#d97706',
      readerBg: '#0e0c09',
      readerText: '#fffbeb',
      readerCoord: '#b45309',
      selectionBg: '#78350f',
      selectionText: '#fef3c7',
    },
  },

  // 6. Gruvbox Dark (Pavel Pertsev)
  {
    id: 'gruvbox-dark',
    name: 'Gruvbox Dark',
    description: 'Retro groove dark palette: warm dark background (#282828) with light fg (#ebdbb2) and soothing warm accents.',
    category: 'gruvbox',
    isDark: true,
    colors: {
      bg: '#282828',
      text: '#ebdbb2',
      textMuted: '#a89984',
      cardBg: '#3c3836',
      border: '#504945',
      accent: '#fabd2f',
      accentHover: '#fe8019',
      ring: '#d79921',
      readerBg: '#282828',
      readerText: '#fbf1c7',
      readerCoord: '#928374',
      selectionBg: '#504945',
      selectionText: '#fbf1c7',
    },
  },

  // 7. Gruvbox Light (Pavel Pertsev)
  {
    id: 'gruvbox-light',
    name: 'Gruvbox Light',
    description: 'Retro groove light palette: soft light parchment background (#fbf1c7) with dark (#282828) text.',
    category: 'gruvbox',
    isDark: false,
    colors: {
      bg: '#fbf1c7',
      text: '#3c3836',
      textMuted: '#7c6f64',
      cardBg: '#ebdbb2',
      border: '#d5c4a1',
      accent: '#b57614',
      accentHover: '#af3a03',
      ring: '#b57614',
      readerBg: '#fbf1c7',
      readerText: '#282828',
      readerCoord: '#928374',
      selectionBg: '#d5c4a1',
      selectionText: '#282828',
    },
  },

  // 8. Catppuccin Mocha (High-contrast Dark)
  {
    id: 'catppuccin-mocha',
    name: 'Catppuccin Mocha',
    description: 'Catppuccin’s deep dark flavor: base (#1e1e2e) background, crisp text (#cdd6f4), and mauve (#cba6f7) accents.',
    category: 'catppuccin',
    isDark: true,
    colors: {
      bg: '#1e1e2e',
      text: '#cdd6f4',
      textMuted: '#a6adc8',
      cardBg: '#181825',
      border: '#313244',
      accent: '#cba6f7',
      accentHover: '#89b4fa',
      ring: '#b4befe',
      readerBg: '#1e1e2e',
      readerText: '#cdd6f4',
      readerCoord: '#6c7086',
      selectionBg: '#313244',
      selectionText: '#cdd6f4',
    },
  },

  // 9. Catppuccin Macchiato
  {
    id: 'catppuccin-macchiato',
    name: 'Catppuccin Macchiato',
    description: 'Catppuccin’s medium dark flavor: rich base (#24273a) background, text (#cad3f5), and lavender accents.',
    category: 'catppuccin',
    isDark: true,
    colors: {
      bg: '#24273a',
      text: '#cad3f5',
      textMuted: '#a5adcb',
      cardBg: '#1e2030',
      border: '#363a4f',
      accent: '#c6a0f6',
      accentHover: '#8aadf4',
      ring: '#b7bdf8',
      readerBg: '#24273a',
      readerText: '#cad3f5',
      readerCoord: '#6e738d',
      selectionBg: '#363a4f',
      selectionText: '#cad3f5',
    },
  },

  // 10. Catppuccin Frappé
  {
    id: 'catppuccin-frappe',
    name: 'Catppuccin Frappé',
    description: 'Catppuccin’s balanced dark flavor: muted base (#303446) background, text (#c6d0f5), and mauve accents.',
    category: 'catppuccin',
    isDark: true,
    colors: {
      bg: '#303446',
      text: '#c6d0f5',
      textMuted: '#a5adce',
      cardBg: '#292c3c',
      border: '#414559',
      accent: '#ca9ee6',
      accentHover: '#8caaee',
      ring: '#babbf1',
      readerBg: '#303446',
      readerText: '#c6d0f5',
      readerCoord: '#737994',
      selectionBg: '#414559',
      selectionText: '#c6d0f5',
    },
  },

  // 11. Catppuccin Latte
  {
    id: 'catppuccin-latte',
    name: 'Catppuccin Latte',
    description: 'Catppuccin’s light flavor: warm base (#eff1f5) background, text (#4c4f69), and lavender accents.',
    category: 'catppuccin',
    isDark: false,
    colors: {
      bg: '#eff1f5',
      text: '#4c4f69',
      textMuted: '#6c6f85',
      cardBg: '#e6e9ef',
      border: '#ccd0da',
      accent: '#7287fd',
      accentHover: '#1e66f5',
      ring: '#8839ef',
      readerBg: '#eff1f5',
      readerText: '#4c4f69',
      readerCoord: '#9ca0b0',
      selectionBg: '#ccd0da',
      selectionText: '#4c4f69',
    },
  },

  // 12. Obsidian OLED
  {
    id: 'obsidian-oled',
    name: 'Obsidian OLED',
    description: 'Pure pitch-black (#000000) background for zero power draw on OLED displays, paired with high-contrast emerald and silver.',
    category: 'oled',
    isDark: true,
    colors: {
      bg: '#000000',
      text: '#e2e8f0',
      textMuted: '#64748b',
      cardBg: '#09090b',
      border: '#18181b',
      accent: '#10b981',
      accentHover: '#34d399',
      ring: '#059669',
      readerBg: '#000000',
      readerText: '#f8fafc',
      readerCoord: '#52525b',
      selectionBg: '#1e293b',
      selectionText: '#10b981',
    },
  },

  // 13. Obsidian Crimson
  {
    id: 'obsidian-crimson',
    name: 'Obsidian Crimson',
    description: 'Pure pitch-black OLED background (#000000) with deep blood-red foreground (#9a2f2f) for zero eye strain in dark environments.',
    category: 'dark-red',
    isDark: true,
    colors: {
      bg: '#000000',
      text: '#9a2f2f',
      textMuted: '#6f2222',
      cardBg: '#0a0202',
      border: '#2a0c0c',
      accent: '#9a2f2f',
      accentHover: '#ba3939',
      ring: '#9a2f2f',
      readerBg: '#000000',
      readerText: '#9a2f2f',
      readerCoord: '#5a1d1d',
      selectionBg: '#330a0a',
      selectionText: '#b83a3a',
    },
  },

  // 14. Crimson Midnight
  {
    id: 'dark-crimson',
    name: 'Crimson Midnight',
    description: 'Deep wine black background with rose-red typography and crimson accent glow.',
    category: 'dark-red',
    isDark: true,
    colors: {
      bg: '#12080a',
      text: '#ffe4e6',
      textMuted: '#fda4af',
      cardBg: '#1f0d11',
      border: '#3f131a',
      accent: '#f43f5e',
      accentHover: '#fb7185',
      ring: '#e11d48',
      readerBg: '#0a0405',
      readerText: '#fff1f2',
      readerCoord: '#9f1239',
      selectionBg: '#881337',
      selectionText: '#ffe4e6',
    },
  },

  // 15. Blood Ember
  {
    id: 'dark-ember',
    name: 'Blood Ember',
    description: 'Scorched dark charcoal background with burning amber and orange fire highlights.',
    category: 'dark-ambient',
    isDark: true,
    colors: {
      bg: '#140a05',
      text: '#fed7aa',
      textMuted: '#fdba74',
      cardBg: '#231208',
      border: '#431f0d',
      accent: '#f97316',
      accentHover: '#fb923c',
      ring: '#ea580c',
      readerBg: '#0d0603',
      readerText: '#ffedd5',
      readerCoord: '#9a3412',
      selectionBg: '#7c2d12',
      selectionText: '#fed7aa',
    },
  },

  // 16. Burgundy Velvet
  {
    id: 'dark-burgundy',
    name: 'Burgundy Velvet',
    description: 'Deep plum and royal velvet background with luminous violet-pink highlights.',
    category: 'dark-ambient',
    isDark: true,
    colors: {
      bg: '#130810',
      text: '#fce7f3',
      textMuted: '#f472b6',
      cardBg: '#210d1c',
      border: '#431437',
      accent: '#ec4899',
      accentHover: '#f472b6',
      ring: '#db2777',
      readerBg: '#0c040a',
      readerText: '#fdf2f8',
      readerCoord: '#9d174d',
      selectionBg: '#831843',
      selectionText: '#fce7f3',
    },
  },

  // 17. Cyberpunk Neon
  {
    id: 'neon-cyberpunk',
    name: 'Cyberpunk Neon',
    description: 'High-voltage electric night: dark violet background with cyan lasers and hot magenta accents.',
    category: 'cyber',
    isDark: true,
    colors: {
      bg: '#0a0518',
      text: '#f0fdf4',
      textMuted: '#a78bfa',
      cardBg: '#130a2a',
      border: '#2e1065',
      accent: '#00ffcc',
      accentHover: '#ff007f',
      ring: '#ff007f',
      readerBg: '#060310',
      readerText: '#ffffff',
      readerCoord: '#7c3aed',
      selectionBg: '#581c87',
      selectionText: '#00ffcc',
    },
  },

  // 18. Emerald Forest
  {
    id: 'forest-glade',
    name: 'Emerald Forest',
    description: 'Deep organic spruce green with refreshing mint and botanical foliage highlights.',
    category: 'dark-ambient',
    isDark: true,
    colors: {
      bg: '#05140c',
      text: '#ecfdf5',
      textMuted: '#6ee7b7',
      cardBg: '#092315',
      border: '#134e2a',
      accent: '#10b981',
      accentHover: '#34d399',
      ring: '#059669',
      readerBg: '#030c07',
      readerText: '#f0fdf4',
      readerCoord: '#059669',
      selectionBg: '#064e3b',
      selectionText: '#d1fae5',
    },
  },

  // 19. Daylight White
  {
    id: 'daylight-pure',
    name: 'Daylight White',
    description: 'Crisp, high-visibility clean paper white background with dark slate typography and blue highlights.',
    category: 'light',
    isDark: false,
    colors: {
      bg: '#ffffff',
      text: '#0f172a',
      textMuted: '#64748b',
      cardBg: '#f8fafc',
      border: '#e2e8f0',
      accent: '#0284c7',
      accentHover: '#0369a1',
      ring: '#0284c7',
      readerBg: '#ffffff',
      readerText: '#0f172a',
      readerCoord: '#94a3b8',
      selectionBg: '#bae6fd',
      selectionText: '#0369a1',
    },
  },

  // 20. Book Parchment
  {
    id: 'warm-parchment',
    name: 'Book Parchment',
    description: 'Warm sepia antique book paper background designed to eliminate blue light fatigue during prolonged reading.',
    category: 'light',
    isDark: false,
    colors: {
      bg: '#faf6ee',
      text: '#292524',
      textMuted: '#78716c',
      cardBg: '#f3ece0',
      border: '#e7dccb',
      accent: '#d97706',
      accentHover: '#b45309',
      ring: '#d97706',
      readerBg: '#faf6ee',
      readerText: '#1c1917',
      readerCoord: '#a8a29e',
      selectionBg: '#fde68a',
      selectionText: '#78350f',
    },
  },
];

export const DEFAULT_THEME_ID = 'axonwall-emerald';
const THEME_STORAGE_KEY = 'axonwall_theme_id';
const CUSTOM_THEMES_STORAGE_KEY = 'axonwall_custom_themes';

/**
 * Retrieves a theme by its unique identifier (checks builtin + custom themes)
 */
export function getThemeById(themeId: string, customThemes: AxonwallTheme[] = []): AxonwallTheme {
  const custom = customThemes.find((t) => t.id === themeId);
  if (custom) return custom;
  const found = BUILTIN_THEMES.find((t) => t.id === themeId);
  return found || BUILTIN_THEMES[0];
}

/**
 * Returns stored custom themes from localStorage
 */
export function getStoredCustomThemes(): AxonwallTheme[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = localStorage.getItem(CUSTOM_THEMES_STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as AxonwallTheme[];
  } catch (err) {
    console.error('Failed to parse custom themes from storage:', err);
    return [];
  }
}

/**
 * Saves a new or modified custom theme to localStorage
 */
export function saveCustomTheme(theme: AxonwallTheme): AxonwallTheme[] {
  if (typeof window === 'undefined') return [];
  const current = getStoredCustomThemes();
  const existingIdx = current.findIndex((t) => t.id === theme.id);
  let updated: AxonwallTheme[];
  if (existingIdx >= 0) {
    updated = [...current];
    updated[existingIdx] = theme;
  } else {
    updated = [...current, theme];
  }
  try {
    localStorage.setItem(CUSTOM_THEMES_STORAGE_KEY, JSON.stringify(updated));
  } catch (err) {
    console.error('Failed to save custom theme to storage:', err);
  }
  return updated;
}

/**
 * Deletes a custom theme from localStorage
 */
export function deleteCustomTheme(themeId: string): AxonwallTheme[] {
  if (typeof window === 'undefined') return [];
  const current = getStoredCustomThemes();
  const updated = current.filter((t) => t.id !== themeId);
  try {
    localStorage.setItem(CUSTOM_THEMES_STORAGE_KEY, JSON.stringify(updated));
  } catch (err) {
    console.error('Failed to delete custom theme:', err);
  }
  return updated;
}

/**
 * Reads the active theme ID from localStorage (or defaults to axonwall-emerald)
 */
export function getStoredThemeId(): string {
  if (typeof window === 'undefined') return DEFAULT_THEME_ID;
  try {
    return localStorage.getItem(THEME_STORAGE_KEY) || DEFAULT_THEME_ID;
  } catch {
    return DEFAULT_THEME_ID;
  }
}

/**
 * Injects CSS variables and sets theme attributes on the document root
 */
export function applyTheme(theme: AxonwallTheme, targetElement?: HTMLElement): void {
  if (typeof document === 'undefined') return;

  const target = targetElement || document.documentElement;
  const colors = theme.colors;

  // Set standard Axonwall theme variables
  target.style.setProperty('--theme-bg', colors.bg);
  target.style.setProperty('--theme-text', colors.text);
  target.style.setProperty('--theme-text-muted', colors.textMuted);
  target.style.setProperty('--theme-card', colors.cardBg);
  target.style.setProperty('--theme-card-bg', colors.cardBg);
  target.style.setProperty('--theme-border', colors.border);
  target.style.setProperty('--theme-accent', colors.accent);
  target.style.setProperty('--theme-accent-hover', colors.accentHover);
  target.style.setProperty('--theme-ring', colors.ring);
  target.style.setProperty('--theme-selection-bg', colors.selectionBg);
  target.style.setProperty('--theme-selection-text', colors.selectionText);

  // Set Winnegans compatibility variables (--wf-*)
  target.style.setProperty('--wf-bg', colors.bg);
  target.style.setProperty('--wf-text', colors.text);
  target.style.setProperty('--wf-text-muted', colors.textMuted);
  target.style.setProperty('--wf-card-bg', colors.cardBg);
  target.style.setProperty('--wf-border', colors.border);
  target.style.setProperty('--wf-accent', colors.accent);
  target.style.setProperty('--wf-accent-hover', colors.accentHover);
  target.style.setProperty('--wf-ring', colors.ring);
  target.style.setProperty('--wf-reader-bg', colors.readerBg || colors.bg);
  target.style.setProperty('--wf-reader-text', colors.readerText || colors.text);
  target.style.setProperty('--wf-reader-coord', colors.readerCoord || colors.accent);
  target.style.setProperty('--wf-selection-bg', colors.selectionBg);
  target.style.setProperty('--wf-selection-text', colors.selectionText);

  // Also style body directly for solid visual cohesion
  if (document.body) {
    document.body.style.backgroundColor = colors.bg;
    document.body.style.color = colors.text;
  }

  // Toggle dark/light class
  if (theme.isDark) {
    target.classList.add('dark');
    target.classList.remove('light');
  } else {
    target.classList.add('light');
    target.classList.remove('dark');
  }

  target.setAttribute('data-theme', theme.id);

  // Persist choice
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme.id);
  } catch (err) {
    // Ignore storage quota/permission errors
  }
}

/**
 * Validates and imports a theme from raw JSON text
 */
export function importThemeFromJSON(jsonText: string): AxonwallTheme | AxonwallTheme[] {
  let parsed: any;
  try {
    parsed = JSON.parse(jsonText);
  } catch (err) {
    throw new Error('Invalid JSON format. Please verify the syntax.');
  }

  // Multi-theme manifest
  if (parsed.themes && Array.isArray(parsed.themes)) {
    const validatedThemes: AxonwallTheme[] = [];
    for (const t of parsed.themes) {
      validatedThemes.push(validateThemeObject(t));
    }
    if (validatedThemes.length === 0) {
      throw new Error('Manifest contains no valid themes.');
    }
    return validatedThemes;
  }

  // Array of themes directly
  if (Array.isArray(parsed)) {
    const validatedThemes: AxonwallTheme[] = [];
    for (const t of parsed) {
      validatedThemes.push(validateThemeObject(t));
    }
    if (validatedThemes.length === 0) {
      throw new Error('JSON array contains no valid themes.');
    }
    return validatedThemes;
  }

  // Single theme
  return validateThemeObject(parsed);
}

function validateThemeObject(obj: any): AxonwallTheme {
  if (!obj || typeof obj !== 'object') {
    throw new Error('Theme definition must be a JSON object.');
  }

  const name = String(obj.name || '').trim();
  if (!name) {
    throw new Error('Theme must specify a non-empty "name".');
  }

  const id = (obj.id ? String(obj.id) : `custom-${name.toLowerCase().replace(/[^a-z0-9_-]/g, '-')}`).trim();
  const colors = obj.colors || {};

  const requiredColors = ['bg', 'text', 'cardBg', 'border', 'accent'];
  for (const rc of requiredColors) {
    if (!colors[rc] || typeof colors[rc] !== 'string') {
      throw new Error(`Theme is missing required color property: "colors.${rc}"`);
    }
  }

  return {
    id,
    name,
    description: String(obj.description || 'Custom imported theme'),
    category: (obj.category as ThemeCategory) || 'custom',
    isDark: typeof obj.isDark === 'boolean' ? obj.isDark : true,
    colors: {
      bg: colors.bg,
      text: colors.text,
      textMuted: colors.textMuted || colors.text,
      cardBg: colors.cardBg,
      border: colors.border,
      accent: colors.accent,
      accentHover: colors.accentHover || colors.accent,
      ring: colors.ring || colors.accent,
      readerBg: colors.readerBg || colors.bg,
      readerText: colors.readerText || colors.text,
      readerCoord: colors.readerCoord || colors.accent,
      selectionBg: colors.selectionBg || colors.cardBg,
      selectionText: colors.selectionText || colors.text,
    },
    author: obj.author ? String(obj.author) : undefined,
    homepage: obj.homepage ? String(obj.homepage) : undefined,
    version: obj.version ? String(obj.version) : '1.0.0',
  };
}

/**
 * Fetches themes from a remote URL or GitHub repository
 * e.g. https://github.com/winnegansFake/winnegansFake -> resolves to raw themes
 */
export async function fetchThemesFromRemote(url: string): Promise<AxonwallTheme[]> {
  let targetUrl = url.trim();

  // If user pasted a github repo link, e.g. https://github.com/user/repo
  const ghMatch = targetUrl.match(/^https?:\/\/github\.com\/([^\/]+)\/([^\/]+)(\/?.*)$/);
  if (ghMatch) {
    const owner = ghMatch[1];
    const repo = ghMatch[2].replace(/\.git$/, '');
    const remainder = ghMatch[3].replace(/^\//, '');

    if (!remainder || remainder === 'tree/main' || remainder === 'tree/master') {
      // Try themes.json on main branch first
      targetUrl = `https://raw.githubusercontent.com/${owner}/${repo}/main/themes.json`;
    } else if (remainder.startsWith('blob/')) {
      targetUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${remainder.replace(/^blob\//, '')}`;
    }
  }

  let response: Response;
  try {
    response = await fetch(targetUrl);
  } catch (err: any) {
    throw new Error(`Network error connecting to remote theme URL: ${err?.message || err}`);
  }

  if (!response.ok) {
    // If fallback to main/themes.json failed on a github repo, try theme.json
    if (targetUrl.endsWith('/themes.json') && ghMatch) {
      const fallbackUrl = targetUrl.replace(/\/themes\.json$/, '/theme.json');
      const fallbackResp = await fetch(fallbackUrl);
      if (fallbackResp.ok) {
        const text = await fallbackResp.text();
        const res = importThemeFromJSON(text);
        return Array.isArray(res) ? res : [res];
      }
    }
    throw new Error(`Failed to fetch themes (HTTP ${response.status}: ${response.statusText})`);
  }

  const text = await response.text();
  const result = importThemeFromJSON(text);
  return Array.isArray(result) ? result : [result];
}

/**
 * Serializes a theme into a formatted JSON string for download or sharing
 */
export function exportThemeToJSON(theme: AxonwallTheme): string {
  const payload = {
    $schema: 'https://axonwall.com/schemas/theme.json',
    id: theme.id,
    name: theme.name,
    description: theme.description,
    category: theme.category,
    isDark: theme.isDark,
    colors: theme.colors,
    author: theme.author || 'Axonwall Community User',
    version: theme.version || '1.0.0',
    homepage: theme.homepage || 'https://axonwall.com/docs/themes',
  };
  return JSON.stringify(payload, null, 2);
}
