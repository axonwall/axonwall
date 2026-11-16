import React from 'react';

interface LogoProps {
  variant?: 'full' | 'icon' | 'badge';
  size?: 'sm' | 'md' | 'lg' | 'xl';
  className?: string;
  showSubtext?: boolean;
}

export const Logo: React.FC<LogoProps> = ({
  variant = 'full',
  size = 'md',
  className = '',
  showSubtext = true,
}) => {
  // Sizing map
  const iconSizes = {
    sm: 'w-7 h-7',
    md: 'w-9 h-9',
    lg: 'w-12 h-12',
    xl: 'w-16 h-16',
  };

  const textSizes = {
    sm: 'text-base',
    md: 'text-lg',
    lg: 'text-2xl',
    xl: 'text-3xl',
  };

  const subtextSizes = {
    sm: 'text-[8px]',
    md: 'text-[9.5px]',
    lg: 'text-[11px]',
    xl: 'text-[13px]',
  };

  const IconSVG = (
    <svg viewBox="0 0 48 48" fill="none" className="w-full h-full drop-shadow-[0_0_12px_rgba(16,185,129,0.4)]">
      <defs>
        <clipPath id="brickClipComp">
          <rect x="2" y="2" width="44" height="44" rx="9" />
        </clipPath>
        <linearGradient id="shieldGradComp" x1="8" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#0f172a" />
          <stop offset="50%" stopColor="#061c18" />
          <stop offset="100%" stopColor="#022c22" />
        </linearGradient>
        <linearGradient id="shieldBorderComp" x1="8" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#34d399" />
          <stop offset="50%" stopColor="#10b981" />
          <stop offset="100%" stopColor="#06b6d4" />
        </linearGradient>
        <linearGradient id="axonLineComp" x1="12" y1="12" x2="36" y2="36" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#34d399" />
          <stop offset="100%" stopColor="#38bdf8" />
        </linearGradient>
        <linearGradient id="axeHaftComp" x1="10" y1="12" x2="38" y2="42" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#cbd5e1" />
          <stop offset="50%" stopColor="#64748b" />
          <stop offset="100%" stopColor="#334155" />
        </linearGradient>
        <linearGradient id="axeBladeLeftComp" x1="3" y1="10" x2="14" y2="22" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#34d399" />
          <stop offset="55%" stopColor="#94a3b8" />
          <stop offset="100%" stopColor="#1e293b" />
        </linearGradient>
        <linearGradient id="axeBladeRightComp" x1="45" y1="10" x2="34" y2="22" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#38bdf8" />
          <stop offset="55%" stopColor="#94a3b8" />
          <stop offset="100%" stopColor="#1e293b" />
        </linearGradient>
        <radialGradient id="centerGlowComp" cx="24" cy="23" r="18" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#10b981" stopOpacity="0.55" />
          <stop offset="100%" stopColor="#10b981" stopOpacity="0" />
        </radialGradient>
      </defs>

      {/* Back Layer: Fortified Dark Brick Wall */}
      <g clipPath="url(#brickClipComp)">
        <rect x="2" y="2" width="44" height="44" rx="9" fill="#070b12" />
        {/* Brick courses & mortar lines */}
        <g stroke="#10b981" strokeOpacity="0.22" strokeWidth="0.65">
          <rect x="2.5" y="3" width="12.5" height="6" rx="0.8" fill="#0f172a" />
          <rect x="16" y="3" width="15" height="6" rx="0.8" fill="#111c2d" />
          <rect x="32" y="3" width="13.5" height="6" rx="0.8" fill="#0f172a" />

          <rect x="2.5" y="10" width="7" height="6" rx="0.8" fill="#111c2d" />
          <rect x="10.5" y="10" width="13" height="6" rx="0.8" fill="#0f172a" />
          <rect x="24.5" y="10" width="13" height="6" rx="0.8" fill="#111c2d" />
          <rect x="38.5" y="10" width="7" height="6" rx="0.8" fill="#0f172a" />

          <rect x="2.5" y="17" width="13" height="6" rx="0.8" fill="#0f172a" />
          <rect x="16.5" y="17" width="15" height="6" rx="0.8" fill="#0b1524" />
          <rect x="32.5" y="17" width="13" height="6" rx="0.8" fill="#0f172a" />

          <rect x="2.5" y="24" width="7.5" height="6" rx="0.8" fill="#111c2d" />
          <rect x="11" y="24" width="12.5" height="6" rx="0.8" fill="#0f172a" />
          <rect x="24.5" y="24" width="12.5" height="6" rx="0.8" fill="#111c2d" />
          <rect x="38" y="24" width="7.5" height="6" rx="0.8" fill="#0f172a" />

          <rect x="2.5" y="31" width="13" height="6" rx="0.8" fill="#0f172a" />
          <rect x="16.5" y="31" width="15" height="6" rx="0.8" fill="#111c2d" />
          <rect x="32.5" y="31" width="13" height="6" rx="0.8" fill="#0f172a" />

          <rect x="2.5" y="38" width="8" height="6.5" rx="0.8" fill="#111c2d" />
          <rect x="11.5" y="38" width="12" height="6.5" rx="0.8" fill="#0f172a" />
          <rect x="24.5" y="38" width="12" height="6.5" rx="0.8" fill="#111c2d" />
          <rect x="37.5" y="38" width="8" height="6.5" rx="0.8" fill="#0f172a" />
        </g>
        <rect x="2" y="2" width="44" height="44" rx="9" stroke="#10b981" strokeOpacity="0.32" strokeWidth="1" fill="none" />
      </g>

      {/* Ambient Radial Backlight on Wall */}
      <circle cx="24" cy="23" r="18" fill="url(#centerGlowComp)" />

      {/* Middle Layer: Axonwall Armor Shield */}
      <path
        d="M24 5.5 L38.5 10.2 C38.5 10.2 39 24 24 42.5 C9 24 9.5 10.2 9.5 10.2 L24 5.5 Z"
        fill="url(#shieldGradComp)"
        stroke="url(#shieldBorderComp)"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />

      {/* Inner Accent Line */}
      <path
        d="M24 9.2 L35.2 13 C35.2 13 35.6 23 24 37.8 C12.4 23 12.8 13 12.8 13 L24 9.2 Z"
        stroke="#10b981"
        strokeOpacity="0.3"
        strokeWidth="0.9"
        fill="none"
      />

      {/* Neural Axon Pathways */}
      <g>
        <path d="M24 12.5 L24 21.5" stroke="url(#axonLineComp)" strokeWidth="1.4" strokeLinecap="round" />
        <path d="M24 21.5 L16.5 17" stroke="url(#axonLineComp)" strokeWidth="1.4" strokeLinecap="round" />
        <path d="M24 21.5 L31.5 17" stroke="url(#axonLineComp)" strokeWidth="1.4" strokeLinecap="round" />
        <path d="M24 21.5 L17.5 28" stroke="url(#axonLineComp)" strokeWidth="1.4" strokeLinecap="round" />
        <path d="M24 21.5 L30.5 28" stroke="url(#axonLineComp)" strokeWidth="1.4" strokeLinecap="round" />

        <path d="M16.5 17 L13.5 19.5" stroke="url(#axonLineComp)" strokeWidth="1.1" strokeLinecap="round" />
        <path d="M31.5 17 L34.5 19.5" stroke="url(#axonLineComp)" strokeWidth="1.1" strokeLinecap="round" />

        {/* Nodes */}
        <circle cx="24" cy="12.5" r="2" fill="#34d399" />
        <circle cx="16.5" cy="17" r="1.8" fill="#38bdf8" />
        <circle cx="31.5" cy="17" r="1.8" fill="#38bdf8" />
        <circle cx="17.5" cy="28" r="1.8" fill="#10b981" />
        <circle cx="30.5" cy="28" r="1.8" fill="#10b981" />

        {/* Central Core Processor Node */}
        <circle cx="24" cy="21.5" r="3.1" fill="#022c22" stroke="#34d399" strokeWidth="1.7" />
        <circle cx="24" cy="21.5" r="1.3" fill="#ffffff" />
      </g>

      {/* Front Layer: Twin Battle Axes Crossing in Front of the Shield */}
      <g>
        {/* Drop-shadow separation strokes over shield face */}
        <path d="M10.5 13 L35 41" stroke="#020617" strokeOpacity="0.85" strokeWidth="3.8" strokeLinecap="round" />
        <path d="M37.5 13 L13 41" stroke="#020617" strokeOpacity="0.85" strokeWidth="3.8" strokeLinecap="round" />

        {/* Axe 1 (Top-Left to Bottom-Right) */}
        <path d="M10.5 13 L35 41" stroke="url(#axeHaftComp)" strokeWidth="2.1" strokeLinecap="round" />
        <path d="M11.4 11.4 L6.2 11.4 L2.6 10.2 C1.8 14 3.2 18.2 6.4 21.6 L9.8 17.6 L12.2 15.6 Z" fill="url(#axeBladeLeftComp)" stroke="#34d399" strokeWidth="1.1" strokeLinejoin="round" />
        <path d="M11.8 11.8 L13.8 10.6 L13.1 13.8" stroke="#94a3b8" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" />

        {/* Axe 2 (Top-Right to Bottom-Left) */}
        <path d="M37.5 13 L13 41" stroke="url(#axeHaftComp)" strokeWidth="2.1" strokeLinecap="round" />
        <path d="M36.6 11.4 L41.8 11.4 L45.4 10.2 C46.2 14 44.8 18.2 41.6 21.6 L38.2 17.6 L35.8 15.6 Z" fill="url(#axeBladeRightComp)" stroke="#38bdf8" strokeWidth="1.1" strokeLinejoin="round" />
        <path d="M36.2 11.8 L34.2 10.6 L34.9 13.8" stroke="#94a3b8" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" />
      </g>
    </svg>
  );

  if (variant === 'icon') {
    return (
      <div className={`relative shrink-0 flex items-center justify-center ${iconSizes[size]} ${className}`}>
        {IconSVG}
      </div>
    );
  }

  return (
    <div className={`flex items-center gap-3 select-none ${className}`}>
      <div className={`relative shrink-0 flex items-center justify-center ${iconSizes[size]}`}>
        {IconSVG}
      </div>
      <div className="flex flex-col">
        <div className="flex items-baseline gap-1.5 leading-none">
          <span className={`font-black tracking-tight text-white ${textSizes[size]}`}>
            Axon<span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-400">wall</span>
          </span>
          {variant === 'badge' && (
            <span className="text-[10px] text-emerald-400 font-mono uppercase px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/25 font-semibold">
              OS
            </span>
          )}
        </div>
        {showSubtext && (
          <span className={`font-mono font-bold tracking-wider text-emerald-400/90 uppercase mt-0.5 ${subtextSizes[size]}`}>
            Linux + nftables
          </span>
        )}
      </div>
    </div>
  );
};
