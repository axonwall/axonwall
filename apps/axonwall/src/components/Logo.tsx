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
    <svg viewBox="0 0 48 48" fill="none" className="w-full h-full drop-shadow-[0_0_12px_rgba(16,185,129,0.35)]">
      <defs>
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
        <radialGradient id="centerGlowComp" cx="24" cy="23" r="14" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#10b981" stopOpacity="0.7" />
          <stop offset="100%" stopColor="#10b981" stopOpacity="0" />
        </radialGradient>
      </defs>

      {/* Ambient Radial Backlight */}
      <circle cx="24" cy="23" r="15" fill="url(#centerGlowComp)" />

      {/* Outer Armor Shield */}
      <path
        d="M24 4.5 L39.5 9.5 C39.5 9.5 40 24 24 43.5 C8 24 8.5 9.5 8.5 9.5 L24 4.5 Z"
        fill="url(#shieldGradComp)"
        stroke="url(#shieldBorderComp)"
        strokeWidth="2"
        strokeLinejoin="round"
      />

      {/* Inner Accent Line */}
      <path
        d="M24 8.5 L36 12.5 C36 12.5 36.5 23 24 38.5 C11.5 23 12 12.5 12 12.5 L24 8.5 Z"
        stroke="#10b981"
        strokeOpacity="0.3"
        strokeWidth="1"
        fill="none"
      />

      {/* Neural Axon Pathways */}
      <g>
        <path d="M24 13 L24 23" stroke="url(#axonLineComp)" strokeWidth="1.6" strokeLinecap="round" />
        <path d="M24 23 L16 18" stroke="url(#axonLineComp)" strokeWidth="1.6" strokeLinecap="round" />
        <path d="M24 23 L32 18" stroke="url(#axonLineComp)" strokeWidth="1.6" strokeLinecap="round" />
        <path d="M24 23 L17 31" stroke="url(#axonLineComp)" strokeWidth="1.6" strokeLinecap="round" />
        <path d="M24 23 L31 31" stroke="url(#axonLineComp)" strokeWidth="1.6" strokeLinecap="round" />

        <path d="M16 18 L12.5 21" stroke="url(#axonLineComp)" strokeWidth="1.2" strokeLinecap="round" />
        <path d="M32 18 L35.5 21" stroke="url(#axonLineComp)" strokeWidth="1.2" strokeLinecap="round" />

        {/* Nodes */}
        <circle cx="24" cy="13" r="2.2" fill="#34d399" />
        <circle cx="16" cy="18" r="2" fill="#38bdf8" />
        <circle cx="32" cy="18" r="2" fill="#38bdf8" />
        <circle cx="17" cy="31" r="2" fill="#10b981" />
        <circle cx="31" cy="31" r="2" fill="#10b981" />

        {/* Central Core Processor Node */}
        <circle cx="24" cy="23" r="3.4" fill="#022c22" stroke="#34d399" strokeWidth="2" />
        <circle cx="24" cy="23" r="1.4" fill="#ffffff" />
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
