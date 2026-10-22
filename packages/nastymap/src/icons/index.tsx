import React from 'react';
import {
  Server,
  Terminal,
  Laptop,
  Shield,
  Router,
  Network,
  Printer,
  Smartphone,
  Database,
  Globe,
  Cloud,
  Cpu,
  HelpCircle,
  Radio,
  Lock,
  Flame,
} from 'lucide-react';

export interface IconProps {
  className?: string;
  size?: number;
  color?: string;
}

export function LinuxIcon({ className = 'w-4 h-4', size = 16, color }: IconProps) {
  return <Terminal className={className} size={size} color={color} />;
}

export function WindowsIcon({ className = 'w-4 h-4', size = 16, color }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      fill="currentColor"
      color={color}
    >
      <path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-12.95-1.8" />
    </svg>
  );
}

export function AppleIcon({ className = 'w-4 h-4', size = 16, color }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      fill="currentColor"
      color={color}
    >
      <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M15.97 6.37c.62-.75 1.04-1.8 0.92-2.85-.9.04-2 .6-2.65 1.35-.58.66-1.09 1.73-0.95 2.76 1.01.08 2.05-.51 2.68-1.26z" />
    </svg>
  );
}

export function CiscoIcon({ className = 'w-4 h-4', size = 16, color }: IconProps) {
  return <Router className={className} size={size} color={color} />;
}

export function BsdIcon({ className = 'w-4 h-4', size = 16, color }: IconProps) {
  return <Flame className={className} size={size} color={color} />;
}

export function AndroidIcon({ className = 'w-4 h-4', size = 16, color }: IconProps) {
  return <Smartphone className={className} size={size} color={color} />;
}

export function FirewallIcon({ className = 'w-4 h-4', size = 16, color }: IconProps) {
  return <Shield className={className} size={size} color={color} />;
}

export function RouterIcon({ className = 'w-4 h-4', size = 16, color }: IconProps) {
  return <Router className={className} size={size} color={color} />;
}

export function SwitchIcon({ className = 'w-4 h-4', size = 16, color }: IconProps) {
  return <Network className={className} size={size} color={color} />;
}

export function PrinterIcon({ className = 'w-4 h-4', size = 16, color }: IconProps) {
  return <Printer className={className} size={size} color={color} />;
}

export function DatabaseIcon({ className = 'w-4 h-4', size = 16, color }: IconProps) {
  return <Database className={className} size={size} color={color} />;
}

export function ScannerOriginIcon({ className = 'w-4 h-4', size = 16, color }: IconProps) {
  return <Radio className={className} size={size} color={color} />;
}

export function ServerDefaultIcon({ className = 'w-4 h-4', size = 16, color }: IconProps) {
  return <Server className={className} size={size} color={color} />;
}

export function UnknownIcon({ className = 'w-4 h-4', size = 16, color }: IconProps) {
  return <HelpCircle className={className} size={size} color={color} />;
}

/**
 * Registry mapping OS family strings to React Icon components.
 * Easily extensible for custom icons!
 */
export const OS_ICON_REGISTRY: Record<string, React.FC<IconProps>> = {
  linux: LinuxIcon,
  ubuntu: LinuxIcon,
  debian: LinuxIcon,
  centos: LinuxIcon,
  redhat: LinuxIcon,
  rhel: LinuxIcon,
  arch: LinuxIcon,
  windows: WindowsIcon,
  microsoft: WindowsIcon,
  macos: AppleIcon,
  apple: AppleIcon,
  darwin: AppleIcon,
  ios: AppleIcon,
  cisco: CiscoIcon,
  'cisco ios': CiscoIcon,
  bsd: BsdIcon,
  freebsd: BsdIcon,
  openbsd: BsdIcon,
  netbsd: BsdIcon,
  android: AndroidIcon,
};

/**
 * Registry mapping device types to React Icon components.
 */
export const DEVICE_ICON_REGISTRY: Record<string, React.FC<IconProps>> = {
  router: RouterIcon,
  switch: SwitchIcon,
  firewall: FirewallIcon,
  printer: PrinterIcon,
  server: ServerDefaultIcon,
  scanner: ScannerOriginIcon,
  database: DatabaseIcon,
  'general purpose': ServerDefaultIcon,
  wap: Radio,
  phone: AndroidIcon,
};

/**
 * Get the appropriate Icon component for a given OS and Device Type.
 */
export function getHostIcon(
  osFamily?: string,
  deviceType?: string,
  nodeType?: string
): React.FC<IconProps> {
  if (nodeType === 'scanner') return ScannerOriginIcon;

  const dev = (deviceType || '').toLowerCase();
  if (DEVICE_ICON_REGISTRY[dev]) return DEVICE_ICON_REGISTRY[dev];

  const os = (osFamily || '').toLowerCase();
  for (const [key, icon] of Object.entries(OS_ICON_REGISTRY)) {
    if (os.includes(key)) return icon;
  }

  return ServerDefaultIcon;
}
