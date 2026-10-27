import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import {
  inferInterfaceRole,
  VowConfigSchema,
  type DesiredState,
  type VowConfig,
  type VowAppOverride,
} from '../../schemas/index.js';
import { isPluginEnabled } from '../../plugins/index.js';

export type VowAppCategory =
  | 'DevOps & GitOps'
  | 'Security & Identity'
  | 'Databases & Storage'
  | 'AI, ML & GPU'
  | 'Observability & Monitoring'
  | 'Collaboration & Business'
  | 'Messaging & IoT'
  | 'Networking & Ingress'
  | 'Custom & Local Charts';

export interface VowAppDefinition {
  id: string;
  name: string;
  category: VowAppCategory;
  description: string;
  enablerVar: string;
  argoPath?: string;
  initPath?: string;
  subdomain?: string;
  port?: number;
  docsUrl?: string;
  icon?: string;
  estimatedMemoryMb: number;
  dependencies?: string[];
  namespace?: string;
  isHelm?: boolean;
}

export interface VowDeploymentPreset {
  id: 'minimal' | 'storage' | 'observability' | 'ai' | 'collaboration' | 'full';
  name: string;
  description: string;
  estimatedMemoryMb: number;
  apps: string[];
}

export interface VowWaffleBlueprint {
  id: string;
  name: string;
  version: string;
  description: string;
  tags: string[];
  defaultNamespace: string;
  defaultStorageClass: string;
  apps: string[];
  stages: Array<{
    id: string;
    name: string;
    description: string;
    mode: 'series' | 'parallel';
    charts: string[];
  }>;
}

export const VOW_PERMISSIONS = [
  'apps:read',
  'apps:deploy',
  'apps:override',
  'argo:sync',
  'flux:sync',
  'flux:bootstrap',
  'webhook:argo',
  'cluster:read',
  'cluster:manage',
  'cluster:nodes:join',
  'config:read',
  'config:update',
  'k8s:read',
  'k8s:logs:read',
  'k8s:exec',
  'tasks:read',
  'tasks:run',
  'data:query',
  'remote:exec',
  'secrets:read',
  'security:read',
  'backups:manage',
  'chaos:run',
  'dns:update',
  'export:run',
  'helm:manage',
  'namespaces:manage',
  'network:manage',
  'rollouts:manage',
  'storage:manage',
  'builder:run',
  'ai:diagnose',
  'system:manage',
  'users:manage_permissions',
] as const;

export type VowPermission = (typeof VOW_PERMISSIONS)[number];

export const VOW_ROLES = ['owner', 'admin', 'operator', 'viewer', 'webhook'] as const;
export type VowRole = (typeof VOW_ROLES)[number];

export const VOW_ROLE_PERMISSIONS: Record<VowRole, readonly VowPermission[]> = {
  owner: VOW_PERMISSIONS,
  admin: VOW_PERMISSIONS.filter((p) => p !== 'users:manage_permissions'),
  operator: [
    'apps:read',
    'apps:deploy',
    'argo:sync',
    'flux:sync',
    'cluster:read',
    'config:read',
    'k8s:read',
    'k8s:logs:read',
    'tasks:read',
    'tasks:run',
    'namespaces:manage',
    'rollouts:manage',
    'helm:manage',
    'backups:manage',
    'security:read',
  ],
  viewer: ['apps:read', 'cluster:read', 'config:read', 'k8s:read', 'tasks:read', 'security:read'],
  webhook: ['webhook:argo'],
};

export const VOW_APP_CATALOG: VowAppDefinition[] = [
  // DevOps & GitOps
  {
    id: 'argocd',
    name: 'ArgoCD',
    category: 'DevOps & GitOps',
    description: 'Declarative, GitOps continuous delivery tool for Kubernetes',
    enablerVar: 'ARGOCD_ENABLED',
    argoPath: 'argo/argo-cd',
    subdomain: 'argocd',
    port: 443,
    docsUrl: 'https://argo-cd.readthedocs.io/',
    icon: 'GitBranch',
    estimatedMemoryMb: 512,
    namespace: 'argocd',
    isHelm: true,
  },
  {
    id: 'flux',
    name: 'FluxCD',
    category: 'DevOps & GitOps',
    description: 'Open and extensible GitOps continuous delivery solution for Kubernetes (Toolkit v2)',
    enablerVar: 'FLUX_ENABLED',
    argoPath: 'argo/flux',
    subdomain: 'flux',
    port: 443,
    docsUrl: 'https://fluxcd.io/',
    icon: 'GitBranch',
    estimatedMemoryMb: 512,
    namespace: 'flux-system',
    isHelm: true,
  },
  {
    id: 'goharbor',
    name: 'Harbor Registry',
    category: 'DevOps & GitOps',
    description: 'Cloud Native repository for storing and scanning container images and Helm charts',
    enablerVar: 'GOHARBOR_ENABLED',
    argoPath: 'argo/goharbor',
    subdomain: 'harbor',
    port: 443,
    docsUrl: 'https://goharbor.io/docs/',
    icon: 'Container',
    estimatedMemoryMb: 1024,
    dependencies: ['kubegres'],
    namespace: 'harbor',
    isHelm: true,
  },
  {
    id: 'rancher',
    name: 'Rancher',
    category: 'DevOps & GitOps',
    description: 'Complete container management platform for multi-cluster Kubernetes',
    enablerVar: 'RANCHER_ENABLED',
    argoPath: 'argo/rancher',
    subdomain: 'rancher',
    port: 443,
    docsUrl: 'https://rancher.com/docs/',
    icon: 'LayoutGrid',
    estimatedMemoryMb: 1536,
    namespace: 'cattle-system',
    isHelm: true,
  },
  {
    id: 'velero',
    name: 'Velero',
    category: 'DevOps & GitOps',
    description: 'Backup and migrate Kubernetes applications and persistent volumes',
    enablerVar: 'VELERO_ENABLED',
    argoPath: 'argo/velero',
    docsUrl: 'https://velero.io/docs/',
    icon: 'Archive',
    estimatedMemoryMb: 256,
    namespace: 'velero',
    isHelm: true,
  },
  {
    id: 'spegel',
    name: 'Spegel',
    category: 'DevOps & GitOps',
    description: 'Stateless peer-to-peer registry mirror for Kubernetes worker nodes',
    enablerVar: 'SPEGEL_ENABLED',
    argoPath: 'argo/spegel',
    subdomain: 'spegel',
    docsUrl: 'https://spegel.dev/',
    icon: 'Share2',
    estimatedMemoryMb: 128,
    namespace: 'spegel',
    isHelm: true,
  },
  {
    id: 'nextjs-docker',
    name: 'Next.js App',
    category: 'DevOps & GitOps',
    description: 'Containerized Next.js application deployment with cache PVC and ingress',
    enablerVar: 'NEXTJS_DOCKER_ENABLED',
    argoPath: 'argo/nextjs-docker',
    subdomain: 'nextjsdocker',
    port: 443,
    icon: 'AppWindow',
    estimatedMemoryMb: 256,
    namespace: 'nextjs',
    isHelm: true,
  },

  // Security & Identity
  {
    id: 'keycloak',
    name: 'Keycloak',
    category: 'Security & Identity',
    description: 'Open source Identity and Access Management (OAuth2, OIDC, SAML)',
    enablerVar: 'KEYCLOAK_ENABLED',
    argoPath: 'argo/keycloak',
    initPath: 'init/keycloak',
    subdomain: 'keycloak',
    port: 443,
    docsUrl: 'https://www.keycloak.org/documentation',
    icon: 'ShieldCheck',
    estimatedMemoryMb: 1024,
    dependencies: ['kubegres'],
    namespace: 'keycloak',
    isHelm: true,
  },
  {
    id: 'bao',
    name: 'OpenBao',
    category: 'Security & Identity',
    description: 'Open source secret management, dynamic credentials, and encryption-as-a-service',
    enablerVar: 'BAO_ENABLED',
    argoPath: 'argo/bao',
    initPath: 'init/bao',
    subdomain: 'baoui',
    port: 443,
    docsUrl: 'https://openbao.org/docs/',
    icon: 'KeyRound',
    estimatedMemoryMb: 256,
    namespace: 'bao',
    isHelm: true,
  },
  {
    id: 'openldap',
    name: 'OpenLDAP & phpLDAPadmin',
    category: 'Security & Identity',
    description: 'Directory service daemon and web-based administration client',
    enablerVar: 'OPENLDAP_ENABLED',
    argoPath: 'argo/openldap',
    subdomain: 'phpldapadmin',
    port: 443,
    docsUrl: 'https://www.openldap.org/doc/',
    icon: 'Users',
    estimatedMemoryMb: 256,
    namespace: 'openldap',
    isHelm: true,
  },
  {
    id: 'certmanager',
    name: 'Cert-Manager & mkcert',
    category: 'Security & Identity',
    description: "Automated TLS certificate controller using local mkcert CA or Let's Encrypt",
    enablerVar: 'CERTMANAGER_ENABLED',
    initPath: 'init/certmanager-mkcert',
    docsUrl: 'https://cert-manager.io/docs/',
    icon: 'Lock',
    estimatedMemoryMb: 256,
    namespace: 'cert-manager',
    isHelm: true,
  },

  // Databases & Storage
  {
    id: 'kubegres',
    name: 'Kubegres (PostgreSQL)',
    category: 'Databases & Storage',
    description: 'Kubernetes operator to manage PostgreSQL clusters with replication & failover',
    enablerVar: 'KUBEGRES_ENABLED',
    initPath: 'init/kubegres',
    docsUrl: 'https://www.kubegres.io/',
    icon: 'Database',
    estimatedMemoryMb: 512,
    namespace: 'kubegres-system',
    isHelm: false,
  },
  {
    id: 'mariadb-operator',
    name: 'MariaDB Operator',
    category: 'Databases & Storage',
    description: 'Kubernetes native operator for managing MariaDB Galera clusters and backups',
    enablerVar: 'MARIADB_OPERATOR_ENABLED',
    argoPath: 'argo/mariadb-operator',
    subdomain: 'mariadb-operator',
    docsUrl: 'https://mariadb.com/kb/en/mariadb-kubernetes-operator/',
    icon: 'Database',
    estimatedMemoryMb: 384,
    namespace: 'mariadb-system',
    isHelm: true,
  },
  {
    id: 'minio-tenant',
    name: 'MinIO Object Storage',
    category: 'Databases & Storage',
    description: 'High-performance, S3-compatible enterprise object storage tenant',
    enablerVar: 'MINIO_TENANT_ENABLED',
    argoPath: 'argo/minio-tenant',
    initPath: 'init/pre-minio-tenant',
    subdomain: 'minio-console',
    port: 443,
    docsUrl: 'https://min.io/docs/minio/kubernetes/upstream/',
    icon: 'HardDrive',
    estimatedMemoryMb: 512,
    namespace: 'minio',
    isHelm: true,
  },
  {
    id: 'seaweedfs',
    name: 'SeaweedFS',
    category: 'Databases & Storage',
    description: 'Fast distributed storage system for blobs, objects, files, and data lakes',
    enablerVar: 'SEAWEEDFS_ENABLED',
    argoPath: 'argo/seaweedFS',
    subdomain: 'seaweedfs',
    docsUrl: 'https://github.com/seaweedfs/seaweedfs',
    icon: 'Layers',
    estimatedMemoryMb: 512,
    namespace: 'seaweedfs',
    isHelm: true,
  },
  {
    id: 'openebs',
    name: 'OpenEBS',
    category: 'Databases & Storage',
    description: 'Container Attached Storage providing Local PVs (LVM/ZFS) and ReadWriteMany NFS',
    enablerVar: 'OPENEBS_ENABLED',
    argoPath: 'argo/openebs',
    initPath: 'init/openebs',
    docsUrl: 'https://openebs.io/docs',
    icon: 'Server',
    estimatedMemoryMb: 512,
    namespace: 'openebs',
    isHelm: true,
  },
  {
    id: 'rook-ceph-operator',
    name: 'Rook Ceph',
    category: 'Databases & Storage',
    description: 'Cloud-native storage orchestrator for distributed Ceph clusters',
    enablerVar: 'ROOK_CEPH_OPERATOR_ENABLED',
    argoPath: 'argo/rook-ceph-operator',
    initPath: 'init/pre-rook-ceph-operator',
    docsUrl: 'https://rook.io/docs/rook/latest/',
    icon: 'Cpu',
    estimatedMemoryMb: 1024,
    namespace: 'rook-ceph',
    isHelm: true,
  },
  {
    id: 'supabase',
    name: 'Supabase',
    category: 'Databases & Storage',
    description: 'Open source Firebase alternative: Postgres, Auth, Realtime, Instant APIs',
    enablerVar: 'SUPABASE_ENABLED',
    argoPath: 'argo/supabase',
    initPath: 'init/pre-supabase',
    subdomain: 'supa',
    port: 443,
    docsUrl: 'https://supabase.com/docs',
    icon: 'Zap',
    estimatedMemoryMb: 1024,
    dependencies: ['kubegres'],
    namespace: 'supabase',
    isHelm: true,
  },
  {
    id: 'trino',
    name: 'Trino',
    category: 'Databases & Storage',
    description: 'Fast distributed SQL query engine for big data and lakehouses',
    enablerVar: 'TRINO_ENABLED',
    argoPath: 'argo/trino',
    subdomain: 'trino',
    docsUrl: 'https://trino.io/docs/current/',
    icon: 'Search',
    estimatedMemoryMb: 1024,
    namespace: 'trino',
    isHelm: true,
  },

  // Observability & Monitoring
  {
    id: 'kube-prometheus-stack',
    name: 'Prometheus & Grafana',
    category: 'Observability & Monitoring',
    description: 'Full metrics monitoring stack with Prometheus, Grafana, and Alertmanager',
    enablerVar: 'KUBE_PROMETHEUS_STACK_ENABLED',
    argoPath: 'argo/kube-prometheus-stack',
    subdomain: 'grafana',
    port: 443,
    docsUrl: 'https://prometheus-community.github.io/helm-charts/',
    icon: 'LineChart',
    estimatedMemoryMb: 1536,
    namespace: 'monitoring',
    isHelm: true,
  },
  {
    id: 'opensearch',
    name: 'OpenSearch & Dashboards',
    category: 'Observability & Monitoring',
    description: 'Distributed search and analytics suite with real-time visualization dashboards',
    enablerVar: 'OPENSEARCH_ENABLED',
    argoPath: 'argo/opensearch',
    subdomain: 'opensearch-dashboards',
    port: 443,
    docsUrl: 'https://opensearch.org/docs/latest/',
    icon: 'SearchCode',
    estimatedMemoryMb: 2048,
    namespace: 'opensearch',
    isHelm: true,
  },
  {
    id: 'kubeshark',
    name: 'Kubeshark',
    category: 'Observability & Monitoring',
    description: 'Deep network packet inspector and traffic analyzer for Kubernetes (Wireshark for k8s)',
    enablerVar: 'KUBESHARK_ENABLED',
    argoPath: 'argo/kubeshark',
    subdomain: 'kubeshark',
    port: 443,
    docsUrl: 'https://docs.kubeshark.co/',
    icon: 'Radio',
    estimatedMemoryMb: 512,
    namespace: 'kubeshark',
    isHelm: true,
  },
  {
    id: 'opentelemetry-operator',
    name: 'OpenTelemetry Operator',
    category: 'Observability & Monitoring',
    description: 'Manages OpenTelemetry Collectors and auto-instrumentation for traces and metrics',
    enablerVar: 'OPENTELEMETRY_OPERATOR_ENABLED',
    argoPath: 'argo/opentelemetry-operator',
    initPath: 'init/opentelemetry-operator',
    docsUrl: 'https://opentelemetry.io/docs/',
    icon: 'Activity',
    estimatedMemoryMb: 256,
    namespace: 'opentelemetry-operator-system',
    isHelm: true,
  },
  {
    id: 'fluent-bit',
    name: 'Fluent Bit',
    category: 'Observability & Monitoring',
    description: 'Fast, lightweight log processor and forwarder for Kubernetes',
    enablerVar: 'FLUENT_BIT_ENABLED',
    argoPath: 'argo/fluent-bit',
    docsUrl: 'https://fluentbit.io/documentation/',
    icon: 'FileText',
    estimatedMemoryMb: 128,
    namespace: 'fluent-bit',
    isHelm: true,
  },
  {
    id: 'sloth',
    name: 'Sloth',
    category: 'Observability & Monitoring',
    description: 'Easy, reliable Prometheus Service Level Objectives (SLOs) and error budgets',
    enablerVar: 'SLOTH_ENABLED',
    argoPath: 'argo/sloth',
    subdomain: 'sloth',
    docsUrl: 'https://sloth.dev/',
    icon: 'Gauge',
    estimatedMemoryMb: 128,
    namespace: 'sloth',
    isHelm: true,
  },
  {
    id: 'vigil',
    name: 'Vigil',
    category: 'Observability & Monitoring',
    description: 'Open source status page and infrastructure monitoring service',
    enablerVar: 'VIGIL_ENABLED',
    argoPath: 'argo/vigil',
    subdomain: 'vigil',
    docsUrl: 'https://github.com/valeriansaliou/vigil',
    icon: 'BellRing',
    estimatedMemoryMb: 128,
    namespace: 'vigil',
    isHelm: true,
  },

  // Collaboration & Business
  {
    id: 'nextcloud',
    name: 'Nextcloud Hub',
    category: 'Collaboration & Business',
    description: 'Self-hosted productivity platform: file storage, calendar, contacts, and Collabora Office',
    enablerVar: 'NEXTCLOUD_ENABLED',
    argoPath: 'argo/nextcloud',
    subdomain: 'nextcloud',
    port: 443,
    docsUrl: 'https://docs.nextcloud.com/',
    icon: 'Cloud',
    estimatedMemoryMb: 1024,
    dependencies: ['kubegres', 'openebs'],
    namespace: 'nextcloud',
    isHelm: true,
  },
  {
    id: 'openproject',
    name: 'OpenProject',
    category: 'Collaboration & Business',
    description: 'Open source project management software for classic, agile, and hybrid workflows',
    enablerVar: 'OPENPROJECT_ENABLED',
    argoPath: 'argo/openproject',
    subdomain: 'openproject',
    port: 443,
    docsUrl: 'https://www.openproject.org/docs/',
    icon: 'CheckSquare',
    estimatedMemoryMb: 1024,
    dependencies: ['kubegres'],
    namespace: 'openproject',
    isHelm: true,
  },
  {
    id: 'drupal',
    name: 'Drupal CMS',
    category: 'Collaboration & Business',
    description: 'Enterprise open-source content management framework',
    enablerVar: 'DRUPAL_ENABLED',
    argoPath: 'argo/drupal',
    subdomain: 'drupal',
    port: 443,
    docsUrl: 'https://www.drupal.org/docs',
    icon: 'FileCode',
    estimatedMemoryMb: 512,
    dependencies: ['mariadb-operator'],
    namespace: 'drupal',
    isHelm: true,
  },
  {
    id: 'fossbilling',
    name: 'FOSSBilling',
    category: 'Collaboration & Business',
    description: 'Free and open source hosting management and client billing platform',
    enablerVar: 'FOSSBILLING_ENABLED',
    argoPath: 'argo/fossbilling',
    initPath: 'init/fossbilling',
    subdomain: 'fossbilling',
    port: 443,
    docsUrl: 'https://fossbilling.org/docs',
    icon: 'CreditCard',
    estimatedMemoryMb: 256,
    dependencies: ['mariadb-operator'],
    namespace: 'fossbilling',
    isHelm: true,
  },
  {
    id: 'opencti',
    name: 'OpenCTI',
    category: 'Collaboration & Business',
    description: 'Cyber Threat Intelligence knowledge platform for managing cybersecurity threats',
    enablerVar: 'OPENCTI_ENABLED',
    argoPath: 'argo/opencti',
    initPath: 'init/opencti',
    subdomain: 'opencti',
    port: 443,
    docsUrl: 'https://docs.opencti.io/',
    icon: 'ShieldAlert',
    estimatedMemoryMb: 1024,
    dependencies: ['opensearch', 'minio-tenant'],
    namespace: 'opencti',
    isHelm: true,
  },
  {
    id: 'resourcespace',
    name: 'ResourceSpace',
    category: 'Collaboration & Business',
    description: 'Digital asset management (DAM) platform for enterprise media and branding',
    enablerVar: 'RESOURCESPACE_ENABLED',
    argoPath: 'argo/resourcespace',
    subdomain: 'resourcespace',
    port: 443,
    docsUrl: 'https://www.resourcespace.com/knowledge-base/',
    icon: 'Image',
    estimatedMemoryMb: 512,
    dependencies: ['mariadb-operator'],
    namespace: 'resourcespace',
    isHelm: true,
  },

  // AI, ML & GPU
  {
    id: 'kubeflow',
    name: 'Kubeflow',
    category: 'AI, ML & GPU',
    description: 'Complete cloud-native machine learning toolkit for Kubernetes',
    enablerVar: 'KUBEFLOW_ENABLED',
    argoPath: 'argo/kubeflow',
    initPath: 'init/kubeflow',
    docsUrl: 'https://www.kubeflow.org/docs/',
    icon: 'Sparkles',
    estimatedMemoryMb: 4096,
    namespace: 'kubeflow',
    isHelm: false,
  },
  {
    id: 'gpu-operator',
    name: 'NVIDIA GPU Operator',
    category: 'AI, ML & GPU',
    description: 'Automates provisioning of NVIDIA software components on Kubernetes nodes',
    enablerVar: 'GPU_OPERATOR_ENABLED',
    argoPath: 'argo/gpu-operator',
    initPath: 'init/pre-gpu-operator',
    docsUrl: 'https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/',
    icon: 'Cpu',
    estimatedMemoryMb: 512,
    namespace: 'gpu-operator',
    isHelm: true,
  },
  {
    id: 'cvat',
    name: 'CVAT',
    category: 'AI, ML & GPU',
    description: 'Computer Vision Annotation Tool for images, video, and AI dataset labeling',
    enablerVar: 'CVAT_ENABLED',
    argoPath: 'argo/cvat',
    subdomain: 'cvat',
    port: 443,
    docsUrl: 'https://opencv.github.io/cvat/docs/',
    icon: 'Video',
    estimatedMemoryMb: 1024,
    dependencies: ['kubegres'],
    namespace: 'cvat',
    isHelm: true,
  },
  {
    id: 'node-feature-discovery',
    name: 'Node Feature Discovery',
    category: 'AI, ML & GPU',
    description: 'Detects hardware features, instruction sets, and accelerators on k8s nodes',
    enablerVar: 'NODE_FEATURE_DISCOVERY_ENABLED',
    argoPath: 'argo/node-feature-discovery',
    initPath: 'init/pre-node-feature-discovery',
    docsUrl: 'https://kubernetes-sigs.github.io/node-feature-discovery/',
    icon: 'Microchip',
    estimatedMemoryMb: 128,
    namespace: 'node-feature-discovery',
    isHelm: true,
  },
  {
    id: 'ollama',
    name: 'Ollama (In-Cluster LLM)',
    category: 'AI, ML & GPU',
    description: 'Get up and running with large language models locally inside your Kubernetes cluster',
    enablerVar: 'OLLAMA_ENABLED',
    argoPath: 'argo/ollama',
    subdomain: 'ollama',
    port: 11434,
    docsUrl: 'https://ollama.com/',
    icon: 'Bot',
    estimatedMemoryMb: 2048,
    namespace: 'ollama',
    isHelm: true,
  },
  {
    id: 'vllm',
    name: 'vLLM Inference Server',
    category: 'AI, ML & GPU',
    description: 'High-throughput and memory-efficient LLM serving engine for Kubernetes clusters',
    enablerVar: 'VLLM_ENABLED',
    argoPath: 'argo/vllm',
    subdomain: 'vllm',
    port: 8000,
    docsUrl: 'https://docs.vllm.ai/',
    icon: 'Cpu',
    estimatedMemoryMb: 4096,
    namespace: 'vllm',
    isHelm: true,
  },

  // Messaging & IoT
  {
    id: 'mosquitto',
    name: 'Eclipse Mosquitto (MQTT)',
    category: 'Messaging & IoT',
    description: 'Lightweight publish/subscribe message broker using the MQTT protocol',
    enablerVar: 'AR80_MOSQUITTO_ENABLED',
    argoPath: 'argo/ar80-mosquitto',
    subdomain: 'ar80-mosquitto',
    docsUrl: 'https://mosquitto.org/documentation/',
    icon: 'RadioTower',
    estimatedMemoryMb: 128,
    namespace: 'mosquitto',
    isHelm: true,
  },
  {
    id: 'vmq-operator',
    name: 'VerneMQ Operator',
    category: 'Messaging & IoT',
    description: 'High-performance, distributed MQTT broker operator with clustering',
    enablerVar: 'VMQ_OPERATOR_ENABLED',
    argoPath: 'argo/vmq-operator',
    initPath: 'init/vmq-operator',
    docsUrl: 'https://vernemq.com/docs/',
    icon: 'Share2',
    estimatedMemoryMb: 256,
    namespace: 'vernemq',
    isHelm: true,
  },
  {
    id: 'airflow',
    name: 'Apache Airflow',
    category: 'Messaging & IoT',
    description: 'Platform to programmatically author, schedule, and monitor data workflows',
    enablerVar: 'AIRFLOW_ENABLED',
    argoPath: 'argo/airflow',
    subdomain: 'airflow',
    port: 443,
    docsUrl: 'https://airflow.apache.org/docs/',
    icon: 'Workflow',
    estimatedMemoryMb: 1536,
    dependencies: ['kubegres'],
    namespace: 'airflow',
    isHelm: true,
  },
];

export const VOW_DEPLOYMENT_PRESETS: VowDeploymentPreset[] = [
  {
    id: 'minimal',
    name: 'Core / Minimal',
    description: 'ArgoCD + Ingress + Cert-Manager (Ideal for low-resource appliances)',
    estimatedMemoryMb: 1536,
    apps: ['argocd', 'certmanager'],
  },
  {
    id: 'storage',
    name: 'Dev & Storage',
    description: 'Core + PostgreSQL (Kubegres) + MinIO S3 + OpenEBS',
    estimatedMemoryMb: 3584,
    apps: ['argocd', 'certmanager', 'kubegres', 'minio-tenant', 'openebs'],
  },
  {
    id: 'observability',
    name: 'Observability Stack',
    description: 'Core + Prometheus, Grafana, OpenSearch & Dashboards, Sloth, Vigil',
    estimatedMemoryMb: 6144,
    apps: ['argocd', 'certmanager', 'kube-prometheus-stack', 'opensearch', 'sloth', 'vigil'],
  },
  {
    id: 'ai',
    name: 'AI & Machine Learning',
    description: 'Core + Kubeflow, CVAT, NVIDIA GPU Operator, Node Feature Discovery, Ollama, vLLM',
    estimatedMemoryMb: 12288,
    apps: ['argocd', 'certmanager', 'kubegres', 'kubeflow', 'cvat', 'gpu-operator', 'node-feature-discovery', 'ollama', 'vllm'],
  },
  {
    id: 'collaboration',
    name: 'Productivity & Business',
    description: 'Core + Nextcloud, OpenProject, Drupal CMS, Keycloak IAM',
    estimatedMemoryMb: 6144,
    apps: ['argocd', 'certmanager', 'kubegres', 'openebs', 'keycloak', 'nextcloud', 'openproject', 'drupal'],
  },
  {
    id: 'full',
    name: 'Full Suite',
    description: 'All 40+ applications and operators (High-memory appliance / 32GB+ RAM)',
    estimatedMemoryMb: 24576,
    apps: VOW_APP_CATALOG.map((a) => a.id),
  },
];

export const VOW_WAFFLE_BLUEPRINTS: VowWaffleBlueprint[] = [
  {
    id: 'blueprint-nextjs-supabase',
    name: 'Next.js SSR + Supabase Backend',
    version: '1.0.0',
    description:
      'Modern Full-Stack Next.js SSR application with self-hosted Supabase Auth, PostgreSQL 16 with pgvector, and OpenEBS LocalPV storage.',
    tags: ['nextjs', 'react', 'supabase', 'postgres', 'openebs', 'fullstack'],
    defaultNamespace: 'nextjs-supabase',
    defaultStorageClass: 'axonwall-zfs-local',
    apps: ['openebs', 'kubegres', 'supabase', 'nextjs-docker'],
    stages: [
      {
        id: '00-storage-foundation',
        name: 'Distributed Storage Fabric',
        description: 'Deploy OpenEBS Dynamic LocalPV engine for fast NVMe/ZFS volume claims.',
        mode: 'series',
        charts: ['openebs'],
      },
      {
        id: '10-data-backend',
        name: 'Data & Authentication Engine',
        description: 'Deploy self-hosted Supabase with PostgreSQL 16, pgvector, and Auth REST API.',
        mode: 'series',
        charts: ['kubegres', 'supabase'],
      },
      {
        id: '20-web-application',
        name: 'Next.js Frontend Application',
        description: 'Deploy high-performance Next.js application wired to internal Supabase service.',
        mode: 'series',
        charts: ['nextjs-docker'],
      },
    ],
  },
  {
    id: 'blueprint-python-mongodb',
    name: 'Python FastAPI Microservice + Distributed Storage',
    version: '1.0.0',
    description:
      'Python FastAPI/Flask microservice coupled with stateful database and OpenEBS persistent storage.',
    tags: ['python', 'fastapi', 'openebs', 'observability'],
    defaultNamespace: 'python-app',
    defaultStorageClass: 'axonwall-zfs-local',
    apps: ['openebs', 'kube-prometheus-stack', 'opentelemetry-operator'],
    stages: [
      {
        id: '00-storage',
        name: 'Storage Provisioning',
        description: 'Ensure OpenEBS LocalPV and ZFS storage classes are active.',
        mode: 'series',
        charts: ['openebs'],
      },
      {
        id: '10-telemetry',
        name: 'OpenTelemetry & Prometheus',
        description: 'Deploy OpenTelemetry auto-instrumentation and Grafana dashboards.',
        mode: 'parallel',
        charts: ['opentelemetry-operator', 'kube-prometheus-stack'],
      },
    ],
  },
  {
    id: 'blueprint-jupyter-cassandra',
    name: 'AI/ML Data Science Lakehouse (Kubeflow + Trino + MinIO)',
    version: '1.0.0',
    description:
      'Interactive AI/ML lakehouse combining Kubeflow notebooks, Trino distributed SQL, MinIO S3 object storage, and local Ollama/vLLM inference.',
    tags: ['ai', 'kubeflow', 'trino', 'minio', 'ollama', 'vllm'],
    defaultNamespace: 'ai-lakehouse',
    defaultStorageClass: 'axonwall-zfs-local',
    apps: ['openebs', 'minio-tenant', 'trino', 'kubeflow', 'ollama'],
    stages: [
      {
        id: '00-object-lake',
        name: 'S3 Object Storage & SQL Engine',
        description: 'Deploy MinIO S3 tenant and Trino distributed query engine.',
        mode: 'series',
        charts: ['openebs', 'minio-tenant', 'trino'],
      },
      {
        id: '10-ai-workbenches',
        name: 'Kubeflow & Local LLM Serving',
        description: 'Deploy Kubeflow pipelines and in-cluster Ollama LLM engine.',
        mode: 'parallel',
        charts: ['kubeflow', 'ollama'],
      },
    ],
  },
  {
    id: 'blueprint-kctf',
    name: 'Kubernetes CTF & Cyber Range Infrastructure',
    version: '1.0.0',
    description:
      'Sandboxed Kubernetes CTF & cyber range environment with network policy isolation, Kubeshark deep packet inspection, and OpenSearch telemetry.',
    tags: ['kctf', 'security', 'kubeshark', 'opensearch', 'cyber-range'],
    defaultNamespace: 'kctf-range',
    defaultStorageClass: 'axonwall-zfs-local',
    apps: ['certmanager', 'openebs', 'kubeshark', 'opensearch'],
    stages: [
      {
        id: '00-isolation-storage',
        name: 'Storage & Certificate Provisioning',
        description: 'Provision OpenEBS LocalPV and Cert-Manager TLS issuers.',
        mode: 'series',
        charts: ['certmanager', 'openebs'],
      },
      {
        id: '10-range-telemetry',
        name: 'Packet Inspection & SIEM',
        description: 'Deploy Kubeshark L7 packet capture and OpenSearch analytics.',
        mode: 'parallel',
        charts: ['kubeshark', 'opensearch'],
      },
    ],
  },
  {
    id: 'blueprint-zero-trust-storage',
    name: 'Zero-Trust Identity & Encrypted Vault Fabric',
    version: '1.0.0',
    description:
      'Zero-Trust enterprise identity and secret management with Keycloak OIDC, OpenBao KMS/Vault, OpenLDAP, Cert-Manager mkcert, and Harbor registry.',
    tags: ['zero-trust', 'keycloak', 'openbao', 'harbor', 'mkcert'],
    defaultNamespace: 'zero-trust',
    defaultStorageClass: 'axonwall-replicated-ha',
    apps: ['certmanager', 'kubegres', 'keycloak', 'bao', 'openldap', 'goharbor'],
    stages: [
      {
        id: '00-pki-db',
        name: 'PKI & Replicated PostgreSQL',
        description: 'Bootstrap Cert-Manager local CA and Kubegres HA PostgreSQL.',
        mode: 'series',
        charts: ['certmanager', 'kubegres'],
      },
      {
        id: '10-identity-vault',
        name: 'Identity & Secret Management',
        description: 'Deploy Keycloak OIDC, OpenLDAP directory, OpenBao Vault, and Harbor Registry.',
        mode: 'parallel',
        charts: ['keycloak', 'bao', 'openldap', 'goharbor'],
      },
    ],
  },
  {
    id: 'blueprint-homelab',
    name: 'Self-Hosted Enterprise Collaboration & Homelab Suite',
    version: '1.0.0',
    description:
      'Complete self-hosted productivity cloud with Nextcloud Hub, OpenProject, Keycloak SSO, Mosquitto MQTT IoT broker, and Grafana monitoring.',
    tags: ['homelab', 'nextcloud', 'openproject', 'mqtt', 'grafana'],
    defaultNamespace: 'homelab',
    defaultStorageClass: 'axonwall-zfs-local',
    apps: ['certmanager', 'openebs', 'kubegres', 'keycloak', 'nextcloud', 'openproject', 'mosquitto', 'kube-prometheus-stack'],
    stages: [
      {
        id: '00-foundation',
        name: 'Storage, Database & SSO Foundation',
        description: 'Provision OpenEBS, Kubegres PostgreSQL, Cert-Manager, and Keycloak IAM.',
        mode: 'series',
        charts: ['certmanager', 'openebs', 'kubegres', 'keycloak'],
      },
      {
        id: '10-productivity-iot',
        name: 'Productivity & IoT Services',
        description: 'Deploy Nextcloud Hub, OpenProject, Mosquitto MQTT, and Prometheus/Grafana.',
        mode: 'parallel',
        charts: ['nextcloud', 'openproject', 'mosquitto', 'kube-prometheus-stack'],
      },
    ],
  },
];

export function findVowAppById(id: string): VowAppDefinition | undefined {
  return VOW_APP_CATALOG.find((a) => a.id === id);
}

/**
 * Resolves intra-catalog app dependencies (e.g., `goharbor` -> `kubegres`, `nextcloud` -> `kubegres`, `openebs`).
 */
export function resolveVowAppDependencies(enabledAppIds: string[]): {
  resolvedApps: string[];
  autoAddedDependencies: string[];
} {
  const resolved = new Set<string>();
  const autoAdded: string[] = [];
  const initialSet = new Set(enabledAppIds);

  const visit = (appId: string, isDep: boolean) => {
    const app = findVowAppById(appId);
    if (!app) return;
    for (const depId of app.dependencies ?? []) {
      visit(depId, true);
    }
    if (!resolved.has(appId)) {
      resolved.add(appId);
      if (isDep && !initialSet.has(appId)) {
        autoAdded.push(appId);
      }
    }
  };

  for (const id of enabledAppIds) {
    visit(id, false);
  }

  return {
    resolvedApps: Array.from(resolved),
    autoAddedDependencies: autoAdded,
  };
}

interface ArgoApplicationYaml {
  spec?: {
    source?: {
      repoURL?: string;
      path?: string;
      helm?: { valuesObject?: unknown; values?: unknown };
    };
    destination?: { namespace?: string };
  };
}

/**
 * Synthesizes a FluxCD GitRepository + HelmRelease (or Kustomization) from an ArgoCD Application CRD.
 * Ported directly from `@vow/orchestrator` (`packages/orchestrator/src/flux.ts`).
 */
export function synthesizeFluxFromArgo(
  argoContent: string,
  appName: string,
  fluxNs = 'flux-system',
  resolved: { interval?: string; branch?: string } = {}
): string {
  const interval = resolved.interval ?? '${THIS_FLUX_INTERVAL:-5m}';
  const branch = resolved.branch ?? '${THIS_FLUX_BRANCH:-main}';
  let parsed: ArgoApplicationYaml;
  try {
    parsed = (parseYaml(argoContent, { uniqueKeys: false }) as ArgoApplicationYaml) || {};
  } catch {
    parsed = {};
  }

  const spec = parsed.spec || {};
  const source = spec.source || {};
  const destination = spec.destination || {};
  const targetNs = destination.namespace || '${THIS_NAMESPACE}';
  const repoUrl = source.repoURL || '${THIS_REPO_URL}';
  const chartPath = source.path || '';
  const isHelm = Boolean(source.helm);

  const gitRepoDoc = {
    apiVersion: 'source.toolkit.fluxcd.io/v1',
    kind: 'GitRepository',
    metadata: {
      name: `${appName}-repo`,
      namespace: fluxNs,
    },
    spec: {
      interval,
      url: repoUrl,
      ref: {
        branch,
      },
    },
  };

  if (isHelm) {
    let helmValues: unknown = {};
    const rawValues = source.helm?.valuesObject || source.helm?.values;
    if (rawValues) {
      try {
        helmValues =
          typeof rawValues === 'string'
            ? parseYaml(rawValues, { uniqueKeys: false }) || {}
            : rawValues;
      } catch {
        helmValues = {};
      }
    }

    const helmReleaseDoc = {
      apiVersion: 'helm.toolkit.fluxcd.io/v2',
      kind: 'HelmRelease',
      metadata: {
        name: appName,
        namespace: targetNs,
      },
      spec: {
        interval,
        targetNamespace: targetNs,
        chart: {
          spec: {
            chart: chartPath,
            sourceRef: {
              kind: 'GitRepository',
              name: `${appName}-repo`,
              namespace: fluxNs,
            },
          },
        },
        values: helmValues,
      },
    };

    return `${stringifyYaml(gitRepoDoc).trim()}\n---\n${stringifyYaml(helmReleaseDoc).trim()}\n`;
  }

  const kustomizationDoc = {
    apiVersion: 'kustomize.toolkit.fluxcd.io/v1',
    kind: 'Kustomization',
    metadata: {
      name: appName,
      namespace: fluxNs,
    },
    spec: {
      interval,
      targetNamespace: targetNs,
      prune: true,
      sourceRef: {
        kind: 'GitRepository',
        name: `${appName}-repo`,
      },
      path: `./${chartPath}`,
    },
  };

  return `${stringifyYaml(gitRepoDoc).trim()}\n---\n${stringifyYaml(kustomizationDoc).trim()}\n`;
}

/**
 * Generates an ArgoCD Application CRD for a VOW catalog app on the Axonwall K3s cluster.
 */
export function compileVowArgoApplicationYaml(
  app: VowAppDefinition,
  config: VowConfig,
  override?: VowAppOverride
): string {
  const targetNs = override?.namespace || app.namespace || app.id;
  const storageClass = override?.storageClass || 'axonwall-zfs-local';
  const subdomain = override?.customSubdomain || app.subdomain || app.id;
  const fqdn = `${subdomain}.${config.domain}`;
  const chartPath = app.argoPath || app.initPath || `argo/${app.id}`;

  let customValuesObj: Record<string, unknown> = {};
  if (override?.customValuesYaml?.trim()) {
    try {
      const parsed = parseYaml(override.customValuesYaml, { uniqueKeys: false });
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        customValuesObj = parsed as Record<string, unknown>;
      }
    } catch {
      // Ignore malformed custom override snippet
    }
  }

  const valuesObject: Record<string, unknown> = {
    global: {
      domain: config.domain,
      storageClass,
    },
    ...(app.subdomain
      ? {
          ingress: {
            enabled: true,
            hostname: fqdn,
            tls: config.localTlsMkcert,
            annotations: {
              'cert-manager.io/cluster-issuer': config.localTlsMkcert ? 'mkcert-ca-issuer' : 'letsencrypt-prod',
            },
          },
        }
      : {}),
    ...customValuesObj,
  };

  const argoDoc: Record<string, unknown> = {
    apiVersion: 'argoproj.io/v1alpha1',
    kind: 'Application',
    metadata: {
      name: app.id,
      namespace: 'argocd',
      labels: {
        'app.kubernetes.io/managed-by': 'vigilant-octo-waffle',
        'axonwall.io/plugin': 'vigilant-octo-waffle',
      },
    },
    spec: {
      project: 'default',
      source: {
        repoURL: config.gitRepoUrl,
        targetRevision: config.gitBranch,
        path: chartPath,
        ...(app.isHelm !== false
          ? {
              helm: {
                valuesObject,
              },
            }
          : {}),
      },
      destination: {
        server: 'https://kubernetes.default.svc',
        namespace: targetNs,
      },
      syncPolicy: {
        automated: {
          prune: true,
          selfHeal: true,
        },
        syncOptions: ['CreateNamespace=true', 'ServerSideApply=true'],
      },
    },
  };

  return stringifyYaml(argoDoc).trim();
}

/**
 * Compiles Unbound DNS local-zone and local-data A records for all enabled VOW application subdomains.
 */
export function compileVowUnboundOverrides(state: DesiredState): string {
  const vow = state.vow;
  if (!vow?.enabled || !vow.syncUnboundDns) {
    return '# Vigilant Octo Waffle DNS integration is disabled\n';
  }
  if (!isPluginEnabled('core-k3s', state)) {
    return '# Vigilant Octo Waffle DNS integration skipped: dependency core-k3s is disabled\n';
  }

  const domain = vow.domain || 'vow.axonwall.local';
  const lanIface =
    state.interfaces.find((i) => i.enabled && i.name.toLowerCase() === 'lan' && i.ipv4Address) ||
    state.interfaces.find((i) => i.enabled && inferInterfaceRole(i) === 'lan' && i.ipv4Address) ||
    state.interfaces.find((i) => i.name.toLowerCase() === 'lan');
  const lanIp = lanIface?.ipv4Address?.split('/')[0] || '192.168.1.1';

  const { resolvedApps } = resolveVowAppDependencies(vow.enabledApps ?? []);
  const lines: string[] = [
    `# Vigilant Octo Waffle (VOW) Local DNS Ingress Zone (${domain})`,
    `server:`,
    `  local-zone: "${domain}." transparent`,
    `  local-data: "vow.${domain}. IN A ${lanIp}"`,
  ];

  for (const appId of resolvedApps) {
    const app = findVowAppById(appId);
    if (!app) continue;
    const override = vow.appOverrides?.find((o) => o.appId === appId);
    const sub = override?.customSubdomain || app.subdomain;
    if (!sub) continue;
    lines.push(`  local-data: "${sub}.${domain}. IN A ${lanIp}"`);
  }

  lines.push('');
  return lines.join('\n');
}

/**
 * Compiles the `.env.enabler` configuration compatible with `/home/djehauti/git/DeployCoop/vigilant-octo-waffle`.
 */
export function compileVowEnablerEnv(config: VowConfig): string {
  const { resolvedApps } = resolveVowAppDependencies(config.enabledApps ?? []);
  const enabledSet = new Set(resolvedApps);

  const lines: string[] = [
    '# =============================================================================',
    '# Vigilant Octo Waffle (VOW) — Auto-Generated Environment & Enabler Flags',
    '# Managed by Axonwall Plugin: vigilant-octo-waffle (Requires: core-k3s)',
    '# =============================================================================',
    `CD_RUNNER="${config.cdRunner}"`,
    `K8S_DISTRO="k3s"`,
    `THIS_DOMAIN_NAME="${config.domain}"`,
    `THIS_REPO_URL="${config.gitRepoUrl}"`,
    `THIS_FLUX_BRANCH="${config.gitBranch}"`,
    `THIS_FLUX_INTERVAL="${config.fluxInterval}"`,
    `LOCAL_TLS_MKCERT="${config.localTlsMkcert ? 'true' : 'false'}"`,
    `VOW_AUTHZ_ENABLED="${config.authzEnabled ? 'true' : 'false'}"`,
    '',
    '# Application Enabler Flags',
  ];

  for (const app of VOW_APP_CATALOG) {
    const isEnabled = enabledSet.has(app.id);
    lines.push(`export ${app.enablerVar}=${isEnabled ? 'true' : 'false'}`);
  }

  lines.push('');
  return lines.join('\n');
}

/**
 * Compiles the `.vow/authz.yaml` CASL authorization store configuration.
 */
export function compileVowAuthzYaml(config: VowConfig): string {
  const role = config.defaultRole || 'admin';
  const doc = {
    version: 1,
    enabled: config.authzEnabled,
    defaultRole: role,
    roles: {
      owner: VOW_ROLE_PERMISSIONS.owner,
      admin: VOW_ROLE_PERMISSIONS.admin,
      operator: VOW_ROLE_PERMISSIONS.operator,
      viewer: VOW_ROLE_PERMISSIONS.viewer,
      webhook: VOW_ROLE_PERMISSIONS.webhook,
    },
    principals: [
      {
        id: 'axonwall-admin',
        kind: 'user',
        displayName: 'Axonwall Appliance Administrator',
        role: 'owner',
        grants: [],
        revocations: [],
      },
    ],
  };
  return `# Vigilant Octo Waffle CASL Authorization Policy (.vow/authz.yaml)\n${stringifyYaml(doc)}`;
}

export interface CompiledVowBundle {
  enabled: boolean;
  k3sDependencyMet: boolean;
  resolvedApps: string[];
  autoAddedDependencies: string[];
  estimatedMemoryMb: number;
  argoManifestsYaml: string;
  fluxManifestsYaml: string;
  combinedK3sManifestsYaml: string;
  unboundOverrides: string;
  enablerEnv: string;
  authzYaml: string;
}

/**
 * Compiles the full Vigilant Octo Waffle deployment bundle for Axonwall K3s.
 * Enforces the `core-k3s` plugin dependency before emitting Kubernetes manifests.
 */
export function compileVowBundle(state: DesiredState): CompiledVowBundle {
  const k3sEnabled = isPluginEnabled('core-k3s', state);
  const vowConfig: VowConfig = state.vow ?? VowConfigSchema.parse({ enabled: false });
  const vowRequested = Boolean(
    vowConfig.enabled || state.plugins?.some((p) => p.id === 'vigilant-octo-waffle' && p.enabled)
  );

  if (!vowRequested) {
    return {
      enabled: false,
      k3sDependencyMet: k3sEnabled,
      resolvedApps: [],
      autoAddedDependencies: [],
      estimatedMemoryMb: 0,
      argoManifestsYaml: '# Vigilant Octo Waffle is disabled\n',
      fluxManifestsYaml: '# Vigilant Octo Waffle is disabled\n',
      combinedK3sManifestsYaml: '# Vigilant Octo Waffle is disabled\n',
      unboundOverrides: '# Vigilant Octo Waffle DNS integration is disabled\n',
      enablerEnv: '# Vigilant Octo Waffle is disabled\n',
      authzYaml: '# Vigilant Octo Waffle CASL AuthZ is disabled\n',
    };
  }

  if (!k3sEnabled) {
    const depMsg =
      '# ERROR: Vigilant Octo Waffle (vigilant-octo-waffle) requires the Kubernetes (core-k3s) plugin to be enabled.\n';
    return {
      enabled: false,
      k3sDependencyMet: false,
      resolvedApps: [],
      autoAddedDependencies: [],
      estimatedMemoryMb: 0,
      argoManifestsYaml: depMsg,
      fluxManifestsYaml: depMsg,
      combinedK3sManifestsYaml: depMsg,
      unboundOverrides: depMsg,
      enablerEnv: depMsg,
      authzYaml: depMsg,
    };
  }

  const { resolvedApps, autoAddedDependencies } = resolveVowAppDependencies(vowConfig.enabledApps ?? []);
  let estimatedMemoryMb = 0;
  const argoDocs: string[] = [];
  const fluxDocs: string[] = [];

  for (const appId of resolvedApps) {
    const app = findVowAppById(appId);
    if (!app) continue;
    estimatedMemoryMb += app.estimatedMemoryMb;

    const override = vowConfig.appOverrides?.find((o) => o.appId === appId);
    const argoYaml = compileVowArgoApplicationYaml(app, vowConfig, override);
    argoDocs.push(argoYaml);

    const fluxYaml = synthesizeFluxFromArgo(argoYaml, app.id, 'flux-system', {
      interval: vowConfig.fluxInterval,
      branch: vowConfig.gitBranch,
    });
    fluxDocs.push(fluxYaml.trim());
  }

  const argoManifestsYaml =
    argoDocs.length > 0 ? `${argoDocs.join('\n---\n')}\n` : '# No ArgoCD applications enabled\n';
  const fluxManifestsYaml =
    fluxDocs.length > 0 ? `${fluxDocs.join('\n---\n')}\n` : '# No FluxCD applications enabled\n';

  let combinedK3sManifestsYaml: string;
  if (vowConfig.cdRunner === 'argocd') {
    combinedK3sManifestsYaml = argoManifestsYaml;
  } else if (vowConfig.cdRunner === 'flux') {
    combinedK3sManifestsYaml = fluxManifestsYaml;
  } else {
    combinedK3sManifestsYaml = `${argoManifestsYaml}---\n${fluxManifestsYaml}`;
  }

  return {
    enabled: true,
    k3sDependencyMet: true,
    resolvedApps,
    autoAddedDependencies,
    estimatedMemoryMb,
    argoManifestsYaml,
    fluxManifestsYaml,
    combinedK3sManifestsYaml,
    unboundOverrides: compileVowUnboundOverrides(state),
    enablerEnv: compileVowEnablerEnv(vowConfig),
    authzYaml: compileVowAuthzYaml(vowConfig),
  };
}
