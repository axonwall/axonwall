#!/usr/bin/env bash
# ==============================================================================
# update-kubeconfig.sh — Axonwall K3s Credentials & ~/.kube/config Synchronizer
#
# Retrieves administrative credentials from an Axonwall K3s cluster and
# merges/writes them into the current user's ~/.kube/config file.
#
# Supports:
#   • Local execution directly on an Axonwall host (/etc/rancher/k3s/k3s.yaml)
#   • Remote execution over SSH from an administrator's workstation/laptop
#   • Automatic failover VIP resolution (e.g. 10.80.0.200:6443)
#   • Non-destructive merging into existing ~/.kube/config with automated backup
# ==============================================================================
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
KUBEDIR="${HOME}/.kube"
DEFAULT_KUBECONFIG="${KUBECONFIG:-${KUBEDIR}/config}"

TARGET_HOST=""
SERVER_OVERRIDE=""
CONTEXT_NAME="axonwall-k3s"
USER_NAME="axonwall-admin"
CLUSTER_NAME="axonwall-k3s"
USE_VIP=false
OVERWRITE=false
PRINT_ONLY=false
SSH_USER="${USER:-thoth3430}"
SSH_PORT="22"

show_help() {
  cat <<EOF
Usage:
  ${SCRIPT_NAME} [options] [HOST]

Arguments:
  HOST                      Remote appliance hostname or IP (e.g. 10.80.0.200, thoth3430@10.80.0.202).
                            If omitted, the script inspects the local machine (/etc/rancher/k3s/k3s.yaml).

Options:
  -s, --server <URL>        Override the Kubernetes API server URL (e.g. https://10.80.0.200:6443).
      --vip                 Use cluster HA floating Virtual IP (10.80.0.200:6443) instead of localhost.
  -c, --context <name>      Name of the context and cluster to create or update (default: ${CONTEXT_NAME}).
  -u, --user <name>         Name of the user credentials entry (default: ${USER_NAME}).
  -o, --output <path>       Target kubeconfig file path (default: ${DEFAULT_KUBECONFIG}).
  -f, --force, --overwrite  Overwrite the target kubeconfig completely instead of merging contexts.
  -p, --print               Print the generated kubeconfig YAML to stdout instead of writing to disk.
      --port <port>         SSH port for remote connections (default: 22).
  -h, --help                Show this help message.

Examples:
  # On an Axonwall appliance (klaxon/saxon):
  ${SCRIPT_NAME}                      # Sets up ~/.kube/config for the current user
  ${SCRIPT_NAME} --vip                # Points ~/.kube/config to the HA Virtual IP (10.80.0.200:6443)

  # On your admin workstation:
  ${SCRIPT_NAME} 10.80.0.200          # Fetches credentials via SSH from the HA cluster VIP
  ${SCRIPT_NAME} thoth3430@10.80.0.202 # Fetches credentials from klaxon node
EOF
}

# Parse command line options
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_help
      exit 0
      ;;
    -s|--server)
      SERVER_OVERRIDE="$2"
      shift 2
      ;;
    --vip)
      USE_VIP=true
      shift
      ;;
    -c|--context)
      CONTEXT_NAME="$2"
      CLUSTER_NAME="$2"
      shift 2
      ;;
    -u|--user)
      USER_NAME="$2"
      shift 2
      ;;
    -o|--output)
      DEFAULT_KUBECONFIG="$2"
      shift 2
      ;;
    -f|--force|--overwrite)
      OVERWRITE=true
      shift
      ;;
    -p|--print)
      PRINT_ONLY=true
      shift
      ;;
    --port)
      SSH_PORT="$2"
      shift 2
      ;;
    -*)
      echo "Unknown option: $1" >&2
      show_help >&2
      exit 1
      ;;
    *)
      if [[ -z "${TARGET_HOST}" ]]; then
        TARGET_HOST="$1"
        shift
      else
        echo "Unexpected argument: $1" >&2
        show_help >&2
        exit 1
      fi
      ;;
  esac
done

# Temporary files cleanup
TMP_DIR="$(mktemp -d /tmp/axonwall-kubeconfig.XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT

RAW_YAML="${TMP_DIR}/raw.yaml"
PROCESSED_YAML="${TMP_DIR}/processed.yaml"

# 1. Fetch raw kubeconfig YAML
if [[ -z "${TARGET_HOST}" ]]; then
  # Local mode: read /etc/rancher/k3s/k3s.yaml
  LOCAL_K3S_CONFIG="/etc/rancher/k3s/k3s.yaml"
  if [[ ! -f "${LOCAL_K3S_CONFIG}" ]]; then
    echo "Error: ${LOCAL_K3S_CONFIG} not found on this system." >&2
    echo "If you are running on your workstation, please specify the appliance IP:" >&2
    echo "  ${SCRIPT_NAME} 10.80.0.200" >&2
    exit 1
  fi

  if [[ -r "${LOCAL_K3S_CONFIG}" ]]; then
    cp "${LOCAL_K3S_CONFIG}" "${RAW_YAML}"
  else
    if command -v sudo >/dev/null 2>&1; then
      echo "Elevating with sudo to read ${LOCAL_K3S_CONFIG}..."
      sudo cat "${LOCAL_K3S_CONFIG}" > "${RAW_YAML}"
      # Also ensure the axonwall-api group can read it in the future
      if getent group axonwall-api >/dev/null 2>&1; then
        sudo chown :axonwall-api "${LOCAL_K3S_CONFIG}" 2>/dev/null || true
        sudo chmod 0640 "${LOCAL_K3S_CONFIG}" 2>/dev/null || true
      fi
    else
      echo "Error: Cannot read ${LOCAL_K3S_CONFIG} and sudo is not available." >&2
      exit 1
    fi
  fi
else
  # Remote mode: fetch over SSH
  SSH_TARGET="${TARGET_HOST}"
  CLEAN_IP="${TARGET_HOST}"
  if [[ "${TARGET_HOST}" == *"@"* ]]; then
    CLEAN_IP="${TARGET_HOST#*@}"
  fi

  echo "Fetching K3s configuration from ${SSH_TARGET}..."
  ssh -p "${SSH_PORT}" "${SSH_TARGET}" "sudo cat /etc/rancher/k3s/k3s.yaml 2>/dev/null || cat /etc/rancher/k3s/k3s.yaml" > "${RAW_YAML}"
fi

if [[ ! -s "${RAW_YAML}" ]]; then
  echo "Error: Failed to obtain valid kubeconfig from source." >&2
  exit 1
fi

# 2. Determine target API server endpoint
SERVER_URL=""
if [[ -n "${SERVER_OVERRIDE}" ]]; then
  SERVER_URL="${SERVER_OVERRIDE}"
elif [[ "${USE_VIP}" == "true" ]]; then
  # Try to find HA VIP if local, or fallback to default Axonwall LAN VIP 10.80.0.200
  HA_VIP="10.80.0.200"
  if [[ -f "/etc/axonwall/ha.yaml" ]]; then
    FOUND_VIP="$(python3 -c '
import re
with open("/etc/axonwall/ha.yaml") as f:
    vips = re.findall(r"-\s*([0-9.]+)/\d+", f.read())
lan_vips = [v for v in vips if v.startswith("10.") or v.startswith("192.168.") or re.match(r"^172\.(1[6-9]|2\d|3[01])\.", v)]
print(lan_vips[0] if lan_vips else (vips[0] if vips else "10.80.0.200"))
' 2>/dev/null || true)"
    if [[ -n "${FOUND_VIP}" ]]; then
      HA_VIP="${FOUND_VIP}"
    fi
  fi
  SERVER_URL="https://${HA_VIP}:6443"
elif [[ -n "${TARGET_HOST}" ]]; then
  # For remote hosts, point to remote host IP instead of 127.0.0.1
  CLEAN_IP="${TARGET_HOST}"
  [[ "${TARGET_HOST}" == *"@"* ]] && CLEAN_IP="${TARGET_HOST#*@}"
  SERVER_URL="https://${CLEAN_IP}:6443"
else
  # Local host default: 127.0.0.1
  SERVER_URL="https://127.0.0.1:6443"
fi

# 3. Process YAML: update server endpoint, cluster, user, and context names
python3 - <<EOF
import re, sys

try:
    with open("${RAW_YAML}", "r") as f:
        content = f.read()

    server_url = "${SERVER_URL}"
    cluster_name = "${CLUSTER_NAME}"
    user_name = "${USER_NAME}"
    context_name = "${CONTEXT_NAME}"

    if server_url:
        content = re.sub(r"(\s*server:\s*)https?://[^\s]+", rf"\g<1>{server_url}", content)

    content = re.sub(r"(\s*name:\s*)default(\s*\ncontexts:)", rf"\g<1>{cluster_name}\g<2>", content)
    content = re.sub(r"(\s*cluster:\s*)default", rf"\g<1>{cluster_name}", content)
    content = re.sub(r"(\s*user:\s*)default", rf"\g<1>{user_name}", content)
    content = re.sub(r"(\s*name:\s*)default(\s*\ncurrent-context:)", rf"\g<1>{context_name}\g<2>", content)
    content = re.sub(r"(\s*current-context:\s*)default", rf"\g<1>{context_name}", content)
    content = re.sub(r"(\s*-\s*name:\s*)default(\s*\n\s*user:)", rf"\g<1>{user_name}\g<2>", content)

    with open("${PROCESSED_YAML}", "w") as f:
        f.write(content)
except Exception as e:
    sys.exit(2)
EOF

PY_STATUS=$?
if [[ ${PY_STATUS} -ne 0 ]]; then
  # Fallback: using sed
  sed -e "s|server: https://127.0.0.1:6443|server: ${SERVER_URL}|g" \
      -e "s|name: default|name: ${CONTEXT_NAME}|g" \
      -e "s|cluster: default|cluster: ${CLUSTER_NAME}|g" \
      -e "s|user: default|user: ${USER_NAME}|g" \
      -e "s|current-context: default|current-context: ${CONTEXT_NAME}|g" \
      "${RAW_YAML}" > "${PROCESSED_YAML}"
fi

# 4. Print or Save to kubeconfig
if [[ "${PRINT_ONLY}" == "true" ]]; then
  cat "${PROCESSED_YAML}"
  exit 0
fi

TARGET_DIR="$(dirname "${DEFAULT_KUBECONFIG}")"
mkdir -p "${TARGET_DIR}"
chmod 700 "${TARGET_DIR}"

if [[ -f "${DEFAULT_KUBECONFIG}" ]] && [[ -s "${DEFAULT_KUBECONFIG}" ]] && [[ "${OVERWRITE}" == "false" ]]; then
  # Backup existing config
  BACKUP_PATH="${DEFAULT_KUBECONFIG}.bak.$(date +%Y%m%d%H%M%S)"
  cp "${DEFAULT_KUBECONFIG}" "${BACKUP_PATH}"
  echo "Existing kubeconfig backed up to: ${BACKUP_PATH}"

  if command -v kubectl >/dev/null 2>&1; then
    echo "Merging context '${CONTEXT_NAME}' into ${DEFAULT_KUBECONFIG}..."
    MERGED_CONF="${TMP_DIR}/merged.yaml"
    KUBECONFIG="${DEFAULT_KUBECONFIG}:${PROCESSED_YAML}" kubectl config view --flatten > "${MERGED_CONF}"
    mv "${MERGED_CONF}" "${DEFAULT_KUBECONFIG}"
    kubectl --kubeconfig="${DEFAULT_KUBECONFIG}" config use-context "${CONTEXT_NAME}" >/dev/null 2>&1 || true
  else
    # Simple replace if kubectl is not available locally
    cp "${PROCESSED_YAML}" "${DEFAULT_KUBECONFIG}"
  fi
else
  echo "Writing credentials to ${DEFAULT_KUBECONFIG}..."
  cp "${PROCESSED_YAML}" "${DEFAULT_KUBECONFIG}"
fi

chmod 600 "${DEFAULT_KUBECONFIG}"

echo "✓ Successfully installed K3s credentials for context '${CONTEXT_NAME}' into ${DEFAULT_KUBECONFIG}"
echo "  Server: ${SERVER_URL}"

# 5. Connection Verification
if command -v kubectl >/dev/null 2>&1; then
  echo ""
  echo "Testing cluster connectivity with kubectl..."
  if kubectl --kubeconfig="${DEFAULT_KUBECONFIG}" --request-timeout='6s' get nodes -o wide 2>/dev/null; then
    echo ""
    echo "✓ Cluster connectivity verified! You can now run:"
    echo "    kubectl get nodes"
    echo "    kubectl get pods -A"
  else
    echo "Notice: Could not contact API server at ${SERVER_URL} immediately."
    echo "If you are using an HA VIP or remote IP, ensure network connectivity and firewall rules."
  fi
fi
