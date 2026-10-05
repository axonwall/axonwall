#!/usr/bin/env bash
set -euo pipefail

# Axonwall Cloud VIP Failover Hook for Virtual Machines
# Triggered by keepalived notify_master / notify_backup scripts or HA supervisor

PROVIDER="${1:-aws}" # aws | azure | gcp
ACTION="${2:-master}" # master | backup
VIP="${3:-192.168.100.1}"
INTERFACE_ID="${4:-eni-0123456789abcdef0}"

echo "[axonwall-cloud-ha] Triggering VIP failover for provider=${PROVIDER}, action=${ACTION}, vip=${VIP}"

case "${PROVIDER}" in
  aws)
    if [[ "${ACTION}" == "master" ]]; then
      echo "[aws] Assigning secondary private IP ${VIP} to ${INTERFACE_ID}..."
      aws ec2 assign-private-ip-addresses \
        --network-interface-id "${INTERFACE_ID}" \
        --private-ip-addresses "${VIP}" \
        --allow-reassignment
    else
      echo "[aws] Standing by as backup node."
    fi
    ;;

  azure)
    ROUTE_TABLE="${5:-axonwall-rt}"
    RESOURCE_GROUP="${6:-axonwall-rg}"
    NEXT_HOP="${7:-10.0.1.4}"
    if [[ "${ACTION}" == "master" ]]; then
      echo "[azure] Updating UDR route table ${ROUTE_TABLE} default hop to ${NEXT_HOP}..."
      az network route-table route update \
        --resource-group "${RESOURCE_GROUP}" \
        --route-table-name "${ROUTE_TABLE}" \
        --name "default-egress" \
        --next-hop-ip-address "${NEXT_HOP}"
    fi
    ;;

  gcp)
    ROUTE_NAME="${5:-axonwall-default-route}"
    INSTANCE_NAME="${6:-axonwall-node-01}"
    ZONE="${7:-us-central1-a}"
    if [[ "${ACTION}" == "master" ]]; then
      echo "[gcp] Updating route ${ROUTE_NAME} next hop instance to ${INSTANCE_NAME}..."
      gcloud compute routes delete "${ROUTE_NAME}" --quiet || true
      gcloud compute routes create "${ROUTE_NAME}" \
        --destination-range "0.0.0.0/0" \
        --next-hop-instance "${INSTANCE_NAME}" \
        --next-hop-instance-zone "${ZONE}"
    fi
    ;;

  *)
    echo "Unknown cloud provider: ${PROVIDER}"
    exit 1
    ;;
esac

echo "[axonwall-cloud-ha] Failover hook completed successfully."
