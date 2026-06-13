#!/bin/bash

echo "Creating Vault roles..."

SERVICES=("odoo" "n8n" "nextcloud" "mautic" "frappe" "wazuh" "jenkins")

for SERVICE in "${SERVICES[@]}"; do
  kubectl exec -n vault vault-0 -- vault write auth/kubernetes/role/$SERVICE \
    bound_service_account_names=$SERVICE \
    bound_service_account_namespaces=$SERVICE \
    policies=$SERVICE \
    alias_name_source=serviceaccount_name \
    audience="k3s" \
    token_ttl=1h
  echo "Created role: $SERVICE"
done

echo "All roles created!"
kubectl exec -n vault vault-0 -- vault list auth/kubernetes/role