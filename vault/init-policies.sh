#!/bin/bash

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_ROOT_TOKEN}"

if [ -z "$VAULT_TOKEN" ]; then
  echo "ERROR: VAULT_ROOT_TOKEN is not set!"
  exit 1
fi

write_policy() {
  local name=$1
  local policy=$2

  response=$(curl -s -o /dev/null -w "%{http_code}" \
    --header "X-Vault-Token: $VAULT_TOKEN" \
    --header "Content-Type: application/json" \
    --request PUT \
    --data "{\"policy\": \"$policy\"}" \
    "$VAULT_ADDR/v1/sys/policies/acl/$name")

  if [ "$response" == "204" ]; then
    echo " Policy $name created"
  else
    echo " Failed to create policy $name (HTTP $response)"
  fi
}

echo "Creating Vault policies..."

write_policy "odoo" "path \\\"secret\/data\/odoo\\\" { capabilities = [\\\"read\\\"] }"
write_policy "n8n" "path \\\"secret\/data\/n8n\\\" { capabilities = [\\\"read\\\"] }"
write_policy "nextcloud" "path \\\"secret\/data\/next_cloud\\\" { capabilities = [\\\"read\\\"] }"
write_policy "mautic" "path \\\"secret\/data\/mautic\\\" { capabilities = [\\\"read\\\"] }"
write_policy "frappe" "path \\\"secret\/data\/frappe\\\" { capabilities = [\\\"read\\\"] }"
write_policy "wazuh" "path \\\"secret\/data\/wazuh\\\" { capabilities = [\\\"read\\\"] }"
write_policy "jenkins" "path \\\"secret\/data\/*\\\" { capabilities = [\\\"read\\\", \\\"list\\\"] }"
write_policy "wordpress" "path \\\"secret/data/wordpress\\\" { capabilities = [\\\"read\\\"] }"
echo ""
echo "All policies done!"
