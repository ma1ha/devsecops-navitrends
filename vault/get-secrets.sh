#!/bin/bash

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_ROOT_TOKEN}"

if [ -z "$VAULT_TOKEN" ]; then
  echo " ERROR: VAULT_ROOT_TOKEN is not set!"
  echo "Run: export VAULT_ROOT_TOKEN=your-token-here"
  exit 1
fi

get_secret() {
  local path=$1
  local field=$2
  curl -s \
    --header "X-Vault-Token: $VAULT_TOKEN" \
    "http://127.0.0.1:8200/v1/secret/data/$path" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['data']['$field'])"
}

echo " Pulling secrets from Vault..."

# ODOO
export ODOO_POSTGRES_DB=$(get_secret "odoo" "POSTGRES_DB")
export ODOO_POSTGRES_USER=$(get_secret "odoo" "POSTGRES_USER")
export ODOO_POSTGRES_PASSWORD=$(get_secret "odoo" "POSTGRES_PASSWORD")

# N8N
export N8N_POSTGRES_DB=$(get_secret "n8n" "POSTGRES_DB")
export N8N_POSTGRES_USER=$(get_secret "n8n" "POSTGRES_USER")
export N8N_POSTGRES_PASSWORD=$(get_secret "n8n" "POSTGRES_PASSWORD")
export N8N_ENCRYPTION_KEY=$(get_secret "n8n" "ENCRYPTION_KEY")
export N8N_JWT_SECRET=$(get_secret "n8n" "JWT_SECRET")

# NEXTCLOUD
export NC_POSTGRES_DB=$(get_secret "next_cloud" "POSTGRES_DB")
export NC_POSTGRES_USER=$(get_secret "next_cloud" "POSTGRES_USER")
export NC_POSTGRES_PASSWORD=$(get_secret "next_cloud" "POSTGRES_PASSWORD")

# MAUTIC
export MAUTIC_MYSQL_DB=$(get_secret "mautic" "MYSQL_DB")
export MAUTIC_MYSQL_USER=$(get_secret "mautic" "MYSQL_USER")
export MAUTIC_MYSQL_PASSWORD=$(get_secret "mautic" "MYSQL_PASSWORD")
export MAUTIC_MYSQL_ROOT_PASSWORD=$(get_secret "mautic" "MYSQL_ROOT_PASSWORD")
export MAUTIC_ADMIN_EMAIL=$(get_secret "mautic" "ADMIN_EMAIL")
export MAUTIC_ADMIN_USERNAME=$(get_secret "mautic" "ADMIN_USERNAME")
export MAUTIC_ADMIN_PASSWORD=$(get_secret "mautic" "ADMIN_PASSWORD")

# FRAPPE
export FRAPPE_MYSQL_ROOT_PASSWORD=$(get_secret "frappe" "FRAPPE_MYSQL_ROOT_PASSWORD")
export FRAPPE_ADMIN_PASSWORD=$(get_secret "frappe" "FRAPPE_ADMIN_PASSWORD")
export FRAPPE_ENCRYPTION_KEY=$(get_secret "frappe" "FRAPPE_ENCRYPTION_KEY")

# WAZUH
export WAZUH_MANAGER_IP=$(get_secret "wazuh" "MANAGER_IP")
export WAZUH_AGENT_NAME=$(get_secret "wazuh" "AGENT_NAME")
export WAZUH_API_USER=$(get_secret "wazuh" "API_USER")
export WAZUH_API_PASS=$(get_secret "wazuh" "API_PASS")
export WAZUH_REGISTRATION_PASS=$(get_secret "wazuh" "REGISTRATION_PASS")
export WAZUH_DASHBOARD_USER=$(get_secret "wazuh" "DASHBOARD_USER")
export WAZUH_DASHBOARD_PASS=$(get_secret "wazuh" "DASHBOARD_PASS")
export WAZUH_INDEXER_PASS=$(get_secret "wazuh" "INDEXER_PASS")
export WAZUH_KIBANA_PASS=$(get_secret "wazuh" "KIBANA_PASS")
#WORDPRESS
export WORDPRESS_DB_NAME=$(get_secret "wordpress" "MYSQL_DATABASE")
export WORDPRESS_DB_USER=$(get_secret "wordpress" "MYSQL_USER")
export WORDPRESS_DB_PASSWORD=$(get_secret "wordpress" "MYSQL_PASSWORD")
export WORDPRESS_DB_ROOT_PASSWORD=$(get_secret "wordpress" "MYSQL_ROOT_PASSWORD")
export WORDPRESS_TABLE_PREFIX=$(get_secret "wordpress" "TABLE_PREFIX")
export WORDPRESS_AUTH_KEY=$(get_secret "wordpress" "AUTH_KEY")
export WORDPRESS_SECURE_AUTH_KEY=$(get_secret "wordpress" "SECURE_AUTH_KEY")
export WORDPRESS_LOGGED_IN_KEY=$(get_secret "wordpress" "LOGGED_IN_KEY")
export WORDPRESS_NONCE_KEY=$(get_secret "wordpress" "NONCE_KEY")
export WORDPRESS_AUTH_SALT=$(get_secret "wordpress" "AUTH_SALT")
export WORDPRESS_SECURE_AUTH_SALT=$(get_secret "wordpress" "SECURE_AUTH_SALT")
export WORDPRESS_LOGGED_IN_SALT=$(get_secret "wordpress" "LOGGED_IN_SALT")
export WORDPRESS_NONCE_SALT=$(get_secret "wordpress" "NONCE_SALT")
echo ""
echo " All secrets loaded into environment!"
echo ""
