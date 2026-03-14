param(
    [string]$VAULT_ADDR  = "http://localhost:8200",
    [string]$VAULT_TOKEN = $env:VAULT_ROOT_TOKEN
)

$HEADERS = @{ "X-Vault-Token" = $VAULT_TOKEN }

function Get-VaultSecret {
    param($path, $field)
    $response = Invoke-RestMethod `
        -Uri "$VAULT_ADDR/v1/secret/data/$path" `
        -Headers $HEADERS
    return $response.data.data.$field
}

Write-Host "Pulling secrets from Vault..."

$env:ODOO_POSTGRES_DB       = Get-VaultSecret "odoo" "POSTGRES_DB"
$env:ODOO_POSTGRES_USER     = Get-VaultSecret "odoo" "POSTGRES_USER"
$env:ODOO_POSTGRES_PASSWORD = Get-VaultSecret "odoo" "POSTGRES_PASSWORD"

# N8N
$env:N8N_POSTGRES_DB                    = Get-VaultSecret "n8n" "POSTGRES_DB"
$env:N8N_POSTGRES_USER                  = Get-VaultSecret "n8n" "POSTGRES_USER"
$env:N8N_POSTGRES_PASSWORD              = Get-VaultSecret "n8n" "POSTGRES_PASSWORD"
$env:N8N_ENCRYPTION_KEY                 = Get-VaultSecret "n8n" "ENCRYPTION_KEY"
$env:N8N_JWT_SECRET = Get-VaultSecret "n8n" "JWT_SECRET"

# NEXTCLOUD
$env:NC_POSTGRES_DB       = Get-VaultSecret "next_cloud" "POSTGRES_DB"
$env:NC_POSTGRES_USER     = Get-VaultSecret "next_cloud" "POSTGRES_USER"
$env:NC_POSTGRES_PASSWORD = Get-VaultSecret "next_cloud" "POSTGRES_PASSWORD"

# FRAPPE

$env:FRAPPE_MYSQL_ROOT_PASSWORD = Get-VaultSecret "frappe" "MYSQL_ROOT_PASSWORD"

# MAUTIC
$env:MAUTIC_MYSQL_DB            = Get-VaultSecret "mautic" "MYSQL_DB"
$env:MAUTIC_MYSQL_USER          = Get-VaultSecret "mautic" "MYSQL_USER"
$env:MAUTIC_MYSQL_PASSWORD      = Get-VaultSecret "mautic" "MYSQL_PASSWORD"
$env:MAUTIC_MYSQL_ROOT_PASSWORD = Get-VaultSecret "mautic" "MYSQL_ROOT_PASSWORD"
$env:MAUTIC_ADMIN_EMAIL         = Get-VaultSecret "mautic" "ADMIN_EMAIL"
$env:MAUTIC_ADMIN_USERNAME      = Get-VaultSecret "mautic" "ADMIN_USERNAME"
$env:MAUTIC_ADMIN_PASSWORD      = Get-VaultSecret "mautic" "ADMIN_PASSWORD"
Write-Host "All secrets loaded into environment!"