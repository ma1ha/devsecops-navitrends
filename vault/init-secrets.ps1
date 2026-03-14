param(
    [string]$VAULT_ADDR  = "http://localhost:8200",
    [string]$VAULT_TOKEN = $env:VAULT_ROOT_TOKEN
)

$HEADERS = @{ 
    "X-Vault-Token" = $VAULT_TOKEN
    "Content-Type"  = "application/json"
}

function Set-VaultSecret {
    param($path, $data)
    $body = @{ data = $data } | ConvertTo-Json
    Invoke-RestMethod -Uri "$VAULT_ADDR/v1/secret/data/$path" `
        -Method POST -Headers $HEADERS -Body $body
    Write-Host "✅ $path saved"
}

Write-Host "Initializing Vault secrets..."

Set-VaultSecret "odoo" @{
    POSTGRES_DB       = "odoo_prod"
    POSTGRES_USER     = "odoo_prod"
    POSTGRES_PASSWORD = "odoo_prod"
}

Set-VaultSecret "n8n" @{
    POSTGRES_DB       = "n8n"
    POSTGRES_USER     = "n8n"
    POSTGRES_PASSWORD = "n8n"
    ENCRYPTION_KEY    = "jQ0cr19zmp992Vb09tlpRgNn0rdlxImB"
    JWT_SECRET        = "jQ0cr19zmp992Vb09tlpRgNn0rdlxImB"
}

Set-VaultSecret "next_cloud" @{
    POSTGRES_DB       = "nextcloud"
    POSTGRES_USER     = "nextcloud"
    POSTGRES_PASSWORD = "nextcloud"
}

Set-VaultSecret "mautic" @{
    MYSQL_DB            = "mautic"
    MYSQL_USER          = "mautic"
    MYSQL_PASSWORD      = "mautic"
    MYSQL_ROOT_PASSWORD = "mautic"
    ADMIN_EMAIL         = "ameniboukottaya@gmail.com"
    ADMIN_USERNAME      = "admin"
    ADMIN_PASSWORD      = "admin"
}

Set-VaultSecret "frappe" @{
    MYSQL_ROOT_PASSWORD = "frappe"
}

Write-Host "✅ All secrets initialized!"