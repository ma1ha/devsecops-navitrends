pipeline {
    agent any

    environment {
        REPORT_DIR = "${WORKSPACE}\\security-reports"
        BUILD_TAG  = "devsecops-${BUILD_NUMBER}"
        VAULT_ADDR = "http://localhost:8200"
    }

    stages {

        stage('Checkout') {
            steps {
                git url: 'https://github.com/ma1ha/devsecops-navitrends',
                    branch: 'main'
            }
        }

stage('Unseal Vault') {
    steps {
        withCredentials([
            string(credentialsId: 'VAULT-UNSEAL-KEY-1', variable: 'KEY1'),
            string(credentialsId: 'VAULT-UNSEAL-KEY-2', variable: 'KEY2'),
            string(credentialsId: 'VAULT-UNSEAL-KEY-3', variable: 'KEY3')
        ]) {
            powershell '''
                $addr = $env:VAULT_ADDR

                # Check status — sealed vault returns non-200 so we catch the error
                try {
                    $status = Invoke-RestMethod -Uri "$addr/v1/sys/health"
                    if ($status.sealed -eq $false) {
                        Write-Host "Vault already unsealed, skipping..."
                        exit 0
                    }
                } catch {
                    Write-Host "Vault is sealed or unreachable, proceeding to unseal..."
                }

                # Unseal
                $body1 = @{ key = $env:KEY1 } | ConvertTo-Json
                $body2 = @{ key = $env:KEY2 } | ConvertTo-Json
                $body3 = @{ key = $env:KEY3 } | ConvertTo-Json
                Invoke-RestMethod -Uri "$addr/v1/sys/unseal" -Method PUT -ContentType "application/json" -Body $body1
                Invoke-RestMethod -Uri "$addr/v1/sys/unseal" -Method PUT -ContentType "application/json" -Body $body2
                Invoke-RestMethod -Uri "$addr/v1/sys/unseal" -Method PUT -ContentType "application/json" -Body $body3
                Write-Host "Vault unsealed successfully"
            '''
        }
    }
}
        stage('Verify Vault Status') {
            steps {
                powershell '''
                    $status = Invoke-RestMethod -Uri "$env:VAULT_ADDR/v1/sys/health"
                    if ($status.sealed -eq $false) {
                        Write-Host "Vault is UNSEALED — Storage: $($status.storage_type) — Version: $($status.version)"
                    } else {
                        Write-Error "Vault is still SEALED"
                        exit 1
                    }
                '''
            }
        }
stage('Load Vault Secrets') {
    steps {
        withCredentials([
            string(credentialsId: 'VAULT-TOKEN', variable: 'VAULT_TOKEN')
        ]) {
            powershell '''
                $addr = $env:VAULT_ADDR
                $headers = @{ "X-Vault-Token" = $env:VAULT_TOKEN }

                function Get-Secret($path) {
                    try {
                        return (Invoke-RestMethod -Uri "$addr/v1/secret/data/$path" -Headers $headers).data.data
                    } catch {
                        Write-Error "Failed to load secret from Vault path: $path -- $_"
                        exit 1
                    }
                }

                function Write-NoBom($path, $content) {
                    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
                    [System.IO.File]::WriteAllText($path, $content, $utf8NoBom)
                }

                function Assert-Keys($name, $obj, $requiredKeys) {
                    $missing = @()

                    foreach ($key in $requiredKeys) {
                        $value = $obj.PSObject.Properties[$key]
                        if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value.Value)) {
                            $missing += $key
                        }
                    }

                    if ($missing.Count -gt 0) {
                        Write-Error "$name secrets missing keys: $($missing -join ', ')"
                        exit 1
                    }

                    Write-Host "$name secrets validated: $($requiredKeys -join ', ')"
                }

                Write-Host "Loading secrets from Vault..."

                $odoo   = Get-Secret "odoo"
                $n8n    = Get-Secret "n8n"
                $nc     = Get-Secret "next_cloud"
                $mautic = Get-Secret "mautic"
                $frappe = Get-Secret "frappe"

                Assert-Keys "odoo"   $odoo   @("POSTGRES_DB","POSTGRES_USER","POSTGRES_PASSWORD")
                Assert-Keys "n8n"    $n8n    @("POSTGRES_DB","POSTGRES_USER","POSTGRES_PASSWORD","ENCRYPTION_KEY","JWT_SECRET")
                Assert-Keys "nextcloud" $nc  @("POSTGRES_DB","POSTGRES_USER","POSTGRES_PASSWORD")
                Assert-Keys "mautic" $mautic @("MYSQL_DB","MYSQL_USER","MYSQL_PASSWORD","MYSQL_ROOT_PASSWORD","ADMIN_EMAIL","ADMIN_USERNAME","ADMIN_PASSWORD")
                Assert-Keys "frappe" $frappe @("MYSQL_ROOT_PASSWORD")

                $ws = $env:WORKSPACE

                Write-NoBom ([IO.Path]::Combine($ws, "odoo", ".env.vault")) @"
ODOO_POSTGRES_DB=$($odoo.POSTGRES_DB)
ODOO_POSTGRES_USER=$($odoo.POSTGRES_USER)
ODOO_POSTGRES_PASSWORD=$($odoo.POSTGRES_PASSWORD)
"@

                Write-NoBom ([IO.Path]::Combine($ws, "n8n", ".env.vault")) @"
N8N_POSTGRES_DB=$($n8n.POSTGRES_DB)
N8N_POSTGRES_USER=$($n8n.POSTGRES_USER)
N8N_POSTGRES_PASSWORD=$($n8n.POSTGRES_PASSWORD)
N8N_ENCRYPTION_KEY=$($n8n.ENCRYPTION_KEY)
N8N_JWT_SECRET=$($n8n.JWT_SECRET)
"@

                Write-NoBom ([IO.Path]::Combine($ws, "nextcloud", ".env.vault")) @"
NC_POSTGRES_DB=$($nc.POSTGRES_DB)
NC_POSTGRES_USER=$($nc.POSTGRES_USER)
NC_POSTGRES_PASSWORD=$($nc.POSTGRES_PASSWORD)
"@

                Write-NoBom ([IO.Path]::Combine($ws, "mautic", ".env.vault")) @"
MAUTIC_MYSQL_DB=$($mautic.MYSQL_DB)
MAUTIC_MYSQL_USER=$($mautic.MYSQL_USER)
MAUTIC_MYSQL_PASSWORD=$($mautic.MYSQL_PASSWORD)
MAUTIC_MYSQL_ROOT_PASSWORD=$($mautic.MYSQL_ROOT_PASSWORD)
MAUTIC_ADMIN_EMAIL=$($mautic.ADMIN_EMAIL)
MAUTIC_ADMIN_USERNAME=$($mautic.ADMIN_USERNAME)
MAUTIC_ADMIN_PASSWORD=$($mautic.ADMIN_PASSWORD)
"@

                Write-NoBom ([IO.Path]::Combine($ws, "frappe", ".env.vault")) @"
FRAPPE_MYSQL_ROOT_PASSWORD=$($frappe.MYSQL_ROOT_PASSWORD)
"@

                Write-Host "All secrets loaded and written to .env.vault files"

                @("odoo", "n8n", "nextcloud", "mautic", "frappe") | ForEach-Object {
                    $f = [IO.Path]::Combine($ws, $_, ".env.vault")
                    if (-not (Test-Path $f)) {
                        Write-Error "$_ .env.vault was not created"
                        exit 1
                    }
                    if ((Get-Item $f).Length -le 0) {
                        Write-Error "$_ .env.vault is empty"
                        exit 1
                    }
                    Write-Host "$_ .env.vault OK"
                }
            '''
        }
    }
}
        stage('Setup') {
            steps {
                bat "if not exist \"${REPORT_DIR}\" mkdir \"${REPORT_DIR}\""
            }
        }
/*
        stage('Secret Detection - Gitleaks') {
            steps {
                script {
                    def exitCode = bat(
                        script: """
                            docker run --rm ^
                                -v "${WORKSPACE}:/repo" ^
                                zricethezav/gitleaks:latest detect ^
                                --source /repo ^
                                --report-format json ^
                                --report-path /repo/security-reports/gitleaks-report.json ^
                                --verbose
                        """,
                        returnStatus: true
                    )
                    if (exitCode != 0) {
                        unstable('Secrets detected in repo! Check gitleaks-report.json')
                    } else {
                        echo "No secrets detected!"
                    }
                }
            }
        }

        stage('Lint - DCLint') {
            steps {
                script {
                    def services = ['n8n', 'mautic', 'odoo', 'nextcloud', 'frappe']
                    services.each { service ->
                        echo "Linting ${service}..."
                        def exitCode = bat(
                            script: """
                                docker run --rm ^
                                    -v "${WORKSPACE}\\${service}:/workspace" ^
                                    zavoloklom/dclint:latest ^
                                    /workspace/docker-compose.yml ^
                                    --format json ^
                                    > "${WORKSPACE}\\security-reports\\dclint-${service}.json" 2>&1
                            """,
                            returnStatus: true
                        )
                        if (exitCode != 0) {
                            unstable("Lint issues found in ${service}!")
                        } else {
                            echo "${service} lint passed!"
                        }
                    }
                }
            }
        }

        stage('SAST - Semgrep') {
            steps {
                script {
                    def exitCode = bat(
                        script: """
                            docker run --rm ^
                                -v "${WORKSPACE}:/src" ^
                                returntocorp/semgrep:latest ^
                                semgrep scan ^
                                --config=auto ^
                                --json ^
                                --output=/src/security-reports/semgrep-report.json ^
                                /src
                        """,
                        returnStatus: true
                    )
                    if (exitCode != 0) {
                        unstable('SAST findings detected! Check semgrep-report.json')
                    } else {
                        echo "SAST scan clean!"
                    }
                }
            }
        }

        stage('Pull Images') {
            steps {
                script {
                    def services = ['n8n', 'nextcloud', 'mautic', 'odoo']
                    services.each { service ->
                        echo "Pulling images for ${service}..."
                        bat """
                            docker compose ^
                                -f ${WORKSPACE}\\${service}\\docker-compose.yml ^
                                --env-file ${WORKSPACE}\\${service}\\.env ^
                                --env-file ${WORKSPACE}\\${service}\\.env.vault ^
                                -p ${service} ^
                                pull
                        """
                    }
                }
            }
        }

        stage('Container Scan - Trivy (Raw Images)') {
            steps {
                script {
                    def images = [
                        [name: 'n8n',       image: 'n8nio/n8n:2.11.4'],
                        [name: 'nextcloud', image: 'nextcloud:33-apache'],
                        [name: 'mautic',    image: 'mautic/mautic:5-apache'],
                        [name: 'odoo',      image: 'odoo:18.0'],
                        [name: 'postgres',  image: 'postgres:15.10'],
                        [name: 'mariadb',   image: 'mariadb:10.11'],
                        [name: 'redis',     image: 'redis:7-alpine']
                    ]
                    images.each { svc ->
                        echo "Scanning ${svc.name}..."
                        def exitCode = bat(
                            script: """
                                docker run --rm ^
                                    -v /var/run/docker.sock:/var/run/docker.sock ^
                                    -v "${REPORT_DIR}:/output" ^
                                    aquasec/trivy:0.50.4 image ^
                                    --format template ^
                                    --template "@contrib/html.tpl" ^
                                    --output /output/trivy-${svc.name}.html ^
                                    --severity HIGH,CRITICAL ^
                                    --timeout 10m ^
                                    ${svc.image}
                            """,
                            returnStatus: true
                        )
                        if (exitCode != 0) {
                            unstable("Vulnerabilities found in ${svc.name}!")
                        } else {
                            echo "${svc.name} scan clean!"
                        }
                    }
                }
            }
        }
*/
        stage('Build Custom Images') {
            steps {
                script {
                    echo "Building custom Mautic image..."
                    bat """
                        docker compose ^
                            -f ${WORKSPACE}\\mautic\\docker-compose.yml ^
                            --env-file ${WORKSPACE}\\mautic\\.env ^
                            --env-file ${WORKSPACE}\\mautic\\.env.vault ^
                            -p mautic ^
                            build --no-cache
                        docker tag mautic-mautic:latest mautic-mautic:${BUILD_TAG}
                    """
                }
            }
        }
/*
        stage('Container Scan - Trivy (Mautic Custom)') {
            steps {
                script {
                    echo "Scanning custom Mautic image..."
                    def exitCode = bat(
                        script: """
                            docker run --rm ^
                                -v /var/run/docker.sock:/var/run/docker.sock ^
                                -v "${REPORT_DIR}:/output" ^
                                aquasec/trivy:0.50.4 image ^
                                --format template ^
                                --template "@contrib/html.tpl" ^
                                --output /output/trivy-mautic-custom.html ^
                                --severity HIGH,CRITICAL ^
                                --timeout 10m ^
                                mautic-mautic:${BUILD_TAG}
                        """,
                        returnStatus: true
                    )
                    if (exitCode != 0) {
                        unstable("Vulnerabilities still found in custom Mautic image!")
                    } else {
                        echo "Custom Mautic image scan clean!"
                    }
                }
            }
        }
        */

        stage('Deploy') {
            steps {
                script {
                    def services = ['n8n', 'nextcloud', 'mautic', 'odoo']
                    services.each { service ->
                        echo "Deploying ${service}..."
                        bat """
                            docker compose ^
                                -f ${WORKSPACE}\\${service}\\docker-compose.yml ^
                                --env-file ${WORKSPACE}\\${service}\\.env ^
                                --env-file ${WORKSPACE}\\${service}\\.env.vault ^
                                -p ${service} ^
                                up -d
                        """
                    }
                }
            }
        }

stage('Health Check') {
    steps {
        script {
            echo "Giving the services 60 seconds to start..."
            sleep(time: 60, unit: 'SECONDS')

            def services = ['odoo-app', 'n8n-app', 'nextcloud-app', 'mautic-app']

            services.each { container ->
                def healthy = false

                for (int attempt = 1; attempt <= 5; attempt++) {
                    def status = bat(
                        script: "docker inspect --format={{.State.Health.Status}} ${container}",
                        returnStdout: true
                    ).trim().readLines().last()

                    echo "${container} health status: ${status}"

                    if (status == 'healthy') {
                        healthy = true
                        echo "${container} is healthy."
                        break
                    }

                    if (attempt < 5) {
                        echo "Still waiting for ${container}... retrying in 20 seconds."
                        sleep(time: 20, unit: 'SECONDS')
                    }
                }

                if (!healthy) {
                    echo "Health check failed for ${container}. Printing details..."
                    bat "docker inspect --format=\"{{json .State.Health}}\" ${container}"
                    bat "docker logs ${container}"
                    unstable("${container} did not become healthy after 5 checks.")
                }
            }
        }
    }
}
stage('DAST - OWASP ZAP') {
    steps {
        script {
            def targets = [
                [name: 'odoo',      url: 'http://host.docker.internal:8069'],
                [name: 'n8n',       url: 'http://host.docker.internal:5678'],
                [name: 'nextcloud', url: 'http://host.docker.internal:8082'],
                [name: 'mautic',    url: 'http://host.docker.internal:8081']
            ]

            targets.each { svc ->
                echo "ZAP scanning ${svc.name} at ${svc.url}..."
                def exitCode = bat(
                    script: """
                        docker run --rm ^
                            --add-host=host.docker.internal:host-gateway ^
                            -v "${REPORT_DIR}:/zap/wrk" ^
                            ghcr.io/zaproxy/zaproxy:stable ^
                            zap-baseline.py ^
                            -t ${svc.url} ^
                            -r zap-${svc.name}.html ^
                            -I
                    """,
                    returnStatus: true
                )

                if (exitCode != 0) {
                    unstable("ZAP found issues in ${svc.name}!")
                } else {
                    echo "${svc.name} ZAP scan clean!"
                }
            }
        }
    }
}
    }

    post {
        always {
            powershell '''
                $files = @(
                    "$env:WORKSPACE\\odoo\\.env.vault",
                    "$env:WORKSPACE\\n8n\\.env.vault",
                    "$env:WORKSPACE\\nextcloud\\.env.vault",
                    "$env:WORKSPACE\\mautic\\.env.vault",
                    "$env:WORKSPACE\\frappe\\.env.vault"
                )
                foreach ($f in $files) {
                    if (Test-Path $f) { Remove-Item $f -Force; Write-Host "Deleted $f" }
                }
            '''
            archiveArtifacts artifacts: 'security-reports/**/*', allowEmptyArchive: true
            echo "Security reports archived."
        }
        unstable {
            echo "Pipeline completed with warnings — review security reports before production."
        }
        success {
            echo "Pipeline completed successfully — all checks passed."
        }
        failure {
            echo "Pipeline failed — check the logs."
        }
    }
}