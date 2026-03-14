pipeline {
    agent any

    environment {
        REPORT_DIR = "${WORKSPACE}\\security-reports"
        BUILD_TAG  = "devsecops-${BUILD_NUMBER}"
        VAULT_ADDR = "http://localhost:8200"
    }

    stages {

        stage('Start Vault') {
            steps {
                script {
                    def vaultRunning = bat(
                        script: 'docker ps --filter "name=vault" --filter "status=running" -q',
                        returnStdout: true
                    ).trim()

                    if (!vaultRunning) {
                        echo "Starting Vault..."
                        bat "docker compose -f ${WORKSPACE}\\vault\\docker-compose.yml up -d"
                        sleep(time: 5, unit: 'SECONDS')
                    } else {
                        echo "Vault already running!"
                    }
                }
            }
        }

        stage('Init Vault Secrets') {
            steps {
                withCredentials([string(credentialsId: 'vault-token', variable: 'VAULT_TOKEN')]) {
                    script {
                        def response = bat(
                            script: """
                                curl -s -o nul -w "%%{http_code}" ^
                                -H "X-Vault-Token: %VAULT_TOKEN%" ^
                                http://localhost:8200/v1/secret/data/odoo
                            """,
                            returnStdout: true
                        ).trim()

                        def statusCode = response[-3..-1]

                        if (statusCode == '404') {
                            echo "Secrets not found, initializing..."
                            bat """
                                powershell -ExecutionPolicy Bypass -Command ^
                                "$env:VAULT_ROOT_TOKEN = '%VAULT_TOKEN%'; ^
                                .\\vault\\init-secrets.ps1"
                            """
                            echo "Vault secrets initialized!"
                        } else {
                            echo "Vault secrets already exist!"
                        }
                    }
                }
            }
        }

        stage('Checkout') {
            steps {
                git url: 'https://github.com/ma1ha/devsecops-navitrends',
                    branch: 'main'
            }
        }

        stage('Setup') {
            steps {
                bat "if not exist \"${REPORT_DIR}\" mkdir \"${REPORT_DIR}\""
            }
        }

        stage('Load Vault Secrets') {
            steps {
                withCredentials([string(credentialsId: 'vault-token', variable: 'VAULT_TOKEN')]) {
                    script {
                        def secrets = [
                            [path: 'odoo',       key: 'POSTGRES_DB',         env: 'ODOO_POSTGRES_DB'],
                            [path: 'odoo',       key: 'POSTGRES_USER',       env: 'ODOO_POSTGRES_USER'],
                            [path: 'odoo',       key: 'POSTGRES_PASSWORD',   env: 'ODOO_POSTGRES_PASSWORD'],
                            [path: 'n8n',        key: 'POSTGRES_DB',         env: 'N8N_POSTGRES_DB'],
                            [path: 'n8n',        key: 'POSTGRES_USER',       env: 'N8N_POSTGRES_USER'],
                            [path: 'n8n',        key: 'POSTGRES_PASSWORD',   env: 'N8N_POSTGRES_PASSWORD'],
                            [path: 'n8n',        key: 'ENCRYPTION_KEY',      env: 'N8N_ENCRYPTION_KEY'],
                            [path: 'n8n',        key: 'JWT_SECRET',          env: 'N8N_JWT_SECRET'],
                            [path: 'next_cloud', key: 'POSTGRES_DB',         env: 'NC_POSTGRES_DB'],
                            [path: 'next_cloud', key: 'POSTGRES_USER',       env: 'NC_POSTGRES_USER'],
                            [path: 'next_cloud', key: 'POSTGRES_PASSWORD',   env: 'NC_POSTGRES_PASSWORD'],
                            [path: 'mautic',     key: 'MYSQL_DB',            env: 'MAUTIC_MYSQL_DB'],
                            [path: 'mautic',     key: 'MYSQL_USER',          env: 'MAUTIC_MYSQL_USER'],
                            [path: 'mautic',     key: 'MYSQL_PASSWORD',      env: 'MAUTIC_MYSQL_PASSWORD'],
                            [path: 'mautic',     key: 'MYSQL_ROOT_PASSWORD', env: 'MAUTIC_MYSQL_ROOT_PASSWORD'],
                            [path: 'mautic',     key: 'ADMIN_EMAIL',         env: 'MAUTIC_ADMIN_EMAIL'],
                            [path: 'mautic',     key: 'ADMIN_USERNAME',      env: 'MAUTIC_ADMIN_USERNAME'],
                            [path: 'mautic',     key: 'ADMIN_PASSWORD',      env: 'MAUTIC_ADMIN_PASSWORD'],
                            [path: 'frappe',     key: 'MYSQL_ROOT_PASSWORD', env: 'FRAPPE_MYSQL_ROOT_PASSWORD'],
                        ]

                        secrets.each { s ->
                            def raw = bat(
                                script: """
                                    curl -s ^
                                    -H "X-Vault-Token: %VAULT_TOKEN%" ^
                                    http://localhost:8200/v1/secret/data/${s.path}
                                """,
                                returnStdout: true
                            ).trim()

                            // strip windows cmd echo lines, keep only json
                            def jsonText = raw.readLines()
                                .find { it.trim().startsWith('{') }

                            def json = new groovy.json.JsonSlurper().parseText(jsonText)
                            env."${s.env}" = json.data.data."${s.key}"
                        }
                        echo "All Vault secrets loaded!"
                    }
                }
            }
        }

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

        stage('Lint - dclint') {
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
                                    lint /workspace ^
                                    --format json ^
                                    --output /workspace/dclint-report.json
                            """,
                            returnStatus: true
                        )
                        bat """
                            if exist "${WORKSPACE}\\${service}\\dclint-report.json" ^
                                copy "${WORKSPACE}\\${service}\\dclint-report.json" ^
                                "${REPORT_DIR}\\dclint-report-${service}.json"
                        """
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
                        bat "docker compose -f ${WORKSPACE}\\${service}\\docker-compose.yml pull"
                    }
                }
            }
        }

        stage('Container Scan - Trivy') {
            steps {
                script {
                    def images = [
                        [name: 'n8n',       image: 'n8nio/n8n:1.82.3'],
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

        stage('Deploy') {
            steps {
                script {
                    def services = ['n8n', 'nextcloud', 'mautic', 'odoo']
                    services.each { service ->
                        echo "Deploying ${service}..."
                        bat "docker compose -f ${WORKSPACE}\\${service}\\docker-compose.yml up -d"
                    }
                }
            }
        }

        stage('Health Check') {
            steps {
                script {
                    echo "Waiting 30s for services to start..."
                    sleep(time: 30, unit: 'SECONDS')

                    def checks = [
                        [name: 'Odoo',      cmd: 'docker exec odoo-app wget -qO- http://localhost:8069/web/health'],
                        [name: 'n8n',       cmd: 'docker exec n8n-app wget -qO- http://localhost:5678/healthz'],
                        [name: 'Nextcloud', cmd: 'docker exec nextcloud-app curl -sf http://localhost/status.php'],
                        [name: 'Mautic',    cmd: 'docker exec mautic-app curl -sf http://localhost']
                    ]

                    checks.each { check ->
                        def exitCode = bat(script: check.cmd, returnStatus: true)
                        if (exitCode != 0) {
                            unstable("${check.name} health check failed!")
                        } else {
                            echo "${check.name} is up!"
                        }
                    }
                }
            }
        }

    }

    post {
        always {
            archiveArtifacts artifacts: 'security-reports/**/*',
                             allowEmptyArchive: true
            echo "Security reports archived."
        }
        unstable {
            echo "Pipeline completed with warnings - review reports before production."
        }
        success {
            echo "Pipeline completed successfully - all checks passed."
        }
        failure {
            echo "Pipeline failed - check the logs."
        }
    }
}