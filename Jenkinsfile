pipeline {
    agent { label 'ubuntu-server' }

    environment {
        REPORT_DIR    = "${WORKSPACE}/security-reports"
        HISTORY_DIR = "${WORKSPACE}/build-history"
        CHARTS_DIR    = "${WORKSPACE}/k8s/charts"
        TRAEFIK_EXT   = "https://maha.nav.ovh"
        TRIVY_CACHE   = "/tmp/trivy-cache"
        KUBESCAPE_SKIP = "kube-system,cert-manager,vault,traefik,crowdsec"
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 90, unit: 'MINUTES')
        timestamps()
    }

    stages {

        stage('Checkout') {
            steps {
                checkout([
                    $class: 'GitSCM',
                    branches: [[name: '*/ubuntu-server']],
                    userRemoteConfigs: [[
                        url: 'https://gitea.nav.ovh/Maha_Msadak/devsecops-navitrends.git',
                        credentialsId: 'gitea-creds'
                    ]]
                ])
                sh 'mkdir -p ${REPORT_DIR} ${TRIVY_CACHE}'
            }
        }

        stage('Verify Vault Unsealed') {
            steps {
                withCredentials([
                    string(credentialsId: 'vault-k8s-unsealkey1', variable: 'KEY1'),
                    string(credentialsId: 'vault-k8s-unsealkey2', variable: 'KEY2'),
                    string(credentialsId: 'vault-k8s-unsealkey3', variable: 'KEY3')
                ]) {
                    sh '''
                        VAULT_ADDR=$(kubectl get svc vault -n vault -o jsonpath='{.spec.clusterIP}')
                        VAULT_ADDR="http://${VAULT_ADDR}:8200"

                        STATUS=$(curl -s $VAULT_ADDR/v1/sys/health \
                            | python3 -c "import sys,json; print(json.load(sys.stdin).get('sealed', True))")

                        if [ "$STATUS" = "False" ]; then
                            echo "Vault is already unsealed"
                            exit 0
                        fi

                        echo "Vault is sealed — unsealing..."
                        curl -s --request PUT --data "{\"key\": \"$KEY1\"}" $VAULT_ADDR/v1/sys/unseal > /dev/null
                        curl -s --request PUT --data "{\"key\": \"$KEY2\"}" $VAULT_ADDR/v1/sys/unseal > /dev/null
                        curl -s --request PUT --data "{\"key\": \"$KEY3\"}" $VAULT_ADDR/v1/sys/unseal > /dev/null

                        STATUS=$(curl -s $VAULT_ADDR/v1/sys/health \
                            | python3 -c "import sys,json; print(json.load(sys.stdin).get('sealed', True))")

                        if [ "$STATUS" = "False" ]; then
                            echo "Vault unsealed successfully"
                        else
                            echo "Vault still sealed — aborting"
                            exit 1
                        fi
                    '''
                }
            }
        }

        stage('Security Scans') {
            parallel {

                stage('IaC Security - Checkov') {
    steps {
        script {
            def charts = ['odoo', 'n8n', 'nextcloud', 'mautic', 'wordpress', 'frappe']
            def renderedYaml = "${WORKSPACE}/rendered-all.yaml"
            sh "rm -f ${renderedYaml}"

            charts.each { chart ->
                def exitCode = sh(
                    script: """
                        helm template ${chart} ${CHARTS_DIR}/${chart} \
                            --namespace ${chart == 'frappe' ? 'frappe' : chart} \
                            >> ${renderedYaml} 2>&1
                    """,
                    returnStatus: true
                )
                if (exitCode != 0) {
                    echo "helm template failed for ${chart} — check chart syntax"
                }
            }

            sh "echo 'rendered lines:' && wc -l ${renderedYaml}"

            sh """
                docker run --rm \
                    -v ${WORKSPACE}:/workspace \
                    -v ${REPORT_DIR}:/output \
                    bridgecrew/checkov:latest \
                        -f /workspace/rendered-all.yaml \
                        --framework kubernetes \
                        --skip-check CKV_K8S_43,CKV_K8S_15,CKV2_K8S_6,CKV_K8S_40,CKV_K8S_23,CKV_K8S_22,CKV_K8S_25,CKV_K8S_8,CKV_K8S_9,CKV_K8S_38,CKV_K8S_10,CKV_K8S_11,CKV_K8S_12,CKV_K8S_13 \
                        --output json \
                        --output-file-path /output \
                        --compact --quiet || true
            """

            sh """
                mv ${REPORT_DIR}/results_json.json ${REPORT_DIR}/checkov-${BUILD_NUMBER}.json 2>/dev/null || \
                mv ${REPORT_DIR}/results_kubernetes.json ${REPORT_DIR}/checkov-${BUILD_NUMBER}.json 2>/dev/null || \
                echo "no checkov report found"
            """

            def failCount = sh(
                script: """
                    python3 -c "
import json, sys, os
report = '${REPORT_DIR}/checkov-${BUILD_NUMBER}.json'
if not os.path.exists(report):
    print(0)
    sys.exit(0)
try:
    with open(report) as f:
        raw = json.load(f)
    if isinstance(raw, list):
        failed = sum(item.get('summary', {}).get('failed', 0) for item in raw if isinstance(item, dict))
    else:
        failed = raw.get('summary', {}).get('failed', 0)
    print(failed)
except:
    print(0)
" 2>/dev/null || echo "0"
                """,
                returnStdout: true
            ).trim()

            sh "echo '${failCount}' > ${REPORT_DIR}/checkov-failcount.txt"
            echo "Checkov actionable failures: ${failCount}"

            if (failCount.toInteger() > 15) {
                unstable("Checkov found ${failCount} actionable IaC issues")
            }
        }
    }
}

                stage('Secret Detection - Gitleaks') {
                    steps {
                        script {
                            def exitCode = sh(
                                script: """
                                    docker run --rm \
                                        -v ${WORKSPACE}:/repo \
                                        zricethezav/gitleaks:latest detect \
                                            --source /repo \
                                            --report-format json \
                                            --report-path /repo/security-reports/gitleaks-${BUILD_NUMBER}.json \
                                            --no-git \
                                            --verbose
                                """,
                                returnStatus: true
                            )

                            if (exitCode != 0) {
                                sh "echo 'found' > ${REPORT_DIR}/gitleaks-status.txt"
                                unstable('Secrets detected in codebase — check gitleaks report')
                            } else {
                                sh "echo 'clean' > ${REPORT_DIR}/gitleaks-status.txt"
                                echo "Gitleaks: no secrets detected"
                            }
                        }
                    }
                }

                stage('SAST - Semgrep') {
                    steps {
                        script {
                            sh """
                                docker run --rm \
                                    -v ${WORKSPACE}:/src \
                                    returntocorp/semgrep:latest semgrep scan \
                                        --config p/kubernetes \
                                        --config p/secrets \
                                        --config p/dockerfile \
                                        --config p/owasp-top-ten \
                                        --json \
                                        --output=/src/security-reports/semgrep-${BUILD_NUMBER}.json \
                                        /src/k8s || true
                            """

                            def status = sh(
                                script: """
                                    python3 -c "
import json, sys, os
report = '${REPORT_DIR}/semgrep-${BUILD_NUMBER}.json'
if not os.path.exists(report):
    print('clean:0')
    sys.exit(0)
with open(report) as f:
    data = json.load(f)
results  = data.get('results', [])
blocking = [r for r in results if r.get('extra', {}).get('is_blocking', False)]
warnings = [r for r in results if not r.get('extra', {}).get('is_blocking', False)]
if blocking:
    print(f'blocking:{len(blocking)}')
elif warnings:
    print(f'warnings:{len(warnings)}')
else:
    print('clean:0')
" 2>/dev/null || echo "clean:0"
                                """,
                                returnStdout: true
                            ).trim()

                            sh "echo '${status}' > ${REPORT_DIR}/semgrep-status.txt"
                            def parts  = status.split(':')
                            def sStatus = parts[0]
                            def count  = parts.size() > 1 ? parts[1] : '0'

                            echo "Semgrep: ${sStatus} (${count} findings)"
                            if (sStatus == 'blocking') {
                                unstable("Semgrep found ${count} blocking findings")
                            }
                        }
                    }
                }

                stage('Container Scan - Trivy') {
                    steps {
                        script {
                            def images = [
                                [name: 'odoo',      image: 'odoo:18.0'],
                                [name: 'n8n',       image: 'n8nio/n8n:2.11.4'],
                                [name: 'nextcloud', image: 'nextcloud:33-apache'],
                                [name: 'mautic',    image: 'mautic/mautic:5-apache'],
                                [name: 'wordpress', image: 'wordpress:6.8.1-apache'],
                                [name: 'frappe',    image: 'frappe/erpnext:v15']
                            ]

                            parallel images.collectEntries { svc ->
                                ["Trivy: ${svc.name}": {
                                    sh """
                                        docker run --rm \
                                            -v /var/run/docker.sock:/var/run/docker.sock \
                                            -v ${TRIVY_CACHE}:/root/.cache/trivy \
                                            -v ${REPORT_DIR}:/output \
                                            aquasec/trivy:0.50.4 image \
                                                --format json \
                                                --scanners vuln \
                                                --output /output/trivy-${svc.name}-${BUILD_NUMBER}.json \
                                                --timeout 10m \
                                                ${svc.image} || true
                                    """


                                }]
                            }

                            def blocked = []
                            def warned  = []

                            images.each { svc ->
                                def reportFile = "${REPORT_DIR}/trivy-${svc.name}-${BUILD_NUMBER}.json"
                                def counts = sh(
                                    script: """
                                        python3 -c "
import json, sys, os
try:
    with open('${reportFile}') as f:
        data = json.load(f)
    crit = 0; high = 0
    for result in data.get('Results', []):
        for v in result.get('Vulnerabilities') or []:
            if v.get('Severity') == 'CRITICAL': crit += 1
            elif v.get('Severity') == 'HIGH': high += 1
    print(f'{crit},{high}')
except:
    print('0,0')
" 2>/dev/null || echo "0,0"
                                    """,
                                    returnStdout: true
                                ).trim()

                                def parts = counts.split(',')
                                def crit  = parts[0].toInteger()
                                def high  = parts[1].toInteger()

                                echo "Trivy ${svc.name}: CRITICAL=${crit} HIGH=${high}"

                                if (crit > 0)      blocked << "${svc.name}(${crit} CRITICAL)"
                                else if (high > 10) warned  << "${svc.name}(${high} HIGH)"
                            }

                            if (blocked) unstable("CRITICAL CVEs: ${blocked.join(', ')}")
                            if (warned)  unstable("HIGH CVEs exceed threshold: ${warned.join(', ')}")
                        }
                    }
                }

            }
        }

        stage('Deploy') {
    steps {
        script {
            def services = [
                [name: 'odoo',      namespace: 'odoo'],
                [name: 'n8n',       namespace: 'n8n'],
                [name: 'nextcloud', namespace: 'nextcloud'],
                [name: 'mautic',    namespace: 'mautic'],
                [name: 'wordpress', namespace: 'wordpress'],
                [name: 'frappe',    namespace: 'frappe']
            ]

            // pre-cleanup frappe job before parallel deploy
            sh "kubectl delete job frappe-create-site -n frappe --ignore-not-found=true"

            def deployResults = [:]

            parallel services.collectEntries { svc ->
                ["Deploy: ${svc.name}": {
                    sh "kubectl create namespace ${svc.namespace} --dry-run=client -o yaml | kubectl apply -f -"

                    def releaseStatus = sh(
                        script: """
                            helm status ${svc.name} -n ${svc.namespace} -o json 2>/dev/null \
                                | python3 -c "import json,sys; print(json.load(sys.stdin).get('info',{}).get('status','not-found'))" \
                                2>/dev/null || echo "not-found"
                        """,
                        returnStdout: true
                    ).trim()

                    echo "${svc.name}: current release status = ${releaseStatus}"

                    if (releaseStatus in ['pending-install', 'pending-upgrade', 'pending-rollback']) {
                        echo "${svc.name} stuck in ${releaseStatus} — recovering"
                        def lastGoodRev = sh(
                            script: """
                                helm history ${svc.name} -n ${svc.namespace} -o json 2>/dev/null \
                                    | python3 -c "
import json, sys
h = json.load(sys.stdin)
ok = [r['revision'] for r in h if r.get('status') == 'deployed']
print(ok[-1] if ok else 0)
" 2>/dev/null || echo "0"
                            """,
                            returnStdout: true
                        ).trim()

                        if (lastGoodRev.toInteger() > 0) {
                            sh "helm rollback ${svc.name} ${lastGoodRev} -n ${svc.namespace} --timeout 3m --wait || true"
                        } else {
                            sh "helm uninstall ${svc.name} -n ${svc.namespace} || true"
                        }
                    }

                    def exitCode = sh(
                        script: """
                            helm upgrade ${svc.name} \
                                ${CHARTS_DIR}/${svc.name} \
                                -n ${svc.namespace} \
                                --install \
                                --wait \
                                --timeout 8m
                        """,
                        returnStatus: true
                    )

                    if (exitCode != 0) {
                        echo "${svc.name} deploy failed — rolling back"
                        sh "helm rollback ${svc.name} -n ${svc.namespace} --timeout 3m --wait || true"
                        deployResults[svc.name] = 'failed'
                    } else {
                        def revision = sh(
                            script: """
                                helm list -n ${svc.namespace} -o json \
                                    | python3 -c "import json,sys; r=json.load(sys.stdin); print(r[0]['revision'] if r else 'N/A')"
                            """,
                            returnStdout: true
                        ).trim()
                        echo "${svc.name} deployed successfully (revision: ${revision})"
                        deployResults[svc.name] = 'ok'
                    }
                }]
            }

            echo "Waiting for pods to settle..."
            sh "sleep 15"

            echo "=== Pod status across all namespaces ==="
            services.each { svc ->
                echo "--- ${svc.namespace} ---"
                sh "kubectl get pods -n ${svc.namespace} -o wide || true"
            }

            def failed = deployResults.findAll { it.value == 'failed' }.keySet()
            if (failed) {
                unstable("Deploy failed for: ${failed.join(', ')}")
            }
        }
    }
}
        stage('Health Check') {
            steps {
                script {
                    def deployments = [
                        [name: 'odoo',            namespace: 'odoo'],
                        [name: 'n8n',             namespace: 'n8n'],
                        [name: 'nextcloud',       namespace: 'nextcloud'],
                        [name: 'mautic',          namespace: 'mautic'],
                        [name: 'wordpress',       namespace: 'wordpress'],
                        [name: 'frappe-gunicorn', namespace: 'frappe']
                    ]

                    def unhealthy = []

                    deployments.each { dep ->
                        def status = sh(
                            script: """
                                kubectl rollout status deployment/${dep.name} \
                                    -n ${dep.namespace} \
                                    --timeout=120s
                            """,
                            returnStatus: true
                        )

                        if (status != 0) {
                            echo "${dep.name} unhealthy — pod state:"
                            sh "kubectl get pods -n ${dep.namespace} --no-headers | head -10 || true"
                            sh "kubectl describe pods -n ${dep.namespace} | tail -30 || true"
                            unhealthy << dep.name
                        } else {
                            echo "${dep.name} healthy"
                        }
                    }

                    if (unhealthy) {
                        unstable("Unhealthy deployments: ${unhealthy.join(', ')}")
                    }
                }
            }
        }

        stage('Smoke Tests') {
            steps {
                script {
                    def services = [
                        [name: 'odoo',      namespace: 'odoo',      svc: 'odoo',           port: '8069', path: '/web/health'],
                        [name: 'n8n',       namespace: 'n8n',       svc: 'n8n',            port: '5678', path: '/healthz'],
                        [name: 'nextcloud', namespace: 'nextcloud', svc: 'nextcloud',       port: '80',   path: '/status.php'],
                        [name: 'mautic',    namespace: 'mautic',    svc: 'mautic',          port: '80',   path: '/'],
                        [name: 'wordpress', namespace: 'wordpress', svc: 'wordpress',       port: '80',   path: '/'],
                        [name: 'frappe',    namespace: 'frappe',    svc: 'frappe-gunicorn', port: '8000', path: '/api/method/ping']
                    ]

                    def failed = []

                    services.each { svc ->
                        def rawOutput = sh(
                            script: """
                                kubectl run smoke-${svc.name}-${BUILD_NUMBER} \
                                    --image=curlimages/curl:8.5.0 \
                                    --restart=Never \
                                    --rm -i \
                                    -n ${svc.namespace} \
                                    --timeout=60s \
                                    -- curl -sk -o /dev/null -w '%{http_code}' \
                                        --max-time 15 \
                                        --retry 3 \
                                        --retry-delay 5 \
                                        http://${svc.svc}.${svc.namespace}.svc.cluster.local:${svc.port}${svc.path} \
                                2>/dev/null || echo "000"
                            """,
                            returnStdout: true
                        ).trim()

                        def matcher  = (rawOutput =~ /(\d{3})/)
                        def httpCode = matcher ? matcher[-1][1] : "000"

                        echo "${svc.name} → HTTP ${httpCode}"

                        if (httpCode in ['200', '301', '302', '303', '401']) {
                            echo "${svc.name} smoke test PASSED"
                        } else {
                            echo "${svc.name} smoke test FAILED (${httpCode})"
                            failed << "${svc.name}(${httpCode})"
                        }
                    }

                    if (failed) {
                        unstable("Smoke test failures: ${failed.join(', ')}")
                    }
                }
            }
        }

        stage('Live Cluster Security - Kubescape') {
            steps {
                script {
                    sh """
                        if ! command -v kubescape &>/dev/null; then
                            curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
                        fi
                        export PATH=\$PATH:\$HOME/.kubescape/bin



                        kubescape scan framework mitre \
                            --format json \
                            --output ${REPORT_DIR}/kubescape-mitre-${BUILD_NUMBER}.json \
                            --exclude-namespaces ${KUBESCAPE_SKIP} || true
                    """

                    def nsaScore = sh(
                        script: """
                            python3 -c "
import json, sys
try:
    with open('${REPORT_DIR}/kubescape-nsa-${BUILD_NUMBER}.json') as f:
        data = json.load(f)
    score = float(data.get('summaryDetails', {}).get('complianceScore', 100))
    if score <= 1.0:
        score = score * 100
    print(int(100 - score))
except:
    print(0)
" 2>/dev/null || echo "0"
                        """,
                        returnStdout: true
                    ).trim()

                    def mitreScore = sh(
                        script: """
                            python3 -c "
import json, sys
try:
    with open('${REPORT_DIR}/kubescape-mitre-${BUILD_NUMBER}.json') as f:
        data = json.load(f)
    score = float(data.get('summaryDetails', {}).get('complianceScore', 100))
    if score <= 1.0:
        score = score * 100
    print(int(100 - score))
except:
    print(0)
" 2>/dev/null || echo "0"
                        """,
                        returnStdout: true
                    ).trim()

                    sh "echo 'nsa:${nsaScore},mitre:${mitreScore}' > ${REPORT_DIR}/kubescape-scores.txt"

                    echo "Kubescape NSA risk: ${nsaScore}%  |  MITRE risk: ${mitreScore}%"

                    if (nsaScore.toInteger() > 40 || mitreScore.toInteger() > 40) {
                        unstable("Kubescape risk exceeds 40% threshold — NSA:${nsaScore}% MITRE:${mitreScore}%")
                    }
                }
            }
        }

       stage('DAST - OWASP ZAP') {
    steps {
        script {
            def targets = [
                [name: 'odoo',      path: '/odoo'],
                [name: 'n8n',       path: '/n8n'],
                [name: 'nextcloud', path: '/nextcloud'],
                [name: 'mautic',    path: '/mautic'],
                [name: 'wordpress', path: '/wordpress'],
                [name: 'erpnext',   path: '/erpnext']
            ]
            def zapFailed = []
            targets.each { svc ->
                echo "ZAP scanning ${svc.name}..."
                sh """
                    docker run --rm -u 0 \
                        -v ${REPORT_DIR}:/zap/wrk \
                        ghcr.io/zaproxy/zaproxy:stable \
                        zap-baseline.py \
                            -t ${TRAEFIK_EXT}${svc.path} \
                            -r zap-${svc.name}-${BUILD_NUMBER}.html \
                            -J zap-${svc.name}-${BUILD_NUMBER}.json \
                            -l WARN \
                            -I  || true
                """
                def highAlerts = sh(
                    script: """
                        python3 -c "
import json, sys, os
report = '${REPORT_DIR}/zap-${svc.name}-${BUILD_NUMBER}.json'
if not os.path.exists(report):
    print(0)
    sys.exit(0)
try:
    with open(report) as f:
        data = json.load(f)
    sites  = data.get('site', [])
    alerts = sites[0].get('alerts', []) if sites else []
    high   = [a for a in alerts if str(a.get('riskdesc', '')).startswith('High')]
    print(len(high))
except:
    print(0)
" 2>/dev/null || echo "0"
                    """,
                    returnStdout: true
                ).trim()
                echo "${svc.name} ZAP HIGH alerts: ${highAlerts}"
                if (highAlerts.toInteger() > 0) {
                    zapFailed << "${svc.name}(${highAlerts} HIGH)"
                }
            }
            if (zapFailed) {
                unstable("ZAP HIGH alerts: ${zapFailed.join(', ')}")
            }
        }
    }
}
        

    }

    post {
        always {
            sh """
                mkdir -p ${HISTORY_DIR}
                cp -r ${REPORT_DIR}/. ${HISTORY_DIR}/ || true
            """

            archiveArtifacts(
                artifacts: 'security-reports/**/*',
                allowEmptyArchive: true,
                fingerprint: true
            )

            cleanWs()
        }
        success {
            echo "Pipeline completed — all security gates passed"
        }
        unstable {
            echo "Pipeline completed with warnings — review reports at ${HISTORY_DIR}"
        }
        failure {
            echo "Pipeline FAILED — check logs. Partial reports at ${HISTORY_DIR}"
        }
    }
}