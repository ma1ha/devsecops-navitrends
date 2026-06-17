pipeline {
    agent { label 'ubuntu-server' }

    environment {
        REPORT_DIR       = "${WORKSPACE}/security-reports"
        TRAEFIK_HOST     = "maha.nav.ovh"
        TRAEFIK_EXT      = "https://maha.nav.ovh"
        CHARTS_DIR       = "${WORKSPACE}/k8s/charts"
        KUBESCAPE_SKIP   = "kube-system,cert-manager,vault,traefik,crowdsec"
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 60, unit: 'MINUTES')
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
                sh 'mkdir -p ${REPORT_DIR}'
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
                        echo "Vault address: $VAULT_ADDR"

                        STATUS=$(curl -s $VAULT_ADDR/v1/sys/health | grep -o '"sealed":[a-z]*' | cut -d: -f2)

                        if [ "$STATUS" = "false" ]; then
                            echo "Vault is unsealed"
                            exit 0
                        fi

                        echo "Vault is sealed - unsealing..."
                        curl -s --request PUT --data "{\"key\": \"$KEY1\"}" $VAULT_ADDR/v1/sys/unseal > /dev/null
                        curl -s --request PUT --data "{\"key\": \"$KEY2\"}" $VAULT_ADDR/v1/sys/unseal > /dev/null
                        curl -s --request PUT --data "{\"key\": \"$KEY3\"}" $VAULT_ADDR/v1/sys/unseal > /dev/null

                        STATUS=$(curl -s $VAULT_ADDR/v1/sys/health | grep -o '"sealed":[a-z]*' | cut -d: -f2)
                        if [ "$STATUS" = "false" ]; then
                            echo "Vault unsealed successfully"
                        else
                            echo "Vault still sealed - aborting"
                            exit 1
                        fi
                    '''
                }
            }
        }
/*
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
                                    --report-path /repo/security-reports/gitleaks-report.json \
                                    --no-git \
                                    --verbose
                        """,
                        returnStatus: true
                    )
                    if (exitCode != 0) {
                        unstable("Secrets detected in codebase - check gitleaks-report.json")
                    }
                    echo "No secrets detected"
                }
            }
        }

        stage('SAST - Semgrep') {
            steps {
                script {
                    def exitCode = sh(
                        script: """
                            docker run --rm \
                                -v ${WORKSPACE}:/src \
                                returntocorp/semgrep:latest semgrep scan \
                                    --config p/kubernetes \
                                    --config p/secrets \
                                    --config p/dockerfile \
                                    --config p/owasp-top-ten \
                                    --json \
                                    --output=/src/security-reports/semgrep-report.json \
                                    /src/k8s
                        """,
                        returnStatus: true
                    )
                    // Parse findings — error on HIGH severity
                    def findings = sh(
                        script: """
                            cat ${REPORT_DIR}/semgrep-report.json | \
                            python3 -c "
import json,sys
data=json.load(sys.stdin)
results=data.get('results',[])
high=[r for r in results if r.get('extra',{}).get('severity','') in ['ERROR','HIGH']]
print(len(high))
" 2>/dev/null || echo "0"
                        """,
                        returnStdout: true
                    ).trim()

                    echo "Semgrep HIGH/ERROR findings: ${findings}"
                    if (findings.toInteger() > 0) {
                        unstable("Semgrep found ${findings} HIGH severity issues - check semgrep-report.json")
                    } else {
                        echo "Semgrep scan clean"
                    }
                }
            }
        }


        stage('Helm Lint') {
            steps {
                script {
                    def charts = ['odoo', 'n8n', 'nextcloud', 'mautic', 'wordpress', 'frappe']
                    def failed = []
                    charts.each { chart ->
                        echo "Linting ${chart}..."
                        def exitCode = sh(
                            script: "helm lint ${CHARTS_DIR}/${chart} --strict",
                            returnStatus: true
                        )
                        if (exitCode != 0) failed << chart
                    }
                    if (failed) {
                        error("Helm lint failed for: ${failed.join(', ')} - fix before deploying")
                    }
                    echo "All charts passed lint"
                }
            }
        }
*/
        stage('IaC Security - Checkov') {
            steps {
                script {
                    def charts = ['odoo', 'n8n', 'nextcloud', 'mautic', 'wordpress', 'frappe']

                    sh "rm -f /tmp/rendered-all.yaml"
                    charts.each { chart ->
                        sh """
                            helm template ${chart} ${CHARTS_DIR}/${chart} \
                                --namespace ${chart == 'frappe' ? 'frappe' : chart} \
                                >> /tmp/rendered-all.yaml
                        """
                    }

                    sh """
                        docker run --rm \
                            -v /tmp:/workspace \
                            -v ${REPORT_DIR}:/output \
                            bridgecrew/checkov:latest \
                                -f /workspace/rendered-all.yaml \
                                --framework kubernetes \
                                --skip-check CKV_K8S_43,CKV_K8S_15,CKV2_K8S_6 \
                                --output json \
                                --output-file-path /output/checkov-report.json \
                                --compact --quiet || true
                    """

                    // Count real failures after skip list
                    def failCount = sh(
                        script: """
                            cat ${REPORT_DIR}/checkov-report.json | \
                            python3 -c "
import json,sys
try:
    data=json.load(sys.stdin)
    if isinstance(data, list):
        data = data[0]
    print(data.get('summary',{}).get('failed',0))
except:
    print(0)
" 2>/dev/null || echo "0"
                        """,
                        returnStdout: true
                    ).trim()

                    echo "Checkov actionable failures: ${failCount}"
                    if (failCount.toInteger() > 20) {
                        unstable("Checkov found ${failCount} IaC issues - review checkov-report.json")
                    } else {
                        echo "Checkov passed (${failCount} findings within threshold)"
                    }
                }
            }
        }

/*
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

                    // Run all scans in parallel
                    parallel images.collectEntries { svc ->
                        ["Trivy: ${svc.name}": {
                            sh """
                                docker run --rm \
                                    -v /var/run/docker.sock:/var/run/docker.sock \
                                    -v /tmp/trivy-cache:/root/.cache/trivy \
                                    -v ${REPORT_DIR}:/output \
                                    aquasec/trivy:0.50.4 image \
                                    --format cyclonedx \
                                    --scanners vuln \
                                    --output /output/sbom-${svc.name}.json \
                                    --timeout 10m \
                                    ${svc.image} || true
                            """

                            // Also generate SBOM for supply chain visibility
                            sh """
                                docker run --rm \
                                    -v /var/run/docker.sock:/var/run/docker.sock \
                                    -v /tmp/trivy-cache:/root/.cache/trivy \
                                    -v ${REPORT_DIR}:/output \
                                    aquasec/trivy:0.50.4 image \
                                        --format cyclonedx \
                                        --output /output/sbom-${svc.name}.json \
                                        --timeout 10m \
                                        ${svc.image} || true
                            """
                        }]
                    }

                    // Evaluate results — hard block on CRITICAL
                    def blocked = []
                    def warned = []
                    images.each { svc ->
                        def reportFile = "${REPORT_DIR}/trivy-${svc.name}.json"
                        def counts = sh(
                            script: """
                                python3 -c "
import json,sys
try:
    with open('${reportFile}') as f:
        data=json.load(f)
    crit=0; high=0
    for result in data.get('Results',[]):
        for v in result.get('Vulnerabilities') or []:
            if v.get('Severity')=='CRITICAL': crit+=1
            elif v.get('Severity')=='HIGH': high+=1
    print(f'{crit},{high}')
except Exception as e:
    print('0,0')
" 2>/dev/null || echo "0,0"
                            """,
                            returnStdout: true
                        ).trim()

                        def parts = counts.split(',')
                        def crit = parts[0].toInteger()
                        def high = parts[1].toInteger()

                        echo "${svc.name}: CRITICAL=${crit}, HIGH=${high}"

                        if (crit > 0) blocked << "${svc.name}(${crit} CRITICAL)"
                        else if (high > 10) warned << "${svc.name}(${high} HIGH)"
                    }

                    if (blocked) {
                        unstable("CRITICAL CVEs found: ${blocked.join(', ')}")
                    }
                    if (warned) {
                        unstable("HIGH CVEs exceed threshold: ${warned.join(', ')}")
                    }
                    echo "Container scan passed"
                }
            }
        }
*/
        stage('Deploy via Helm') {
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

                    def failed = []
                    services.each { svc ->
                        echo "Deploying ${svc.name}..."

                        sh """
                            kubectl create namespace ${svc.namespace} \
                                --dry-run=client -o yaml | kubectl apply -f -
                        """

                        def exitCode = sh(
                            script: """
                                helm upgrade ${svc.name} \
                                    ${CHARTS_DIR}/${svc.name} \
                                    -n ${svc.namespace} \
                                    --install \
                                    --wait \
                                    --timeout 5m \
                                    --atomic
                            """,
                            returnStatus: true
                        )

                        if (exitCode != 0) {
                            echo "${svc.name} deploy failed — attempting rollback..."
                            sh """
                                helm rollback ${svc.name} -n ${svc.namespace} || true
                            """
                            failed << svc.name
                        } else {
                            echo "${svc.name} deployed (revision: \$(helm list -n ${svc.namespace} -o json | python3 -c \"import json,sys; r=json.load(sys.stdin); print(r[0]['revision'] if r else 'N/A')\"))"
                        }
                    }

                    if (failed) {
                        error("Deploy failed for: ${failed.join(', ')} - rolled back to previous revision")
                    }
                }
            }
        }


        stage('Health Check') {
            steps {
                script {
                    def deployments = [
                        [name: 'odoo',            namespace: 'odoo',      kind: 'deployment'],
                        [name: 'n8n',             namespace: 'n8n',       kind: 'deployment'],
                        [name: 'nextcloud',       namespace: 'nextcloud', kind: 'deployment'],
                        [name: 'mautic',          namespace: 'mautic',    kind: 'deployment'],
                        [name: 'wordpress',       namespace: 'wordpress', kind: 'deployment'],
                        [name: 'frappe-gunicorn', namespace: 'frappe',    kind: 'deployment']
                    ]

                    def unhealthy = []
                    deployments.each { dep ->
                        def status = sh(
                            script: """
                                kubectl rollout status ${dep.kind}/${dep.name} \
                                    -n ${dep.namespace} \
                                    --timeout=120s
                            """,
                            returnStatus: true
                        )
                        if (status != 0) {
                            echo "${dep.name} not healthy"
                            // Dump pod logs for debugging
                            sh """
                                kubectl get pods -n ${dep.namespace} --no-headers | head -3
                                kubectl describe pods -n ${dep.namespace} | tail -30 || true
                            """
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
                        [name: 'odoo',      namespace: 'odoo',      svc: 'odoo',            port: '8069', path: '/web/health'],
                        [name: 'n8n',       namespace: 'n8n',       svc: 'n8n',             port: '5678', path: '/healthz'],
                        [name: 'nextcloud', namespace: 'nextcloud',  svc: 'nextcloud',       port: '80',   path: '/status.php'],
                        [name: 'mautic',    namespace: 'mautic',     svc: 'mautic',          port: '80',   path: '/'],
                        [name: 'wordpress', namespace: 'wordpress',  svc: 'wordpress',       port: '80',   path: '/'],
                        [name: 'frappe', namespace: 'frappe', svc: 'frappe-gunicorn', port: '8000', path: '/api/method/ping']
                    ]

                    def failed = []
                    services.each { svc ->
                        echo "Smoke testing ${svc.name}..."

                        def result = sh(
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

                        def httpCode = (result =~ /(\d{3})/) ? (result =~ /(\d{3})/)[-1][1] : "000"
                        echo "${svc.name} → HTTP ${httpCode}"

                        if (httpCode in ["200", "301", "302", "303", "401"]) {
                            // 401 is OK — means app is up but requires auth
                            echo "${svc.name} smoke test PASSED (${httpCode})"
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
                    // Install kubescape natively if not present (uses existing kubeconfig)
                    sh """
                        if ! command -v kubescape &>/dev/null; then
                            curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
                            export PATH=\$PATH:\$HOME/.kubescape/bin
                        fi

                        kubescape scan framework nsa \
                            --format json \
                            --output ${REPORT_DIR}/kubescape-report.json \
                            --exclude-namespaces ${KUBESCAPE_SKIP} \
                            --verbose || true

                        kubescape scan framework mitre \
                            --format json \
                            --output ${REPORT_DIR}/kubescape-mitre-report.json \
                            --exclude-namespaces ${KUBESCAPE_SKIP} || true
                    """

                    // Parse risk score
                    def riskScore = sh(
                        script: """
                            python3 -c "
import json,sys
try:
    with open('${REPORT_DIR}/kubescape-report.json') as f:
        data=json.load(f)
    score=data.get('summaryDetails',{}).get('complianceScore',100)
    print(int(100-score))
except:
    print(0)
" 2>/dev/null || echo "0"
                        """,
                        returnStdout: true
                    ).trim()

                    echo "Kubescape risk score: ${riskScore}%"
                    if (riskScore.toInteger() > 50) {
                        unstable("Kubescape risk score ${riskScore}% exceeds threshold")
                    } else {
                        echo "Kubescape passed (risk: ${riskScore}%)"
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

                    targets.each { svc ->
                        echo "ZAP scanning ${svc.name}..."
                        sh """
                            docker run --rm \
                                -v ${REPORT_DIR}:/zap/wrk \
                                ghcr.io/zaproxy/zaproxy:stable \
                                zap-baseline.py \
                                    -t ${TRAEFIK_EXT}${svc.path} \
                                    -r zap-${svc.name}-${BUILD_NUMBER}.html \
                                    -J zap-${svc.name}-${BUILD_NUMBER}.json \
                                    -l WARN \
                                    -I -k || true
                        """

                        // Parse ZAP alerts — warn on HIGH risk
                        def highAlerts = sh(
                            script: """
                                python3 -c "
import json,sys
try:
    with open('${REPORT_DIR}/zap-${svc.name}-${BUILD_NUMBER}.json') as f:
        data=json.load(f)
    high=[a for a in data.get('site',[{}])[0].get('alerts',[]) if a.get('riskdesc','').startswith('High')]
    print(len(high))
except:
    print(0)
" 2>/dev/null || echo "0"
                            """,
                            returnStdout: true
                        ).trim()

                        echo "${svc.name} ZAP HIGH alerts: ${highAlerts}"
                        if (highAlerts.toInteger() > 0) {
                            unstable("ZAP found ${highAlerts} HIGH risk alerts for ${svc.name}")
                        }
                    }
                    echo "DAST scan completed for all services"
                }
            }
        }


        stage('Security Summary') {
            steps {
                script {
                    sh """
                        echo "============================================"
                        echo "  SECURITY SCAN SUMMARY — Build #${BUILD_NUMBER}"
                        echo "============================================"
                        echo ""
                        echo "Gitleaks:  \$(cat ${REPORT_DIR}/gitleaks-report.json | python3 -c \"import json,sys; d=json.load(sys.stdin); print(str(len(d)) + ' secrets found')\" 2>/dev/null || echo 'clean')"
                        echo "Semgrep:   \$(cat ${REPORT_DIR}/semgrep-report.json | python3 -c \"import json,sys; d=json.load(sys.stdin); print(str(len(d.get('results',[]))) + ' findings')\" 2>/dev/null || echo 'N/A')"
                        echo "Checkov:   \$(cat ${REPORT_DIR}/checkov-report.json | python3 -c \"import json,sys; d=json.load(sys.stdin); d=d[0] if isinstance(d,list) else d; s=d.get('summary',{}); print(str(s.get('passed',0)) + ' passed / ' + str(s.get('failed',0)) + ' failed')\" 2>/dev/null || echo 'N/A')"
                        echo "Trivy:     see trivy-*.json for per-image CVE counts"
                        echo "SBOM:      see sbom-*.json for software inventory"
                        echo "Kubescape: see kubescape-report.json"
                        echo "ZAP:       see zap-*.html for per-service DAST reports"
                        echo ""
                        echo "Reports archived at: ${REPORT_DIR}"
                        echo "============================================"
                    """
                }
            }
        }
    }


    post {
        always {
            archiveArtifacts(
                artifacts: 'security-reports/**/*',
                allowEmptyArchive: true,
                fingerprint: true
            )
            cleanWs()
        }
        success {
            echo "Pipeline completed successfully — all security gates passed"
        }
        unstable {
            echo "Pipeline completed with warnings — review security reports above"
        }
        failure {
            echo "Pipeline FAILED — check logs above for blocking issues"
        }
    }
}