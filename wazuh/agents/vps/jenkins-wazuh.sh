#!/usr/bin/env bash

LOG_FILE="/var/log/jenkins-wazuh.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_NUMBER="${BUILD_NUMBER:-unknown}"
BUILD_TAG="${BUILD_TAG:-unknown}"

TOOL=""
SERVICE=""
STATUS=""
FINDINGS=""
REPORT_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tool)        TOOL="$2";        shift 2 ;;
        --service)     SERVICE="$2";     shift 2 ;;
        --status)      STATUS="$2";      shift 2 ;;
        --findings)    FINDINGS="$2";    shift 2 ;;
        --report-file) REPORT_FILE="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

write_event() {
    local level="$1"
    local event_type="$2"
    local fields="$3"
    local json
    json=$(printf '{"timestamp":"%s","build":"%s","level":%d,"event_type":"%s",%s}\n' \
        "$TIMESTAMP" "$BUILD_TAG" "$level" "$event_type" "$fields")
    echo "$json" >> "$LOG_FILE"
}

handle_gitleaks() {
    if [[ "$STATUS" == "clean" ]]; then
        write_event 3 "gitleaks_clean" '"result":"no secrets detected"'
    else
        write_event 14 "gitleaks_secrets_found" '"result":"secrets detected in repository"'
    fi
}

handle_semgrep() {
    local count="${FINDINGS:-0}"
    if [[ "$STATUS" == "blocking" ]]; then
        write_event 10 "semgrep_blocking" "\"result\":\"blocking findings detected\",\"findings\":$count"
    elif [[ "$STATUS" == "warnings" ]]; then
        write_event 5 "semgrep_warnings" "\"result\":\"warnings only\",\"findings\":$count"
    else
        write_event 3 "semgrep_clean" '"result":"no findings"'
    fi
}

handle_dclint() {
    local count="${FINDINGS:-0}"
    local svc="${SERVICE:-unknown}"
    if [[ "$STATUS" == "issues" ]]; then
        write_event 4 "dclint_issues" "\"service\":\"$svc\",\"result\":\"lint issues found\",\"findings\":$count"
    else
        write_event 3 "dclint_clean" "\"service\":\"$svc\",\"result\":\"lint passed\""
    fi
}

handle_vault() {
    if [[ "$STATUS" == "sealed" ]]; then
        write_event 8 "vault_sealed" '"result":"Vault is sealed"'
    else
        write_event 3 "vault_healthy" '"result":"Vault is unsealed and healthy"'
    fi
}

handle_lifecycle() {
    local svc="${SERVICE:-unknown}"
    local stage="$TOOL"
    if [[ "$STATUS" == "failed" ]]; then
        write_event 7 "${stage}_failed" "\"service\":\"$svc\",\"result\":\"failed\""
    else
        write_event 3 "${stage}_passed" "\"service\":\"$svc\",\"result\":\"passed\""
    fi
}

handle_trivy() {
    local svc="${SERVICE:-unknown}"
    local report="$REPORT_FILE"

    if [[ ! -f "$report" ]]; then
        write_event 3 "trivy_error" "\"service\":\"$svc\",\"result\":\"report file not found\""
        return
    fi

    python3 - <<PYEOF
import json

LEVEL_MAP = {"CRITICAL": 12, "HIGH": 10, "MEDIUM": 7}
LOG_FILE  = "$LOG_FILE"
TIMESTAMP = "$TIMESTAMP"
BUILD_TAG = "$BUILD_TAG"
SERVICE   = "$svc"

with open("$report") as f:
    data = json.load(f)

results = data.get("Results", [])
total = 0

for result in results:
    target = result.get("Target", "unknown")
    vulns = result.get("Vulnerabilities") or []
    for v in vulns:
        sev = v.get("Severity", "")
        if sev not in LEVEL_MAP:
            continue
        level = LEVEL_MAP[sev]
        cve   = v.get("VulnerabilityID", "unknown")
        pkg   = v.get("PkgName", "unknown")
        inst  = v.get("InstalledVersion", "unknown")
        fixed = v.get("FixedVersion", "none")
        total += 1
        line = (
            '{"timestamp":"%s","build":"%s","level":%d,'
            '"event_type":"trivy_finding",'
            '"service":"%s","target":"%s","cve":"%s",'
            '"severity":"%s","package":"%s",'
            '"installed":"%s","fixed":"%s"}\n'
        ) % (TIMESTAMP, BUILD_TAG, level, SERVICE, target, cve, sev, pkg, inst, fixed)
        with open(LOG_FILE, "a") as lf:
            lf.write(line)

if total == 0:
    summary_level = 3
    summary_result = "no vulnerabilities found"
else:
    summary_level = 12
    summary_result = "%d vulnerabilities found" % total

line = (
    '{"timestamp":"%s","build":"%s","level":%d,'
    '"event_type":"trivy_summary",'
    '"service":"%s","findings":%d,"result":"%s"}\n'
) % (TIMESTAMP, BUILD_TAG, summary_level, SERVICE, total, summary_result)
with open(LOG_FILE, "a") as lf:
    lf.write(line)
PYEOF
}

handle_zap() {
    local svc="${SERVICE:-unknown}"
    local report="$REPORT_FILE"

    if [[ ! -f "$report" ]]; then
        write_event 3 "zap_error" "\"service\":\"$svc\",\"result\":\"report file not found\""
        return
    fi

    python3 - <<PYEOF
import re

LOG_FILE  = "$LOG_FILE"
TIMESTAMP = "$TIMESTAMP"
BUILD_TAG = "$BUILD_TAG"
SERVICE   = "$svc"

KEPT_WARN_IDS = {"10020", "10038", "10202", "10055", "10003", "10054", "10031", "10110", "10098"}
FINDING_RE = re.compile(r'^(WARN-NEW|FAIL-NEW):\s+(.+?)\s+\[(\d+)\]\s+x\s+(\d+)')
total_kept = 0

with open("$report") as f:
    for line in f:
        m = FINDING_RE.match(line.strip())
        if not m:
            continue
        ftype     = m.group(1)
        rule_name = m.group(2)
        rule_id   = m.group(3)
        count     = int(m.group(4))
        if ftype == "WARN-NEW" and rule_id not in KEPT_WARN_IDS:
            continue
        level = 8 if ftype == "FAIL-NEW" else 5
        total_kept += 1
        out = (
            '{"timestamp":"%s","build":"%s","level":%d,'
            '"event_type":"zap_finding",'
            '"service":"%s","type":"%s","rule_id":"%s",'
            '"rule_name":"%s","count":%d}\n'
        ) % (TIMESTAMP, BUILD_TAG, level, SERVICE, ftype, rule_id, rule_name, count)
        with open(LOG_FILE, "a") as lf:
            lf.write(out)

if total_kept == 0:
    summary_level = 3
    summary_result = "no significant findings"
else:
    summary_level = 8
    summary_result = "%d significant findings" % total_kept

out = (
    '{"timestamp":"%s","build":"%s","level":%d,'
    '"event_type":"zap_summary",'
    '"service":"%s","findings":%d,"result":"%s"}\n'
) % (TIMESTAMP, BUILD_TAG, summary_level, SERVICE, total_kept, summary_result)
with open(LOG_FILE, "a") as lf:
    lf.write(out)
PYEOF
}

case "$TOOL" in
    gitleaks) handle_gitleaks ;;
    semgrep)  handle_semgrep  ;;
    dclint)   handle_dclint   ;;
    vault)    handle_vault    ;;
    trivy)    handle_trivy    ;;
    zap)      handle_zap      ;;
    deploy|health|smoke) handle_lifecycle ;;
    *)
        echo "ERROR: unknown tool '$TOOL'"
        exit 1
        ;;
esac