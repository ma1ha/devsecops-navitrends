
param(
    [ValidateSet("build_result","security_scan","deployment","pipeline_failure","trivy_scan","secret_detected")]
    [string]$EventType = "build_result",

    [string]$JobName      = $env:JOB_NAME,
    [string]$BuildNumber  = $env:BUILD_NUMBER,

    [ValidateSet("SUCCESS","FAILURE","UNSTABLE","ABORTED","IN_PROGRESS")]
    [string]$Status       = "IN_PROGRESS",

    [string]$Detail       = "",
    [int]$Severity        = 3
)

$timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"

$event = @{
    timestamp    = $timestamp
    source       = "jenkins"
    event_type   = $EventType
    host         = $env:COMPUTERNAME
    job_name     = $JobName
    build_number = $BuildNumber
    status       = $Status
    severity     = $Severity
    detail       = $Detail
    git_branch   = $env:GIT_BRANCH   ?? "N/A"
    git_commit   = $env:GIT_COMMIT   ?? "N/A"
    build_url    = $env:BUILD_URL    ?? "N/A"
    project      = "devsecops-navitrends"
} | ConvertTo-Json -Compress

$agentLog = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
Add-Content -Path $agentLog -Value $event -Encoding UTF8

Write-Host "[Wazuh] Event sent: $EventType | $JobName #$BuildNumber | $Status"