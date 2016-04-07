param (
    [parameter(Mandatory=$False)] [switch] $Production
)
$StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
Write-Host "initialized: $(Get-Date)"

$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (Get-Module ps-cm-ss) { Remove-Module ps-cm-ss }
Import-Module $ScriptPath\ps-cm-ss.psm1 -Verbose

Show-HostInfo

$idx = 1
$len = (Get-SequenceList).Count

Write-Host "$len enabled tasks found in configuration file" -ForegroundColor Cyan

foreach ($pkg in Get-SequenceList) {
    if ($Production) {
        $result = Invoke-Payload -ProductKey $pkg -Commit
    }
    else {
        $result = Invoke-Payload -ProductKey $pkg
    }
    Write-Host "`tstep...... $idx of $len"
    $idx++
}
Write-Host "------------------------------------"
Write-Host "runtime elapsed..." -ForegroundColor Cyan
$StopWatch.Elapsed