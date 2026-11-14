# Run with read access to the Security log on an authorized Windows lab.
# Export preserves source events. It does not clear logs or change audit settings.
param([string]$OutputDirectory = ".\event-export")
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$channels = @("Security", "Microsoft-Windows-Sysmon/Operational")
foreach ($channel in $channels) {
    $name = $channel.Replace("/", "_")
    $destination = Join-Path $OutputDirectory ($name + ".evtx")
    & wevtutil epl $channel $destination /ow:true
    if ($LASTEXITCODE -ne 0) { throw "Export failed for $channel" }
}
Get-ChildItem $OutputDirectory -Filter *.evtx |
    Get-FileHash -Algorithm SHA256 |
    Export-Csv (Join-Path $OutputDirectory "sha256.csv") -NoTypeInformation
