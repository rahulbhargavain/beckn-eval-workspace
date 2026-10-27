param([string]$BaseUrl = "http://localhost:8080")

# Stub runner: executes tests/scenarios/*.json over HTTP. Pending scenarios are skipped.
# Only top-level status is asserted until jsonpath support is added.
$root = Split-Path $PSScriptRoot -Parent
$fail = 0
foreach ($f in Get-ChildItem "$root/tests/scenarios/*.json") {
    $s = Get-Content $f -Raw | ConvertFrom-Json
    if ($s.pending) { Write-Host "SKIP $($s.name): $($s.pendingReason)"; continue }
    $body = Get-Content "$root/tests/$($s.request.body)" -Raw
    try {
        $r = Invoke-WebRequest -Method $s.request.method -Uri "$BaseUrl$($s.request.path)" -Body $body -ContentType "application/json" -SkipHttpErrorCheck
        if ([int]$r.StatusCode -eq $s.expect.status) { Write-Host "PASS $($s.name)" }
        else { Write-Host "FAIL $($s.name): got $($r.StatusCode)"; $fail++ }
    } catch { Write-Host "FAIL $($s.name): $_"; $fail++ }
}
exit $fail
