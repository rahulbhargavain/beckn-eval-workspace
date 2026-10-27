param(
    [string]$BaseUrl = "http://localhost:8080",
    [string]$Profile = "conformance/profiles/bpp-core.json",
    [string]$Identity,
    [string]$Participant = "local"
)
# Delegates to the Python conformance runner (needs PyNaCl for signed scenarios).
$root = Split-Path $PSScriptRoot -Parent
$py = Join-Path $root "mockup/.venv/Scripts/python.exe"
if (-not (Test-Path $py)) { $py = "python" }
$args = @("-m", "conformance.runner", "--base-url", $BaseUrl, "--profile", $Profile, "--participant", $Participant)
if ($Identity) { $args += @("--identity", $Identity) }
Push-Location $root
& $py @args
$code = $LASTEXITCODE
Pop-Location
exit $code
