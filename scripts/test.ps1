param(
    [Parameter(Mandatory)][string]$BaseUrl,
    [Parameter(Mandatory)][string]$Participant,
    [string]$ProfilePath = "conformance/profiles/bpp-core.json",
    [string]$Identity,
    [string]$IssuerKey,
    [string[]]$SutKey,   # KEYID=BASE64_PUBLIC_KEY of the node under test (verifies its response Signature)
    [string]$Out
)
# Delegates to the Python conformance runner (PyNaCl needed for signed scenarios).
# Exits non-zero unless the verdict is CERTIFIED; a missing interpreter is exit 2, never 0.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$py = Join-Path $root "mockup/.venv/Scripts/python.exe"
if (-not (Test-Path $py)) { $py = "python" }
if (-not (Get-Command $py -ErrorAction SilentlyContinue)) {
    Write-Error "Python interpreter not found ($py). Create mockup/.venv or install Python + conformance/requirements.txt."
    exit 2
}
# Resolve caller-relative paths before changing directory.
$runnerArgs = @("-m", "conformance.runner", "--base-url", $BaseUrl, "--participant", $Participant,
                "--profile", (Resolve-Path $ProfilePath).Path)
if ($Identity)  { $runnerArgs += @("--identity",   (Resolve-Path $Identity).Path) }
if ($IssuerKey) { $runnerArgs += @("--issuer-key", (Resolve-Path $IssuerKey).Path) }
foreach ($k in $SutKey) { $runnerArgs += @("--sut-key", $k) }
if ($Out)       { $runnerArgs += @("--out", [IO.Path]::GetFullPath($Out)) }
Push-Location $root
try {
    & $py @runnerArgs
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}
if ($null -eq $code) { exit 2 }
exit $code
