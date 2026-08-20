# Dreamiez production bootstrap wrapper - PowerShell 5.1 - ASCII only
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$RepoRoot = Split-Path -Parent $PSScriptRoot
$SecretRoot = Join-Path (Split-Path -Parent $RepoRoot) 'DreamiezOracleSecrets'
$env:DREAMIEZ_SECRET_DIR = $SecretRoot

Write-Host 'DREAMIEZ PRODUCTION KEY CEREMONY' -ForegroundColor Cyan
Write-Host '=================================' -ForegroundColor Cyan

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw 'Node.js is required. Install Node.js 20+ and rerun.'
}

$privateFiles = Get-ChildItem -Path $RepoRoot -Recurse -File -Filter '*.pem' -ErrorAction SilentlyContinue
if ($privateFiles) {
    throw 'Refusing to continue: PEM key material already exists inside the repository.'
}

node (Join-Path $PSScriptRoot 'bootstrap-production.js')
if ($LASTEXITCODE -ne 0) { throw 'Production bootstrap failed.' }

$privateKey = Join-Path $SecretRoot 'issuer-private-key.pem'
$did = Join-Path $RepoRoot 'public\.well-known\did.json'
$event = Join-Path $RepoRoot 'public\bootstrap\event-000001.json'

if (-not (Test-Path $privateKey)) { throw 'Private key was not created outside repo.' }
if (-not (Test-Path $did)) { throw 'DID document was not created.' }
if (-not (Test-Path $event)) { throw 'Bootstrap event was not created.' }

$inside = Get-ChildItem -Path $RepoRoot -Recurse -File -Filter '*.pem' -ErrorAction SilentlyContinue
if ($inside) { throw 'FAIL: private key material exists inside repository.' }

$proof = [ordered]@{
    timestamp_utc = (Get-Date).ToUniversalTime().ToString('o')
    repository = 'KelpCoin/dreamiez-oracle'
    issuer = 'did:web:dreamiez.org'
    private_key_outside_repo = $true
    did_exists = $true
    bootstrap_event_exists = $true
    result = 'PASS'
}
$proofDir = Join-Path $RepoRoot 'proof'
New-Item -ItemType Directory -Force -Path $proofDir | Out-Null
$proof | ConvertTo-Json | Out-File (Join-Path $proofDir 'production-bootstrap-local.json') -Encoding UTF8

Write-Host ''
Write-Host 'PASS' -ForegroundColor Green
Write-Host ('Private key: ' + $privateKey)
Write-Host ('DID: ' + $did)
Write-Host ('Event: ' + $event)
Write-Host ('Proof: ' + (Join-Path $proofDir 'production-bootstrap-local.json'))
