$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    python scripts/check-public.py
    if ($LASTEXITCODE -ne 0) { throw 'Public source check failed; build blocked' }
    go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go tests failed' }
    Push-Location web
    try {
        npm.cmd ci
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
        npm.cmd run build
        if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed' }
    } finally { Pop-Location }
    New-Item -ItemType Directory -Force dist/bin | Out-Null
    $managerText = [IO.File]::ReadAllText((Join-Path $repoRoot 'scripts/nekopassctl.sh')).Replace("`r`n", "`n")
    [IO.File]::WriteAllText((Join-Path $repoRoot 'dist/bin/nekopassctl'), $managerText, (New-Object System.Text.UTF8Encoding($false)))
    $previousOS = $env:GOOS
    $previousArch = $env:GOARCH
    $previousCGO = $env:CGO_ENABLED
    try {
        $env:GOOS = 'linux'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
        go build -trimpath -o dist/bin/nekopass ./cmd/nekopass
        if ($LASTEXITCODE -ne 0) { throw 'Control build failed' }
        go build -trimpath -o dist/bin/nekopass-agent ./cmd/nekopass-agent
        if ($LASTEXITCODE -ne 0) { throw 'Agent build failed' }
    } finally { $env:GOOS = $previousOS; $env:GOARCH = $previousArch; $env:CGO_ENABLED = $previousCGO }
} finally { Pop-Location }
