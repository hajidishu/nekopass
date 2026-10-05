param([string]$Version = 'v0.14.1', [string]$DownloadBase = 'https://github.com/hajidishu/nekopass/releases/download')
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' -or $Version.Contains('..')) { throw 'Invalid version' }
if ($DownloadBase) {
    $parsed = [Uri]$DownloadBase
    if ($parsed.Scheme -ne 'https' -or -not $parsed.Host -or $parsed.UserInfo -or $parsed.Query -or $parsed.Fragment -or $DownloadBase -match "['`r`n]") { throw 'DownloadBase must be an HTTPS directory URL' }
}
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
$previousOS = $env:GOOS; $previousArch = $env:GOARCH; $previousCGO = $env:CGO_ENABLED
try {
    python scripts/check-public.py
    if ($LASTEXITCODE -ne 0) { throw 'Public source check failed' }
    go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go tests failed' }
    Push-Location web
    try {
        $npmCommand = if ($env:OS -eq 'Windows_NT') { 'npm.cmd' } else { 'npm' }
        & $npmCommand ci
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
        & $npmCommand test
        if ($LASTEXITCODE -ne 0) { throw 'Frontend tests failed' }
        & $npmCommand run build
        if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed' }
    } finally { Pop-Location }
    $assets = Join-Path $repoRoot 'dist/oss/nekopass'
    $releases = Join-Path $assets "releases/$Version"
    New-Item -ItemType Directory -Force $releases | Out-Null
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $manager = [IO.File]::ReadAllText((Join-Path $repoRoot 'scripts/nekopassctl.sh')).Replace("`r`n", "`n")
    $installer = [IO.File]::ReadAllText((Join-Path $repoRoot 'scripts/install-panel.sh')).Replace("`r`n", "`n")
    $payload = "write_manager_payload() {`ncat <<'NEKOPASS_MANAGER_PAYLOAD'`n" + $manager.TrimEnd() + "`nNEKOPASS_MANAGER_PAYLOAD`n}`n"
    $updater = [IO.File]::ReadAllText((Join-Path $repoRoot 'scripts/nekopass-update.py')).Replace("`r`n", "`n")
    $updaterPayload = "write_updater_payload() {`ncat <<'NEKOPASS_UPDATER_PAYLOAD'`n" + $updater.TrimEnd() + "`nNEKOPASS_UPDATER_PAYLOAD`n}`n"
    $installer = $installer.Replace('# PACKAGED_MANAGER', $payload).Replace('# PACKAGED_UPDATER', $updaterPayload).Replace("DEFAULT_DOWNLOAD_BASE='https://github.com/hajidishu/nekopass/releases/download'", "DEFAULT_DOWNLOAD_BASE='$($DownloadBase.TrimEnd('/'))'")
    $installer = $installer.Replace('v0.14.1', $Version)
    [IO.File]::WriteAllText((Join-Path $assets 'install-panel.sh'), $installer, $utf8)
    $env:GOOS = 'linux'; $env:CGO_ENABLED = '0'
    foreach ($architecture in @('amd64','arm64')) {
        $env:GOARCH = $architecture
        $binary = Join-Path $releases "nekopass-panel-$architecture.bin"
        go build -trimpath -ldflags "-X github.com/nekopass/nekopass/internal/release.Version=$Version" -o $binary ./cmd/nekopass
        if ($LASTEXITCODE -ne 0) { throw "Panel build failed: $architecture" }
        if ($IsLinux -and $architecture -eq 'amd64' -and $env:NEKOPASS_TEST_DATABASE_URL) {
            python tests/panel_startup_test.py --binary $binary
            if ($LASTEXITCODE -ne 0) { throw 'Panel startup smoke test failed' }
        }
        # Explicit file list; archives never inherit deployment configs/certificates.
        python scripts/package-panel.py --binary $binary --web web/dist --manager scripts/nekopassctl.sh --output (Join-Path $releases "nekopass-panel-linux-$architecture.tar.gz")
        if ($LASTEXITCODE -ne 0) { throw "Panel archive failed: $architecture" }
        Remove-Item -LiteralPath $binary
    }
    & (Join-Path $PSScriptRoot 'package-agent.ps1') -Version $Version
    if (-not $?) { throw 'Agent packaging failed' }
    $manifestPath = Join-Path $repoRoot 'dist/oss/OSS_UPLOAD.md'
    $panelManifest = "`n## Panel one-click installer`n`n- nekopass/install-panel.sh`n- nekopass/releases/$Version/nekopass-panel-linux-amd64.tar.gz`n- nekopass/releases/$Version/nekopass-panel-linux-arm64.tar.gz`n"
    [IO.File]::WriteAllText($manifestPath, [IO.File]::ReadAllText($manifestPath) + $panelManifest, $utf8)
    Write-Output "Panel installer and linux amd64/arm64 releases ready: $assets"
} finally {
    $env:GOOS = $previousOS; $env:GOARCH = $previousArch; $env:CGO_ENABLED = $previousCGO
    Pop-Location
}
