param([string]$Version = 'v0.14.6')
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' -or $Version.Contains('..')) { throw 'Invalid version' }
$repoRoot = Split-Path -Parent $PSScriptRoot
python (Join-Path $repoRoot 'scripts/check-public.py')
if ($LASTEXITCODE -ne 0) { throw 'Public source check failed; packaging blocked' }
$assetRoot = Join-Path $repoRoot 'dist/oss/nekopass'
$releaseRoot = Join-Path $assetRoot "releases/$Version"
$utf8 = New-Object System.Text.UTF8Encoding($false)
New-Item -ItemType Directory -Force $releaseRoot | Out-Null
$installerPath = Join-Path $assetRoot 'install-agent.sh'
$installerText = [IO.File]::ReadAllText((Join-Path $repoRoot 'scripts/install-agent.sh')).Replace("`r`n", "`n")
$managerText = [IO.File]::ReadAllText((Join-Path $repoRoot 'scripts/nekopassctl.sh')).Replace("`r`n", "`n")
$managerPayload = "write_manager_payload() {`ncat <<'NEKOPASS_MANAGER_PAYLOAD'`n" + $managerText.TrimEnd() + "`nNEKOPASS_MANAGER_PAYLOAD`n}`n"
$updaterText = [IO.File]::ReadAllText((Join-Path $repoRoot 'scripts/nekopass-update.py')).Replace("`r`n", "`n")
$updaterPayload = "write_updater_payload() {`ncat <<'NEKOPASS_UPDATER_PAYLOAD'`n" + $updaterText.TrimEnd() + "`nNEKOPASS_UPDATER_PAYLOAD`n}`n"
$installerText = $installerText.Replace('# PACKAGED_MANAGER', $managerPayload).Replace('# PACKAGED_UPDATER', $updaterPayload).Replace('v0.14.6', $Version)
[IO.File]::WriteAllText($installerPath, $installerText, $utf8)
[IO.File]::WriteAllText((Join-Path $assetRoot 'nekopassctl.sh'), $managerText, $utf8)
[IO.File]::WriteAllText((Join-Path $assetRoot 'nekopass-update.py'), $updaterText, $utf8)
$previousOS = $env:GOOS
$previousArch = $env:GOARCH
$previousCGO = $env:CGO_ENABLED
Push-Location $repoRoot
try {
    $env:GOOS = 'linux'; $env:CGO_ENABLED = '0'
    foreach ($architecture in @('amd64','arm64')) {
        $env:GOARCH = $architecture
        $fileName = "nekopass-agent-linux-$architecture"
        $outputPath = Join-Path $releaseRoot $fileName
        go build -trimpath -ldflags "-X github.com/nekopass/nekopass/internal/release.Version=$Version" -o $outputPath ./cmd/nekopass-agent
        if ($LASTEXITCODE -ne 0) { throw "Build failed: $architecture" }
    }
    # Remove obsolete generated checksum files from earlier packaging runs.
    $resolvedAssets = [IO.Path]::GetFullPath($assetRoot).TrimEnd('\') + '\'
    foreach ($oldFile in Get-ChildItem -LiteralPath $assetRoot -Recurse -File | Where-Object { $_.Name -eq 'SHA256SUMS' -or $_.Extension -eq '.sha256' }) {
        if (-not $oldFile.FullName.StartsWith($resolvedAssets, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected artifact path' }
        Remove-Item -LiteralPath $oldFile.FullName
    }
    if (Test-Path -LiteralPath (Join-Path $assetRoot 'ca.crt')) { Remove-Item -LiteralPath (Join-Path $assetRoot 'ca.crt') }
    $settings = [ordered]@{
        site_name = 'Nekopass'; panel_url = 'https://YOUR-PANEL.example.com:8443'; agent_host = 'YOUR-PANEL.example.com'; agent_port = 9443; agent_transport = 'tls'
        installer_url = 'https://github.com/hajidishu/nekopass/releases/latest/download/install-agent.sh'
        release_base_url = 'https://github.com/hajidishu/nekopass/releases/download'; agent_version = 'latest'
        install_token_minutes = 30
    }
    [IO.File]::WriteAllText((Join-Path $repoRoot 'dist/oss/settings.example.json'), ($settings | ConvertTo-Json) + "`n", $utf8)
    $manifest = @"
# OSS upload manifest

Upload these files preserving the paths relative to dist/oss:

- nekopass/install-agent.sh
- nekopass/nekopassctl.sh (optional standalone service manager; also embedded in the installer)
- nekopass/releases/$Version/nekopass-agent-linux-amd64
- nekopass/releases/$Version/nekopass-agent-linux-arm64

Never upload the control TLS private key, agent.env or any state.db.

Use settings.example.json as a reference for /admin/settings.
Fill in the download URLs and panel connection details. No checksum files are required.
The packaged installer installs /usr/local/bin/nekopassctl without an extra download.
"@
    [IO.File]::WriteAllText((Join-Path $repoRoot 'dist/oss/OSS_UPLOAD.md'), $manifest.Replace("`r`n", "`n"), $utf8)
    Write-Output "Release assets ready: $assetRoot"
} finally { Pop-Location; $env:GOOS = $previousOS; $env:GOARCH = $previousArch; $env:CGO_ENABLED = $previousCGO }
