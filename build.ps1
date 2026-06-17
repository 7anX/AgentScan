#!/usr/bin/env pwsh
# build.ps1 — AgentScan one-shot build script (Windows / cross-platform PowerShell)
# Usage:
#   .\build.ps1                        # native binary
#   .\build.ps1 -OS linux -Arch amd64  # cross-compile
#   .\build.ps1 -OS windows -Arch amd64
#   .\build.ps1 -OS darwin -Arch arm64

param(
    [string]$OS   = "",
    [string]$Arch = ""
)

$Name      = "agentscan"
$Version   = "0.1.0"
$Module    = "github.com/agentscan/agentscan"
$OutputDir = "dist"

# 默认当前平台
if (-not $OS)   { $OS   = (go env GOOS)   }
if (-not $Arch) { $Arch = (go env GOARCH) }

# Windows 加 .exe
$Binary = $Name
if ($OS -eq "windows") { $Binary = "$Name.exe" }

$null = New-Item -ItemType Directory -Path $OutputDir -Force
$Output = "$OutputDir\$Binary"

$BuildTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$LdFlags   = "-s -w -X '$Module/internal/version.Version=$Version' -X '$Module/internal/version.BuildTime=$BuildTime'"

Write-Host "▶ Building $Name v$Version for $OS/$Arch..." -ForegroundColor Cyan

$env:GOOS   = $OS
$env:GOARCH = $Arch

go build -trimpath -ldflags $LdFlags -o $Output .

if ($LASTEXITCODE -ne 0) {
    Write-Host "✗ Build failed" -ForegroundColor Red
    exit 1
}

$size = (Get-Item $Output).Length
Write-Host "✓ Built: $Output  ($([math]::Round($size/1KB, 1)) KB)" -ForegroundColor Green

# 本机平台时验证
$nativeOS   = (go env GOOS)
$nativeArch = (go env GOARCH)
if ($OS -eq $nativeOS -and $Arch -eq $nativeArch) {
    Write-Host ""
    Write-Host "▶ Verifying binary..." -ForegroundColor Cyan
    & ".\$Output" --version
    Write-Host ""
    Write-Host "▶ Usage:" -ForegroundColor Cyan
    & ".\$Output" scan --help
}
