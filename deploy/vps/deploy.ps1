# websec-auditor -> VPS deploy helper (run from Windows PowerShell)
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File deploy\vps\deploy.ps1 `
#       -VpsIp "1.2.3.4" -SshUser root -Domain websec-audit.site -Email you@example.com
#
# Prereqs (all built into Windows 10/11):
#   - ssh.exe / scp.exe (OpenSSH client)     - tar.exe (bsdtar)
#
param(
  [Parameter(Mandatory=$true)][string]$VpsIp,
  [string]$SshUser = "root",
  [string]$Domain = "websec-audit.site",
  [string]$Email = "admin@websec-auditor.site",
  [string]$Project = "D:\websec-auditor"
)

$ErrorActionPreference = "Stop"
$work = Join-Path $env:TEMP "websec-vps-deploy"
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Path $work | Out-Null

Write-Host "==> [1/4] Packaging project (excluding local-only/Vercel artifacts)..." -ForegroundColor Cyan
$tarball = Join-Path $work "websec-auditor.tar.gz"

# stage only the files needed on the VPS (drop Vercel-only + local-only artifacts)
$stage = Join-Path $work "stage"
New-Item -ItemType Directory -Path $stage | Out-Null
Copy-Item -Recurse -Path (Join-Path $Project "websec_auditor") -Destination $stage
Copy-Item -Recurse -Path (Join-Path $Project "data") -Destination $stage
Copy-Item -Path (Join-Path $Project "websec_cli.py") -Destination $stage
Copy-Item -Path (Join-Path $Project "requirements.txt") -Destination $stage
# drop Vercel-only + local-only artifacts
Remove-Item -Recurse -Force (Join-Path $stage "websec_auditor\__pycache__") -ErrorAction SilentlyContinue
& tar.exe -czf $tarball -C $stage .
Write-Host "  -> package size: $((Get-Item $tarball).Length) bytes"

$remoteDir = "/root/websec-auditor-deploy"
Write-Host "==> [2/4] Preparing remote dir and uploading to $SshUser@$VpsIp..." -ForegroundColor Cyan
ssh.exe "${SshUser}@${VpsIp}" "mkdir -p $remoteDir"
scp.exe $tarball (Join-Path $Project "deploy\vps\setup.sh") (Join-Path $Project "deploy\vps\websec-auditor.service") (Join-Path $Project "deploy\vps\nginx-websec-auditor.conf") "${SshUser}@${VpsIp}:${remoteDir}/"

Write-Host "==> [3/4] Extracting app files on VPS..." -ForegroundColor Cyan
ssh.exe "${SshUser}@${VpsIp}" "cd $remoteDir && mkdir -p app && tar -xzf websec-auditor.tar.gz -C app && ls app"

Write-Host "==> [4/4] Running setup.sh (installs deps, service, nginx, TLS)..." -ForegroundColor Cyan
Write-Host "  -> this needs your VPS root password if SSH key is not set up."
ssh.exe -t "${SshUser}@${VpsIp}" "cd $remoteDir && cp -r app/* . && bash setup.sh $Domain $Email"

Write-Host ""
Write-Host "DONE. Visit:  https://$Domain" -ForegroundColor Green
