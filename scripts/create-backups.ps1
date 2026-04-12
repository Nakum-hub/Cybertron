[CmdletBinding()]
param(
    [string]$ProjectRoot = "C:\app\Cybertron\workspace"
)

$ErrorActionPreference = "Stop"

function New-StagingCopy {
    param(
        [string]$Source,
        [string]$Destination,
        [string[]]$ExcludePatterns
    )

    if (Test-Path $Destination) {
        Remove-Item -Recurse -Force $Destination
    }

    New-Item -ItemType Directory -Force -Path $Destination | Out-Null

    $sourceRoot = (Resolve-Path $Source).Path
    $items = Get-ChildItem -LiteralPath $sourceRoot -Recurse -Force -File
    foreach ($item in $items) {
        $relative = $item.FullName.Substring($sourceRoot.Length).TrimStart('\')
        $skip = $false
        if ($relative -like ".env.*" -and $relative -like "*.example") {
            $skip = $false
        }
        else {
        foreach ($pattern in $ExcludePatterns) {
            if ($relative -like $pattern) {
                $skip = $true
                break
            }
        }
        }
        if ($skip) {
            continue
        }

        $target = Join-Path $Destination $relative
        $targetDir = Split-Path -Parent $target
        if (-not (Test-Path $targetDir)) {
            New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
        }
        Copy-Item -LiteralPath $item.FullName -Destination $target -Force
    }
}

if (-not (Test-Path $ProjectRoot)) {
    throw "Project root not found: $ProjectRoot"
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$workspaceName = Split-Path -Leaf $ProjectRoot
$root = Split-Path -Parent $ProjectRoot
$backupRoot = Join-Path $root "backups"
$tmpRoot = Join-Path $backupRoot ".staging"
$fullStage = Join-Path $tmpRoot "full-$timestamp"
$gitStage = Join-Path $tmpRoot "git-safe-$timestamp"
$fullZip = Join-Path $backupRoot "$workspaceName-full-$timestamp.zip"
$gitZip = Join-Path $backupRoot "$workspaceName-git-safe-$timestamp.zip"

New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null
New-Item -ItemType Directory -Force -Path $tmpRoot | Out-Null

$fullExcludes = @(
    "node_modules\*",
    ".vite\*",
    ".cache\*",
    "**\node_modules\*"
)

$gitSafeExcludes = @(
    "node_modules\*",
    ".runtime\*",
    "uploads\*",
    "*.log",
    ".env",
    ".env.*",
    ".env.production.local",
    ".env.production.s3.local",
    "app\frontend\dist\*",
    "backups\*",
    ".runlogs\*",
    "**\node_modules\*"
)

New-StagingCopy -Source $ProjectRoot -Destination $fullStage -ExcludePatterns $fullExcludes
New-StagingCopy -Source $ProjectRoot -Destination $gitStage -ExcludePatterns $gitSafeExcludes

if (Test-Path $fullZip) {
    Remove-Item -Force $fullZip
}
if (Test-Path $gitZip) {
    Remove-Item -Force $gitZip
}

Compress-Archive -Path (Join-Path $fullStage "*") -DestinationPath $fullZip -CompressionLevel Optimal
Compress-Archive -Path (Join-Path $gitStage "*") -DestinationPath $gitZip -CompressionLevel Optimal

$manifest = @{
    generatedAt = (Get-Date).ToString("o")
    projectRoot = $ProjectRoot
    fullBackup = $fullZip
    gitSafeBackup = $gitZip
    notes = @(
        "Full backup is for local recovery. Keep it private.",
        "Git-safe backup excludes runtime payloads, local env files, logs, uploads, and caches.",
        "Do not push the full backup to GitHub."
    )
}

$manifestPath = Join-Path $backupRoot "backup-manifest-$timestamp.json"
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Remove-Item -Recurse -Force $tmpRoot

[pscustomobject]@{
    Ok = $true
    FullBackup = $fullZip
    GitSafeBackup = $gitZip
    Manifest = $manifestPath
} | ConvertTo-Json -Depth 3
