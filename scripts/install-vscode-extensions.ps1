param(
  [ValidateSet("minimal", "expanded", "optional")]
  [string]$Set = "minimal",
  [switch]$Force
)

$codeCmd = "C:\Users\sadas\AppData\Local\Programs\Microsoft VS Code\bin\code.cmd"

if (-not (Test-Path $codeCmd)) {
  Write-Error "VS Code CLI not found at $codeCmd"
  exit 1
}

$extensionSets = @{
  minimal = @(
    "github.copilot",
    "github.copilot-chat",
    "github.vscode-pull-request-github",
    "github.vscode-github-actions",
    "dbaeumer.vscode-eslint",
    "ms-playwright.playwright",
    "redhat.vscode-yaml"
  )
  expanded = @(
    "github.copilot",
    "github.copilot-chat",
    "github.vscode-pull-request-github",
    "github.vscode-github-actions",
    "github.codespaces",
    "ms-vscode-remote.remote-containers",
    "dbaeumer.vscode-eslint",
    "ms-azuretools.vscode-containers",
    "ms-playwright.playwright",
    "redhat.vscode-yaml",
    "humao.rest-client"
  )
  optional = @(
    "eamodio.gitlens",
    "github.vscode-github-actions"
  )
}

$installed = & $codeCmd --list-extensions
$targets = $extensionSets[$Set]

foreach ($extension in $targets) {
  if (-not $Force -and $installed -contains $extension) {
    Write-Host "Already installed: $extension"
    continue
  }

  Write-Host "Installing: $extension"
  & $codeCmd --install-extension $extension | Out-Host
  $installed = & $codeCmd --list-extensions

  if ($installed -contains $extension) {
    Write-Host "Confirmed: $extension"
    continue
  }

  if ($extension -eq "github.copilot" -and $installed -contains "github.copilot-chat") {
    Write-Host "Note: VS Code reports github.copilot-chat, but not github.copilot, after install on this machine. Confirm Copilot entitlement in the editor UI."
    continue
  }

  Write-Warning "Extension did not appear in --list-extensions after install: $extension"
}
