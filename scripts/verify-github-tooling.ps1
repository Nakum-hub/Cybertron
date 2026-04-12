$codeCmd = "C:\Users\sadas\AppData\Local\Programs\Microsoft VS Code\bin\code.cmd"
$ghCmd = $null
$requiredExtensions = @(
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

Write-Host "GitHub tooling verification for Cybertron"
Write-Host ""

if (Test-Path $codeCmd) {
  Write-Host "VS Code CLI: found"
  $installed = & $codeCmd --list-extensions
  foreach ($extension in $requiredExtensions) {
    if ($installed -contains $extension) {
      Write-Host "[ok] extension installed: $extension"
      continue
    }

    if ($extension -eq "github.copilot" -and $installed -contains "github.copilot-chat") {
      Write-Host "[check] github.copilot not listed, but github.copilot-chat is installed. Confirm Copilot entitlement in VS Code UI."
      continue
    }

    Write-Host "[missing] extension not installed: $extension"
  }
} else {
  Write-Host "[missing] VS Code CLI not found at $codeCmd"
}

if (Get-Command gh -ErrorAction SilentlyContinue) {
  $ghCmd = (Get-Command gh -ErrorAction SilentlyContinue).Source
} elseif (Test-Path "C:\Program Files\GitHub CLI\gh.exe") {
  $ghCmd = "C:\Program Files\GitHub CLI\gh.exe"
}

if ($ghCmd) {
  Write-Host "GitHub CLI: found"
  & $ghCmd auth status
} else {
  Write-Host "[missing] GitHub CLI not installed"
}
