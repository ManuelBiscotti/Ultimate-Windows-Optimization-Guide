<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))"
: end batch / begin powershell #>

$Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + " (Administrator)"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.PrivateData.ProgressBackgroundColor = "Black"
$Host.PrivateData.ProgressForegroundColor = "White"
Clear-Host

$progresspreference = 'silentlycontinue'
$ErrorActionPreference = 'SilentlyContinue'
				   
Write-Host "1. Copilot: Off (Recommended)"
Write-Host "2. Copilot: Default"

while ($true) {
    $choice = Read-Host " "
    if ($choice -match '^[1-2]$') {
        switch ($choice) {
            1 {
                Clear-Host
                try {
                    Set-Content -LiteralPath "$env:TEMP\RemoveWindowsAI.ps1" -Force -Value (
                        (Invoke-WebRequest "https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1" -UseBasicParsing).Content `
                        -replace '(?m)^.*ReadKey\(\).*$\r?\n?', ''
                    ) | Out-Null

                    Start-Process powershell.exe -NoNewWindow -Wait -ArgumentList @(
                        '-NoProfile','-ExecutionPolicy','Bypass',
                        '-File',"$env:TEMP\RemoveWindowsAI.ps1",
                        '-NonInteractive','-BackupMode','-AllOptions'
                    ) | Out-Null
                }
                catch {
                    if (-not (Test-Path -LiteralPath "$env:TEMP\Copilot.ps1")) {
                        Invoke-WebRequest 'https://github.com/FR33THYFR33THY/Ultimate-Windows-Optimization-Guide/raw/refs/heads/main/6%20Windows/3%20Copilot.ps1' -OutFile "$env:TEMP\Copilot.ps1" -UseBasicParsing
                    }
                    (Get-Content "$env:TEMP\Copilot.ps1" -Raw) -replace 'Read-Host.*','1' | Invoke-Expression
                }

				Clear-Host
                Write-Host "Restart to apply . . ."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                exit
            }

            2 {
                Clear-Host
                try {
                    Set-Content -LiteralPath "$env:TEMP\RemoveWindowsAI.ps1" -Force -Value (
                        (Invoke-WebRequest "https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1" -UseBasicParsing).Content `
                        -replace '(?m)^.*ReadKey\(\).*$\r?\n?', ''
                    ) | Out-Null

                    Start-Process powershell.exe -NoNewWindow -Wait -ArgumentList @(
                        '-NoProfile','-ExecutionPolicy','Bypass',
                        '-File',"$env:TEMP\RemoveWindowsAI.ps1",
                        '-NonInteractive','-RevertMode','-AllOptions'
                    ) | Out-Null
                }
                catch {
                    if (-not (Test-Path -LiteralPath "$env:TEMP\Copilot.ps1")) {
                        Invoke-WebRequest 'https://github.com/FR33THYFR33THY/Ultimate-Windows-Optimization-Guide/raw/refs/heads/main/6%20Windows/3%20Copilot.ps1' -OutFile "$env:TEMP\Copilot.ps1" -UseBasicParsing
                    }
                    (Get-Content "$env:TEMP\Copilot.ps1" -Raw) -replace 'Read-Host.*','2' | Invoke-Expression
                }

				Clear-Host
                Write-Host "Restart to apply . . ."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                exit
            }
        }
    } else {
        Write-Host "Invalid input. Please select a valid option (1-2)."
    }
}
