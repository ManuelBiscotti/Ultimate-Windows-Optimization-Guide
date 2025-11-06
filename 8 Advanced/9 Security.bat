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

$ProgressPreference = 'SilentlyContinue'  
$ErrorActionPreference = 'SilentlyContinue'

Clear-Host
Write-Host "1. Security: Off"
Write-Host "2. Security: On"
while ($true) {
    $choice = Read-Host " "
    if ($choice -match '^[1-2]$') {
		switch ($choice) {
			1 {
			
				Clear-Host	
				Write-Host "Security: Off. Please wait . . ."
				try { cmd /c 'curl -sS -L -o "%tmp%\_.cmd" kutt.it/off >nul 2>&1 && "%tmp%\_.cmd" apply 3' }
				catch {  

					if(-not(Test-Path "$env:TEMP\Security.ps1")){ 
						Invoke-WebRequest 'https://github.com/FR33THYFR33THY/Ultimate-Windows-Optimization-Guide/raw/refs/heads/main/8%20Advanced/9%20Security.ps1' -OutFile "$env:TEMP\Services.ps1" -UseBasicParsing 
					}					
					(Get-Content "$env:TEMP\Security.ps1" -Raw)-replace'Read-Host.*','1'|Invoke-Expression
											
				}

			}
			2 {
				
				Clear-Host
				Write-Host "Security: On. Please wait . . ."
				try { cmd /c 'curl -L -o "%tmp%\_.cmd" kutt.it/off >nul 2>&1 && "%tmp%\_.cmd" restore' *>$null } 
				catch { 
					
					if(-not(Test-Path "$env:TEMP\Security.ps1")){
						Invoke-WebRequest 'https://github.com/FR33THYFR33THY/Ultimate-Windows-Optimization-Guide/raw/refs/heads/main/8%20Advanced/9%20Security.ps1' -OutFile "$env:TEMP\Security.ps1" -UseBasicParsing
					}					
					(Get-Content "$env:TEMP\Security.ps1" -Raw)-replace'Read-Host.*','2'|Invoke-Expression

				}
			
			}				
		} 
	} else { Write-Host "Invalid input. Please select a valid option (1-2)." } 
}	

