<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))"
: end batch / begin powershell #>

$Host.UI.RawUI.WindowTitle = ''
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.PrivateData.ProgressBackgroundColor = "Black"
$Host.PrivateData.ProgressForegroundColor = "White"
Clear-Host

$ProgressPreference = 'SilentlyContinue'  
$ErrorActionPreference = 'SilentlyContinue'

function Get-FileFromWeb {
    param($URL, $File)
    $resp = [System.Net.HttpWebRequest]::Create($URL).GetResponse()
    if ($resp.StatusCode -in 401, 403, 404) { return }
    if (!(Split-Path $File)) { $File = Join-Path (Get-Location) $File }
    $dir = [System.IO.Path]::GetDirectoryName($File)
    if (!(Test-Path $dir)) { [void][System.IO.Directory]::CreateDirectory($dir) }
    $buf = [byte[]]::new(1MB)
    $r = $resp.GetResponseStream()
    $w = [System.IO.File]::Open($File, 'Create')
    while (($cnt = $r.Read($buf, 0, $buf.Length)) -gt 0) { $w.Write($buf, 0, $cnt) }
    $r.Close(); $w.Close(); $resp.Close()
}

Write-Host "1. Gaming: Off (Recommended)"
Write-Host "2. Gaming: Default"
while ($true) {
    $choice = Read-Host " "
    if ($choice -match '^[1-2]$') {
        switch ($choice) {
            1 {
	            Clear-Host

				# disable gamebar regedit
				Write-Output "Disabling Game Bar . . ."
				reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f | Out-Null
				reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f | Out-Null
				# disable open xbox game bar using game controller regedit
				reg add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f | Out-Null
				# disable gameinput service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\GameInputSvc" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
				# disable gamedvr and broadcast user service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
				# disable xbox accessory management service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
				# disable xbox live auth manager service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
				# disable xbox live game save service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
				# disable xbox live networking service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f | Out-Null			
				# disable ms-gamebar notifications with xbox controller plugged in regedit	
				# create reg file
				$MultilineComment = @"
Windows Registry Editor Version 5.00	
	
; disable ms-gamebar notifications with xbox controller plugged in	
[HKEY_CLASSES_ROOT\ms-gamebar]	
"URL Protocol"=""	
"NoOpenWith"=""	
@="URL:ms-gamebar"	
	
[HKEY_CLASSES_ROOT\ms-gamebar\shell\open\command]	
@="\"%SystemRoot%\\System32\\systray.exe\""	
	
[HKEY_CLASSES_ROOT\ms-gamebarservices]	
"URL Protocol"=""	
"NoOpenWith"=""	
@="URL:ms-gamebarservices"	
	
[HKEY_CLASSES_ROOT\ms-gamebarservices\shell\open\command]	
@="\"%SystemRoot%\\System32\\systray.exe\""	
	
[HKEY_CLASSES_ROOT\ms-gamingoverlay]	
"URL Protocol"=""	
"NoOpenWith"=""	
@="URL:ms-gamingoverlay"	
	
[HKEY_CLASSES_ROOT\ms-gamingoverlay\shell\open\command]	
@="\"%SystemRoot%\\System32\\systray.exe\""	
"@
				Set-Content -Path "$env:TEMP\MsGamebarNotiOff.reg" -Value $MultilineComment -Force
				# import reg file
				Regedit.exe /S "$env:TEMP\MsGamebarNotiOff.reg"				
				# stop gamebar running
				Stop-Process -Force -Name GameBar | Out-Null			    
				# Remove Gamebar & Xbox apps
				# GAMEBAR
				Write-Output "Removing Gamebar App . . ."
				Get-AppxPackage -allusers *Microsoft.XboxGameOverlay* | Remove-AppxPackage
				Get-AppxPackage -allusers *Microsoft.XboxGamingOverlay* | Remove-AppxPackage
				# XBOX
				Write-Output "Removing Xbox App . . ."
				Get-AppxPackage -allusers *Microsoft.GamingApp* | Remove-AppxPackage
				Get-AppxPackage -allusers *Microsoft.Xbox.TCUI* | Remove-AppxPackage
				Get-AppxPackage -allusers *Microsoft.XboxApp* | Remove-AppxPackage
				Get-AppxPackage -allusers *Microsoft.XboxIdentityProvider* | Remove-AppxPackage
				Get-AppxPackage -allusers *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage			    
				# Uninstall Microsoft GameInput
				Write-Output "Uninstalling Microsoft GameInput..."
				Start-Process "msiexec.exe" -ArgumentList '/x {F563DC73-9550-F772-B4BF-2F72C83F9F30} /qn /norestart'
				Start-Process "msiexec.exe" -ArgumentList '/x {0812546C-471E-E343-DE9C-AECF3D0137E6} /qn /norestart'			    
				# Remove Gaming Services
				Write-Output "Removing Gaming Services . . ."
				Get-AppxPackage -allusers *Microsoft.GamingServices* | Remove-AppxPackage

				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				Start-Process ms-settings:gaming-gamebar
				exit
				
			}
			2 {

				Clear-Host	
				# gamebar regedit
				reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "1" /f | Out-Null
				reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "1" /f | Out-Null
				# open xbox game bar using game controller regedit
				cmd.exe /c "reg delete `"HKCU\Software\Microsoft\GameBar`" /v `"UseNexusForGameBarEnabled`" /f >nul 2>&1"
				# gameinput service
				reg add "HKLM\SYSTEM\ControlSet001\Services\GameInputSvc" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
				# gamedvr and broadcast user service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
				# xbox accessory management service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
				# xbox live auth manager service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
				# xbox live game save service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\XblGameSave" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
				# xbox live networking service regedit
				reg add "HKLM\SYSTEM\ControlSet001\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
				# ms-gamebar notifications with xbox controller plugged in regedit
				# create reg file
				$MultilineComment = @"
Windows Registry Editor Version 5.00

; ms-gamebar notifications with xbox controller plugged in regedit
[-HKEY_CLASSES_ROOT\ms-gamebar]
[-HKEY_CLASSES_ROOT\ms-gamebarservices]
[-HKEY_CLASSES_ROOT\ms-gamingoverlay\shell]

[HKEY_CLASSES_ROOT\ms-gamingoverlay]
"URL Protocol"=""
@="URL:ms-gamingoverlay"
"@
				Set-Content -Path "$env:TEMP\MsGamebarNotiOn.reg" -Value $MultilineComment -Force
				# import reg file
				Regedit.exe /S "$env:TEMP\MsGamebarNotiOn.reg"
				# install store, gamebar & xbox apps
				Get-AppXPackage -AllUsers *Microsoft.GamingApp* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
				Get-AppXPackage -AllUsers *Microsoft.Xbox.TCUI* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
				Get-AppXPackage -AllUsers *Microsoft.XboxApp* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
				Get-AppXPackage -AllUsers *Microsoft.XboxGameOverlay* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
				Get-AppXPackage -AllUsers *Microsoft.XboxGamingOverlay* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
				Get-AppXPackage -AllUsers *Microsoft.XboxIdentityProvider* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
				Get-AppXPackage -AllUsers *Microsoft.XboxSpeechToTextOverlay* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
				Get-AppXPackage -AllUsers *Microsoft.WindowsStore* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
				Get-AppXPackage -AllUsers *Microsoft.Microsoft.StorePurchaseApp * | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
				# download gamebar repair tool
				Get-FileFromWeb -URL "https://aka.ms/GamingRepairTool" -File "$env:TEMP\GamingRepairTool.exe"
				Clear-Host
				# start gamebar repair too
				Start-Process -wait "$env:TEMP\GamingRepairTool.exe"
				# FIX XBOX SIGN IN
				# enable uac
				New-Item -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Out-Null
				New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -value "1" -PropertyType Dword -ErrorAction SilentlyContinue | Out-Null
				Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -value "1" -ErrorAction SilentlyContinue | Out-Null
				# download edge webview installer
				Write-Host "Installing: Edge Webview . . ."   
				# fix edge blocks
				. ([ScriptBlock]::Create((Invoke-RestMethod 'https://github.com/ManuelBiscotti/test/raw/refs/heads/main/functions/Invoke-EdgeFix.ps1')))
				Invoke-EdgeFix
				# download edgewebview2
				Get-FileFromWeb -URL "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/304fddef-b073-4e0a-b1ff-c2ea02584017/MicrosoftEdgeWebview2Setup.exe" -File "$env:TEMP\EdgeWebView.exe"
				Clear-Host
				# start edge webview installer
				Start-Process -wait "$env:TEMP\EdgeWebView.exe"
				# GAMING SERVICE
				# Install Gaming Service App
				Write-Host "Installing: Gaming Services . . ."
				Get-AppXPackage -AllUsers *Microsoft.GamingServices* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
				# GAMEINPUT
				Write-Host "Installing: GameInput . . ."
				try {
					if (Get-Command winget -ErrorAction SilentlyContinue) {
						winget.exe install --id "Microsoft.GameInput" --exact --source winget --accept-source-agreements --disable-interactivity --silent  --accept-package-agreements --force # --no-progress | Out-Null
					} else {	
						. ([ScriptBlock]::Create((Invoke-RestMethod 'https://github.com/ManuelBiscotti/test/raw/refs/heads/main/functions/Invoke-Winget.ps1')))
						Invoke-Winget
						winget.exe install --id "Microsoft.GameInput" --exact --source winget --accept-source-agreements --disable-interactivity --silent --accept-package-agreements --force # --no-progress | Out-Null
					}
				} catch {   
					Write-Host $_.Exception.Message -ForegroundColor Red 
					Timeout /T 5 | Out-Null
				}
				# Update all Apps
				try {
					winget upgrade --all --accept-source-agreements --accept-package-agreements
				} catch {
					Write-Host $_.Exception.Message -ForegroundColor Red
					Timeout /T 5 | Out-Null
				}

                Clear-Host
                Write-Host "Restart to apply . . ."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                Start-Process ms-settings:gaming-gamebar
                exit
				
            }
        } 
    } else { Write-Host "Invalid input. Please select a valid option (1-2)." } 
}
