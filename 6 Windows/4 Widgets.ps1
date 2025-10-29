If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")){
  Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
  Exit
}

$Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + " (Administrator)"
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

Write-Host "1. Widgets: Off (Recommended)"
Write-Host "2. Widgets: Default"
while ($true) {
    $choice = Read-Host " "
    if ($choice -match '^[1-2]$') {
    	switch ($choice) {
    		1 {

				Clear-Host

				# disable widgets regedit
				reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" /v "value" /t REG_DWORD /d "0" /f | Out-Null
				# remove windows widgets from taskbar regedit
				reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f | Out-Null
				# stop widgets running
				Stop-Process -Force -Name Widgets -ErrorAction SilentlyContinue | Out-Null
				Stop-Process -Force -Name WidgetService -ErrorAction SilentlyContinue | Out-Null

				# Windows 10
				if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -le 19045) {
		
					Write-Host "Removing News and interests .	. ."
		
					# Disable News and interests (Win 10)
					New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' -Force | Out-Null
					Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' -Name 'EnableFeeds' -Value 0 -Type DWord | Out-Null

				}
	
				# Windows 11
				elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000) {
		
					Write-Host "Removing Widgets . . ."	
		
					# Remove Widgets related apps
					Get-AppxPackage -allusers *Microsoft.WidgetsPlatformRuntime* | Remove-AppxPackage
					Get-AppxPackage -allusers *MicrosoftWindows.Client.WebExperience* | Remove-AppxPackage
					Get-AppxPackage -allusers *Microsoft.StartExperiencesApp* | Remove-AppxPackage

					# Disable Widgets
					reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" /v "value" /t REG_DWORD /d "0" /f | Out-Null
					# remove windows widgets from taskbar regedit
					reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f | Out-Null
	
				}else{Write-Host $_.Exception.Message -ForegroundColor Red}

				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				exit

      		}
    		2 {

				Clear-Host
				# widgets regedit
				reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" /v "value" /t REG_DWORD /d "1" /f | Out-Null
				# windows widgets from taskbar regedit
				cmd /c "reg delete `"HKLM\SOFTWARE\Policies\Microsoft\Dsh`" /f >nul 2>&1"

				# Windows 10
				if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -le 19045) {
					Write-Host "Fixing News and interests .	. ."
					# Install Edge
					# enable edge updates regedit
					cmd /c "reg delete `"HKLM\SOFTWARE\Microsoft\EdgeUpdate`" /f >nul 2>&1"		
					# download edge installer
					Get-FileFromWeb -URL "https://go.microsoft.com/fwlink/?linkid=2109047&Channel=Stable&language=en&brand=M100" -File "$env:TEMP\Edge.exe"
					Clear-Host
					# start edge installer
					Start-Process -wait "$env:TEMP\Edge.exe"
					# install uwp edge
					# Get-AppXPackage -AllUsers *Microsoft.MicrosoftEdge.Stable* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}		
		
					# Re-enable News and interests
					Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' -Name 'EnableFeeds' -ErrorAction SilentlyContinue
					Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' -ErrorAction SilentlyContinue
				}
	
				# Windows 11
				elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000) {
					Write-Host "Fixing Widgets . . ."

					# download edge webview installer
					Get-FileFromWeb -URL "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/304fddef-b073-4e0a-b1ff-c2ea02584017/MicrosoftEdgeWebview2Setup.exe" -File "$env:TEMP\EdgeWebView.exe"
					Clear-Host
					# start edge webview installer
					Start-Process -wait "$env:TEMP\EdgeWebView.exe"
		
					# Widgets Platform Runtime
					Get-AppXPackage -AllUsers *Microsoft.WidgetsPlatformRuntime* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
					# Windows Web Experience App
					Get-AppXPackage -AllUsers *MicrosoftWindows.Client.WebExperience* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
					# Start Experiences App
					Get-AppxPackage -AllUsers *Microsoft.StartExperiencesApp* | ForEach-Object {
    					Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue
					}

					# Update Apps
					if (Get-Command winget -ErrorAction SilentlyContinue) {
   		 				winget upgrade --all --accept-source-agreements --accept-package-agreements
					} else {
						# STORE
						Clear-Host
						Write-Host "Installing: Store. Please wait . . ."
						# install store
						Get-AppXPackage -AllUsers *Microsoft.WindowsStore* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
						Get-AppXPackage -AllUsers *Microsoft.Microsoft.StorePurchaseApp * | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
	    
						# Fix PUR-AuthenticationFailure
						# Enable Microsoft Account Sign-in Assistant
						$batchCode = @'
@echo off
:: https://privacy.sexy — v0.13.8 — Sun, 19 Oct 2025 08:43:23 GMT
:: Initialize environment
setlocal EnableExtensions DisableDelayedExpansion


:: Disable Microsoft Account Sign-in Assistant (breaks Microsoft Store and Microsoft Account sign-in) (revert)
echo --- Disable Microsoft Account Sign-in Assistant (breaks Microsoft Store and Microsoft Account sign-in) (revert)
:: Restore service(s) to default state: `wlidsvc`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'wlidsvc'; $defaultStartupMode = 'Manual'; $ignoreMissingOnRevert =  $false; Write-Host "^""Reverting service `"^""$serviceName`"^"" start to `"^""$defaultStartupMode`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if (!$service) { if ($ignoreMissingOnRevert) { Write-Output "^""Skipping: The service `"^""$serviceName`"^"" is not found. No action required."^""; Exit 0; }; Write-Warning "^""Failed to revert changes to the service `"^""$serviceName`"^"". The service is not found."^""; Exit 1; }; <# -- 2. Enable or skip if already enabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if (!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq "^""$defaultStartupMode"^"") { Write-Host "^""`"^""$serviceName`"^"" has already expected startup mode: `"^""$defaultStartupMode`"^"". No action required."^""; } else { try { Set-Service -Name "^""$serviceName"^"" -StartupType "^""$defaultStartupMode"^"" -Confirm:$false -ErrorAction Stop; Write-Host "^""Reverted `"^""$serviceName`"^"" with `"^""$defaultStartupMode`"^"" start, this may require restarting your computer."^""; } catch { Write-Error "^""Failed to enable `"^""$serviceName`"^"": $_"^""; Exit 1; }; }; <# -- 4. Start if not running (must be enabled first) #>; if ($defaultStartupMode -eq 'Automatic' -or $defaultStartupMode -eq 'Boot' -or $defaultStartupMode -eq 'System') { if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is not running, starting it."^""; try { Start-Service $serviceName -ErrorAction Stop; Write-Host "^""Started `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Failed to start `"^""$serviceName`"^"", requires restart, it will be started after reboot.`r`n$_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is already running, no need to start."^""; }; }"
:: ----------------------------------------------------------


:: Restore previous environment settings
endlocal
exit
'@
			    		$batPath = "$env:TEMP\EnableMSAccountSignInAssistant.bat"
			    		Set-Content -Path $batPath -Value $batchCode -Encoding ASCII
			    		Start-Process -FilePath $batPath -WindowStyle Hidden -Wait
		    
			    		try {
			        		# Open Downloads and Updates
			        		Start-Process "ms-windows-store://downloads"
			    		}catch{
			        		Write-Host "MS Store failed to install correctly, trying another method . . ."
			        		Get-FileFromWeb -URL "https://github.com/ManuelBiscotti/test/raw/refs/heads/main/tools/MS_Store.msix" -File "$env:TEMP\MS_Store.msix"
			        		Clear-Host
			        		Start-Process "$env:TEMP\MS_Store.msix" -Wait
							Start-Process "ms-windows-store://downloadsandupdates"
			    		}
					}										
				}else{Write-Host $_.Exception.Message -ForegroundColor Red}
	
				Clear-Host
				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				exit

      		}
   		 } 		
	} else { Write-Host "Invalid input. Please select a valid option (1-2)." } 
}
