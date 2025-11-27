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

function show-menu {
	Clear-Host
	Write-Host " 1. Remove : All Bloatware (Recommended)"
    Write-Host " 2. Install: Store"
	Write-Host " 3. Install: All UWP Apps"
    Write-Host " 4. Install: UWP Features"
    Write-Host " 5. Install: Legacy Features"
	Write-Host " 6. Install: One Drive"
    Write-Host " 7. Install: Remote Desktop Connection"
    Write-Host " 8. Install: Legacy Snipping Tool W10"
    Write-Host " 9. Install: Legacy Paint W10"
    Write-Host "10. Install: GameInput"
}
	show-menu
    while ($true) {
        $choice = Read-Host " "
        if ($choice -match '^(10|[1-9])$') {
        switch ($choice) {
            1 {

                Clear-Host
                Write-Host "Uninstalling: UWP Apps. Please wait . . ."
                # uninstall all uwp apps keep nvidia & cbs
                # cbs needed for w11 explorer
	            Get-AppxPackage -AllUsers |
	            Where-Object {
	                $_.Name -notlike '*NVIDIA*' -and
	                $_.Name -notlike '*CBS*' -and
	                $_.Name -notlike '*Microsoft.Windows.Ai.Copilot.Provider*' -and
	                $_.Name -notlike '*Microsoft.Copilot*' -and			
	                $_.Name -notlike '*Gaming*' -and
	                $_.Name -notlike '*Xbox*' -and
		            $_.Name -notlike '*Widgets*' -and
	                $_.Name -notlike '*Experience*'
	            } | Remove-AppxPackage
                Timeout /T 2 | Out-Null
				# install hevc video extension needed for amd recording
				Get-AppXPackage -AllUsers *Microsoft.HEVCVideoExtension* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
				Timeout /T 2 | Out-Null
				# install heif image extension needed for some files
				Get-AppXPackage -AllUsers *Microsoft.HEIFImageExtension* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
				Timeout /T 2 | Out-Null
				# install photo viewer
				'tif','tiff','bmp','dib','gif','jfif','jpe','jpeg','jpg','jxr','png','ico'|ForEach-Object{
				    reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".${_}" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >$null 2>&1
				    reg add "HKCU\SOFTWARE\Classes\.${_}" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >$null 2>&1
				}
				Timeout /T 2 | Out-Null
				# install notepad w11
				if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000){
				    # create notepad start menu shortcut
				    $shell = New-Object -ComObject WScript.Shell
				    $shortcut = $shell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk")
				    $shortcut.TargetPath = "$env:SystemRoot\System32\notepad.exe"
				    $shortcut.Save()
					# restore new text document context menu item
					Invoke-WebRequest -Uri "https://github.com/vishnusai-karumuri/Registry-Fixes/raw/refs/heads/master/Restore_New_Text_Document_context_menu_item.reg" -OutFile "$env:TEMP\Restore_New_Text_Document_context_menu_item.reg"
					Start-Process regedit.exe -ArgumentList "/s `"$env:TEMP\Restore_New_Text_Document_context_menu_item.reg`"" -Wait	
				}else{Write-Host $_.Exception.Message -ForegroundColor Red}
				Timeout /T 2 | Out-Null	
				Clear-Host

				Write-Host "Uninstalling: UWP Features. Please wait . . ."	
				# uninstall all uwp features	
				# network drivers, media player & notepad left out	
				Remove-WindowsCapability -Online -Name "App.StepsRecorder~~~~0.0.1.0" | Out-Null	
				Remove-WindowsCapability -Online -Name "App.Support.QuickAssist~~~~0.0.1.0" | Out-Null	
				Remove-WindowsCapability -Online -Name "Browser.InternetExplorer~~~~0.0.11.0" | Out-Null	
				Remove-WindowsCapability -Online -Name "DirectX.Configuration.Database~~~~0.0.1.0" | Out-Null	
				Remove-WindowsCapability -Online -Name "Hello.Face.18967~~~~0.0.1.0" | Out-Null	
				Remove-WindowsCapability -Online -Name "Hello.Face.20134~~~~0.0.1.0" | Out-Null	
				Remove-WindowsCapability -Online -Name "MathRecognizer~~~~0.0.1.0" | Out-Null	
				# Remove-WindowsCapability -Online -Name "Media.WindowsMediaPlayer~~~~0.0.12.0" | Out-Null	
				Remove-WindowsCapability -Online -Name "Microsoft.Wallpapers.Extended~~~~0.0.1.0" | Out-Null	
				Remove-WindowsCapability -Online -Name "Microsoft.Windows.MSPaint~~~~0.0.1.0" | Out-Null	
				# Remove-WindowsCapability -Online -Name "Microsoft.Windows.Notepad.System~~~~0.0.1.0" | Out-Null	
				# Remove-WindowsCapability -Online -Name "Microsoft.Windows.Notepad~~~~0.0.1.0" | Out-Null	
				Remove-WindowsCapability -Online -Name "Microsoft.Windows.PowerShell.ISE~~~~0.0.1.0" | Out-Null	
				Remove-WindowsCapability -Online -Name "Microsoft.Windows.WordPad~~~~0.0.1.0" | Out-Null	
				Remove-WindowsCapability -Online -Name "OneCoreUAP.OneSync~~~~0.0.1.0" | Out-Null	
				Remove-WindowsCapability -Online -Name "OpenSSH.Client~~~~0.0.1.0" | Out-Null	
				Remove-WindowsCapability -Online -Name "Print.Fax.Scan~~~~0.0.1.0" | Out-Null	
				Remove-WindowsCapability -Online -Name "Print.Management.Console~~~~0.0.1.0" | Out-Null	
				# breaks installer & uninstaller programs
				# Remove-WindowsCapability -Online -Name "VBSCRIPT~~~~" | Out-Null	
				Remove-WindowsCapability -Online -Name "WMIC~~~~" | Out-Null	
				# breaks uwp snippingtool w10	
				# Remove-WindowsCapability -Online -Name "Windows.Client.ShellComponents~~~~0.0.1.0" | Out-Null	
				Remove-WindowsCapability -Online -Name "Windows.Kernel.LA57~~~~0.0.1.0" | Out-Null	
				# remove character map start shortcut	
				Remove-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\System Tools\Character Map.lnk" -Force -ErrorAction SilentlyContinue | Out-Null	
				Clear-Host	
				Write-Host "Uninstalling: Legacy Features. Please wait . . ."	
				# uninstall all legacy features	
				# .net framework 4.8 advanced services and media features left out	
				# Dism /Online /NoRestart /Disable-Feature /FeatureName:NetFx4-AdvSrvs | Out-Null	
				Dism /Online /NoRestart /Disable-Feature /FeatureName:WCF-Services45 | Out-Null	
				Dism /Online /NoRestart /Disable-Feature /FeatureName:WCF-TCP-PortSharing45 | Out-Null	
				# media features	
				# Dism /Online /NoRestart /Disable-Feature /FeatureName:MediaPlayback | Out-Null	
				Dism /Online /NoRestart /Disable-Feature /FeatureName:Printing-PrintToPDFServices-Features | Out-Null	
				Dism /Online /NoRestart /Disable-Feature /FeatureName:Printing-XPSServices-Features | Out-Null	
				Dism /Online /NoRestart /Disable-Feature /FeatureName:Printing-Foundation-Features | Out-Null	
				Dism /Online /NoRestart /Disable-Feature /FeatureName:Printing-Foundation-InternetPrinting-Client | Out-Null	
				Dism /Online /NoRestart /Disable-Feature /FeatureName:MSRDC-Infrastructure | Out-Null	
				# breaks search	
				# Dism /Online /NoRestart /Disable-Feature /FeatureName:SearchEngine-Client-Package | Out-Null	
				Dism /Online /NoRestart /Disable-Feature /FeatureName:SMB1Protocol | Out-Null	
				Dism /Online /NoRestart /Disable-Feature /FeatureName:SMB1Protocol-Client | Out-Null	
				Dism /Online /NoRestart /Disable-Feature /FeatureName:SMB1Protocol-Deprecation | Out-Null	
				Dism /Online /NoRestart /Disable-Feature /FeatureName:SmbDirect | Out-Null	
				Dism /Online /NoRestart /Disable-Feature /FeatureName:Windows-Identity-Foundation | Out-Null	
				Dism /Online /NoRestart /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2Root | Out-Null	
				Dism /Online /NoRestart /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2 | Out-Null	
				Dism /Online /NoRestart /Disable-Feature /FeatureName:WorkFolders-Client | Out-Null	
				Clear-Host	
				Write-Host "Uninstalling: Legacy Apps. Please wait . . ."	
				# uninstall microsoft update health tools w11	
				cmd /c "MsiExec.exe /X{C6FD611E-7EFE-488C-A0E0-974C09EF6473} /qn >nul 2>&1"	
				# uninstall microsoft update health tools w10	
				cmd /c "MsiExec.exe /X{1FC1A6C2-576E-489A-9B4A-92D21F542136} /qn >nul 2>&1"	
				# clean microsoft update health tools w10	
				cmd /c "reg delete `"HKLM\SYSTEM\ControlSet001\Services\uhssvc`" /f >nul 2>&1"	
				Unregister-ScheduledTask -TaskName PLUGScheduler -Confirm:$false -ErrorAction SilentlyContinue | Out-Null	
				# uninstall update for windows 10 for x64-based systems	
				cmd /c "MsiExec.exe /X{B9A7A138-BFD5-4C73-A269-F78CCA28150E} /qn >nul 2>&1"	
				cmd /c "MsiExec.exe /X{85C69797-7336-4E83-8D97-32A7C8465A3B} /qn >nul 2>&1"	
				# (KB5001716)	
				cmd /c "MsiExec.exe /X{B8D93870-98D1-4980-AFCA-E26563CDFB79} /qn >nul 2>&1"	
				# uninstall microsoft gameinput	
				cmd /c "MsiExec.exe /X{F563DC73-9550-F772-B4BF-2F72C83F9F30} /qn >nul 2>&1"	
				cmd /c "MsiExec.exe /X{0812546C-471E-E343-DE9C-AECF3D0137E6} /qn >nul 2>&1"	
				# stop onedrive running	
				Stop-Process -Force -Name OneDrive -ErrorAction SilentlyContinue | Out-Null	
				# uninstall onedrive w10	
				cmd /c "C:\Windows\SysWOW64\OneDriveSetup.exe -uninstall >nul 2>&1"	
				# clean onedrive w10 	
				Get-ScheduledTask | Where-Object {$_.Taskname -match 'OneDrive'} | Unregister-ScheduledTask -Confirm:$false	
				# uninstall onedrive w11	
				cmd /c "C:\Windows\System32\OneDriveSetup.exe -uninstall >nul 2>&1"	
				# clean adobe type manager w10	
				cmd /c "reg delete `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`" /f >nul 2>&1"	
				Clear-Host	
				# uninstall old snippingtool w10	
				# Uninstall SnippingTool Legacy
				if (Test-Path "C:\Windows\System32\SnippingTool.exe") {
				    Start-Process "C:\Windows\System32\SnippingTool.exe" -ArgumentList "/Uninstall"
				    $processExists = Get-Process -Name SnippingTool -ErrorAction SilentlyContinue
				    if ($processExists) {
				        do {
				            $openWindows = Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | Select-Object -ExpandProperty MainWindowTitle
				            if ($openWindows -contains 'Snipping Tool') {
				                Stop-Process -Name SnippingTool -Force -ErrorAction SilentlyContinue
				                break
				            }
				        } while ($true)
				    }
				}
				<#				
				# kill Microsoft Text Input Application	
				cmd /c "taskkill /F /IM TextInputHost.exe >nul 2>&1"	
				$d=Get-ChildItem "$env:SystemRoot\SystemApps" -Dir -Filter "MicrosoftWindows.Client.CBS_*"|Select-Object -First 1 -ExpandProperty FullName	
				if($d){$x=Join-Path $d "TextInputHost.exe"	
				if(Test-Path $x){cmd /c "takeown /f `"$x`" >nul 2>&1 & icacls `"$x`" /grant *S-1-3-4:F >nul 2>&1 & move /y `"$x`" `"$env:SystemRoot\TextInputHost.exe.bak`" >nul 2>&1"}	
				}
				#>
	            # Create System Properties Start menu shortcut
	            $t="$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\System Properties.lnk"
	            $s=(New-Object -ComObject WScript.Shell).CreateShortcut($t)
	            $s.TargetPath="$env:SystemRoot\System32\SystemPropertiesAdvanced.exe"
	            $s.IconLocation="$env:SystemRoot\System32\SystemPropertiesAdvanced.exe"
	            $s.Save() >$null 2>&1

				# uninstall remote desktop connection	
				Start-Process "mstsc" -ArgumentList "/Uninstall"	
				Clear-Host	
				Write-Host "Restart to apply . . ."	
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")	
				show-menu	

			}
			2 {

				Clear-Host
				Write-Host "Installing: Store. Please wait . . ."
				# install store
				Get-AppXPackage -AllUsers *Microsoft.WindowsStore* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
				Get-AppXPackage -AllUsers *Microsoft.Microsoft.StorePurchaseApp * | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
	    
				# Fix [ PUR-AuthenticationFailure ]
				# enable Microsoft Account Sign-in Assistant
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
			        # try Open Phone Link App page
			        Start-Process "ms-windows-store://pdp/?ProductId=9NMPJ99VJBWV"
			    }catch{
			        Write-Host "MS Store failed to install correctly, trying another method . . ."
			        Get-FileFromWeb -URL "https://github.com/ManuelBiscotti/test/raw/refs/heads/main/tools/MS_Store.msix" -File "$env:TEMP\MS_Store.msix"
			        Clear-Host
			        Start-Process "$env:TEMP\MS_Store.msix"
			    }
			    Clear-Host
			    show-menu
		    
			  }	  
			3 {

				Clear-Host
                Write-Host "Installing: All UWP Apps. Please wait . . ."
                # install all uwp apps
                Get-AppxPackage -AllUsers| ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
                Clear-Host
                Write-Host "Restart to apply . . ."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                show-menu

			}	  
			4 {

				Clear-Host
				Write-Host "Install: UWP Features . . ."
				Write-Host ""
				Write-Host "Installing multiple features at once may fail."
				Write-Host "If so, restart PC between each feature install."
				Write-Host ""
				# open uwp optional features
				Start-Process "ms-settings:optionalfeatures"
				# uwp list
				Write-Host ""
				Write-Host "---------------------------------------------"
				Write-Host "      Default Windows Install List W11"
				Write-Host "---------------------------------------------"
				Write-Host ""
				Write-Host "-Extended Theme Content"
				Write-Host "-Facial Recognition (Windows Hello)"
				Write-Host "-Internet Explorer mode"
				Write-Host "-Math Recognizer"
				Write-Host "-Notepad (system)"
				Write-Host "-OpenSSH Client"
				Write-Host "-Print Management"
				Write-Host "-Steps Recorder"
				Write-Host "-WMIC"
				Write-Host "-Windows Media Player Legacy (App)"
				Write-Host "-Windows PowerShell ISE"
				Write-Host "-WordPad"
				Write-Host ""
				Write-Host "---------------------------------------------"
				Write-Host "      Default Windows Install List W10"
				Write-Host "---------------------------------------------"
				Write-Host ""
				Write-Host "-Internet Explorer 11"
				Write-Host "-Math Recognizer"
				Write-Host "-Microsoft Quick Assist (App)"
				Write-Host "-Notepad (system)"
				Write-Host "-OpenSSH Client"
				Write-Host "-Print Management Console"
				Write-Host "-Steps Recorder"
				Write-Host "-Windows Fax and Scan"
				Write-Host "-Windows Hello Face"
				Write-Host "-Windows Media Player Legacy (App)"
				Write-Host "-Windows PowerShell Integrated Scripting Environment"
				Write-Host "-WordPad"
				Write-Host ""
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				Clear-Host
				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				show-menu
				
			}
			5 {

				Clear-Host
				Write-Host "Install: Legacy Features . . ."
				# open legacy optional features
				Start-Process "C:\Windows\System32\OptionalFeatures.exe"
				# legacy list
				Write-Host ""
				Write-Host "---------------------------------------------"
				Write-Host "      Default Windows Install List W11"
				Write-Host "---------------------------------------------"
				Write-Host ""
				Write-Host "-.Net Framework 4.8 Advanced Services +"
				Write-Host "-WCF Services +"
				Write-Host "-TCP Port Sharing"
				Write-Host "-Media Features +"
				Write-Host "-Windows Media Player Legacy (App)"
				Write-Host "-Microsoft Print to PDF"
				Write-Host "-Print and Document Services +"
				Write-Host "-Internet Printing Client"
				Write-Host "-Remote Differential Compression API Support"
				Write-Host "-SMB Direct"
				Write-Host "-Windows PowerShell 2.0 +"
				Write-Host "-Windows PowerShell 2.0 Engine"
				Write-Host "-Work Folders Client"
				Write-Host ""
				Write-Host "---------------------------------------------"
				Write-Host "      Default Windows Install List W10"
				Write-Host "---------------------------------------------"
				Write-Host ""
				Write-Host "-.Net Framework 4.8 Advanced Services +"
				Write-Host "-WCF Services +"
				Write-Host "-TCP Port Sharing"
				Write-Host "-Internet Explorer 11"
				Write-Host "-Media Features +"
				Write-Host "-Windows Media Player"
				Write-Host "-Microsoft Print to PDF"
				Write-Host "-Microsoft XPS Document Writer"
				Write-Host "-Print and Document Services +"
				Write-Host "-Internet Printing Client"
				Write-Host "-Remote Differential Compression API Support"
				Write-Host "-SMB 1.0/CIFS File Sharing Support +"
				Write-Host "-SMB 1.0/CIFS Automatic Removal"
				Write-Host "-SMB 1.0/CIFS Client"
				Write-Host "-SMB Direct"
				Write-Host "-Windows PowerShell 2.0 +"
				Write-Host "-Windows PowerShell 2.0 Engine"
				Write-Host "-Work Folders Client"
				Write-Host ""
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				Clear-Host
				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				show-menu
				
			}
			6 {

				Clear-Host
				Write-Host "Installing: One Drive. Please wait . . ."
				# install onedrive w10
				cmd /c "C:\Windows\SysWOW64\OneDriveSetup.exe >nul 2>&1"
				# install onedrive w11
				cmd /c "C:\Windows\System32\OneDriveSetup.exe >nul 2>&1"
				Start-Process "$env:OneDrive"
				Clear-Host
				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				show-menu
				
			}	  
			7 {
				
				Clear-Host
				Write-Host "Installing: Remote Desktop Connection. Please wait . . ."
				# download remote desktop connection
				Get-FileFromWeb -URL "https://go.microsoft.com/fwlink/?linkid=2247659" -File "$env:TEMP\setup.exe"
				# install remote desktop connection 
				cmd /c "%TEMP%\setup.exe >nul 2>&1"
				Timeout T/1 | Out-Null
				Start-Process "mstsc"
				Clear-Host
				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				show-menu
				
			}
			8 {
				
				Clear-Host
				Write-Host "Installing: Legacy Snipping Tool W10. Please wait . . ."
				# Ensure target directory exists
				New-Item -Path "C:\Program Files\Windows NT\Accessories" -ItemType Directory -Force | Out-Null	
				# Ensure Accessories folder exists
				New-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories" -ItemType Directory -Force | Out-Null		
				# Snipping Tool (Windows 10 Version 1803)		
				Get-FileFromWeb -URL "https://github.com/ManueITest/Windows/raw/main/SnippingTool.zip" -File "$env:TEMP\SnippingTool.zip"		
				Expand-Archive -Path "$env:TEMP\SnippingTool.zip" -DestinationPath "C:\Program Files\Windows NT\Accessories" -Force			
				# Create Snipping Tool Start menu shortcut		
				$shell = New-Object -ComObject WScript.Shell		
				$shortcut = $shell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Snipping Tool.lnk")		
				$shortcut.TargetPath = "C:\Program Files\Windows NT\Accessories\SnippingTool.exe"	
				$shortcut.Save()
				Timeout T/1 | Out-Null
				Start-Process "C:\Program Files\Windows NT\Accessories\SnippingTool.exe"
				Clear-Host
				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				show-menu
				
			}
			9 {
				
				Clear-Host
				Write-Host "Installing: Legacy Paint W10. Please wait . . ."
				# Ensure target directory exists
				New-Item -Path "C:\Program Files\Windows NT\Accessories" -ItemType Directory -Force | Out-Null	
				# Ensure Accessories folder exists
				New-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories" -ItemType Directory -Force | Out-Null		
				# classic Paint (mspaint) app taken from Windows 10 Build 14393
				Get-FileFromWeb -URL "https://github.com/ManueITest/Windows/raw/main/Classic%20Paint.zip" -File "$env:TEMP\ClassicPaint.zip"
				Expand-Archive -Path "$env:TEMP\ClassicPaint.zip" -DestinationPath "C:\Program Files\Windows NT\Accessories" -Force	
				# Create Paint Start menu shortcut  
				$shortcut = $shell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Paint.lnk")
				$shortcut.TargetPath = "C:\Program Files\Windows NT\Accessories\mspaint1.exe"
				$shortcut.Save()
				Timeout T/1 | Out-Null
				Start-Process "C:\Program Files\Windows NT\Accessories\mspaint1.exe"
				Clear-Host
				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				show-menu
				
			}    
			10 {
			
				Write-Host "Installing: GameInput . . ."
					
				if (Get-Command winget -ErrorAction SilentlyContinue) {
					winget.exe install --id "Microsoft.GameInput" --exact --source winget --accept-source-agreements --disable-interactivity --silent  --accept-package-agreements --force --no-progress | Out-Null
				} else {
				
					$exe = "$env:TEMP\7zip.exe"
					$url = (Invoke-RestMethod "https://api.github.com/repos/ip7z/7zip/releases/latest").assets |
						Where-Object { $_.name -like "*x64.exe" } |
						Select-Object -First 1 -ExpandProperty browser_download_url						
					Get-FileFromWeb $url -File $exe					
					Start-Process -FilePath $exe -ArgumentList '/S' -Wait
						
					Get-FileFromWeb -URL "https://www.nuget.org/api/v2/package/Microsoft.GameInput" -File "$env:TEMP\microsoft.gameinput.nupkg"						
					$zip = "$env:ProgramFiles\7-Zip\7z.exe"
					Start-Process $zip -ArgumentList "x `"$env:TEMP\microsoft.gameinput.nupkg`" -o`"$env:TEMP`" -y" -Wait						
					Start-Process "msiexec.exe" -ArgumentList "/i `"$env:TEMP\redist\GameInputRedist.msi`" /quiet /norestart" -Wait

				}

			}    
		} 
	} else { Write-Host "Invalid input. Please select a valid option (1-10)." } 
}