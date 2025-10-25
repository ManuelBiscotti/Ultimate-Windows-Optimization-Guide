    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator"))
    {Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit}
    $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + " (Administrator)"
    $Host.UI.RawUI.BackgroundColor = "Black"
	$Host.PrivateData.ProgressBackgroundColor = "Black"
    $Host.PrivateData.ProgressForegroundColor = "White"
    Clear-Host

    function Get-FileFromWeb {
    param ([Parameter(Mandatory)][string]$URL, [Parameter(Mandatory)][string]$File)
    function Show-Progress {
    param ([Parameter(Mandatory)][Single]$TotalValue, [Parameter(Mandatory)][Single]$CurrentValue, [Parameter(Mandatory)][string]$ProgressText, [Parameter()][int]$BarSize = 10, [Parameter()][switch]$Complete)
    $percent = $CurrentValue / $TotalValue
    $percentComplete = $percent * 100
    if ($psISE) { Write-Progress "$ProgressText" -id 0 -percentComplete $percentComplete }
    else { Write-Host -NoNewLine "`r$ProgressText $(''.PadRight($BarSize * $percent, [char]9608).PadRight($BarSize, [char]9617)) $($percentComplete.ToString('##0.00').PadLeft(6)) % " }
    }
    try {
    $request = [System.Net.HttpWebRequest]::Create($URL)
    $response = $request.GetResponse()
    if ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403 -or $response.StatusCode -eq 404) { throw "Remote file either doesn't exist, is unauthorized, or is forbidden for '$URL'." }
    if ($File -match '^\.\\') { $File = Join-Path (Get-Location -PSProvider 'FileSystem') ($File -Split '^\.')[1] }
    if ($File -and !(Split-Path $File)) { $File = Join-Path (Get-Location -PSProvider 'FileSystem') $File }
    if ($File) { $fileDirectory = $([System.IO.Path]::GetDirectoryName($File)); if (!(Test-Path($fileDirectory))) { [System.IO.Directory]::CreateDirectory($fileDirectory) | Out-Null } }
    [long]$fullSize = $response.ContentLength
    [byte[]]$buffer = new-object byte[] 1048576
    [long]$total = [long]$count = 0
    $reader = $response.GetResponseStream()
    $writer = new-object System.IO.FileStream $File, 'Create'
    do {
    $count = $reader.Read($buffer, 0, $buffer.Length)
    $writer.Write($buffer, 0, $count)
    $total += $count
    if ($fullSize -gt 0) { Show-Progress -TotalValue $fullSize -CurrentValue $total -ProgressText " $($File.Name)" }
    } while ($count -gt 0)
    }
    finally {
    $reader.Close()
    $writer.Close()
    }
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
		              }
	show-menu
    while ($true) {
    $choice = Read-Host " "
    if ($choice -match '^[1-9]$') {
    switch ($choice) {
    1 {

Clear-Host
$progresspreference = 'silentlycontinue'
Write-Host "Start Menu Taskbar: Clean . . ."
# CLEAN TASKBAR
# unpin all taskbar icons
cmd /c "reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband /f >nul 2>&1"
Remove-Item -Recurse -Force "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch" -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer" -Name "Quick Launch" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch" -Name "User Pinned" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned" -Name "TaskBar" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned" -Name "ImplicitAppShortcuts" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
# CLEAN START MENU W11
if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000) {
# Remove all pinned apps from Start https://github.com/Raphire/Win11Debloat/tree/refs/heads/master/Assets/Start				
Get-Process StartMenuExperienceHost | Stop-Process -Force | Out-Null; Start-Sleep -Milliseconds 200		
$dst="$env:LOCALAPPDATA\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start2.bin"		
if (!(Test-Path (Split-Path $dst))){New-Item -Path (Split-Path $dst) -ItemType Directory -Force}  		
Invoke-WebRequest -Uri 'https://github.com/Raphire/Win11Debloat/raw/refs/heads/master/Assets/Start/start2.bin' -OutFile $dst -UseBasicParsing  		
}
# CLEAN START MENU W10
elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -le 19045) {
# delete startmenulayout.xml
Remove-Item -Recurse -Force "$env:SystemDrive\Windows\StartMenuLayout.xml" -ErrorAction SilentlyContinue | Out-Null
# create startmenulayout.xml
$MultilineComment = @'
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
	<LayoutOptions StartTileGroupCellWidth="6" />
	<DefaultLayoutOverride>
		<StartLayoutCollection>
			<defaultlayout:StartLayout GroupCellWidth="6" />
		</StartLayoutCollection>
	</DefaultLayoutOverride>
</LayoutModificationTemplate>
'@
Set-Content -Path "C:\Windows\StartMenuLayout.xml" -Value $MultilineComment -Force -Encoding ASCII		
# assign startmenulayout.xml registry
$layoutFile="C:\Windows\StartMenuLayout.xml"
$regAliases = @("HKLM", "HKCU")
foreach ($regAlias in $regAliases){
$basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"		
$keyPath = $basePath + "\Explorer"		
IF(!(Test-Path -Path $keyPath)) { New-Item -Path $basePath -Name "Explorer" | Out-Null }			
Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1 | Out-Null		
Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile | Out-Null		
}
Stop-Process -Force -Name explorer -ErrorAction SilentlyContinue | Out-Null	
Timeout /T 5 | Out-Null
# disable lockedstartlayout registry		
foreach ($regAlias in $regAliases){		
$basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"		
$keyPath = $basePath + "\Explorer"		
Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0 | Out-Null		
}
# restart explorer
Stop-Process -Force -Name explorer -ErrorAction SilentlyContinue | Out-Null
# delete startmenulayout.xml
Remove-Item -Recurse -Force "$env:SystemDrive\Windows\StartMenuLayout.xml" -ErrorAction SilentlyContinue | Out-Null
Clear-Host	
}
else{Write-Host $_.Exception.Message -ForegroundColor Red}
# Signout Lockscreen
# create new image
Add-Type -AssemblyName System.Windows.Forms
$screenWidth = [System.Windows.Forms.SystemInformation]::PrimaryMonitorSize.Width
$screenHeight = [System.Windows.Forms.SystemInformation]::PrimaryMonitorSize.Height
Add-Type -AssemblyName System.Drawing
$file = "C:\Windows\Black.jpg"
$edit = New-Object System.Drawing.Bitmap $screenWidth, $screenHeight
$color = [System.Drawing.Brushes]::Black
$graphics = [System.Drawing.Graphics]::FromImage($edit)
$graphics.FillRectangle($color, 0, 0, $edit.Width, $edit.Height)
$graphics.Dispose()
$edit.Save($file)
$edit.Dispose()
# set image settings
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" /v "LockScreenImagePath" /t REG_SZ /d "C:\Windows\Black.jpg" /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" /v "LockScreenImageStatus" /t REG_DWORD /d "1" /f | Out-Null
Write-Host "Uninstalling: UWP Apps. Please wait . . ."
# uninstall all uwp apps keep nvidia & cbs
# cbs needed for w11 explorer
Get-AppXPackage -AllUsers | Where-Object { $_.Name -notlike '*NVIDIA*' -and $_.Name -notlike '*CBS*' } | Remove-AppxPackage -ErrorAction SilentlyContinue
Timeout /T 2 | Out-Null
# install hevc video extension needed for amd recording
Get-AppXPackage -AllUsers *Microsoft.HEVCVideoExtension* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Timeout /T 2 | Out-Null
# install heif image extension needed for some files
Get-AppXPackage -AllUsers *Microsoft.HEIFImageExtension* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Timeout /T 2 | Out-Null
# install notepad w11
if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000){
# create notepad start menu shortcut
$shortcut = $shell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk")
$shortcut.TargetPath = "$env:SystemRoot\System32\notepad.exe"
$shortcut.Save()
# restore new text document context menu item
Invoke-WebRequest -Uri "https://github.com/vishnusai-karumuri/Registry-Fixes/raw/refs/heads/master/Restore_New_Text_Document_context_menu_item.reg" -OutFile "$env:TEMP\Restore_New_Text_Document_context_menu_item.reg"
Start-Process regedit.exe -ArgumentList "/s `"$env:TEMP\Restore_New_Text_Document_context_menu_item.reg`"" -Wait	
# add edit with notepad to right-click context menu
# create reg file
$MultilineComment = @'
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\*\shell\Edit with &Notepad]
"Icon"="C:\\Windows\\System32\\notepad.exe,0"

[HKEY_CLASSES_ROOT\*\shell\Edit with &Notepad\command]
@="C:\\Windows\\System32\\notepad.exe \"%1\""
'@
Set-Content -Path "$env:TEMP\Restore_New_Text_Document_context_menu_item.reg" -Value $MultilineComment -Force
# import reg file
Regedit.exe /S "$env:TEMP\Restore_New_Text_Document_context_menu_item.reg"
}
else{Write-Host $_.Exception.Message -ForegroundColor Red}
Timeout /T 2 | Out-Null
# install photo viewer
'tif','tiff','bmp','dib','gif','jfif','jpe','jpeg','jpg','jxr','png','ico'|ForEach-Object{reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".${_}" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >$null 2>&1;reg add "HKCU\SOFTWARE\Classes\.${_}" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >$null 2>&1}
Timeout /T 2 | Out-Null
# install notepad w11
Get-AppXPackage -AllUsers *Microsoft.WindowsNotepad* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
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
# Remove-WindowsCapability -Online -Name "Microsoft.Windows.Ethernet.Client.Intel.E1i68x64~~~~0.0.1.0" | Out-Null
# Remove-WindowsCapability -Online -Name "Microsoft.Windows.Ethernet.Client.Intel.E2f68~~~~0.0.1.0" | Out-Null
# Remove-WindowsCapability -Online -Name "Microsoft.Windows.Ethernet.Client.Realtek.Rtcx21x64~~~~0.0.1.0" | Out-Null
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
Clear-Host
Write-Host "Uninstalling: Legacy Features. Please wait . . ."
# uninstall all legacy features
# .net framework 4.8 advanced services left out
# Dism /Online /NoRestart /Disable-Feature /FeatureName:NetFx4-AdvSrvs | Out-Null
Dism /Online /NoRestart /Disable-Feature /FeatureName:WCF-Services45 | Out-Null
Dism /Online /NoRestart /Disable-Feature /FeatureName:WCF-TCP-PortSharing45 | Out-Null
# media features left out
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
# uninstall old snippingtool w10
Start-Process "C:\Windows\System32\SnippingTool.exe" -ArgumentList "/Uninstall"
Clear-Host
# silent window for old snippingtool w10
$processExists = Get-Process -Name SnippingTool -ErrorAction SilentlyContinue
if ($processExists) {
$running = $true
do {
$openWindows = Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | Select-Object MainWindowTitle
foreach ($window in $openWindows) {
if ($window.MainWindowTitle -eq 'Snipping Tool') {
Stop-Process -Force -Name SnippingTool -ErrorAction SilentlyContinue | Out-Null
$running = $false
}
}
} while ($running)
} else {
}
Timeout /T 1 | Out-Null
# uninstall remote desktop connection
Start-Process "mstsc" -ArgumentList "/Uninstall"
Clear-Host
# silent window for remote desktop connection
$processExists = Get-Process -Name mstsc -ErrorAction SilentlyContinue
if ($processExists) {
$running = $true
do {
$openWindows = Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | Select-Object MainWindowTitle
foreach ($window in $openWindows) {
if ($window.MainWindowTitle -eq 'Remote Desktop Connection') {
Stop-Process -Force -Name mstsc -ErrorAction SilentlyContinue | Out-Null
$running = $false
}
}
} while ($running)
} else {
}
Clear-Host
Write-Host "Restart to apply . . ."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
show-menu

      }
    2 {

Clear-Host
$progresspreference = 'silentlycontinue'
Write-Host "Installing: Store. Please wait . . ."
# install store
Get-AppXPackage -AllUsers *Microsoft.WindowsStore* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.Microsoft.StorePurchaseApp * | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Clear-Host
Write-Host "Restart to apply . . ."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
show-menu

      }	  
    3 {

Clear-Host
$progresspreference = 'silentlycontinue'
Write-Host "Installing: All UWP Apps. Please wait . . ."
# install all uwp apps
Get-AppxPackage -AllUsers| Foreach {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
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
Clear-Host
Write-Host "Restart to apply . . ."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
show-menu

      }	  
    7 {

Clear-Host
Write-Host "Installing: Remote Desktop Connection. Please wait . . ."
# download remote desktop connection
Get-FileFromWeb -URL "https://go.microsoft.com/fwlink/?linkid=2247659" -File "$env:TEMP\RemoteDesktopConnection.exe"
# install remote desktop connection 
cmd /c "%TEMP%\RemoteDesktopConnection.exe >nul 2>&1"
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
Write-Host "Restart to apply . . ."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
show-menu

	  }
	  
    } } else { Write-Host "Invalid input. Please select a valid option (1-9)." } }
