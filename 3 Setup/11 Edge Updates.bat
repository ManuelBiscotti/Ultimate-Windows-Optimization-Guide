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

# EDGE
# stop edge running
$stop = "MicrosoftEdgeUpdate", "OneDrive", "WidgetService", "Widgets", "msedge", "Resume", "CrossDeviceResume", "msedgewebview2"
$stop | ForEach-Object { Stop-Process -Name $_ -Force -ErrorAction SilentlyContinue }			
# microsoft-edge-debloater				
Invoke-WebRequest -Uri "https://github.com/bibicadotnet/microsoft-edge-debloater/archive/refs/heads/main.zip" -OutFile "$env:TEMP\main.zip"				
Expand-Archive "$env:TEMP\main.zip" -DestinationPath "$env:TEMP" -Force				
# edge-debloat				
Invoke-WebRequest -Uri "https://github.com/marlock9/edge-debloat/raw/refs/heads/main/edge-debloat.reg" -OutFile "$env:TEMP\edge-debloat.reg"				
# msedge-debloat.reg				
Invoke-WebRequest -Uri "https://gist.github.com/yashgorana/83a2939d739e312820f39703fe991412/raw/f93921f5887b3c7f443bfac35b573e0dc085ad03/msedge-debloat.reg" -OutFile "$env:TEMP\msedge-debloat.reg"
# import reg files				
Regedit.exe /S "$env:TEMP\microsoft-edge-debloater-main\vi.edge.reg"				
Timeout /T 1 | Out-Null				
Regedit.exe /S "$env:TEMP\msedge-debloat.reg"				
Timeout /T 1 | Out-Null				
Regedit.exe /S "$env:TEMP\edge-debloat.reg"				
Timeout /T 2 | Out-Null				
# remove extensions				
Remove-Item -Path "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallForcelist" -Recurse -Force -ErrorAction SilentlyContinue				
			
# create reg file
$MultilineComment = @'
Windows Registry Editor Version 5.00

; Force install uBlock origin and webrtc control extensions
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist]
"1"="odfafepnkmbhccpbejgmiehpchacaeak;https://edge.microsoft.com/extensionwebstorebase/v1/crx"
; "2"="eepeadgljpkkjpbfecfkijnnliikglpl;https://edge.microsoft.com/extensionwebstorebase/v1/crx" ; webrtc control


; Set Brave as default search engine
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge]
"DefaultSearchProviderEnabled"=dword:00000001
"DefaultSearchProviderName"="Brave"
"DefaultSearchProviderSearchURL"="https://search.brave.com/search?q={searchTerms}"
"DefaultSearchProviderSuggestURL"="https://search.brave.com/api/suggest?q={searchTerms}"


; Set Blank New Tab
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF] 
"EnrollmentState"=dword:00000001 
"EnrollmentType"=dword:00000000 
"IsFederated"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF]
"Flags"=dword:00d6fb7f
"AcctUId"="0x000000000000000000000000000000000000000000000000000000000000000000000000"
"RoamingCount"=dword:00000000
"SslClientCertReference"="MY;User;0000000000000000000000000000000000000000"
"ProtoVer"="1.2"

; Black new tab page (no title, pure dark)
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge]
"NewTabPageLocation"="data:text/html,<html><head><meta name='color-scheme' content='dark'><title></title><style>html,body{margin:0;background:#000;height:100%;}</style></head><body></body></html>"


; remove logon edge
[-HKEY_LOCAL_MACHINE\Software\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}]

; disable edge services
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MicrosoftEdgeElevationService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\edgeupdate]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\edgeupdatem]
"Start"=dword:00000004

; block desktop shortcut for all edge channels
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\EdgeUpdate]
"CreateDesktopShortcutDefault"=dword:00000000

; disable edge updates
[HKEY_CURRENT_USER\Software\Policies\Microsoft\EdgeUpdate]
"UpdateDefault"=dword:00000000

; disable auto-updates for all users
; prevent edge from staying up-to-date automatically
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\EdgeUpdate]
"UpdateDefault"=dword:00000000
"AutoUpdateCheckPeriodMinutes"=dword:00000000

; block all update channels
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\EdgeUpdate]
"Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"=dword:00000000
"Update{2CD8A007-E189-4D47-B5A4-DD5A7A6D2766}"=dword:00000000
"Update{65C35B14-6C1D-4122-AC46-7148CC9D6497}"=dword:00000000

; disable Edge as default PDF viewer
[HKEY_CLASSES_ROOT\.pdf]
@="AcroExch.Document.DC"

[HKEY_CLASSES_ROOT\.pdf\OpenWithProgids]
"AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723"=-

; Disable Edge update notifications
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\EdgeUpdate]
"UpdateDefault"=dword:00000000
"AutoUpdateCheckPeriodMinutes"=dword:00000000

; edge telemetry
[-HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
[-HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker]

[HKEY_CURRENT_USER\Software\Policies\Microsoft\MicrosoftEdge\BooksLibrary]
"EnableExtendedBooksTelemetry"=dword:00000000

[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MicrosoftEdge\BooksLibrary]
"EnableExtendedBooksTelemetry"=dword:00000000

; dont send edge data
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection]
"MicrosoftEdgeDataOptIn"=dword:00000000

; edge preload
[HKEY_CURRENT_USER\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader]
"AllowTabPreloading"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader]
"AllowTabPreloading"=dword:00000000

; disable smartscreen in edge
[HKEY_CURRENT_USER\Software\Microsoft\Edge\SmartScreenEnabled]
"(Default)"="0"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Edge\SmartScreenEnabled]
@=dword:00000000

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Edge\SmartScreenPuaEnabled]
@=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter]
"EnabledV9"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\MicrosoftEdge\PhishingFilter]
"EnabledV9"=dword:00000000
'@
				
# import reg file	            
Set-Content -Path "$env:TEMP\Edge.reg" -Value $MultilineComment -Force		            
Regedit.exe /S "$env:TEMP\Edge.reg"		        
Timeout /T 1 | Out-Null	            
# disable edge tasks	            
Get-ScheduledTask | Where-Object { $_.TaskName -like "*Edge*" } | ForEach-Object { Disable-ScheduledTask -TaskName $_.TaskName | Out-Null }

# open web browser
Start-Process "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
