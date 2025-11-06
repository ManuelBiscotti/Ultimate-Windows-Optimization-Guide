# Install or upgrade Brave browser
function Invoke-Brave {
    # Direct download and install
	Write-Host "Installing Brave..." -ForegroundColor Green
    $installer = "$env:TEMP\BraveBrowserSetup.exe"
    Invoke-WebRequest -Uri "https://laptop-updates.brave.com/download/BraveBrowserSetup.exe" -OutFile $installer -UseBasicParsing
    $proc = Start-Process -FilePath $installer -ArgumentList "/silent", "/install" -Wait -PassThru
    if (($proc.ExitCode -eq 0) -or ((Get-ExistingPaths $paths).Count -gt 0)) {
    }
	
<#
    # Upgrade via Winget if available
    if (Get-Command winget.exe) {
        winget.exe upgrade --id "Brave.Brave" --exact --source winget --accept-source-agreements --silent --accept-package-agreements --quiet | Out-Null
    }
#>

	# Debloat Brave after installation
    Write-Host "Debloating Brave..." -ForegroundColor Green 	
	$batchCode = @'
@echo off

taskkill /f /im "BraveUpdate.exe" >nul 2>&1
taskkill /f /im "brave_installer-x64.exe" >nul 2>&1
taskkill /f /im "BraveCrashHandler.exe" >nul 2>&1
taskkill /f /im "BraveCrashHandler64.exe" >nul 2>&1
taskkill /f /im "BraveCrashHandlerArm64.exe" >nul 2>&1
taskkill /f /im "BraveUpdateBroker.exe" >nul 2>&1
taskkill /f /im "BraveUpdateCore.exe" >nul 2>&1
taskkill /f /im "BraveUpdateOnDemand.exe" >nul 2>&1
taskkill /f /im "BraveUpdateSetup.exe" >nul 2>&1
taskkill /f /im "BraveUpdateComRegisterShell64" >nul 2>&1
taskkill /f /im "BraveUpdateComRegisterShellArm64" >nul 2>&1
	
rmdir /s /q "C:\Program Files (x86)\BraveSoftware\Update" >nul 2>&1
	
schtasks /delete /f /tn BraveSoftwareUpdateTaskMachineCore{2320C90E-9617-4C25-88E0-CC10B8F3B6BB} >nul 2>&1
schtasks /delete /f /tn BraveSoftwareUpdateTaskMachineUA{FD1FD78D-BD51-4A16-9F47-EE6518C2D038} >nul 2>&1
	
reg delete "HKLM\Software\Microsoft\Active Setup\Installed Components\{AFE6A462-C574-4B8A-AF43-4CC60DF4563B}" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\{56CA197F-543C-40DC-953C-B9C6196C92A5}" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{0948A341-8E1E-479F-A667-6169E4D5CB2A}" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0948A341-8E1E-479F-A667-6169E4D5CB2A}" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{56CA197F-543C-40DC-953C-B9C6196C92A5}" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\BraveSoftwareUpdateTaskMachineCore" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\BraveSoftwareUpdateTaskMachineUA" /f >nul 2>&1
	
sc config brave start=disabled >nul 2>&1
sc config bravem start=disabled >nul 2>&1
sc config BraveElevationService start=disabled >nul 2>&1	
'@
	$batPath = "$env:TEMP\DebloatBrave.bat"
	Set-Content -Path $batPath -Value $batchCode -Encoding ASCII
	Start-Process -FilePath $batPath -Wait
	Remove-Item $batPath -Force
	
$MultilineComment = @'
Windows Registry Editor Version 5.00	

; Debloat Brave using Chromium policies. Auto-generated using https://github.com/yashgorana/chrome-debloat
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\BraveSoftware\Brave]
"BraveNewsDisabled"=dword:00000001
"BraveP3AEnabled"=dword:00000000
"BraveSpeedreaderEnabled"=dword:00000000
"BraveStatsPingEnabled"=dword:00000000
"BraveTalkDisabled"=dword:00000001
"BraveVPNDisabled"=dword:00000001
"BraveWalletDisabled"=dword:00000001
"BraveWaybackMachineEnabled"=dword:00000000
"BraveWebDiscoveryEnabled"=dword:00000000
; "DefaultBrowserSettingEnabled"=dword:00000000
"TorDisabled"=dword:00000001
"BraveRewardsDisabled"=dword:00000001
"BraveWalletDisabled"=dword:00000001
"BraveVPNDisabled"=dword:00000001
"BraveAIChatEnabled"=dword:00000000
"BraveSyncUrl"=""
"DefaultGeolocationSetting"=dword:00000002
"DefaultNotificationsSetting"=dword:00000002
"DefaultLocalFontsSetting"=dword:00000002
"DefaultSensorsSetting"=dword:00000002
"DefaultSerialGuardSetting"=dword:00000002
"CloudReportingEnabled"=dword:00000000
"DriveDisabled"=dword:00000001
"PasswordManagerEnabled"=dword:00000000
"PasswordSharingEnabled"=dword:00000000
"PasswordLeakDetectionEnabled"=dword:00000000
"QuickAnswersEnabled"=dword:00000000
; "SafeBrowsingExtendedReportingEnabled"=dword:00000000
; "SafeBrowsingSurveysEnabled"=dword:00000000
; "SafeBrowsingDeepScanningEnabled"=dword:00000000
"DeviceActivityHeartbeatEnabled"=dword:00000000
"DeviceMetricsReportingEnabled"=dword:00000000
"HeartbeatEnabled"=dword:00000000
"LogUploadEnabled"=dword:00000000
"ReportAppInventory"=""
"ReportDeviceActivityTimes"=dword:00000000
"ReportDeviceAppInfo"=dword:00000000
"ReportDeviceSystemInfo"=dword:00000000
"ReportDeviceUsers"=dword:00000000
"ReportWebsiteTelemetry"=""
"AlternateErrorPagesEnabled"=dword:00000000
"AutofillCreditCardEnabled"=dword:00000000
"BackgroundModeEnabled"=dword:00000000
"BrowserGuestModeEnabled"=dword:00000000
"BrowserSignin"=dword:00000000
"BuiltInDnsClientEnabled"=dword:00000000
"MetricsReportingEnabled"=dword:00000000
"ParcelTrackingEnabled"=dword:00000000
"RelatedWebsiteSetsEnabled"=dword:00000000
"ShoppingListEnabled"=dword:00000000
"SyncDisabled"=dword:00000001
"ExtensionManifestV2Availability"=dword:00000002

; install extensions
; [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForcelist]
; "1"="cjpalhdlnbpafiamejdnhcphjbkeiagm" ; ublock origin
; "2"="eimadpbcbfnmbkopoojfekhnkhdbieeh" ; dark reader
; "3"="jplgfhpmjnbigmhklmmbgecoobifkmpa" ; proton vpn	
; "4"="nngceckbapebfimnlniiiahkandclblb" ; bitwarden
; "5"="ejkiikneibegknkgimmihdpcbcedgmpo" ; volume booster

; SlimBrave https://github.com/ltx0101/SlimBrave/tree/main
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\BraveSoftware\Brave]
"UrlKeyedAnonymizedDataCollectionEnabled"=dword:00000000
"FeedbackSurveysEnabled"=dword:00000000
"SafeBrowsingProtectionLevel"=dword:00000000
"AutofillAddressEnabled"=dword:00000000
"WebRtcIPHandling"="disable_non_proxied_udp"
"QuicAllowed"=dword:00000000
"BlockThirdPartyCookies"=dword:00000001
"EnableDoNotTrack"=dword:00000001
"ForceGoogleSafeSearch"=dword:00000001
"IPFSEnabled"=dword:00000000
"DnsOverHttpsMode"="off"
"BraveShieldsDisabledForUrls"="[""https://*"",""http://*""]"
"MediaRecommendationsEnabled"=dword:00000000
"AlwaysOpenPdfExternally"=dword:00000001
"TranslateEnabled"=dword:00000000
"SpellcheckEnabled"=dword:00000000
"PromotionsEnabled"=dword:00000000
"SearchSuggestEnabled"=dword:00000000
"PrintingEnabled"=dword:00000000
"DeveloperToolsDisabled"=dword:00000001

; brave-debullshitinator https://github.com/MulesGaming/brave-debloatinator
[HKEY_LOCAL_MACHINE\Software\Policies\BraveSoftware\Brave]
"NewTabPageLocation"="https://search.brave.com"
"NewTabPageContentEnabled"=dword:00000000

[-HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\BraveSoftwareUpdateTaskMachineCore]

[-HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\BraveSoftwareUpdateTaskMachineUA]		
'@
	Set-Content -Path "$env:TEMP\DebloatBrave.reg" -Value $MultilineComment -Force							
	# import reg file				
	Regedit.exe /S "$env:TEMP\DebloatBrave.reg"
	
	# Disable Brave tasks
	Get-ScheduledTask | Where-Object { $_.TaskName -like "*Brave*" } | ForEach-Object { Disable-ScheduledTask -TaskName $_.TaskName | Out-Null }
}