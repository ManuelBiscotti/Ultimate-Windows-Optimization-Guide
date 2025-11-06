function Invoke-Chrome {
	
	Write-Host "Installing Google Chrome..." -ForegroundColor Green
	# Silent install latest Google Chrome (official Google link)
	$chromeInstaller = "$env:TEMP\ChromeSetup.msi"
	Get-FileFromWeb -URL "https://dl.google.com/chrome/install/googlechromestandaloneenterprise64.msi" -File $chromeInstaller
	Start-Process msiexec.exe -ArgumentList "/i `"$chromeInstaller`" /qn /norestart" -Wait
	
	# DEBLOAT CHROME
	$MultilineComment = @"
Windows Registry Editor Version 5.00	

; CHROME
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome]
"StartupBoostEnabled"=dword:00000000
"HardwareAccelerationModeEnabled"=dword:00000000
"BackgroundModeEnabled"=dword:00000000
"HighEfficiencyModeEnabled"=dword:00000001
"DeviceMetricsReportingEnabled"=dword:00000000
"MetricsReportingEnabled"=dword:00000000
"ChromeCleanupReportingEnabled"=dword:00000000
"UserFeedbackAllowed"=dword:00000000
"WebRtcEventLogCollectionAllowed"=dword:00000000
"NetworkPredictionOptions"=dword:00000002 ; Disable DNS prefetching
"ChromeCleanupEnabled"=dword:00000000
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
"SafeBrowsingExtendedReportingEnabled"=dword:00000000
"SafeBrowsingSurveysEnabled"=dword:00000000
"SafeBrowsingDeepScanningEnabled"=dword:00000000
"DeviceActivityHeartbeatEnabled"=dword:00000000
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
"BrowserGuestModeEnabled"=dword:00000000
"BrowserSignin"=dword:00000000
"BuiltInDnsClientEnabled"=dword:00000000
"DefaultBrowserSettingEnabled"=dword:00000000
"ParcelTrackingEnabled"=dword:00000000
"RelatedWebsiteSetsEnabled"=dword:00000000
"ShoppingListEnabled"=dword:00000000
"SyncDisabled"=dword:00000001
"ExtensionManifestV2Availability"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gupdate]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gupdatem]
"Start"=dword:00000004
"@
	
	Set-Content -Path "$env:TEMP\Chrome.reg" -Value $MultilineComment -Force							
	# import reg file				
	Regedit.exe /S "$env:TEMP\Chrome.reg"
	Timeout T/5
	
	# Debloat Google Chrome using Chromium policies
	Invoke-WebRequest -Uri "https://github.com/yashgorana/chrome-debloat/raw/refs/heads/main/generated/windows/chrome.reg" -OutFile "$env:TEMP\chrome.reg"
	if (Test-Path "$env:TEMP\chrome.reg") {
		# import the reg file	
	    Regedit.exe /S "$env:TEMP\chrome.reg"    
		Timeout T/5	
		Remove-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist" -Recurse -Force -ErrorAction SilentlyContinue	
	}    
	
	# install uBlock Origin Lite
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist" -Name "1" -Value "ddkjiahejlhfcafbddmgiahcphecmpfh" -PropertyType String -Force | Out-Null
	
	# remove logon chrome
	cmd /c "reg delete `"HKLM\Software\Microsoft\Active Setup\Installed Components\{8A69D345-D564-463c-AFF1-A69D9E530F96}`" /f >nul 2>&1"
	
	# disable chrome services
	Get-Service | Where-Object Name -match 'Google' | ForEach-Object { Set-Service $_.Name -StartupType Disabled; Stop-Service $_.Name -Force | Out-Null }	
	
	# disable chrome tasks
	Get-ScheduledTask | Where-Object { $_.TaskName -like "*Google*" } | ForEach-Object { Disable-ScheduledTask -TaskName $_.TaskName | Out-Null }
	
}

Invoke-Chrome