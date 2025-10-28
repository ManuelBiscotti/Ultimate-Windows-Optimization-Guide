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
					Get-AppxPackage -AllUsers | Where-Object {$_.Name -like "*Experience*" -or $_.Name -like "*Widgets*"} | Remove-AppxPackage

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
		
					# Reinstall Widgets related apps
					Get-AppXPackage -AllUsers *Microsoft.WidgetsPlatformRuntime * | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
					Get-AppXPackage -AllUsers *MicrosoftWindows.Client.WebExperience * | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
					Get-AppXPackage -AllUsers *Microsoft.StartExperiencesApp * | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
	
				}else{Write-Host $_.Exception.Message -ForegroundColor Red}
	
				Write-Host "Restart to apply . . ."
				$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				exit

      		}
   		 } 		
	} else { Write-Host "Invalid input. Please select a valid option (1-2)." } 
}
