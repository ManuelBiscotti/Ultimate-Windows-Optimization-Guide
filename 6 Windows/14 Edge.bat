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

$ProgressPreference = 'SilentlyContinue'  
$ErrorActionPreference = 'SilentlyContinue'

Write-Host "1. Edge: Off (Recommended)"
Write-Host "2. Edge: Default"
while ($true) {
$choice = Read-Host " "
if ($choice -match '^[1-2]$') {
    switch ($choice) {
		1 {
			
			Clear-Host
			Write-Host "Uninstalling: Edge . . ."
			
			try {
				<#
				EXE Version
				Invoke-WebRequest -Uri "https://github.com/ShadowWhisperer/Remove-MS-Edge/releases/latest/download/Remove-EdgeWeb.exe" -OutFile "$env:TEMP\Remove-EdgeWeb.exe"
				Start-Process "$env:TEMP\Remove-EdgeWeb.exe" -Args "/s" -Wait -NoNewWindow
				Remove-Item "$env:TEMP\Remove-EdgeWeb.exe" -Force
				#>
				# Batch Version
				$batch = "$env:TEMP\Both.bat"
				Invoke-WebRequest 'https://github.com/ShadowWhisperer/Remove-MS-Edge/raw/refs/heads/main/Batch/Both.bat' -OutFile $batch -UseBasicParsing
				(Get-Content $batch -Raw) -replace '(?s)echo \[uac\(\)\].*?:uac\.done','fltmc >nul || (powershell "Start ''%~f0''" & exit) & cd /D "%~dp0"' | Set-Content $batch -Force -Encoding ASCII
				cmd /c "`"$batch`""

			} catch {
			
				<#
					.SYNOPSIS
					Uninstalls or reinstalls Microsoft Edge and its related components. Made by @he3als.
				
					.Description
					Uninstalls or reinstalls Microsoft Edge and its related components in a non-forceful manner, based upon switches or user choices in a TUI.
				
					.PARAMETER UninstallEdge
					Uninstalls Edge, leaving the Edge user data.
				
					.PARAMETER InstallEdge
					Installs Edge, leaving the previous Edge user data.
				
					.PARAMETER InstallWebView
					Installs Edge WebView2 using the Evergreen installer.
				
					.PARAMETER RemoveEdgeData
					Removes all Edge user data. Compatible with -InstallEdge.
				
					.PARAMETER KeepAppX
					Doesn't check for and remove the AppX, in case you want to use alternative AppX removal methods. Doesn't work with UninstallEdge.
				
					.PARAMETER NonInteractive
					When combined with other parameters, this does not prompt the user for anything.
				
					.LINK
					https://github.com/he3als/EdgeRemover
				#>
				
				# Windows 10
				if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -le 19045) {
					
					Invoke-WebRequest `
						-Uri "https://cdn.jsdelivr.net/gh/he3als/EdgeRemover@main/get.ps1" `
						-OutFile ([System.IO.Path]::Combine($env:TEMP, 'EdgeRemover.ps1')) `
						-UseBasicParsing
			    
					Start-Process -FilePath "powershell.exe" `
						-ArgumentList (
							'-NoProfile','-ExecutionPolicy', 'Bypass',
				            '-File', [System.IO.Path]::Combine($env:TEMP, 'EdgeRemover.ps1'),
				            '-UninstallEdge', '-RemoveEdgeData', '-NonInteractive'
						) `
						-Wait
			    
				}
			    
				<#
			    
					.SYNOPSIS
					Uninstall Microsoft Edge 
					
					.DESCRIPTION
					Microsoft Edge will be completely uninstalled. The Microsoft Edge Update service might remain, this is normal as it is required for updating WebView2.
			    
					.LINK
					https://gist.github.com/ave9858/c3451d9f452389ac7607c99d45edecc6
			    
				#>
			    
				# Windows 11
				elseif ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild -ge 22000) {
					
					Invoke-RestMethod "https://gist.github.com/ave9858/c3451d9f452389ac7607c99d45edecc6/raw/UninstallEdge.ps1" |
					ForEach-Object {$_ -replace '\$ErrorActionPreference = "Stop"', '$ErrorActionPreference = "SilentlyContinue"'} |
					Set-Content -Path ([System.IO.Path]::Combine($env:TEMP, 'UninstallEdge.ps1')) -Encoding UTF8
					Start-Process -FilePath "PowerShell.exe" `
						-ArgumentList ('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', [System.IO.Path]::Combine($env:TEMP, 'UninstallEdge.ps1')) `
					-Wait
				}
				else{
					Write-Host $_.Exception.Message -ForegroundColor Red
				}
			    
				<#
				# find edgeupdate.exe
				$edgeupdate = @(); "LocalApplicationData", "ProgramFilesX86", "ProgramFiles" | ForEach-Object {
				$folder = [Environment]::GetFolderPath($_)
				$edgeupdate += Get-ChildItem "$folder\Microsoft\EdgeUpdate\*.*.*.*\MicrosoftEdgeUpdate.exe" -rec -ea 0
				}
				# find edgeupdate & allow uninstall regedit
				$global:REG = "HKCU:\SOFTWARE", "HKLM:\SOFTWARE", "HKCU:\SOFTWARE\Policies", "HKLM:\SOFTWARE\Policies", "HKCU:\SOFTWARE\WOW6432Node", "HKLM:\SOFTWARE\WOW6432Node", "HKCU:\SOFTWARE\WOW6432Node\Policies", "HKLM:\SOFTWARE\WOW6432Node\Policies"
				foreach ($location in $REG) { Remove-Item "$location\Microsoft\EdgeUpdate" -recurse -force -ErrorAction SilentlyContinue }
				# uninstall edgeupdate
				foreach ($path in $edgeupdate) {
				if (Test-Path $path) { Start-Process -Wait $path -Args "/unregsvc" | Out-Null }
				do { Start-Sleep 3 } while ((Get-Process -Name "setup", "MicrosoftEdge*" -ErrorAction SilentlyContinue).Path -like "*\Microsoft\Edge*")
				if (Test-Path $path) { Start-Process -Wait $path -Args "/uninstall" | Out-Null }
				do { Start-Sleep 3 } while ((Get-Process -Name "setup", "MicrosoftEdge*" -ErrorAction SilentlyContinue).Path -like "*\Microsoft\Edge*")
				}
				# remove edgewebview regedit
				cmd /c "reg delete `"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView`" /f >nul 2>&1"
				cmd /c "reg delete `"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView`" /f >nul 2>&1"
				# remove folders edge edgecore edgeupdate edgewebview temp
				Remove-Item -Recurse -Force "$env:SystemDrive\Program Files (x86)\Microsoft" -ErrorAction SilentlyContinue | Out-Null
				# remove edge shortcuts
				Remove-Item -Recurse -Force "$env:SystemDrive\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk" -ErrorAction SilentlyContinue | Out-Null
				Remove-Item -Recurse -Force "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk" -ErrorAction SilentlyContinue | Out-Null
				Remove-Item -Recurse -Force "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk" -ErrorAction SilentlyContinue | Out-Null
				Remove-Item -Recurse -Force "$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Tombstones\Microsoft Edge.lnk" -ErrorAction SilentlyContinue | Out-Null
				Remove-Item -Recurse -Force "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" -ErrorAction SilentlyContinue | Out-Null
				Remove-Item -Recurse -Force "$env:SystemDrive\Users\Public\Desktop\Microsoft Edge.lnk" -ErrorAction SilentlyContinue | Out-Null
				# stop edge running
				$stop = "MicrosoftEdgeUpdate", "OneDrive", "WidgetService", "Widgets", "msedge", "Resume", "CrossDeviceResume", "msedgewebview2"
				$stop | ForEach-Object { Stop-Process -Name $_ -Force -ErrorAction SilentlyContinue }
				# uninstall uwp edge & bing apps
				Get-AppxPackage -allusers *Microsoft.MicrosoftEdge.Stable* | Remove-AppxPackage
				Get-AppxPackage -allusers *Microsoft.BingNews* | Remove-AppxPackage
				Get-AppxPackage -allusers *Microsoft.BingSearch* | Remove-AppxPackage
				Get-AppxPackage -allusers *Microsoft.BingWeather* | Remove-AppxPackage
				#>
			}
			
			Clear-Host
			Write-Host "Restart to apply . . ."
			$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
			exit
			
		}
		2 {
			
			Clear-Host
		    Write-Host "Installing & Updating: Edge . . ."
			# fix edge blocks
			. ([ScriptBlock]::Create((Invoke-RestMethod 'https://github.com/ManuelBiscotti/test/raw/refs/heads/main/functions/Invoke-EdgeFix.ps1')))
			Invoke-EdgeFix
		    # enable edge updates regedit
		    cmd /c "reg delete `"HKLM\SOFTWARE\Microsoft\EdgeUpdate`" /f >nul 2>&1"
		    # remove allow edge uninstall regedit
		    # cmd /c "reg delete `"HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdateDev`" /f >nul 2>&1"
		    # download edge installer
		    Get-FileFromWeb -URL "https://go.microsoft.com/fwlink/?linkid=2109047&Channel=Stable&language=en&brand=M100" -File "$env:TEMP\Edge.exe"
		    # start edge installer
		    Start-Process -wait "$env:TEMP\Edge.exe"
		    # stop edge running
		    $stop = "MicrosoftEdgeUpdate", "OneDrive", "WidgetService", "Widgets", "msedge", "Resume", "CrossDeviceResume", "msedgewebview2"
		    $stop | ForEach-Object { Stop-Process -Name $_ -Force -ErrorAction SilentlyContinue }
		    # download edge webview installer
		    # Get-FileFromWeb -URL "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/304fddef-b073-4e0a-b1ff-c2ea02584017/MicrosoftEdgeWebview2Setup.exe" -File "$env:TEMP\EdgeWebView.exe"
		    # start edge webview installer
		    # Start-Process -wait "$env:TEMP\EdgeWebView.exe"
		    # add edge shortcuts
		    $WshShell = New-Object -comObject WScript.Shell
		    $Shortcut = $WshShell.CreateShortcut("$env:SystemDrive\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk")
		    $Shortcut.TargetPath = "$env:SystemDrive\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
		    $Shortcut.Save()
		    $WshShell = New-Object -comObject WScript.Shell
		    $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk")
		    $Shortcut.TargetPath = "$env:SystemDrive\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
		    $Shortcut.Save()
		    $WshShell = New-Object -comObject WScript.Shell
		    $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk")
		    $Shortcut.TargetPath = "$env:SystemDrive\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
		    $Shortcut.Save()
		    $WshShell = New-Object -comObject WScript.Shell
		    $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Tombstones\Microsoft Edge.lnk")
		    $Shortcut.TargetPath = "$env:SystemDrive\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
		    $Shortcut.Save()
		    $WshShell = New-Object -comObject WScript.Shell
		    $Shortcut = $WshShell.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk")
		    $Shortcut.TargetPath = "$env:SystemDrive\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
		    $Shortcut.Save()
		    $WshShell = New-Object -comObject WScript.Shell
		    $Shortcut = $WshShell.CreateShortcut("$env:SystemDrive\Users\Public\Desktop\Microsoft Edge.lnk")
		    $Shortcut.TargetPath = "$env:SystemDrive\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
		    $Shortcut.Save()
		    Clear-Host
		    Write-Host "Restart to apply . . ."
		    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
		    # open ublock origin in web browser
		    Start-Process "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
		    exit
			
		}
    } 
	} else { Write-Host "Invalid input. Please select a valid option (1-2)." } 
}