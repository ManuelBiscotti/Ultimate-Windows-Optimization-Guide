################
# Powershell 7 #

function Invoke-Powershell7 {

	<#
		.SYNOPSIS
		.DESCRIPTION
			This function installs and configures latest Powershell 7 to be the default Terminal
	#>

	# Installs Windows Terminal
	Write-Host "Installing Windows Terminal..." -ForegroundColor Green
	Get-AppXPackage -AllUsers *Microsoft.WindowsTerminal* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}

	# remove "open in terminal" context menu
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions" -Name "Blocked" -Force | Out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{9F156763-7844-4DC4-B2B1-901F640F5155}" -Value "" -PropertyType String -Force | Out-Null

	Write-Host "Installing Powershell 7..." -ForegroundColor Green
	# download & install latest PowerShell 7 silently
	$api = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
	$rel = Invoke-RestMethod -Uri $api
	$asset = $rel.assets | Where-Object { $_.name -match "win-x64.msi$" } | Select-Object -First 1
	$url = $asset.browser_download_url
	$dest = "$env:TEMP\pwsh-latest.msi"
	Get-FileFromWeb -Url $url -File $dest
	Start-Process msiexec.exe -ArgumentList "/i `"$dest`" /quiet ADD_PATH=1 ENABLE_PSREMOTING=1" -Wait -NoNewWindow

	# Rename Powershell 7 (x64) start menu shortcut
 	Rename-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\PowerShell\PowerShell 7 (x64).lnk" -NewName "PowerShell 7.lnk" -Force
	
	# Allow double-click of .ps1 files
	$regPathPwsh = 'HKCR:\Applications\pwsh.exe\shell\open\command'
	if (-not (Test-Path $regPathPwsh)) { New-Item -Path $regPathPwsh -Force | Out-Null }
	Set-ItemProperty -Path $regPathPwsh -Name '(default)' -Value 'C:\Program Files\PowerShell\7\pwsh.exe -NoLogo -ExecutionPolicy Unrestricted -File "%1"'  
	
	# fetch Invoke-WPFTweakPS7 and set PS7 default
	$ps1 = Join-Path $env:TEMP 'Invoke-WPFTweakPS7.ps1'
	Invoke-WebRequest -Uri 'https://github.com/ChrisTitusTech/winutil/raw/refs/heads/main/functions/public/Invoke-WPFTweakPS7.ps1' -OutFile $ps1 -UseBasicParsing
	
	# clean messageboxes
	(Get-Content $ps1) | Where-Object {$_ -notmatch '\[System\.Windows\.MessageBox'} | Set-Content -Path $ps1 -Encoding UTF8
	
	# run tweak to set PS7 default
	. "$ps1"
	Invoke-WPFTweakPS7 -action PS7

	# CTT PowerShell Profile 
	Invoke-RestMethod "https://github.com/ChrisTitusTech/powershell-profile/raw/main/setup.ps1" | Invoke-Expression

	# Oh My Posh
	Invoke-Winget
	winget.exe install --id "JanDeDobbeleer.OhMyPosh" --exact --source winget --accept-source-agreements --disable-interactivity --silent --accept-package-agreements --force
}

function Invoke-UniGetUI {
	Write-Host "Installing UniGetUI...." -ForegroundColor Green
    # Get latest release
    $relApi = 'https://api.github.com/repos/marticliment/UniGetUI/releases/latest'
    $json = Invoke-RestMethod -Uri $relApi -Headers @{ 'User-Agent' = 'PowerShell' }
    $asset = $json.assets | Where-Object { $_.name -like 'UniGetUI.Installer.exe' } | Select-Object -First 1
    if ($asset) {
        $url = $asset.browser_download_url
        $tmp = "$env:TEMP\UniGetUI.Installer.exe"
        Get-FileFromWeb -URL $url -File $tmp
		Start-Process -FilePath $tmp -ArgumentList "/SP", "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/NoAutoStart", "/ALLUSERS", "/LANG=english" -Wait
    }

	# Remove shortcuts from all common locations
    $shortcutsToRemove = @(
        "$env:PUBLIC\Desktop\UniGetUI.lnk"
        "$env:USERPROFILE\Desktop\UniGetUI.lnk"
		"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\UniGetUI.lnk"
		"$env:APPDATA\Microsoft\Windows\Start Menu\Programs\UniGetUI.lnk"
    )
    
    $shortcutsToRemove | ForEach-Object {
        if (Test-Path $_) { Remove-Item $_ -Force }
    }

    $UniGetUIDir = "C:\Program Files\UniGetUI"
    $batPath = "$UniGetUIDir\UniGetUI.bat"

    # Fixed batch code - removed quotes issue and simplified
    $batchCode = @'
@echo off
set "exe=C:\Program Files\UniGetUI\UniGetUI.exe"
runas /trustlevel:0x20000 "powershell -NoProfile -WindowStyle Hidden -Command Start-Process -FilePath '%exe%'"
exit
'@

    # Ensure directory exists and write batch file
    if (-not (Test-Path $UniGetUIDir)) { 
        New-Item -ItemType Directory -Path $UniGetUIDir -Force | Out-Null 
    }
    Set-Content -Path $batPath -Value $batchCode -Encoding ASCII -Force

    # Create new shortcuts
    $shell = New-Object -ComObject WScript.Shell
    $shortcutsToCreate = @(
        "$env:USERPROFILE\Desktop\UniGetUI.lnk"
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\UniGetUI.lnk"
    )

    foreach ($shortcutPath in $shortcutsToCreate) {
        $sc = $shell.CreateShortcut($shortcutPath)
        $sc.TargetPath = $batPath
        $sc.WorkingDirectory = $UniGetUIDir
        $sc.IconLocation = "$UniGetUIDir\UniGetUI.exe,0"
        $sc.Save()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($sc) | Out-Null
    }

    # Cleanup
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
}