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

# remove startup apps
Remove-Item -Recurse -Force "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Out-Null
Remove-Item -Recurse -Force "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null

# disable startup apps
Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | ForEach-Object {
    # Write-Host "Disabling $($_.Name) Startup . . ."
    foreach ($root in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
                     'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run') {
        $path = Join-Path $root $_.Name
        if (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue) {
            try {
                Set-ItemProperty -Path $root -Name $_.Name -Type Binary `
                    -Value ([byte[]](0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) `
                    -Force -ErrorAction SilentlyContinue
            } catch {}
        }
    }
}

# TASKS
# Write-Host "Disabling OneDrive and Edge Tasks . . ."    
# disable OneDrive and Edge scheduled tasks
Get-ScheduledTask | Where-Object { $_.TaskName -like "*OneDrive*" -or $_.TaskName -like "*Edge*" } | ForEach-Object { Disable-ScheduledTask -TaskName $_.TaskName | Out-Null }
# disable automatic disk defragmentation
schtasks /Change /DISABLE /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null	
# disable security scheduled tasks
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable | Out-Null
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable | Out-Null
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable | Out-Null
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable | Out-Null
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable | Out-Null

Clear-Host
# mark EULA accepted (global + tool-specific)
New-Item -Path HKCU:\Software\Sysinternals -Force | Out-Null
New-ItemProperty -Path HKCU:\Software\Sysinternals -Name EulaAccepted -PropertyType DWord -Value 1 -Force | Out-Null
New-Item -Path HKCU:\Software\Sysinternals\Autoruns -Force | Out-Null
New-ItemProperty -Path HKCU:\Software\Sysinternals\Autoruns -Name EulaAccepted -PropertyType DWord -Value 1 -Force | Out-Null
# start autoruns
Invoke-WebRequest 'https://live.sysinternals.com/tools/autoruns64.exe' -OutFile "$env:TEMP\autoruns64.exe"
Start-Process "$env:TEMP\autoruns64.exe"
  