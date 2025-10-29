if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$Host.UI.RawUI.WindowTitle = ''
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.PrivateData.ProgressBackgroundColor = "Black"
$Host.PrivateData.ProgressForegroundColor = "White"
Clear-Host

$ProgressPreference = 'SilentlyContinue'  
$ErrorActionPreference = 'SilentlyContinue'

function RunAsTI($cmd, $arg) {

	<#
	  [FEATURES]
	  - innovative HKCU load, no need for reg load / unload ping-pong; programs get the user profile
	  - sets ownership privileges, high priority, and explorer support; get System if TI unavailable
	  - accepts special characters in paths for which default run as administrator fails
	  - can copy-paste snippet directly in powershell console then use it manually
	  [USAGE]
	  - First copy-paste RunAsTI snippet before .ps1 script content
	  - Then call it anywhere after to launch programs with arguments as TI
	    RunAsTI regedit
	    RunAsTI powershell '-noprofile -nologo -noexit -c [environment]::Commandline'
	    RunAsTI cmd '/k "whoami /all & color e0"'
	    RunAsTI "C:\System Volume Information"
	  - Or just relaunch the script once if not already running as TI:
	    if (((whoami /user)-split' ')[-1]-ne'S-1-5-18') {
	      RunAsTI powershell "-f $($MyInvocation.MyCommand.Path) $($args[0]) $($args[1..99])"; return
	    }
	  2022.01.28: workaround for 11 release (22000) hindering explorer as TI
	#>

    $id = 'RunAsTI'; $key = "Registry::HKU\$(((whoami /user)-split' ')[-1])\Volatile Environment"; $code = @'
$I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
$D=@(); $T=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $Z=[uintptr]::size
0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += [uintptr]; 4..6|% {$D += $D[$_]."MakeByR`efType"()}
$F='kernel','advapi','advapi', ($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), ([uintptr],$S,$I,$I,$D[9]),([uintptr],$S,$I,$I,[byte[]],$I)
0..2|% {$9=$D[0]."DefinePInvok`eMethod"(('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
$DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"('f' + $n++, $_, 6)}}; 0..5|% {$T += $D[$_]."Creat`eType"()}
0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
$TI=(whoami /groups)-like'*1-16-16384*'; $As=0; if(!$cmd) {$cmd='control';$arg='admintools'}; if ($cmd-eq'This PC'){$cmd='file:'}
if (!$TI) {'TrustedInstaller','lsass','winlogon'|% {if (!$As) {$9=sc.exe start $_; $As=@(get-process -name $_ -ea 0|% {$_})[0]}}
function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
$A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
$Run=@($null, "powershell -win 1 -nop -c iex `$env:R; # $id", 0, 0, 0, 0x0E080600, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
F 'CreateProcess' $Run; return}; $env:R=''; rp $key $id -force; $priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$priv.Invoke($null, @("$_",2))}
$HKU=[uintptr][uint32]2147483651; $NT='S-1-5-18'; $reg=($HKU,$NT,8,2,($HKU -as $D[9])); F 'RegOpenKeyEx' $reg; $LNK=$reg[4]
function L ($1,$2,$3) {sp 'HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3 -force -ea 0
$b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1"); F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
function Q {[int](gwmi win32_process -filter 'name="explorer.exe"'|?{$_.getownersid().sid-eq$NT}|select -last 1).ProcessId}
$11bug=($((gwmi Win32_OperatingSystem).BuildNumber)-eq'22000')-AND(($cmd-eq'file:')-OR(test-path -lit $cmd -PathType Container))
if ($11bug) {'System.Windows.Forms','Microsoft.VisualBasic' |% {[Reflection.Assembly]::LoadWithPartialName("'$_")}}
if ($11bug) {$path='^(l)'+$($cmd -replace '([\+\^\%\~\(\)\[\]])','{$1}')+'{ENTER}'; $cmd='control.exe'; $arg='admintools'}
L ($key-split'\\')[1] $LNK ''; $R=[diagnostics.process]::start($cmd,$arg); if ($R) {$R.PriorityClass='High'; $R.WaitForExit()}
if ($11bug) {$w=0; do {if($w-gt40){break}; sleep -mi 250;$w++} until (Q); [Microsoft.VisualBasic.Interaction]::AppActivate($(Q))}
if ($11bug) {[Windows.Forms.SendKeys]::SendWait($path)}; do {sleep 7} while(Q); L '.Default' $LNK 'Interactive User'
'@; $V = ''; 'cmd', 'arg', 'id', 'key' | ForEach-Object { $V += "`n`$$_='$($(Get-Variable $_ -val)-replace"'","''")';" }; Set-ItemProperty $key $id $($V, $code) -type 7 -force -ea 0
	Start-Process powershell -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas -Wait
} # lean & mean snippet by AveYo, 2022.01.28

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

Write-Host "1. Gaming: Off (Recommended)"
Write-Host "2. Gaming: Default"
while ($true) {
    $choice = Read-Host " "
    if ($choice -match '^[1-2]$') {
        switch ($choice) {
            1 {
	            Clear-Host

	# disable gamebar regedit
	Write-Output "Disabling Game Bar . . ."
	reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f | Out-Null
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f | Out-Null
	# disable open xbox game bar using game controller regedit
	reg add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f | Out-Null
	# disable gameinput service regedit
	reg add "HKLM\SYSTEM\ControlSet001\Services\GameInputSvc" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
	# disable gamedvr and broadcast user service regedit
	reg add "HKLM\SYSTEM\ControlSet001\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
	# disable xbox accessory management service regedit
	reg add "HKLM\SYSTEM\ControlSet001\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
	# disable xbox live auth manager service regedit
	reg add "HKLM\SYSTEM\ControlSet001\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
	# disable xbox live game save service regedit
	reg add "HKLM\SYSTEM\ControlSet001\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
	# disable xbox live networking service regedit
	reg add "HKLM\SYSTEM\ControlSet001\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f | Out-Null
	
	# disable ms-gamebar notifications with xbox controller plugged in regedit	
	# create reg file
	$MultilineComment = @"
Windows Registry Editor Version 5.00	
	
; disable ms-gamebar notifications with xbox controller plugged in	
[HKEY_CLASSES_ROOT\ms-gamebar]	
"URL Protocol"=""	
"NoOpenWith"=""	
@="URL:ms-gamebar"	
	
[HKEY_CLASSES_ROOT\ms-gamebar\shell\open\command]	
@="\"%SystemRoot%\\System32\\systray.exe\""	
	
[HKEY_CLASSES_ROOT\ms-gamebarservices]	
"URL Protocol"=""	
"NoOpenWith"=""	
@="URL:ms-gamebarservices"	
	
[HKEY_CLASSES_ROOT\ms-gamebarservices\shell\open\command]	
@="\"%SystemRoot%\\System32\\systray.exe\""	
	
[HKEY_CLASSES_ROOT\ms-gamingoverlay]	
"URL Protocol"=""	
"NoOpenWith"=""	
@="URL:ms-gamingoverlay"	
	
[HKEY_CLASSES_ROOT\ms-gamingoverlay\shell\open\command]	
@="\"%SystemRoot%\\System32\\systray.exe\""	
"@
	Set-Content -Path "$env:TEMP\MsGamebarNotiOff.reg" -Value $MultilineComment -Force
	# import reg file
	Regedit.exe /S "$env:TEMP\MsGamebarNotiOff.reg"
	
	# stop gamebar running
	Stop-Process -Force -Name GameBar | Out-Null

	# Remove Gamebar & Xbox apps
	# GAMEBAR
	Write-Output "Removing Gamebar App . . ."
	Get-AppxPackage -allusers *Microsoft.XboxGameOverlay* | Remove-AppxPackage
	Get-AppxPackage -allusers *Microsoft.XboxGamingOverlay* | Remove-AppxPackage
	# XBOX
	Write-Output "Removing Xbox App . . ."
	Get-AppxPackage -allusers *Microsoft.GamingApp* | Remove-AppxPackage
	Get-AppxPackage -allusers *Microsoft.Xbox.TCUI* | Remove-AppxPackage
	Get-AppxPackage -allusers *Microsoft.XboxApp* | Remove-AppxPackage
	Get-AppxPackage -allusers *Microsoft.XboxIdentityProvider* | Remove-AppxPackage
	Get-AppxPackage -allusers *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage

	# Uninstall Microsoft GameInput
	Write-Output "Uninstalling Microsoft GameInput..."
	Start-Process "msiexec.exe" -ArgumentList '/x {F563DC73-9550-F772-B4BF-2F72C83F9F30} /qn /norestart'
	Start-Process "msiexec.exe" -ArgumentList '/x {0812546C-471E-E343-DE9C-AECF3D0137E6} /qn /norestart'

	# Disable Gaming Services
	Write-Host "Disabling Gaming Services . . ."

	$MultilineComment = @'
Windows Registry Editor Version 5.00

; Disable Gaming Services
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\GamingServicesNet]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\GamingServices]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\GameInputSvc]
"Start"=dword:00000004
'@
	Set-Content -Path "$env:TEMP\GamingServicesOff.reg" -Value $MultilineComment -Force
	# disable services RunAsTI
	$GamingServicesOff = @'
Regedit.exe /S "$env:TEMP\GamingServicesOff.reg"
'@
	RunAsTI powershell "-nologo -windowstyle hidden -command $GamingServicesOff"
	Timeout /T 5 | Out-Null

	# Remove Gaming Services
	Write-Output "Removing Gaming Services . . ."
	Get-AppxPackage -allusers *Microsoft.GamingServices* | Remove-AppxPackage

Write-Host "Restart to apply . . ."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Start-Process ms-settings:gaming-gamebar
exit
      }
    2 {

	Clear-Host	
# gamebar regedit
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "1" /f | Out-Null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "1" /f | Out-Null
# open xbox game bar using game controller regedit
cmd.exe /c "reg delete `"HKCU\Software\Microsoft\GameBar`" /v `"UseNexusForGameBarEnabled`" /f >nul 2>&1"
# gameinput service
reg add "HKLM\SYSTEM\ControlSet001\Services\GameInputSvc" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
# gamedvr and broadcast user service regedit
reg add "HKLM\SYSTEM\ControlSet001\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
# xbox accessory management service regedit
reg add "HKLM\SYSTEM\ControlSet001\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
# xbox live auth manager service regedit
reg add "HKLM\SYSTEM\ControlSet001\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
# xbox live game save service regedit
reg add "HKLM\SYSTEM\ControlSet001\Services\XblGameSave" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
# xbox live networking service regedit
reg add "HKLM\SYSTEM\ControlSet001\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "3" /f | Out-Null
# ms-gamebar notifications with xbox controller plugged in regedit
# create reg file
$MultilineComment = @"
Windows Registry Editor Version 5.00

; ms-gamebar notifications with xbox controller plugged in regedit
[-HKEY_CLASSES_ROOT\ms-gamebar]
[-HKEY_CLASSES_ROOT\ms-gamebarservices]
[-HKEY_CLASSES_ROOT\ms-gamingoverlay\shell]

[HKEY_CLASSES_ROOT\ms-gamingoverlay]
"URL Protocol"=""
@="URL:ms-gamingoverlay"
"@
Set-Content -Path "$env:TEMP\MsGamebarNotiOn.reg" -Value $MultilineComment -Force
# import reg file
Regedit.exe /S "$env:TEMP\MsGamebarNotiOn.reg"
# install store, gamebar & xbox apps
Get-AppXPackage -AllUsers *Microsoft.GamingApp* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.Xbox.TCUI* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.XboxApp* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.XboxGameOverlay* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.XboxGamingOverlay* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.XboxIdentityProvider* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.XboxSpeechToTextOverlay* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.WindowsStore* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppXPackage -AllUsers *Microsoft.Microsoft.StorePurchaseApp * | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}
# download gamebar repair tool
Get-FileFromWeb -URL "https://aka.ms/GamingRepairTool" -File "$env:TEMP\GamingRepairTool.exe"
Clear-Host
# start gamebar repair too
Start-Process -wait "$env:TEMP\GamingRepairTool.exe"

# FIX XBOX SIGN IN
# enable uac
New-Item -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -value "1" -PropertyType Dword -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -value "1" -ErrorAction SilentlyContinue | Out-Null
# download edge webview installer
Write-Host "Installing: Edge Webview . . ."
    
    # fix edge blocks
	. ([ScriptBlock]::Create((Invoke-RestMethod 'https://github.com/ManuelBiscotti/test/raw/refs/heads/main/functions/Invoke-EdgeFix.ps1')))
	Invoke-EdgeFix

# download edgewebview2
Get-FileFromWeb -URL "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/304fddef-b073-4e0a-b1ff-c2ea02584017/MicrosoftEdgeWebview2Setup.exe" -File "$env:TEMP\EdgeWebView.exe"
Clear-Host
# start edge webview installer
Start-Process -wait "$env:TEMP\EdgeWebView.exe"

# GAMING SERVICE
# Install Gaming Service App
Write-Host "Installing: Gaming Services . . ."
Get-AppXPackage -AllUsers *Microsoft.GamingServices* | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction SilentlyContinue "$($_.InstallLocation)\AppXManifest.xml"}

# Enable Gaming Services
$MultilineComment = @'
Windows Registry Editor Version 5.00

; Enable Gaming Services

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\GamingServicesNet]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\GamingServices]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\GameInputSvc]
"Start"=dword:00000003
'@
	Set-Content -Path "$env:TEMP\GamingServicesOn.reg" -Value $MultilineComment -Force
	# enable services RunAsTI
	$GamingServicesOn = @'
Regedit.exe /S "$env:TEMP\GamingServicesOn.reg"
'@
	RunAsTI powershell "-nologo -windowstyle hidden -command $GamingServicesOn"
	Timeout /T 1 | Out-Null

# GAMEINPUT
# Install GameInput
Write-Host "Installing: GameInput . . ."
if (Get-Command winget -ErrorAction SilentlyContinue) {

    winget.exe install --id "Microsoft.GameInput" --exact --source winget --accept-source-agreements --disable-interactivity --silent --no-progress --accept-package-agreements --force | Out-Null

} else {

	. ([ScriptBlock]::Create((Invoke-RestMethod 'https://github.com/ManuelBiscotti/test/raw/refs/heads/main/functions/Invoke-Winget.ps1')))
	Invoke-Winget
    winget.exe install --id "Microsoft.GameInput" --exact --source winget --accept-source-agreements --disable-interactivity --silent --no-progress --accept-package-agreements --force | Out-Null

} else {

    Write-Host $_.Exception.Message -ForegroundColor Red 
	Timeout /T 5 | Out-Null

}
Clear-Host

# Update all Apps
try {

   	winget upgrade --all --accept-source-agreements --accept-package-agreements

} catch {

    Write-Host $_.Exception.Message -ForegroundColor Red
	Timeout /T 5 | Out-Null

}
Clear-Host

                Clear-Host
                Write-Host "Restart to apply . . ."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                Start-Process ms-settings:gaming-gamebar
                exit
            }
        } 
    } else { Write-Host "Invalid input. Please select a valid option (1-2)." } 
}
