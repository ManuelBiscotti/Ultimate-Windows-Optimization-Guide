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

Clear-Host
Write-Host "1. Services: Off"
Write-Host "2. Services: Default"
while ($true) {
    $choice = Read-Host " "
    if ($choice -match '^[1-2]$') {
		switch ($choice) {
			1 {
			
				Clear-Host
				Write-Host "Services: Off . . ."
						
				try {
					[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
					(Invoke-RestMethod 'https://api.github.com/repos/QuakedK/Service-Destroyer/releases/latest' -Headers @{ 'User-Agent'='PowerShell' } -ErrorAction SilentlyContinue).assets |
				    Where-Object Name -like 'Service-Destroyer-V*.bat' |
				    Select-Object -First 1 |
				    ForEach-Object {
						Invoke-WebRequest -Uri $_.browser_download_url -OutFile (Join-Path $env:TEMP $_.name) -ErrorAction SilentlyContinue
						Start-Process -FilePath (Join-Path $env:TEMP $_.name)
				    }
				} catch {  
				
					if(-not(Test-Path "$env:TEMP\Services.ps1")){ 
						Invoke-WebRequest 'https://github.com/FR33THYFR33THY/Ultimate-Windows-Optimization-Guide/raw/refs/heads/main/8%20Advanced/11%20Services.ps1' -OutFile "$env:TEMP\Services.ps1" -UseBasicParsing 
					}					
					(Get-Content "$env:TEMP\Services.ps1" -Raw)-replace'Read-Host.*','1'|Invoke-Expression
															
				}
				
				cmd /c "bcdedit /deletevalue safeboot >nul 2>&1"
				exit

			}
			2 {
				
				Clear-Host
				Write-Host "Services: Default . . ."
				
				if (Test-Path -LiteralPath 'C:\Service Destroyer\Reg Backup\ServicesBackup.reg') {				
					RunAsTI cmd '/c reg import "C:\Service Destroyer\Reg Backup\ServicesBackup.reg" & reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d 3670016 /f'
				    Timeout /T 5 | Out-Null
					Remove-Item -LiteralPath 'C:\Service Destroyer' -Recurse -Force -ErrorAction SilentlyContinue
					
				    Clear-Host
				    Write-Host "Press any key to restart . . ."
				    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")				
				    cmd /c "bcdedit /deletevalue safeboot >nul 2>&1"
				    shutdown -r -t 00
				    exit
				} else { 

					if(-not(Test-Path "$env:TEMP\Services.ps1")){
						Invoke-WebRequest 'https://github.com/FR33THYFR33THY/Ultimate-Windows-Optimization-Guide/raw/refs/heads/main/8%20Advanced/11%20Services.ps1' -OutFile "$env:TEMP\Services.ps1" -UseBasicParsing
					}					
					(Get-Content "$env:TEMP\Services.ps1" -Raw)-replace'Read-Host.*','2'|Invoke-Expression

				}
			
			}
			
		} 
	} else { Write-Host "Invalid input. Please select a valid option (1-2)." } 
}		
	
				






















