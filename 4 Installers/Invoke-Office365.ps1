#######################
# Microsoft 365 Basic #

function Invoke-Office365 {
	try {
		$dir="$env:ProgramData\Bloatware"
		New-Item $dir -ItemType Directory -Force
		$script=@'
"RuntimeBroker","MoUsoCoreWorker","UserOOBEBroker","SearchApp","ConnectedUserExperiences","ctfmon","CrossDeviceResume","MicrosoftEdgeUpdate","ONENOTEM","OfficeClickToRun" | % { Get-Process $_ | Stop-Process -Force }
"MSDTC","VSS","ClickToRunSvc" | % { Stop-Service $_ -Force }
'@
		$script | Set-Content "$dir\KillBloatware.ps1" -Encoding UTF8 -Force
		$trigger=New-ScheduledTaskTrigger -AtStartup
		$action=New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$dir\KillBloatware.ps1`""
		Register-ScheduledTask -TaskName "KillBloatwareAtStartup" -Action $action -Trigger $trigger -RunLevel Highest -User "SYSTEM" -Force	
	} catch {

	}
									
	Get-FileFromWeb -URL "https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365AppsBasicRetail&platform=x64&language=en-us&version=O16GA" -File "$env:TEMP\OfficeSetup.exe"
	Start-Process -FilePath "$env:TEMP\OfficeSetup.exe" -Wait

	Invoke-WebRequest -Uri "https://github.com/massgravel/Microsoft-Activation-Scripts/raw/refs/heads/master/MAS/Separate-Files-Version/Activators/Ohook_Activation_AIO.cmd" -OutFile "$env:TEMP\Ohook_Activation_AIO.cmd"
	Start-Process "$env:TEMP\Ohook_Activation_AIO.cmd" "/Ohook"
}