# Install CoreTemp
function Invoke-CoreTemp {
	$Installer = Join-Path $env:TEMP 'CoreTempSetup.exe'
	$Url       = "https://www.alcpu.com/CoreTemp/Core-Temp-setup.exe"

	try{
		# Downloading Core Temp
		Write-Host "Downloading Core Temp installer..." -ForegroundColor Green
		Get-FileFromWeb -URL $Url -File $Installer	

		if (Test-Path $Installer) {
			# install Core Temp
			Write-Host "Installing Core Temp..." -ForegroundColor Green	
			Start-Process -FilePath $Installer -ArgumentList '/verysilent' -Wait	
		}
	}catch{
	}

	Write-Host "`nCreating Core Temp configuration file"
	$MultilineComment = @'
[General]
ReadInt=1000;
LogInt=10;
Language=English;
Plugins=0;
EnLog=0;
SingleInstance=1;
AutoUpdateCheck=0;

[Display]
Fahr=0;
Minimized=1;
CloseToSystray=0;
HideTaskbarButton=0;
TextColor=FF000000;
StatusColor=C0FF,FF;
LabelColor=FF000000;

[System tray]
SystrayOption=2;
SystrayTransparentBack=1;
SystrayColorAllBack=0,0;
SystrayColorAllText=D8FF,90FF00;
SystrayColorHighCpuBack=0;
SystrayColorHighCpuText=D8FF;
SystrayColorHighBack=0;
SystrayColorHighText=D8FF;
SystrayColorClockBack=0;
SystrayColorClockText=C0C0C0;
SystrayColorLoadBack=0;
SystrayColorLoadText=C0C0C0;
SystrayColorRamBack=0;
SystrayColorRamText=C0C0C0;
SystrayColorPowerBack=0;
SystrayColorPowerText=C0C0C0;
SystrayDisplayFrequency=0;
SystrayDisplayLoad=0;
SystrayDisplayRam=1;
SystrayDisplayPower=1;
SystrayFontName=Tahoma;
SystrayFontSize=8;

[Windows 7 Taskbar button settings]
W7TBEnable=1;
W7TBOption=0;
W7TBCycleDelay=10;
W7TBFrequencyColor=2;
W7TBDisableMinimizeToTray=0;

[G15 LCD settings]
G15BuiltInFont=1;
G15Time=1;
G1524HTime=0;
G15FontName=Tahoma;
G15FontSize=8;

[Advanced]
ShowDTJ=0;
BusClk=0;
SnmpSharedMemory=0;

[Overheat protection settings]
EnableOHP=0;
NotifyHot=0;
Balloon=1;
Flash=0;
Execute=;
EnableShutDown=0;
ProtectionType=0;
ActivateAt=0;
Seconds=30;
ExecuteOnce=1;
Degrees=90;

[Misc]
Version=0;
TjMaxOffset=0;
AlwaysOnTop=0;
MiniMode=0;
AltFreq=0;

[UI]
SPX=276;
SPY=149;
CoreFrequencySelector=-1;
'@
	Set-Content -Path "C:\Program Files\Core Temp\CoreTemp.ini" -Value $MultilineComment -Force

	@("Core Temp.lnk", "Goodgame Empire.Url") | ForEach-Object {
		$Dsc = "$env:USERPROFILE\Desktop\$_"
		if (Test-Path $Dsc) { Remove-Item $Dsc -Force }
	}
}