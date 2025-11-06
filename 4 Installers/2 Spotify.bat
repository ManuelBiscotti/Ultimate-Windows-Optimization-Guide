<# : batch portion
@echo off
fltmc >nul || (powershell "Start -Verb RunAs '%~f0'" & exit) & cd /D "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw -Encoding UTF8)).Invoke(@(&{$args}%*))"
: end batch / begin powershell #>

# Download the script to temp
$scriptPath = Join-Path $env:TEMP 'run-spotx.ps1'    
Invoke-WebRequest -UseBasicParsing -Uri 'https://spotx-official.github.io/run.ps1' -OutFile $scriptPath    

# Execute the downloaded script with parameters    
& $scriptPath `    
    -m `    
    -sp-over `    
    -new_theme `    
    -canvashome_off `    
    -adsections_off `    
    -podcasts_off `    
    -block_update_on `    
    -DisableStartup `    
    -cl 500 `    
    -no_shortcut    