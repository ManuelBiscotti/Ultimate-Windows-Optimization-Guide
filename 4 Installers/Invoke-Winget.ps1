# Winget
function Invoke-Winget {
    # Ensure TLS 1.2 for secure web requests
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Install or Update Chocolatey and Winget
    if (Get-Command choco.exe) {
        choco upgrade chocolatey -y --ignore-checksums --no-progress --quiet | Out-Null
    } else {
        Write-Host "Installing Chocolatey..." -ForegroundColor Green

        # Clean old remnants safely
        Remove-Item "C:\ProgramData\Chocolatey*" -Recurse -Force
        Remove-Item "C:\ProgramData\ChocolateyHttpCache" -Recurse -Force
        Start-Sleep -Seconds 2

        # Install Chocolatey
        Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

        # Wait until Chocolatey is ready (max 60 sec)
        $timeout = 0
        while (-not (Get-Command choco.exe) -and $timeout -lt 20) {
            Start-Sleep -Seconds 3
            $timeout++
        }
    }

    # Winget
    $winget = Get-Command winget.exe
    $build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild

    if ($winget) {
        choco upgrade winget -y --ignore-checksums # -quiet | Out-Null
    } else {
        if ($build -le 19045) {
            Write-Host "Repairing Winget for Windows 10..." -ForegroundColor Green
            Start-Process powershell.exe -ArgumentList @(
                '-NoProfile',
                '-ExecutionPolicy', 'Bypass',
                '-Command', 'Invoke-RestMethod https://asheroto.com/winget | Invoke-Expression'
            ) -Wait
        } elseif ($build -ge 22000) {
            Write-Host "Repairing Winget for Windows 11..." -ForegroundColor Green
            choco install winget -y --force --ignore-checksums --quiet | Out-Null
        } else {
            Write-Warning "Unsupported Windows build: $build"
        }
    }
}