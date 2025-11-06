function Invoke-Portmaster {
	Write-Host "Installing Edge WebWiew2..." -ForegroundColor Green
	# download edge webview installer
	Get-FileFromWeb -URL "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/304fddef-b073-4e0a-b1ff-c2ea02584017/MicrosoftEdgeWebview2Setup.exe" -File "$env:TEMP\EdgeWebView.exe"
	# start edge webview installer
	Start-Process -wait "$env:TEMP\EdgeWebView.exe"
	# stop edge running
	Write-Host "Installing Portmaster..." -ForegroundColor Green
	# dowsnload portmaster
	Get-FileFromWeb "https://updates.safing.io/latest/windows_amd64/packages/Portmaster_2.0.25_x64-setup.exe" -File "$env:TEMP\Portmaster_x64-setup.exe"
	Start-Process "$env:TEMP\Portmaster_x64-setup.exe" -ArgumentList '/S','/quiet','/norestart' -Wait
}