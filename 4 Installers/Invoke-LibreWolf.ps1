# LibreWolf installation
function Invoke-LibreWolf {
	Write-Host "Installing LibreWolf..." -ForegroundColor Green
    $l = "$env:ProgramFiles\LibreWolf\librewolf.exe"

	$api = "https://gitlab.com/api/v4/projects/librewolf-community%2Fbrowser%2Fbsys6/releases"
	$releases = Invoke-RestMethod -Uri $api

	foreach ($rel in $releases) {
    	foreach ($asset in $rel.assets.links) {
        	if ($asset.url -match "windows" -and $asset.url -match "\.exe$") {
            	$url = $asset.url
            	break
        	}
    	}
    	if ($url) { break }
	}

	if (-not $url) { throw "No Windows installer found." }

	$dest = "$env:TEMP\librewolf-setup.exe"
	Get-FileFromWeb -Url $url -File $dest
	Start-Process $dest "/S" -Wait -NoNewWindow

	if (Test-Path $l) {		                        		                        
	    # if (Get-Command winget) { winget.exe upgrade --id "LibreWolf.LibreWolf" --exact --source winget --accept-source-agreements --silent --accept-package-agreements --quiet | Out-Null }			                        
	    $s = "$env:USERPROFILE\Desktop\LibreWolf.lnk"			                        
	    $wshell = New-Object -ComObject WScript.Shell   # <-- renamed from $W to avoid $w clash			                        
	    $lnk = $wshell.CreateShortcut($s)			                        
	    $lnk.TargetPath = $l			                        
	    $lnk.Save()			                        
	}	

	# create librewolf config file
	$MultilineComment = @"
// credit @PrivacyIsFreedom
// https://codeberg.org/PrivacyIsFreedom/Librewolf/src/branch/main/librewolf.overrides.cfg

defaultPref("privacy.window.maxInnerWidth", 1920);
defaultPref("privacy.window.maxInnerHeight", 1080);
defaultPref("browser.newtabpage.activity-stream.section.highlights.includeBookmarks", false);
defaultPref("browser.urlbar.suggest.engines", false);
defaultPref("browser.urlbar.suggest.bookmark", false);
defaultPref("browser.urlbar.suggest.history", false);
defaultPref("browser.urlbar.suggest.openpage", false);
defaultPref("browser.urlbar.suggest.topsites", false);
defaultPref("layout.spellcheckDefault", 0);
defaultPref("media.hardwaremediakeys.enabled", false);	
defaultPref("media.videocontrols.picture-in-picture.video-toggle.enabled", false);
defaultPref("places.history.enabled", false);
defaultPref("privacy.clearOnShutdown.siteSettings", true);
defaultPref("privacy.cpd.offlineApps", true);
defaultPref("privacy.cpd.siteSettings", true);	
defaultPref("privacy.userContext.enabled", false);	
defaultPref("ui.osk.enabled", false);
defaultPref("dom.push.connection.enabled", false);

// My Overrides
// Set Searx as default Home page  
defaultPref("browser.startup.homepage", "https://searx.stream/");

// Set Searx as default search engine  
defaultPref("browser.policies.runOncePerModification.setDefaultSearchEngine", "SearXNG - searx.be");

// Remove extensions
defaultPref("browser.policies.runOncePerModification.extensionsUninstall", ["google@search.mozilla.org","bing@search.mozilla.org","amazondotcom@search.mozilla.org","ebay@search.mozilla.org","twitter@search.mozilla.org"]);

// Disable WebRTC
defaultPref("media.peerconnection.enabled", false);

// Enable letterboxing
// Adds grey borders in fixed increments to hide real window size
defaultPref("privacy.resistFingerprinting.letterboxing", true);
"@

	$path="$env:USERPROFILE\.librewolf"
	if(!(Test-Path $path)){New-Item -ItemType Directory -Path $path -Force|Out-Null}
	Set-Content -Path "$path\librewolf.overrides.cfg" -Value $MultilineComment -Force

	# Aggressively remove LibreWolf Private Browsing shortcuts
	$shortcut = "LibreWolf Private Browsing.lnk"
	$locations = @(
    	"$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
    	"$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
	)

	$locations | ForEach-Object {
    	Get-ChildItem -Path $_ -Filter $shortcut -Recurse |
        	Remove-Item -Force
	}
}