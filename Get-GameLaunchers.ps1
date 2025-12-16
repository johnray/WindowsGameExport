<#
.SYNOPSIS
    Scans for installed games across multiple platforms and generates .bat launcher files.

.DESCRIPTION
    This script detects games from Steam, Epic Games, GOG, Xbox Game Pass, Amazon Games,
    EA App/Origin, Ubisoft Connect, Battle.net, and optionally performs a filesystem scan
    for standalone games. It verifies detected items are games using Wikipedia and RAWG APIs,
    then generates .bat launcher files for each game.

.PARAMETER Drives
    Array of drive letters to scan for games. Default: all fixed drives.

.PARAMETER OutputDirectory
    Directory where .bat launcher files will be created. Will prompt if not specified.

.PARAMETER RawgApiKey
    Optional RAWG API key for better game verification. Get one free at https://rawg.io/apidocs

.PARAMETER IncludeFilesystemScan
    Enable filesystem scanning for standalone games (slower but more thorough).

.PARAMETER SkipVerification
    Skip online verification and trust all detected games.

.PARAMETER DryRun
    Output detected games without creating any .bat files.

.PARAMETER ConfigFile
    Path to configuration/state JSON file. Default: _state.json in OutputDirectory.

.PARAMETER Exclude
    Array of directory paths to exclude from scanning (useful for large non-game directories).

.EXAMPLE
    .\Get-GameLaunchers.ps1 -Drives "C:", "D:" -OutputDirectory "C:\GameLaunchers"

.EXAMPLE
    .\Get-GameLaunchers.ps1 -DryRun -IncludeFilesystemScan

.EXAMPLE
    .\Get-GameLaunchers.ps1 -IncludeFilesystemScan -Exclude "D:\Media", "D:\Documents", "E:\Backup"
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$Drives,

    [Parameter()]
    [string]$OutputDirectory,

    [Parameter()]
    [string]$RawgApiKey,

    [Parameter()]
    [switch]$IncludeFilesystemScan,

    [Parameter()]
    [switch]$SkipVerification,

    [Parameter()]
    [switch]$DryRun,

    [Parameter()]
    [string]$ConfigFile,

    [Parameter()]
    [string[]]$Exclude
)

#region Helper Functions

function Get-SanitizedFileName {
    param([string]$Name)

    # Remove invalid filename characters
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $sanitized = $Name
    foreach ($char in $invalid) {
        $sanitized = $sanitized.Replace([string]$char, '')
    }
    # Also remove some problematic characters
    $sanitized = $sanitized -replace '[<>:"/\\|?*]', ''
    $sanitized = $sanitized.Trim()
    return $sanitized
}

function Get-NormalizedGameName {
    param([string]$Name)

    # Remove common suffixes for better matching
    $normalized = $Name
    $suffixes = @(
        '\s*[-:]\s*(GOTY|Game of the Year)\s*(Edition)?',
        '\s*[-:]\s*Definitive Edition',
        '\s*[-:]\s*Complete Edition',
        '\s*[-:]\s*Enhanced Edition',
        '\s*[-:]\s*Remastered',
        '\s*[-:]\s*Deluxe\s*(Edition)?',
        '\s*[-:]\s*Ultimate\s*(Edition)?',
        '\s*[-:]\s*Gold\s*(Edition)?',
        '\s*[-:]\s*Premium\s*(Edition)?',
        '\s*[-:]\s*Standard\s*(Edition)?',
        '\s*\(.*?\)$',  # Remove parenthetical suffixes
        '\s*\d{4}$'     # Remove year suffixes
    )

    foreach ($suffix in $suffixes) {
        $normalized = $normalized -replace $suffix, ''
    }

    $normalized = $normalized.Trim()
    return $normalized
}

function Get-GameHash {
    param(
        [string]$Name,
        [string]$Path,
        [string]$Platform
    )

    $str = "$Name|$Path|$Platform"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($str)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash($bytes)
    return [System.BitConverter]::ToString($hash).Replace('-', '').Substring(0, 16)
}

function Write-GameInfo {
    param(
        [string]$Name,
        [string]$Platform,
        [string]$Path,
        [string]$LaunchCommand,
        [bool]$Verified = $false
    )

    [PSCustomObject]@{
        Name = $Name
        Platform = $Platform
        Path = $Path
        LaunchCommand = $LaunchCommand
        Verified = $Verified
        Hash = Get-GameHash -Name $Name -Path $Path -Platform $Platform
    }
}

#endregion

#region VDF Parser (Valve Data Format)

function ConvertFrom-VDF {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Content
    )

    $result = @{}
    $stack = [System.Collections.Stack]::new()
    $stack.Push($result)
    $current = $result

    $lines = $Content -split "`n"

    foreach ($line in $lines) {
        $line = $line.Trim()

        # Skip empty lines and comments
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('//')) {
            continue
        }

        # Opening brace - handled after key
        if ($line -eq '{') {
            continue
        }

        # Closing brace - pop stack
        if ($line -eq '}') {
            if ($stack.Count -gt 1) {
                $stack.Pop() | Out-Null
                $current = $stack.Peek()
            }
            continue
        }

        # Parse quoted key-value pairs or section headers
        if ($line -match '^"([^"]+)"\s*"([^"]*)"') {
            # Key-value pair
            $key = $Matches[1]
            $value = $Matches[2]
            $current[$key] = $value
        }
        elseif ($line -match '^"([^"]+)"') {
            # Section header - next line should be {
            $key = $Matches[1]
            $newSection = @{}
            $current[$key] = $newSection
            $stack.Push($newSection)
            $current = $newSection
        }
    }

    return $result
}

#endregion

#region Platform Detection Functions

function Get-SteamGames {
    [CmdletBinding()]
    param(
        [string[]]$Drives
    )

    Write-Verbose "Scanning for Steam games..."
    $games = @()
    $seenAppIds = @{}

    # Find Steam install path from registry
    $steamPath = $null
    $regPaths = @(
        'HKLM:\SOFTWARE\Wow6432Node\Valve\Steam',
        'HKLM:\SOFTWARE\Valve\Steam'
    )

    foreach ($regPath in $regPaths) {
        try {
            $steamPath = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).InstallPath
            if ($steamPath) { break }
        } catch {}
    }

    if (-not $steamPath) {
        Write-Verbose "Steam not found in registry"
        return $games
    }

    Write-Verbose "Steam found at: $steamPath"

    # Get library folders from libraryfolders.vdf
    $libraryFolders = @($steamPath)
    $vdfPath = Join-Path $steamPath "config\libraryfolders.vdf"

    if (Test-Path $vdfPath) {
        try {
            $vdfContent = Get-Content -Path $vdfPath -Raw
            $vdf = ConvertFrom-VDF -Content $vdfContent

            # libraryfolders structure has numbered keys
            if ($vdf.libraryfolders) {
                foreach ($key in $vdf.libraryfolders.Keys) {
                    if ($key -match '^\d+$') {
                        $folder = $vdf.libraryfolders[$key]
                        if ($folder -is [hashtable] -and $folder.path) {
                            $libraryFolders += $folder.path
                        }
                        elseif ($folder -is [string]) {
                            $libraryFolders += $folder
                        }
                    }
                }
            }
        } catch {
            Write-Verbose "Error parsing libraryfolders.vdf: $_"
        }
    }

    $libraryFolders = $libraryFolders | Select-Object -Unique
    Write-Verbose "Found $($libraryFolders.Count) Steam library folders"

    # Scan each library folder for appmanifest files
    foreach ($library in $libraryFolders) {
        $steamAppsPath = Join-Path $library "steamapps"

        if (-not (Test-Path $steamAppsPath)) {
            continue
        }

        $manifests = Get-ChildItem -Path $steamAppsPath -Filter "appmanifest_*.acf" -ErrorAction SilentlyContinue

        foreach ($manifest in $manifests) {
            try {
                $content = Get-Content -Path $manifest.FullName -Raw
                $acf = ConvertFrom-VDF -Content $content

                if ($acf.AppState) {
                    $appId = $acf.AppState.appid
                    $name = $acf.AppState.name
                    $installDir = $acf.AppState.installdir

                    # Skip if no name or it's a tool/redistributable
                    if (-not $name -or $name -match '^(Steamworks|Proton|Steam Linux)') {
                        continue
                    }

                    # Skip duplicates (same appId already processed)
                    if ($seenAppIds.ContainsKey($appId)) {
                        continue
                    }
                    $seenAppIds[$appId] = $true

                    $gamePath = Join-Path $steamAppsPath "common\$installDir"

                    if (Test-Path $gamePath) {
                        $launchCmd = "start `"`" `"steam://rungameid/$appId`""
                        $games += Write-GameInfo -Name $name -Platform "Steam" -Path $gamePath -LaunchCommand $launchCmd
                        Write-Verbose "Found Steam game: $name"
                    }
                }
            } catch {
                Write-Verbose "Error parsing manifest $($manifest.Name): $_"
            }
        }
    }

    return $games
}

function Get-EpicGames {
    [CmdletBinding()]
    param()

    Write-Verbose "Scanning for Epic Games..."
    $games = @()

    # Find manifest location
    $manifestPath = Join-Path $env:ProgramData "Epic\EpicGamesLauncher\Data\Manifests"

    if (-not (Test-Path $manifestPath)) {
        Write-Verbose "Epic Games manifest folder not found"
        return $games
    }

    $itemFiles = Get-ChildItem -Path $manifestPath -Filter "*.item" -ErrorAction SilentlyContinue

    foreach ($item in $itemFiles) {
        try {
            $json = Get-Content -Path $item.FullName -Raw | ConvertFrom-Json

            $name = $json.DisplayName
            $appName = $json.AppName
            $installPath = $json.InstallLocation

            if (-not $name -or -not $installPath) {
                continue
            }

            if (Test-Path $installPath) {
                $launchCmd = "start `"`" `"com.epicgames.launcher://apps/$($appName)?action=launch&silent=true`""
                $games += Write-GameInfo -Name $name -Platform "Epic" -Path $installPath -LaunchCommand $launchCmd
                Write-Verbose "Found Epic game: $name"
            }
        } catch {
            Write-Verbose "Error parsing Epic manifest $($item.Name): $_"
        }
    }

    return $games
}

function Get-GOGGames {
    [CmdletBinding()]
    param(
        [string[]]$Drives
    )

    Write-Verbose "Scanning for GOG games..."
    $games = @()

    # Try registry first
    $regPaths = @(
        'HKLM:\SOFTWARE\Wow6432Node\GOG.com\Games',
        'HKLM:\SOFTWARE\GOG.com\Games'
    )

    foreach ($regPath in $regPaths) {
        if (Test-Path $regPath) {
            try {
                $gameKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue

                foreach ($gameKey in $gameKeys) {
                    try {
                        $props = Get-ItemProperty -Path $gameKey.PSPath
                        $name = $props.GAMENAME
                        $path = $props.PATH
                        $gameId = $props.gameID

                        if ($name -and $path -and (Test-Path $path)) {
                            # Find Galaxy client for launch
                            $galaxyPath = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\GOG.com\GalaxyClient\paths' -ErrorAction SilentlyContinue).client

                            if ($galaxyPath) {
                                $launchCmd = "`"$galaxyPath`" /command=runGame /gameId=$gameId /path=`"$path`""
                            } else {
                                # Try to find main exe
                                $exe = Get-ChildItem -Path $path -Filter "*.exe" -ErrorAction SilentlyContinue |
                                    Where-Object { $_.Name -notmatch '(unins|setup|config|crash|update|launcher)' } |
                                    Select-Object -First 1
                                if ($exe) {
                                    $launchCmd = "start `"`" `"$($exe.FullName)`""
                                } else {
                                    continue
                                }
                            }

                            $games += Write-GameInfo -Name $name -Platform "GOG" -Path $path -LaunchCommand $launchCmd
                            Write-Verbose "Found GOG game: $name"
                        }
                    } catch {}
                }
            } catch {}
        }
    }

    # Also scan for goggame-*.info files
    foreach ($drive in $Drives) {
        $searchPaths = @(
            (Join-Path $drive "GOG Games"),
            (Join-Path $drive "Games\GOG"),
            (Join-Path $drive "Program Files\GOG Galaxy\Games"),
            (Join-Path $drive "Program Files (x86)\GOG Galaxy\Games")
        )

        foreach ($searchPath in $searchPaths) {
            if (Test-Path $searchPath) {
                $infoFiles = Get-ChildItem -Path $searchPath -Filter "goggame-*.info" -Recurse -Depth 2 -ErrorAction SilentlyContinue

                foreach ($info in $infoFiles) {
                    try {
                        $json = Get-Content -Path $info.FullName -Raw | ConvertFrom-Json
                        $name = $json.name
                        $gameId = $json.gameId
                        $path = $info.DirectoryName

                        # Skip if already found via registry
                        if ($games | Where-Object { $_.Path -eq $path }) {
                            continue
                        }

                        if ($name -and $path) {
                            $galaxyPath = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\GOG.com\GalaxyClient\paths' -ErrorAction SilentlyContinue).client

                            if ($galaxyPath) {
                                $launchCmd = "`"$galaxyPath`" /command=runGame /gameId=$gameId /path=`"$path`""
                            } else {
                                $exe = Get-ChildItem -Path $path -Filter "*.exe" -ErrorAction SilentlyContinue |
                                    Where-Object { $_.Name -notmatch '(unins|setup|config|crash|update|launcher)' } |
                                    Select-Object -First 1
                                if ($exe) {
                                    $launchCmd = "start `"`" `"$($exe.FullName)`""
                                } else {
                                    continue
                                }
                            }

                            $games += Write-GameInfo -Name $name -Platform "GOG" -Path $path -LaunchCommand $launchCmd
                            Write-Verbose "Found GOG game (from info): $name"
                        }
                    } catch {}
                }
            }
        }
    }

    return $games
}

function Get-XboxGames {
    [CmdletBinding()]
    param()

    Write-Verbose "Scanning for Xbox/Microsoft Store games..."
    $games = @()

    # Known game publishers/developers for filtering (must be exact or partial match on publisher)
    $gamePublishers = @(
        'Bethesda',
        'ZeniMax',
        '505Games',
        'Ubisoft',
        'Activision',
        'Bandai',
        'Capcom',
        'DeepSilver',
        'Devolver',
        'FocusHome',
        'Gearbox',
        'Paradox',
        'PrivateDivision',
        'RockstarGames',
        'SquareEnix',
        'THQ',
        'TakeTwo',
        'Warner',
        'CDPROJEKTRED',
        'KochMedia',
        'Sega',
        'Konami',
        '2K',
        'Codemasters',
        'FromSoftware',
        'NamcoBandai',
        'Techland',
        'TeamNinja',
        'Koei'
    )

    # Explicit exclusions - these are NOT games
    $excludePatterns = @(
        # Microsoft apps
        'Microsoft\.Bing',
        'Microsoft\.Edge',
        'Microsoft\.Windows',
        'Microsoft\.Office',
        'Microsoft\.Store',
        'Microsoft\.Xbox\.TCUI',
        'Microsoft\.XboxIdentityProvider',
        'Microsoft\.XboxSpeechToTextOverlay',
        'Microsoft\.XboxGamingOverlay',
        'Microsoft\.XboxGameCallableUI',
        'Microsoft\.SecHealthUI',
        'Microsoft\.GetHelp',
        'Microsoft\.People',
        'Microsoft\.Wallet',
        'Microsoft\.WebMediaExtensions',
        'Microsoft\.VP9VideoExtensions',
        'Microsoft\.HEIFImageExtension',
        'Microsoft\.WebpImageExtension',
        'Microsoft\.ScreenSketch',
        'Microsoft\.Paint',
        'Microsoft\.MSPaint',
        'Microsoft\.YourPhone',
        'Microsoft\.549981C3F5F10', # Cortana
        'Microsoft\.MicrosoftEdge',
        'Microsoft\.Todos',
        'Microsoft\.PowerAutomateDesktop',
        'Microsoft\.OneDrive',
        'Microsoft\.GamingApp',
        'Microsoft\.XboxApp',
        'Microsoft\.WindowsTerminal',
        'Microsoft\.WindowsNotepad',
        'Microsoft\.WindowsCalculator',
        'Microsoft\.WindowsCamera',
        'Microsoft\.WindowsAlarms',
        'Microsoft\.ZuneMusic',
        'Microsoft\.ZuneVideo',
        'Microsoft\.Photos',
        'Microsoft\.SkypeApp',
        'Microsoft\.MicrosoftOfficeHub',
        'Microsoft\.MicrosoftStickyNotes',
        'Microsoft\.Whiteboard',
        'Microsoft\.3DBuilder',
        'Microsoft\.3DViewer',
        'Microsoft\.MixedReality',
        'Microsoft\.Print3D',
        'Microsoft\.Messaging',
        'Microsoft\.OneConnect',
        'Microsoft\.NetworkSpeedTest',
        'Microsoft\.RemoteDesktop',
        'Microsoft\.PowerBI',
        # MicrosoftCorporationII apps
        'MicrosoftCorporationII\.QuickAssist',
        'MicrosoftCorporationII\.WindowsSubsystemForLinux',
        'MicrosoftCorporationII\.WinAppRuntime',
        # MicrosoftWindows apps
        'MicrosoftWindows\.Client',
        'MicrosoftWindows\.CrossDevice',
        # Third party utilities (NOT games)
        'MSTeams',
        'Clipchamp',
        'SpotifyAB',
        'Spotify',
        'Ubuntu',
        'Debian',
        'SUSE',
        'Kali',
        'Canonical',
        'TheDebianProject',
        'WhitewaterFoundry',
        'RealtekSemiconductor',
        'NVIDIACorp',
        'DolbyLaboratories',
        'FileExplorer',
        'SecureAssessmentBrowser',
        'PrintQueueActionCenter',
        'CoreAI',
        'AdvancedMicroDevicesInc', # AMD Radeon Software
        'AppleInc\.iCloud',
        'Apple\.iTunes',
        'MICRO-STARINTERNATION', # MSI Center
        'ASUSTeK', # ASUS utilities
        'IntelCorporation',
        'NVIDIA',
        'Logitech',
        'Corsair',
        'Razer',
        'SteelSeries',
        'Discord',
        'Zoom',
        'Slack',
        'Telegram',
        'WhatsApp',
        'Signal',
        'Opera',
        'Mozilla',
        'Google',
        'Amazon\.Kindle',
        'Audible',
        'Dropbox',
        'Evernote',
        'Adobe',
        'Autodesk',
        'PuTTY',
        'WinSCP',
        'Notepad\+\+',
        'VSCode',
        'PowerToys'
    )

    try {
        $packages = Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object {
            $pkg = $_

            # First check exclusions - these are definitely NOT games
            foreach ($exclude in $excludePatterns) {
                if ($pkg.Name -match $exclude) {
                    return $false
                }
            }

            # Skip system apps and framework packages
            if ($pkg.SignatureKind -eq 'System' -or $pkg.IsFramework -eq $true) {
                return $false
            }

            # Skip if no install location
            if (-not $pkg.InstallLocation) {
                return $false
            }

            # Check if it's in an XboxGames folder (high confidence)
            if ($pkg.InstallLocation -match '\\XboxGames\\') {
                return $true
            }

            # Check if it's from a known game publisher (by name pattern)
            foreach ($publisher in $gamePublishers) {
                if ($pkg.Publisher -like "*$publisher*" -or $pkg.Name -like "*$publisher*") {
                    return $true
                }
            }

            # Check for specific Microsoft game packages
            if ($pkg.Name -match '^Microsoft\.(Minecraft|MicrosoftSolitaireCollection|FlightSimulator|Forza|Halo|SeaOfThieves|StateOfDecay|GearsPOP|AgeOfEmpires|MicrosoftMahjong|MicrosoftJigsaw|MicrosoftCasualGames)') {
                return $true
            }

            # Include third-party apps that are NOT Microsoft and NOT in exclusions
            # These are likely games from Game Pass or MS Store
            if ($pkg.Name -notmatch '^Microsoft\.' -and
                $pkg.Name -notmatch '^Windows\.' -and
                $pkg.Name -notmatch '^windows\.' -and
                $pkg.InstallLocation -match 'WindowsApps') {
                return $true
            }

            return $false
        }

        foreach ($pkg in $packages) {
            try {
                # Get display name from manifest
                $manifestPath = Join-Path $pkg.InstallLocation "AppxManifest.xml"
                $displayName = $null

                if (Test-Path $manifestPath) {
                    try {
                        [xml]$manifest = Get-Content $manifestPath -ErrorAction SilentlyContinue
                        $rawDisplayName = $manifest.Package.Properties.DisplayName
                        if ($rawDisplayName -and $rawDisplayName -notmatch '^ms-resource:') {
                            $displayName = $rawDisplayName
                        }
                    } catch {}
                }

                # If no display name from manifest, try to parse from package name
                if (-not $displayName) {
                    $displayName = $pkg.Name -replace '^Microsoft\.', '' -replace '_.*$', ''
                    # Add spaces between camelCase words only if it's CamelCase
                    if ($displayName -cmatch '[a-z][A-Z]') {
                        $displayName = $displayName -replace '([a-z])([A-Z])', '$1 $2'
                    }
                }

                $name = $displayName.Trim()

                if ($name -and $pkg.InstallLocation -and $name.Length -gt 2) {
                    $launchCmd = "explorer.exe shell:AppsFolder\$($pkg.PackageFamilyName)!App"
                    $games += Write-GameInfo -Name $name -Platform "Xbox" -Path $pkg.InstallLocation -LaunchCommand $launchCmd
                    Write-Verbose "Found Xbox game: $name"
                }
            } catch {}
        }
    } catch {
        Write-Verbose "Error scanning Xbox games: $_"
    }

    # Also scan for Xbox Game Pass games installed to custom XboxGames folders
    # These don't show up in Get-AppxPackage but have appxmanifest.xml in Content folder
    $xboxGamesFolders = @()

    # Check common XboxGames locations on all drives
    $drives = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" | Select-Object -ExpandProperty DeviceID
    foreach ($drive in $drives) {
        $xboxPath = Join-Path $drive "XboxGames"
        if (Test-Path $xboxPath) {
            $xboxGamesFolders += $xboxPath
        }
    }

    foreach ($xboxFolder in $xboxGamesFolders) {
        Write-Verbose "Scanning XboxGames folder: $xboxFolder"
        try {
            $gameFolders = Get-ChildItem -Path $xboxFolder -Directory -ErrorAction SilentlyContinue

            foreach ($gameFolder in $gameFolders) {
                # Skip if already found via Get-AppxPackage
                if ($games | Where-Object { $_.Name -eq $gameFolder.Name }) {
                    continue
                }

                # Check for appxmanifest.xml in Content subfolder
                $manifestPath = Join-Path $gameFolder.FullName "Content\appxmanifest.xml"
                if (Test-Path $manifestPath) {
                    try {
                        [xml]$manifest = Get-Content $manifestPath -ErrorAction SilentlyContinue

                        $displayName = $manifest.Package.Properties.DisplayName
                        if ($displayName -match '^ms-resource:') {
                            # Try to get from Identity or folder name
                            $displayName = $gameFolder.Name
                        }

                        $packageName = $manifest.Package.Identity.Name
                        $appId = $manifest.Package.Applications.Application.Id

                        if ($displayName -and $displayName.Length -gt 2) {
                            # Xbox Game Pass games use a special launch method
                            # shell:AppsFolder\PackageFamilyName!AppId
                            $publisher = $manifest.Package.Identity.Publisher
                            # Extract publisher hash (simplified - real hash is more complex)
                            $publisherHash = ($publisher -replace '[^a-zA-Z0-9]', '').Substring(0, [Math]::Min(13, ($publisher -replace '[^a-zA-Z0-9]', '').Length))

                            $launchCmd = "explorer.exe shell:AppsFolder\$packageName`_$publisherHash!$appId"

                            $games += Write-GameInfo -Name $displayName -Platform "Xbox" -Path $gameFolder.FullName -LaunchCommand $launchCmd
                            Write-Verbose "Found Xbox game (XboxGames folder): $displayName"
                        }
                    } catch {
                        Write-Verbose "Error parsing manifest in $($gameFolder.Name): $_"
                    }
                }
            }
        } catch {
            Write-Verbose "Error scanning XboxGames folder: $_"
        }
    }

    return $games
}

function Get-AmazonGames {
    [CmdletBinding()]
    param()

    Write-Verbose "Scanning for Amazon Games..."
    $games = @()

    # Amazon Games SQLite database location
    $dbPath = Join-Path $env:LOCALAPPDATA "Amazon Games\Data\Games\Sql\GameInstallInfo.sqlite"

    if (-not (Test-Path $dbPath)) {
        Write-Verbose "Amazon Games database not found"
        return $games
    }

    # Try to read SQLite database
    try {
        # Load SQLite assembly if available
        $sqliteLoaded = $false

        # Try loading from GAC or common locations
        $assemblies = @(
            'System.Data.SQLite',
            (Join-Path $PSScriptRoot 'System.Data.SQLite.dll')
        )

        foreach ($asm in $assemblies) {
            try {
                Add-Type -AssemblyName $asm -ErrorAction Stop
                $sqliteLoaded = $true
                break
            } catch {}
        }

        if ($sqliteLoaded) {
            $conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$dbPath;Version=3;Read Only=True;")
            $conn.Open()

            $cmd = $conn.CreateCommand()
            $cmd.CommandText = "SELECT ProductTitle, InstallDirectory, Installed FROM DbSet WHERE Installed = 1"
            $reader = $cmd.ExecuteReader()

            while ($reader.Read()) {
                $name = $reader["ProductTitle"]
                $path = $reader["InstallDirectory"]

                if ($name -and $path -and (Test-Path $path)) {
                    # Find main executable
                    $exe = Get-ChildItem -Path $path -Filter "*.exe" -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -notmatch '(unins|setup|config|crash|update|launcher|fuel)' } |
                        Sort-Object Length -Descending |
                        Select-Object -First 1

                    if ($exe) {
                        $launchCmd = "start `"`" `"$($exe.FullName)`""
                        $games += Write-GameInfo -Name $name -Platform "Amazon" -Path $path -LaunchCommand $launchCmd
                        Write-Verbose "Found Amazon game: $name"
                    }
                }
            }

            $conn.Close()
        } else {
            Write-Verbose "SQLite assembly not available for Amazon Games"
        }
    } catch {
        Write-Verbose "Error reading Amazon Games database: $_"
    }

    return $games
}

function Get-EAGames {
    [CmdletBinding()]
    param()

    Write-Verbose "Scanning for EA/Origin games..."
    $games = @()

    # Check registry for Origin games
    $regPath = 'HKLM:\SOFTWARE\Wow6432Node\Origin Games'

    if (Test-Path $regPath) {
        try {
            $gameKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue

            foreach ($gameKey in $gameKeys) {
                try {
                    $props = Get-ItemProperty -Path $gameKey.PSPath
                    $path = $props.'Install Dir'

                    if ($path -and (Test-Path $path)) {
                        # Get name from folder
                        $name = Split-Path $path -Leaf

                        # Try to find a better name from files
                        $installerData = Join-Path $path "__Installer\installerdata.xml"
                        if (Test-Path $installerData) {
                            try {
                                [xml]$xml = Get-Content $installerData
                                if ($xml.DiPManifest.gameTitles.gameTitle.'#text') {
                                    $name = ($xml.DiPManifest.gameTitles.gameTitle | Where-Object { $_.locale -eq 'en_US' }).'#text'
                                    if (-not $name) {
                                        $name = $xml.DiPManifest.gameTitles.gameTitle[0].'#text'
                                    }
                                }
                            } catch {}
                        }

                        # Find main executable
                        $exe = Get-ChildItem -Path $path -Filter "*.exe" -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -notmatch '(unins|setup|config|crash|update|launcher|activation|EALink|OriginThinSetup)' } |
                            Sort-Object Length -Descending |
                            Select-Object -First 1

                        if ($exe -and $name) {
                            $launchCmd = "start `"`" `"$($exe.FullName)`""
                            $games += Write-GameInfo -Name $name -Platform "EA" -Path $path -LaunchCommand $launchCmd
                            Write-Verbose "Found EA game: $name"
                        }
                    }
                } catch {}
            }
        } catch {}
    }

    # Also check EA Desktop registry
    $eaRegPath = 'HKLM:\SOFTWARE\Wow6432Node\Electronic Arts'
    if (Test-Path $eaRegPath) {
        try {
            $gameKeys = Get-ChildItem -Path $eaRegPath -Recurse -ErrorAction SilentlyContinue |
                Where-Object { (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).'Install Dir' }

            foreach ($gameKey in $gameKeys) {
                try {
                    $props = Get-ItemProperty -Path $gameKey.PSPath
                    $path = $props.'Install Dir'

                    # Skip if already found
                    if ($games | Where-Object { $_.Path -eq $path }) {
                        continue
                    }

                    if ($path -and (Test-Path $path)) {
                        $name = Split-Path $path -Leaf

                        $exe = Get-ChildItem -Path $path -Filter "*.exe" -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -notmatch '(unins|setup|config|crash|update|launcher|activation)' } |
                            Sort-Object Length -Descending |
                            Select-Object -First 1

                        if ($exe -and $name) {
                            $launchCmd = "start `"`" `"$($exe.FullName)`""
                            $games += Write-GameInfo -Name $name -Platform "EA" -Path $path -LaunchCommand $launchCmd
                            Write-Verbose "Found EA game: $name"
                        }
                    }
                } catch {}
            }
        } catch {}
    }

    return $games
}

function Get-UbisoftGames {
    [CmdletBinding()]
    param()

    Write-Verbose "Scanning for Ubisoft Connect games..."
    $games = @()

    $regPath = 'HKLM:\SOFTWARE\Wow6432Node\Ubisoft\Launcher\Installs'

    if (-not (Test-Path $regPath)) {
        Write-Verbose "Ubisoft Connect not found in registry"
        return $games
    }

    try {
        $gameKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue

        foreach ($gameKey in $gameKeys) {
            try {
                $props = Get-ItemProperty -Path $gameKey.PSPath
                $path = $props.InstallDir

                if ($path -and (Test-Path $path)) {
                    # Get name from folder
                    $name = Split-Path $path -Leaf

                    # Find main executable
                    $exe = Get-ChildItem -Path $path -Filter "*.exe" -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -notmatch '(unins|setup|config|crash|update|launcher|uplay|ubiconnect)' } |
                        Sort-Object Length -Descending |
                        Select-Object -First 1

                    if ($exe -and $name) {
                        $launchCmd = "start `"`" `"$($exe.FullName)`""
                        $games += Write-GameInfo -Name $name -Platform "Ubisoft" -Path $path -LaunchCommand $launchCmd
                        Write-Verbose "Found Ubisoft game: $name"
                    }
                }
            } catch {}
        }
    } catch {}

    return $games
}

function Get-BattleNetGames {
    [CmdletBinding()]
    param()

    Write-Verbose "Scanning for Battle.net games..."
    $games = @()

    # Known Battle.net game codes and names
    $battleNetGames = @{
        'wow' = 'World of Warcraft'
        'wow_classic' = 'World of Warcraft Classic'
        'd3' = 'Diablo III'
        'd4' = 'Diablo IV'
        'hs' = 'Hearthstone'
        'hero' = 'Heroes of the Storm'
        'pro' = 'Overwatch 2'
        's1' = 'StarCraft Remastered'
        's2' = 'StarCraft II'
        'w3' = 'Warcraft III Reforged'
        'viper' = 'Call of Duty Black Ops Cold War'
        'odin' = 'Call of Duty Modern Warfare'
        'lazr' = 'Call of Duty MW2 Campaign Remastered'
        'zeus' = 'Call of Duty Black Ops 4'
        'fore' = 'Call of Duty Vanguard'
        'auks' = 'Call of Duty Modern Warfare II'
    }

    # Check registry for individual games
    $regPaths = @(
        'HKLM:\SOFTWARE\Wow6432Node\Blizzard Entertainment',
        'HKLM:\SOFTWARE\Blizzard Entertainment'
    )

    foreach ($regPath in $regPaths) {
        if (Test-Path $regPath) {
            try {
                $gameKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue

                foreach ($gameKey in $gameKeys) {
                    try {
                        $props = Get-ItemProperty -Path $gameKey.PSPath -ErrorAction SilentlyContinue
                        $path = $props.InstallPath

                        if (-not $path) {
                            # Try alternate property names
                            $path = $props.'Install Path'
                        }

                        if ($path -and (Test-Path $path)) {
                            $name = $gameKey.PSChildName

                            # Find matching product code
                            $productCode = $battleNetGames.Keys | Where-Object {
                                $battleNetGames[$_] -like "*$name*"
                            } | Select-Object -First 1

                            if ($productCode) {
                                $launchCmd = "start `"`" `"battlenet://$productCode`""
                            } else {
                                # Direct exe launch
                                $exe = Get-ChildItem -Path $path -Filter "*.exe" -ErrorAction SilentlyContinue |
                                    Where-Object { $_.Name -notmatch '(unins|setup|config|crash|update|launcher|battle\.net)' } |
                                    Sort-Object Length -Descending |
                                    Select-Object -First 1

                                if ($exe) {
                                    $launchCmd = "start `"`" `"$($exe.FullName)`""
                                } else {
                                    continue
                                }
                            }

                            $games += Write-GameInfo -Name $name -Platform "Battle.net" -Path $path -LaunchCommand $launchCmd
                            Write-Verbose "Found Battle.net game: $name"
                        }
                    } catch {}
                }
            } catch {}
        }
    }

    # Try Battle.net config file
    $configPath = Join-Path $env:APPDATA "Battle.net\Battle.net.config"
    if (Test-Path $configPath) {
        try {
            $config = Get-Content $configPath -Raw | ConvertFrom-Json

            # Parse install locations from config
            if ($config.Games) {
                foreach ($game in $config.Games.PSObject.Properties) {
                    $gamePath = $game.Value.InstallPath
                    $gameCode = $game.Name.ToLower()

                    if ($gamePath -and (Test-Path $gamePath)) {
                        # Skip if already found
                        if ($games | Where-Object { $_.Path -eq $gamePath }) {
                            continue
                        }

                        $name = if ($battleNetGames[$gameCode]) { $battleNetGames[$gameCode] } else { $game.Name }

                        if ($battleNetGames[$gameCode]) {
                            $launchCmd = "start `"`" `"battlenet://$gameCode`""
                        } else {
                            $exe = Get-ChildItem -Path $gamePath -Filter "*.exe" -ErrorAction SilentlyContinue |
                                Where-Object { $_.Name -notmatch '(unins|setup|config|crash|update|launcher)' } |
                                Sort-Object Length -Descending |
                                Select-Object -First 1

                            if ($exe) {
                                $launchCmd = "start `"`" `"$($exe.FullName)`""
                            } else {
                                continue
                            }
                        }

                        $games += Write-GameInfo -Name $name -Platform "Battle.net" -Path $gamePath -LaunchCommand $launchCmd
                        Write-Verbose "Found Battle.net game (from config): $name"
                    }
                }
            }
        } catch {
            Write-Verbose "Error parsing Battle.net config: $_"
        }
    }

    return $games
}

function Get-FilesystemGames {
    [CmdletBinding()]
    param(
        [string[]]$Drives,
        [string[]]$UserExcludes = @()
    )

    Write-Verbose "Performing filesystem scan for standalone games..."
    $games = @()

    # Directories to exclude (built-in)
    $excludeDirs = @(
        'Windows', 'System32', 'SysWOW64', 'WinSxS',
        'Program Files\Common Files', 'Program Files (x86)\Common Files',
        'ProgramData', 'Users', '$Recycle.Bin', 'Recovery',
        'Documents and Settings', 'MSOCache', 'PerfLogs',
        'WindowsApps', 'node_modules', '.git', '.svn',
        'Steam\steamapps', 'SteamLibrary\steamapps',
        'Epic Games\Launcher', 'GOG Galaxy\GalaxyClient',
        'Origin', 'EA Desktop', 'Ubisoft\Ubisoft Game Launcher',
        'Battle.net'
    )

    # Directories that commonly contain games
    $gameDirs = @(
        'Games', 'Game', 'Gaming',
        'Program Files', 'Program Files (x86)'
    )

    # Game engine indicators
    $engineIndicators = @{
        'Unity' = @('UnityPlayer.dll', 'UnityCrashHandler*.exe', '*_Data')
        'Unreal' = @('Engine', 'UE4Game*.exe', 'UE5Game*.exe', '*-Win64-Shipping.exe')
        'Godot' = @('*.pck', 'godot*.exe')
        'GameMaker' = @('data.win', '*.yy')
        'RPGMaker' = @('Game.exe', 'RPG_RT.exe', 'RGSS*.dll')
        'Ren''Py' = @('renpy', 'lib\python*')
    }

    foreach ($drive in $Drives) {
        # Get root-level folders that might contain games
        $searchRoots = @()

        foreach ($gameDir in $gameDirs) {
            $path = Join-Path $drive $gameDir
            if (Test-Path $path) {
                $searchRoots += $path
            }
        }

        # Also check root for game folders
        try {
            $rootFolders = Get-ChildItem -Path "$drive\" -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notin $excludeDirs -and $_.Name -notmatch '^[\$\.]' }

            foreach ($folder in $rootFolders) {
                # Check if folder looks like a game directory
                $hasExe = Get-ChildItem -Path $folder.FullName -Filter "*.exe" -ErrorAction SilentlyContinue |
                    Select-Object -First 1

                if ($hasExe) {
                    $searchRoots += $folder.FullName
                }
            }
        } catch {}

        $searchRoots = $searchRoots | Select-Object -Unique

        foreach ($searchRoot in $searchRoots) {
            Write-Verbose "Scanning: $searchRoot"

            try {
                $folders = Get-ChildItem -Path $searchRoot -Directory -ErrorAction SilentlyContinue -Depth 1

                foreach ($folder in $folders) {
                    # Skip excluded directories (built-in)
                    $skip = $false
                    foreach ($exclude in $excludeDirs) {
                        if ($folder.FullName -like "*$exclude*") {
                            $skip = $true
                            break
                        }
                    }
                    # Skip user-excluded directories
                    if (-not $skip) {
                        foreach ($userExclude in $UserExcludes) {
                            if ($folder.FullName -like "$userExclude*" -or $folder.FullName -eq $userExclude) {
                                $skip = $true
                                Write-Verbose "Skipping user-excluded: $($folder.FullName)"
                                break
                            }
                        }
                    }
                    if ($skip) { continue }

                    # Check for game engine indicators
                    $isGame = $false
                    $detectedEngine = $null

                    foreach ($engine in $engineIndicators.Keys) {
                        foreach ($indicator in $engineIndicators[$engine]) {
                            $found = Get-ChildItem -Path $folder.FullName -Filter $indicator -ErrorAction SilentlyContinue |
                                Select-Object -First 1
                            if ($found) {
                                $isGame = $true
                                $detectedEngine = $engine
                                break
                            }
                        }
                        if ($isGame) { break }
                    }

                    # If no engine detected, check for common game file patterns
                    if (-not $isGame) {
                        $exes = Get-ChildItem -Path $folder.FullName -Filter "*.exe" -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -notmatch '(unins|setup|config|crash|update|launcher|vcredist|dxsetup|dotnet|UnityCrash|redist)' }

                        if ($exes.Count -ge 1) {
                            # Check for supporting game files
                            $hasGameFiles = (Test-Path (Join-Path $folder.FullName "*.dll")) -or
                                           (Test-Path (Join-Path $folder.FullName "data")) -or
                                           (Test-Path (Join-Path $folder.FullName "assets")) -or
                                           (Test-Path (Join-Path $folder.FullName "content")) -or
                                           (Test-Path (Join-Path $folder.FullName "Resources"))

                            if ($hasGameFiles) {
                                $isGame = $true
                            }
                        }
                    }

                    if ($isGame) {
                        $name = $folder.Name
                        $path = $folder.FullName

                        # Find main executable
                        $exe = Get-ChildItem -Path $path -Filter "*.exe" -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -notmatch '(unins|setup|config|crash|update|launcher|vcredist|dxsetup|UnityCrash|redist)' } |
                            Sort-Object {
                                # Prefer exe with similar name to folder
                                $similarity = 0
                                if ($_.BaseName -like "*$($folder.Name)*" -or $folder.Name -like "*$($_.BaseName)*") {
                                    $similarity = 100
                                }
                                $similarity + $_.Length
                            } -Descending |
                            Select-Object -First 1

                        if ($exe) {
                            $platform = if ($detectedEngine) { "Standalone-$detectedEngine" } else { "Standalone" }
                            $launchCmd = "start `"`" `"$($exe.FullName)`""
                            $games += Write-GameInfo -Name $name -Platform $platform -Path $path -LaunchCommand $launchCmd
                            Write-Verbose "Found standalone game: $name ($platform)"
                        }
                    }
                }
            } catch {
                Write-Verbose "Error scanning $searchRoot`: $_"
            }
        }
    }

    return $games
}

#endregion

#region Verification Functions

function Test-WikipediaGame {
    [CmdletBinding()]
    param(
        [string]$GameName
    )

    $normalized = Get-NormalizedGameName -Name $GameName
    $encoded = [System.Web.HttpUtility]::UrlEncode($normalized)

    $url = "https://en.wikipedia.org/w/api.php?action=query&titles=$encoded&prop=categories&cllimit=50&format=json"

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -ErrorAction Stop

        # Check if page exists
        $pages = $response.query.pages
        $pageId = ($pages.PSObject.Properties | Select-Object -First 1).Name

        if ($pageId -eq '-1') {
            # Page not found, try with " (video game)" suffix
            $url2 = "https://en.wikipedia.org/w/api.php?action=query&titles=$encoded%20(video%20game)&prop=categories&cllimit=50&format=json"
            $response = Invoke-RestMethod -Uri $url2 -Method Get -ErrorAction Stop
            $pages = $response.query.pages
            $pageId = ($pages.PSObject.Properties | Select-Object -First 1).Name

            if ($pageId -eq '-1') {
                return $false
            }
        }

        # Check categories for video game indicators
        $categories = $pages.$pageId.categories
        if ($categories) {
            $gameCategories = $categories | Where-Object {
                $_.title -match '(video game|Video game|Windows game|PC game|PlayStation|Xbox game|Nintendo|Steam game|multiplayer game|single-player game)'
            }

            if ($gameCategories) {
                return $true
            }
        }

        return $false
    } catch {
        Write-Verbose "Wikipedia API error for '$GameName': $_"
        return $null  # Unknown, API failed
    }
}

function Test-RawgGame {
    [CmdletBinding()]
    param(
        [string]$GameName,
        [string]$ApiKey
    )

    if (-not $ApiKey) {
        return $null
    }

    $normalized = Get-NormalizedGameName -Name $GameName
    $encoded = [System.Web.HttpUtility]::UrlEncode($normalized)

    $url = "https://api.rawg.io/api/games?key=$ApiKey&search=$encoded&page_size=1"

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -ErrorAction Stop

        if ($response.count -gt 0) {
            $result = $response.results[0]
            # Check if the name is reasonably similar
            $similarity = [Math]::Max(
                $result.name.ToLower().Contains($normalized.ToLower().Substring(0, [Math]::Min(10, $normalized.Length))),
                $normalized.ToLower().Contains($result.name.ToLower().Substring(0, [Math]::Min(10, $result.name.Length)))
            )

            return $similarity -or ($response.count -eq 1)
        }

        return $false
    } catch {
        Write-Verbose "RAWG API error for '$GameName': $_"
        return $null
    }
}

function Confirm-IsGame {
    [CmdletBinding()]
    param(
        [string]$GameName,
        [string]$RawgApiKey,
        [switch]$SkipVerification
    )

    if ($SkipVerification) {
        return $true
    }

    Write-Verbose "Verifying: $GameName"

    # Try Wikipedia first
    $wikiResult = Test-WikipediaGame -GameName $GameName

    # Rate limiting
    Start-Sleep -Milliseconds 500

    if ($wikiResult -eq $true) {
        return $true
    }

    # Try RAWG if available and Wikipedia didn't confirm
    if ($RawgApiKey) {
        $rawgResult = Test-RawgGame -GameName $GameName -ApiKey $RawgApiKey
        Start-Sleep -Milliseconds 500

        if ($rawgResult -eq $true) {
            return $true
        }
    }

    # If we got explicit false from both, it's not verified
    # If we got null (API errors), consider it unverified but not rejected
    return $false
}

#endregion

#region Launcher Generation

function New-GameLauncher {
    [CmdletBinding()]
    param(
        [PSCustomObject]$Game,
        [string]$OutputDirectory,
        [switch]$DryRun
    )

    $sanitizedName = Get-SanitizedFileName -Name $Game.Name
    $fileName = "$sanitizedName ($($Game.Platform)).bat"

    $targetDir = if ($Game.Verified) { $OutputDirectory } else { Join-Path $OutputDirectory "Unverified" }
    $filePath = Join-Path $targetDir $fileName

    if ($DryRun) {
        Write-Host "Would create: $filePath" -ForegroundColor Cyan
        return $filePath
    }

    # Ensure directory exists
    if (-not (Test-Path $targetDir)) {
        New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
    }

    $batContent = @"
@echo off
REM Game: $($Game.Name)
REM Platform: $($Game.Platform)
REM Path: $($Game.Path)
REM Verified: $(if ($Game.Verified) { 'Yes' } else { 'No' })
REM Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
$($Game.LaunchCommand)
"@

    Set-Content -Path $filePath -Value $batContent -Encoding ASCII

    return $filePath
}

function Update-GameLaunchers {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Games,
        [string]$OutputDirectory,
        [hashtable]$State,
        [switch]$DryRun
    )

    $created = 0
    $updated = 0
    $unchanged = 0

    foreach ($game in $Games) {
        $hash = $game.Hash
        $wasVerified = $State[$hash].Verified
        $existed = $State.ContainsKey($hash)

        if ($existed -and $wasVerified -eq $game.Verified) {
            $unchanged++
            continue
        }

        $filePath = New-GameLauncher -Game $game -OutputDirectory $OutputDirectory -DryRun:$DryRun

        if ($existed) {
            $updated++
            Write-Host "Updated: $($game.Name) ($($game.Platform))" -ForegroundColor Yellow
        } else {
            $created++
            Write-Host "Created: $($game.Name) ($($game.Platform))" -ForegroundColor Green
        }

        # Update state
        $State[$hash] = @{
            Name = $game.Name
            Platform = $game.Platform
            Path = $game.Path
            Verified = $game.Verified
            LastUpdated = (Get-Date).ToString('o')
        }
    }

    return @{
        Created = $created
        Updated = $updated
        Unchanged = $unchanged
    }
}

#endregion

#region Main Script

# Add System.Web for URL encoding
Add-Type -AssemblyName System.Web

# Get drives if not specified
if (-not $Drives) {
    $Drives = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" |
        Select-Object -ExpandProperty DeviceID
    Write-Host "Detected drives: $($Drives -join ', ')" -ForegroundColor Cyan
}

# Prompt for output directory if not specified
if (-not $OutputDirectory) {
    $OutputDirectory = Read-Host "Enter output directory for .bat files"
    if (-not $OutputDirectory) {
        $OutputDirectory = Join-Path $env:USERPROFILE "GameLaunchers"
    }
}

# Ensure output directory exists
if (-not (Test-Path $OutputDirectory) -and -not $DryRun) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}

# State file
if (-not $ConfigFile) {
    $ConfigFile = Join-Path $OutputDirectory "_state.json"
}

# Load existing state
$state = @{}
if ((Test-Path $ConfigFile) -and -not $DryRun) {
    try {
        $stateJson = Get-Content -Path $ConfigFile -Raw | ConvertFrom-Json
        foreach ($prop in $stateJson.PSObject.Properties) {
            $state[$prop.Name] = $prop.Value
        }
    } catch {
        Write-Warning "Could not load state file, starting fresh"
    }
}

Write-Host "`n=== Game Launcher Generator ===" -ForegroundColor Cyan
Write-Host "Output: $OutputDirectory"
Write-Host "Drives: $($Drives -join ', ')"
if ($Exclude) { Write-Host "Excludes: $($Exclude -join ', ')" -ForegroundColor Gray }
if ($DryRun) { Write-Host "Mode: DRY RUN (no files will be created)" -ForegroundColor Yellow }
Write-Host ""

# Collect all games
$allGames = @()

Write-Host "Scanning for games..." -ForegroundColor Cyan

# Steam
$steamGames = Get-SteamGames -Drives $Drives -Verbose:$VerbosePreference
Write-Host "  Steam: $($steamGames.Count) games found"
$allGames += $steamGames

# Epic
$epicGames = Get-EpicGames -Verbose:$VerbosePreference
Write-Host "  Epic Games: $($epicGames.Count) games found"
$allGames += $epicGames

# GOG
$gogGames = Get-GOGGames -Drives $Drives -Verbose:$VerbosePreference
Write-Host "  GOG: $($gogGames.Count) games found"
$allGames += $gogGames

# Xbox
$xboxGames = Get-XboxGames -Verbose:$VerbosePreference
Write-Host "  Xbox/Microsoft Store: $($xboxGames.Count) games found"
$allGames += $xboxGames

# Amazon
$amazonGames = Get-AmazonGames -Verbose:$VerbosePreference
Write-Host "  Amazon Games: $($amazonGames.Count) games found"
$allGames += $amazonGames

# EA
$eaGames = Get-EAGames -Verbose:$VerbosePreference
Write-Host "  EA/Origin: $($eaGames.Count) games found"
$allGames += $eaGames

# Ubisoft
$ubisoftGames = Get-UbisoftGames -Verbose:$VerbosePreference
Write-Host "  Ubisoft Connect: $($ubisoftGames.Count) games found"
$allGames += $ubisoftGames

# Battle.net
$battleNetGames = Get-BattleNetGames -Verbose:$VerbosePreference
Write-Host "  Battle.net: $($battleNetGames.Count) games found"
$allGames += $battleNetGames

# Filesystem scan (optional)
if ($IncludeFilesystemScan) {
    $fsGames = Get-FilesystemGames -Drives $Drives -UserExcludes $Exclude -Verbose:$VerbosePreference
    Write-Host "  Filesystem scan: $($fsGames.Count) potential games found"
    $allGames += $fsGames
}

Write-Host "`nTotal: $($allGames.Count) games detected" -ForegroundColor Green

# DryRun mode - just output the list
if ($DryRun) {
    Write-Host "`n=== Detected Games ===" -ForegroundColor Cyan
    $allGames | Sort-Object Platform, Name | ForEach-Object {
        Write-Host "  [$($_.Platform)] $($_.Name)" -ForegroundColor White
        Write-Host "    Path: $($_.Path)" -ForegroundColor Gray
    }
    Write-Host "`nDry run complete. No files were created." -ForegroundColor Yellow
    exit 0
}

# Verify games
if (-not $SkipVerification -and $allGames.Count -gt 0) {
    Write-Host "`nVerifying games online (this may take a while)..." -ForegroundColor Cyan
    $verified = 0
    $unverified = 0

    foreach ($game in $allGames) {
        $isVerified = Confirm-IsGame -GameName $game.Name -RawgApiKey $RawgApiKey -SkipVerification:$SkipVerification
        $game.Verified = $isVerified

        if ($isVerified) {
            $verified++
            Write-Host "  [OK] $($game.Name)" -ForegroundColor Green
        } else {
            $unverified++
            Write-Host "  [??] $($game.Name)" -ForegroundColor Yellow
        }
    }

    Write-Host "`nVerification: $verified verified, $unverified unverified" -ForegroundColor Cyan
} else {
    # Mark all as verified if skipping verification
    foreach ($game in $allGames) {
        $game.Verified = $true
    }
}

# Generate launchers
Write-Host "`nGenerating launcher files..." -ForegroundColor Cyan
$results = Update-GameLaunchers -Games $allGames -OutputDirectory $OutputDirectory -State $state -DryRun:$DryRun

# Save state
if (-not $DryRun) {
    $state | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigFile
}

# Summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "  Created: $($results.Created)" -ForegroundColor Green
Write-Host "  Updated: $($results.Updated)" -ForegroundColor Yellow
Write-Host "  Unchanged: $($results.Unchanged)" -ForegroundColor Gray
Write-Host "  Output: $OutputDirectory" -ForegroundColor White

#endregion
