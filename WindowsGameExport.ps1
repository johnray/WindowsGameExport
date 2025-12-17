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

.PARAMETER IgnoreUnverified
    Skip unverified games entirely instead of placing them in the Unverified subfolder.

.PARAMETER DryRun
    Output detected games without creating any .bat files.

.PARAMETER ConfigFile
    Path to configuration/state JSON file. Default: _state.json in OutputDirectory.

.PARAMETER Exclude
    Array of directory paths to exclude from scanning (useful for large non-game directories).

.EXAMPLE
    .\WindowsGameExport.ps1 -Drives "C:", "D:" -OutputDirectory "C:\GameLaunchers"

.EXAMPLE
    .\WindowsGameExport.ps1 -DryRun -IncludeFilesystemScan

.EXAMPLE
    .\WindowsGameExport.ps1 -IncludeFilesystemScan -Exclude "D:\Media", "D:\Documents", "E:\Backup"
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
    [switch]$IgnoreUnverified,

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

    # Note: We no longer use hardcoded exclusion lists.
    # All detected items will be verified online via Wikipedia/RAWG.
    # This dynamic approach handles any app without manual maintenance.

    try {
        $packages = Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object {
            $pkg = $_

            # Skip system apps and framework packages (these are never games)
            if ($pkg.SignatureKind -eq 'System' -or $pkg.IsFramework -eq $true) {
                return $false
            }

            # Skip if no install location
            if (-not $pkg.InstallLocation) {
                return $false
            }

            # High confidence: XboxGames folder - definitely games
            if ($pkg.InstallLocation -match '\\XboxGames\\') {
                return $true
            }

            # Include all WindowsApps packages - verification will filter non-games
            if ($pkg.InstallLocation -match 'WindowsApps') {
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

    # Directories to exclude - only core system directories
    # Application-specific exclusions are NOT used; verification handles filtering
    $excludeDirs = @(
        'Windows', 'System32', 'SysWOW64', 'WinSxS',
        'Program Files\Common Files', 'Program Files (x86)\Common Files',
        'ProgramData', 'Users', '$Recycle.Bin', 'Recovery',
        'Documents and Settings', 'MSOCache', 'PerfLogs',
        'WindowsApps', 'node_modules', '.git', '.svn'
    )
    # Note: We no longer exclude platform-specific folders (Steam, Epic, etc.)
    # Those platforms are scanned separately, and duplicates are handled by hash

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
        'Electron' = @('chrome_100_percent.pak', 'resources.pak', 'libEGL.dll', 'ffmpeg.dll')
        'Spring' = @('spring.exe', 'springsettings.cfg')  # For games like Beyond All Reason
    }

    # Helper function to check if a folder is a game
    function Test-IsGameFolder {
        param(
            [string]$FolderPath,
            [string]$FolderName
        )

        $result = @{ IsGame = $false; Engine = $null; Exe = $null; Name = $FolderName }

        # Check for game engine indicators
        foreach ($engine in $engineIndicators.Keys) {
            foreach ($indicator in $engineIndicators[$engine]) {
                $found = Get-ChildItem -Path $FolderPath -Filter $indicator -ErrorAction SilentlyContinue |
                    Select-Object -First 1
                if ($found) {
                    $result.IsGame = $true
                    $result.Engine = $engine
                    break
                }
            }
            if ($result.IsGame) { break }
        }

        # Check for executables with matching folder name
        if (-not $result.IsGame) {
            $matchingExe = Get-ChildItem -Path $FolderPath -Filter "*.exe" -ErrorAction SilentlyContinue |
                Where-Object {
                    $baseName = $_.BaseName -replace '[^a-zA-Z0-9]', ''
                    $folderClean = $FolderName -replace '[^a-zA-Z0-9]', ''
                    $baseName -like "*$folderClean*" -or $folderClean -like "*$baseName*"
                } |
                Select-Object -First 1

            if ($matchingExe) {
                $result.IsGame = $true
                $result.Exe = $matchingExe
            }
        }

        # If still not identified, check for common game file patterns
        if (-not $result.IsGame) {
            $exes = Get-ChildItem -Path $FolderPath -Filter "*.exe" -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notmatch '(unins|setup|config|crash|update|launcher|vcredist|dxsetup|dotnet|UnityCrash|redist)' }

            if ($exes.Count -ge 1) {
                # Check for supporting game files
                $hasGameFiles = (Get-ChildItem -Path $FolderPath -Filter "*.dll" -ErrorAction SilentlyContinue | Select-Object -First 1) -or
                               (Test-Path (Join-Path $FolderPath "data")) -or
                               (Test-Path (Join-Path $FolderPath "assets")) -or
                               (Test-Path (Join-Path $FolderPath "content")) -or
                               (Test-Path (Join-Path $FolderPath "Resources")) -or
                               (Test-Path (Join-Path $FolderPath "bin"))

                if ($hasGameFiles) {
                    $result.IsGame = $true
                }
            }
        }

        # Find the best executable
        if ($result.IsGame -and -not $result.Exe) {
            $result.Exe = Get-ChildItem -Path $FolderPath -Filter "*.exe" -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notmatch '(unins|setup|config|crash|update|launcher|vcredist|dxsetup|UnityCrash|redist)' } |
                Sort-Object {
                    $score = 0
                    # Prefer exe with similar name to folder
                    $baseName = $_.BaseName -replace '[^a-zA-Z0-9]', ''
                    $folderClean = $FolderName -replace '[^a-zA-Z0-9]', ''
                    if ($baseName -like "*$folderClean*" -or $folderClean -like "*$baseName*") {
                        $score += 1000
                    }
                    # Prefer larger executables (usually the main game)
                    $score + $_.Length / 1MB
                } -Descending |
                Select-Object -First 1
        }

        # Try to get a better name from the exe
        if ($result.Exe) {
            $exeName = $result.Exe.BaseName -replace '-', ' ' -replace '_', ' '
            # If exe name looks better than folder name, use it
            if ($exeName.Length -gt 3 -and $exeName -notmatch '^(game|app|launch|start|play)$') {
                $result.Name = $exeName
            }
        }

        return $result
    }

    foreach ($drive in $Drives) {
        Write-Verbose "Scanning drive: $drive"

        # First, check root-level folders directly as potential games
        try {
            $rootFolders = Get-ChildItem -Path "$drive\" -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notin $excludeDirs -and $_.Name -notmatch '^[\$\.]' }

            foreach ($folder in $rootFolders) {
                # Skip excluded directories
                $skip = $false
                foreach ($exclude in $excludeDirs) {
                    if ($folder.FullName -like "*$exclude*") {
                        $skip = $true
                        break
                    }
                }
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

                # Check if this root-level folder itself is a game
                $gameCheck = Test-IsGameFolder -FolderPath $folder.FullName -FolderName $folder.Name
                if ($gameCheck.IsGame -and $gameCheck.Exe) {
                    $platform = if ($gameCheck.Engine) { "Standalone-$($gameCheck.Engine)" } else { "Standalone" }
                    $launchCmd = "start `"`" `"$($gameCheck.Exe.FullName)`""
                    $games += Write-GameInfo -Name $gameCheck.Name -Platform $platform -Path $folder.FullName -LaunchCommand $launchCmd
                    Write-Verbose "Found standalone game (root): $($gameCheck.Name) ($platform)"
                }
            }
        } catch {
            Write-Verbose "Error scanning root of $drive`: $_"
        }

        # Get directories that commonly contain games
        $searchRoots = @()
        foreach ($gameDir in $gameDirs) {
            $path = Join-Path $drive $gameDir
            if (Test-Path $path) {
                $searchRoots += $path
            }
        }

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

                    # Use the helper function to check if this is a game
                    $gameCheck = Test-IsGameFolder -FolderPath $folder.FullName -FolderName $folder.Name

                    if ($gameCheck.IsGame -and $gameCheck.Exe) {
                        $platform = if ($gameCheck.Engine) { "Standalone-$($gameCheck.Engine)" } else { "Standalone" }
                        $launchCmd = "start `"`" `"$($gameCheck.Exe.FullName)`""
                        $games += Write-GameInfo -Name $gameCheck.Name -Platform $platform -Path $folder.FullName -LaunchCommand $launchCmd
                        Write-Verbose "Found standalone game: $($gameCheck.Name) ($platform)"
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

function Test-WikipediaSearch {
    # Simple: Search Wikipedia for "[name]" and check if "game" appears prominently
    param([string]$Name)

    $normalized = Get-NormalizedGameName -Name $Name
    $encoded = [System.Web.HttpUtility]::UrlEncode($normalized)

    # Search Wikipedia for the name
    $url = "https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=$encoded&srlimit=3&format=json"

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 10 -ErrorAction Stop

        if ($response.query.search.Count -gt 0) {
            $nameLower = $normalized.ToLower()

            foreach ($result in $response.query.search) {
                $title = $result.title
                $titleLower = $title.ToLower()

                # Check if this result is about our item
                if (-not $titleLower.Contains($nameLower.Split(' ')[0])) {
                    continue
                }

                # Simple check: Does the title or snippet say "game"?
                $snippet = $result.snippet -replace '<[^>]+>', ''
                $combined = "$title $snippet"

                if ($combined -match '\bgame\b') {
                    Write-Verbose "Wikipedia: '$title' mentions game"
                    return $true
                } else {
                    Write-Verbose "Wikipedia: '$title' does NOT mention game"
                    return $false
                }
            }
        }

        return $null
    } catch {
        Write-Verbose "Wikipedia search error: $_"
        return $null
    }
}

function Test-WikipediaGame {
    [CmdletBinding()]
    param(
        [string]$GameName
    )

    $normalized = Get-NormalizedGameName -Name $GameName
    $encoded = [System.Web.HttpUtility]::UrlEncode($normalized)

    # Get both categories and a snippet of the page content
    $url = "https://en.wikipedia.org/w/api.php?action=query&titles=$encoded&prop=categories|extracts&cllimit=50&exintro=1&explaintext=1&exsentences=5&format=json"

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -ErrorAction Stop

        # Check if page exists
        $pages = $response.query.pages
        $pageId = ($pages.PSObject.Properties | Select-Object -First 1).Name

        if ($pageId -eq '-1') {
            # Page not found, try with " (video game)" suffix
            $url2 = "https://en.wikipedia.org/w/api.php?action=query&titles=$encoded%20(video%20game)&prop=categories|extracts&cllimit=50&exintro=1&explaintext=1&exsentences=5&format=json"
            $response = Invoke-RestMethod -Uri $url2 -Method Get -ErrorAction Stop
            $pages = $response.query.pages
            $pageId = ($pages.PSObject.Properties | Select-Object -First 1).Name

            if ($pageId -eq '-1') {
                return $null  # Not found
            }
        }

        $page = $pages.$pageId
        $extract = $page.extract

        # First check if it's explicitly NOT a game (check extract text)
        if ($extract) {
            $nonGamePatterns = @(
                'is a web browser',
                'is an? (?:email|mail) (?:client|application)',
                'is an? operating system',
                'is a Linux distribution',
                'is a company',
                'is a corporation',
                'is a (?:technology|software|hardware) company',
                'is a (?:software|system) utility',
                'is a file manager',
                'is a text editor',
                'is a cloud storage',
                'is a messaging',
                'is a communication',
                'digital distribution platform',
                'app store',
                'is a media player',
                'is a graphics driver',
                'is a control panel'
            )

            foreach ($pattern in $nonGamePatterns) {
                if ($extract -match $pattern) {
                    Write-Verbose "Wikipedia found non-game pattern '$pattern' for '$GameName'"
                    return $false
                }
            }
        }

        # Check categories for video game indicators (most reliable)
        $categories = $page.categories
        if ($categories) {
            $gameCategoryPatterns = @(
                'video games$',
                'Video games$',
                'Windows games',
                'PC games',
                'PlayStation .* games',
                'Xbox .* games',
                'Nintendo .* games',
                'Steam games',
                'multiplayer .*games',
                'single-player .*games',
                'games developed',
                'games by genre'
            )

            foreach ($cat in $categories) {
                foreach ($pattern in $gameCategoryPatterns) {
                    if ($cat.title -match $pattern) {
                        Write-Verbose "Wikipedia found game category '$($cat.title)' for '$GameName'"
                        return $true
                    }
                }
            }
        }

        # Also check the extract/intro text for game-related patterns
        if ($extract) {
            $gamePatterns = @(
                'is a .*video game',
                'is a .*computer game',
                'is an? .*action game',
                'is an? .*adventure game',
                'is an? .*role-playing game',
                'is an? .*shooter',
                'is an? .*platformer',
                'is an? .*strategy game',
                'is an? .*simulation',
                'is an? .*racing game',
                'is an? .*puzzle game',
                'video game developed by',
                'video game published by'
            )

            foreach ($pattern in $gamePatterns) {
                if ($extract -match $pattern) {
                    Write-Verbose "Wikipedia found game pattern '$pattern' for '$GameName'"
                    return $true
                }
            }
        }

        return $null  # Inconclusive
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

        if ($response.count -gt 0 -and $response.results) {
            $result = $response.results[0]
            if (-not $result.name) {
                return $false
            }

            # Check if the name is reasonably similar
            $normalizedLower = $normalized.ToLower()
            $resultLower = $result.name.ToLower()
            $checkLen = [Math]::Min(10, [Math]::Min($normalizedLower.Length, $resultLower.Length))

            if ($checkLen -gt 0) {
                $isSimilar = $resultLower.Contains($normalizedLower.Substring(0, $checkLen)) -or
                             $normalizedLower.Contains($resultLower.Substring(0, $checkLen))
                return $isSimilar
            }

            return $response.count -eq 1
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
        [string]$Platform,
        [string]$RawgApiKey,
        [switch]$SkipVerification
    )

    if ($SkipVerification) {
        return $true
    }

    Write-Verbose "Verifying: $GameName ($Platform)"

    # Trusted gaming platforms - these don't distribute non-games
    # If something is from Steam/Epic/GOG/Battle.net, it's a game
    $trustedPlatforms = @('Steam', 'Epic', 'GOG', 'Battle.net', 'Amazon', 'EA', 'Ubisoft')
    if ($Platform -in $trustedPlatforms) {
        Write-Verbose "Trusted platform ($Platform) - auto-verified"
        return $true
    }

    # Xbox platform - trust if it's from the XboxGames folder (GamePass games)
    # Otherwise verify, as WindowsApps contains many non-games
    if ($Platform -eq 'Xbox') {
        # This will be checked via the Path in the calling code
        # For now, do full verification for Xbox packages
    }

    # Search Wikipedia for "[name] video game" and check results
    $searchResult = Test-WikipediaSearch -Name $GameName
    Start-Sleep -Milliseconds 300

    if ($searchResult -eq $true) {
        return $true
    }
    if ($searchResult -eq $false) {
        return $false
    }

    # Try direct Wikipedia page lookup
    $wikiResult = Test-WikipediaGame -GameName $GameName
    Start-Sleep -Milliseconds 300

    if ($wikiResult -eq $true) {
        return $true
    }
    if ($wikiResult -eq $false) {
        return $false
    }

    # Try RAWG if available
    if ($RawgApiKey) {
        $rawgResult = Test-RawgGame -GameName $GameName -ApiKey $RawgApiKey
        Start-Sleep -Milliseconds 300

        if ($rawgResult -eq $true) {
            return $true
        }
        if ($rawgResult -eq $false) {
            return $false
        }
    }

    # All methods were inconclusive - mark as unverified
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
        [switch]$DryRun,
        [switch]$IgnoreUnverified
    )

    $created = 0
    $updated = 0
    $unchanged = 0
    $skipped = 0

    foreach ($game in $Games) {
        # Skip unverified games if IgnoreUnverified is set
        if ($IgnoreUnverified -and -not $game.Verified) {
            $skipped++
            Write-Host "    [SKIP] " -ForegroundColor DarkYellow -NoNewline
            Write-Host "$($game.Name) " -ForegroundColor DarkGray -NoNewline
            Write-Host "($($game.Platform))" -ForegroundColor DarkGray
            continue
        }

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
            Write-Host "    [UPD]  " -ForegroundColor Yellow -NoNewline
            Write-Host "$($game.Name) " -ForegroundColor White -NoNewline
            Write-Host "($($game.Platform))" -ForegroundColor DarkGray
        } else {
            $created++
            Write-Host "    [NEW]  " -ForegroundColor Green -NoNewline
            Write-Host "$($game.Name) " -ForegroundColor White -NoNewline
            Write-Host "($($game.Platform))" -ForegroundColor DarkGray
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
        Skipped = $skipped
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
}

# Prompt for output directory if not specified (skip for DryRun)
if (-not $OutputDirectory -and -not $DryRun) {
    $OutputDirectory = Read-Host "Enter output directory for .bat files"
    if (-not $OutputDirectory) {
        $OutputDirectory = Join-Path $env:USERPROFILE "GameLaunchers"
    }
}

# Ensure output directory exists
if ($OutputDirectory -and -not (Test-Path $OutputDirectory) -and -not $DryRun) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}

# State file
if (-not $ConfigFile -and $OutputDirectory) {
    $ConfigFile = Join-Path $OutputDirectory "_state.json"
}

# Load existing state
$state = @{}
if ($ConfigFile -and (Test-Path $ConfigFile) -and -not $DryRun) {
    try {
        $stateJson = Get-Content -Path $ConfigFile -Raw | ConvertFrom-Json
        foreach ($prop in $stateJson.PSObject.Properties) {
            $state[$prop.Name] = $prop.Value
        }
    } catch {
        Write-Warning "Could not load state file, starting fresh"
    }
}

# Display header
Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Cyan
Write-Host "                    WINDOWS GAME EXPORT" -ForegroundColor White
Write-Host "  ============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Configuration:" -ForegroundColor DarkGray
Write-Host "    Drives:  $($Drives -join ', ')" -ForegroundColor White
if (-not $DryRun -and $OutputDirectory) {
    Write-Host "    Output:  $OutputDirectory" -ForegroundColor White
}
if ($Exclude) {
    Write-Host "    Exclude: $($Exclude -join ', ')" -ForegroundColor DarkYellow
}
if ($DryRun) {
    Write-Host "    Mode:    DRY RUN (no files will be created)" -ForegroundColor Yellow
}
Write-Host ""

# Collect all games
$allGames = @()

Write-Host "  Scanning platforms..." -ForegroundColor Cyan
Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray

# Helper to format platform results
function Write-PlatformLine {
    param([string]$Name, [int]$Count, [string]$Color = "White")
    $countStr = if ($Count -gt 0) { "$Count games" } else { "-" }
    $countColor = if ($Count -gt 0) { "Green" } else { "DarkGray" }
    Write-Host "    " -NoNewline
    Write-Host "$Name".PadRight(20) -ForegroundColor $Color -NoNewline
    Write-Host $countStr -ForegroundColor $countColor
}

# Steam
$steamGames = Get-SteamGames -Drives $Drives -Verbose:$VerbosePreference
Write-PlatformLine -Name "Steam" -Count $steamGames.Count -Color "Cyan"
$allGames += $steamGames

# Epic
$epicGames = Get-EpicGames -Verbose:$VerbosePreference
Write-PlatformLine -Name "Epic Games" -Count $epicGames.Count -Color "Yellow"
$allGames += $epicGames

# GOG
$gogGames = Get-GOGGames -Drives $Drives -Verbose:$VerbosePreference
Write-PlatformLine -Name "GOG Galaxy" -Count $gogGames.Count -Color "Magenta"
$allGames += $gogGames

# Xbox
$xboxGames = Get-XboxGames -Verbose:$VerbosePreference
Write-PlatformLine -Name "Xbox / MS Store" -Count $xboxGames.Count -Color "Green"
$allGames += $xboxGames

# Amazon
$amazonGames = Get-AmazonGames -Verbose:$VerbosePreference
Write-PlatformLine -Name "Amazon Games" -Count $amazonGames.Count -Color "DarkYellow"
$allGames += $amazonGames

# EA
$eaGames = Get-EAGames -Verbose:$VerbosePreference
Write-PlatformLine -Name "EA / Origin" -Count $eaGames.Count -Color "Red"
$allGames += $eaGames

# Ubisoft
$ubisoftGames = Get-UbisoftGames -Verbose:$VerbosePreference
Write-PlatformLine -Name "Ubisoft Connect" -Count $ubisoftGames.Count -Color "DarkCyan"
$allGames += $ubisoftGames

# Battle.net
$battleNetGames = Get-BattleNetGames -Verbose:$VerbosePreference
Write-PlatformLine -Name "Battle.net" -Count $battleNetGames.Count -Color "Blue"
$allGames += $battleNetGames

# Filesystem scan (optional)
if ($IncludeFilesystemScan) {
    $fsGames = Get-FilesystemGames -Drives $Drives -UserExcludes $Exclude -Verbose:$VerbosePreference
    Write-PlatformLine -Name "Filesystem Scan" -Count $fsGames.Count -Color "Gray"
    $allGames += $fsGames
}

Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "    TOTAL" -ForegroundColor White -NoNewline
Write-Host "               $($allGames.Count) games" -ForegroundColor Cyan
Write-Host ""

# DryRun mode - just output the list
if ($DryRun) {
    Write-Host "  Detected Games:" -ForegroundColor Cyan
    Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray

    $sortedGames = $allGames | Sort-Object Platform, Name
    $currentPlatform = ""

    foreach ($game in $sortedGames) {
        if ($game.Platform -ne $currentPlatform) {
            $currentPlatform = $game.Platform
            Write-Host ""
            Write-Host "    [$currentPlatform]" -ForegroundColor Yellow
        }
        Write-Host "      > $($game.Name)" -ForegroundColor White
        Write-Host "        $($game.Path)" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Green
    Write-Host "    Dry run complete. No files were created." -ForegroundColor Yellow
    Write-Host "  ============================================================" -ForegroundColor Green
    Write-Host ""
    exit 0
}

# Verify games
if (-not $SkipVerification -and $allGames.Count -gt 0) {
    Write-Host "  Verifying games (Wikipedia/RAWG)..." -ForegroundColor Cyan
    Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
    $verified = 0
    $unverified = 0

    foreach ($game in $allGames) {
        # Xbox games from XboxGames folder are trusted (Game Pass games)
        if ($game.Platform -eq 'Xbox' -and $game.Path -match '\\XboxGames\\') {
            $isVerified = $true
            Write-Verbose "Xbox Game Pass (XboxGames folder) - auto-verified"
        } else {
            $isVerified = Confirm-IsGame -GameName $game.Name -Platform $game.Platform -RawgApiKey $RawgApiKey -SkipVerification:$SkipVerification
        }
        $game.Verified = $isVerified

        if ($isVerified) {
            $verified++
            Write-Host "    [OK] " -ForegroundColor Green -NoNewline
            Write-Host "$($game.Name)" -ForegroundColor White
        } else {
            $unverified++
            Write-Host "    [??] " -ForegroundColor Yellow -NoNewline
            Write-Host "$($game.Name)" -ForegroundColor DarkGray
        }
    }

    Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "    Verified: $verified  |  Unverified: $unverified" -ForegroundColor Cyan
    Write-Host ""
} else {
    # Mark all as verified if skipping verification
    foreach ($game in $allGames) {
        $game.Verified = $true
    }
}

# Generate launchers
Write-Host "  Generating launcher files..." -ForegroundColor Cyan
Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
$results = Update-GameLaunchers -Games $allGames -OutputDirectory $OutputDirectory -State $state -DryRun:$DryRun -IgnoreUnverified:$IgnoreUnverified

# Save state
if (-not $DryRun) {
    $state | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigFile
}

# Summary
Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Green
Write-Host "                         COMPLETE" -ForegroundColor White
Write-Host "  ============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "    Created:   " -ForegroundColor Gray -NoNewline
Write-Host "$($results.Created) new launchers" -ForegroundColor Cyan
Write-Host "    Updated:   " -ForegroundColor Gray -NoNewline
Write-Host "$($results.Updated) launchers" -ForegroundColor Yellow
Write-Host "    Unchanged: " -ForegroundColor Gray -NoNewline
Write-Host "$($results.Unchanged) launchers" -ForegroundColor DarkGray
if ($results.Skipped -gt 0) {
    Write-Host "    Skipped:   " -ForegroundColor Gray -NoNewline
    Write-Host "$($results.Skipped) unverified" -ForegroundColor DarkYellow
}
Write-Host ""
Write-Host "    Output: $OutputDirectory" -ForegroundColor White
Write-Host ""

#endregion
