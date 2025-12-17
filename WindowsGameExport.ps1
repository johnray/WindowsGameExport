<#
.SYNOPSIS
    Scans for installed games across multiple platforms and generates .bat launcher files.

.DESCRIPTION
    This script detects games from Steam, Epic Games, GOG, Xbox Game Pass, Amazon Games,
    EA App/Origin, Ubisoft Connect, Battle.net, and optionally performs a filesystem scan
    for standalone games. It verifies detected items are games using Wikipedia, IGN, and
    RAWG APIs, then generates .bat launcher files for each game.

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

.PARAMETER IncludeList
    Path to a text file containing game names to always include (one per line).
    These games bypass verification and are always marked as verified.
    Supports wildcards (*) for pattern matching.

.PARAMETER ExcludeList
    Path to a text file containing game names to always exclude (one per line).
    These games are skipped entirely and no launchers are created for them.
    Supports wildcards (*) for pattern matching.

.EXAMPLE
    .\WindowsGameExport.ps1 -Drives "C:", "D:" -OutputDirectory "C:\GameLaunchers"

.EXAMPLE
    .\WindowsGameExport.ps1 -DryRun -IncludeFilesystemScan

.EXAMPLE
    .\WindowsGameExport.ps1 -IncludeFilesystemScan -Exclude "D:\Media", "D:\Documents", "E:\Backup"

.EXAMPLE
    .\WindowsGameExport.ps1 -OutputDirectory "C:\GameLaunchers" -IncludeList "_include.txt" -ExcludeList "_exclude.txt"
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
    [string[]]$Exclude,

    [Parameter()]
    [string]$IncludeList,

    [Parameter()]
    [string]$ExcludeList
)

#region Welcome Screen

function Show-WelcomeScreen {
    <#
    .SYNOPSIS
        Display an interactive welcome screen when script is run without parameters
    #>

    Clear-Host

    # ASCII Art Banner (ASCII-safe)
    Write-Host ""
    Write-Host "  __        ___           _                    " -ForegroundColor Cyan
    Write-Host "  \ \      / (_)_ __   __| | _____      _____  " -ForegroundColor Cyan
    Write-Host "   \ \ /\ / /| | '_ \ / _`` |/ _ \ \ /\ / / __| " -ForegroundColor Cyan
    Write-Host "    \ V  V / | | | | | (_| | (_) \ V  V /\__ \ " -ForegroundColor Cyan
    Write-Host "     \_/\_/  |_|_| |_|\__,_|\___/ \_/\_/ |___/ " -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    ____                         _____                       _   " -ForegroundColor Magenta
    Write-Host "   / ___| __ _ _ __ ___   ___   | ____|_  ___ __   ___  _ __| |_ " -ForegroundColor Magenta
    Write-Host "  | |  _ / _`` | '_ `` _ \ / _ \  |  _| \ \/ / '_ \ / _ \| '__| __|" -ForegroundColor Magenta
    Write-Host "  | |_| | (_| | | | | | |  __/  | |___ >  <| |_) | (_) | |  | |_ " -ForegroundColor Magenta
    Write-Host "   \____|\__,_|_| |_| |_|\___|  |_____/_/\_\ .__/ \___/|_|   \__|" -ForegroundColor Magenta
    Write-Host "                                           |_|                   " -ForegroundColor Magenta
    Write-Host ""

    # Tagline
    Write-Host "  +==================================================================+" -ForegroundColor Magenta
    Write-Host "  |   Detect games across all platforms & generate launcher files   |" -ForegroundColor Magenta
    Write-Host "  +==================================================================+" -ForegroundColor Magenta
    Write-Host ""

    # Supported Platforms
    Write-Host "  +------------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  SUPPORTED PLATFORMS                                             |" -ForegroundColor Yellow
    Write-Host "  |                                                                  |" -ForegroundColor DarkGray
    Write-Host "  |    * Steam              * Xbox Game Pass / MS Store              |" -ForegroundColor White
    Write-Host "  |    * Epic Games Store   * Amazon Games                           |" -ForegroundColor White
    Write-Host "  |    * GOG Galaxy         * EA App / Origin                        |" -ForegroundColor White
    Write-Host "  |    * Ubisoft Connect    * Battle.net                             |" -ForegroundColor White
    Write-Host "  |    * Standalone Games (filesystem scan with engine detection)    |" -ForegroundColor White
    Write-Host "  |                                                                  |" -ForegroundColor DarkGray
    Write-Host "  +------------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""

    # Quick Start
    Write-Host "  +------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |  QUICK START                                                     |" -ForegroundColor Yellow
    Write-Host "  +------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Preview what games would be found (no files created):" -ForegroundColor DarkGray
    Write-Host '    .\WindowsGameExport.ps1 -DryRun' -ForegroundColor Green
    Write-Host ""
    Write-Host "  Create launcher files in a directory:" -ForegroundColor DarkGray
    Write-Host '    .\WindowsGameExport.ps1 -OutputDirectory "C:\GameLaunchers"' -ForegroundColor Green
    Write-Host ""
    Write-Host "  Scan specific drives only:" -ForegroundColor DarkGray
    Write-Host '    .\WindowsGameExport.ps1 -Drives "D:", "E:" -OutputDirectory "D:\Launchers"' -ForegroundColor Green
    Write-Host ""
    Write-Host "  Include standalone games (slower, more thorough):" -ForegroundColor DarkGray
    Write-Host '    .\WindowsGameExport.ps1 -IncludeFilesystemScan -OutputDirectory "C:\Launchers"' -ForegroundColor Green
    Write-Host ""
    Write-Host "  Skip online verification (faster, trust all detected):" -ForegroundColor DarkGray
    Write-Host '    .\WindowsGameExport.ps1 -SkipVerification -OutputDirectory "C:\Launchers"' -ForegroundColor Green
    Write-Host ""

    # Parameters
    Write-Host "  +------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |  PARAMETERS                                                      |" -ForegroundColor Yellow
    Write-Host "  +------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    -OutputDirectory        Where to create .bat launcher files" -ForegroundColor White
    Write-Host "    -Drives                 Specific drives to scan (default: all fixed)" -ForegroundColor DarkGray
    Write-Host "    -DryRun                 Preview without creating files" -ForegroundColor DarkGray
    Write-Host "    -IncludeFilesystemScan  Scan for standalone games" -ForegroundColor DarkGray
    Write-Host "    -SkipVerification       Skip Wikipedia/IGN verification" -ForegroundColor DarkGray
    Write-Host "    -IgnoreUnverified       Don't create launchers for unverified items" -ForegroundColor DarkGray
    Write-Host "    -Exclude                Directories to skip during filesystem scan" -ForegroundColor DarkGray
    Write-Host "    -IncludeList            Text file of game names to always include" -ForegroundColor DarkGray
    Write-Host "    -ExcludeList            Text file of game names to always exclude" -ForegroundColor DarkGray
    Write-Host "    -RawgApiKey             Optional RAWG API key for better verification" -ForegroundColor DarkGray
    Write-Host "    -ConfigFile             Custom state file path" -ForegroundColor DarkGray
    Write-Host ""

    # Verification info
    Write-Host "  +------------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  GAME VERIFICATION                                               |" -ForegroundColor Yellow
    Write-Host "  |                                                                  |" -ForegroundColor DarkGray
    Write-Host "  |  Games from trusted platforms (Steam, Epic, GOG, etc.) are       |" -ForegroundColor White
    Write-Host "  |  auto-verified. Xbox/MS Store items are verified via:            |" -ForegroundColor White
    Write-Host "  |                                                                  |" -ForegroundColor DarkGray
    Write-Host "  |    1. Wikipedia API (searches for video game articles)           |" -ForegroundColor White
    Write-Host "  |    2. IGN Game Database (checks for game pages)                  |" -ForegroundColor White
    Write-Host "  |    3. RAWG API (optional, requires free API key)                 |" -ForegroundColor White
    Write-Host "  |                                                                  |" -ForegroundColor DarkGray
    Write-Host "  |  Unverified items go to an 'Unverified' subfolder.               |" -ForegroundColor White
    Write-Host "  |                                                                  |" -ForegroundColor DarkGray
    Write-Host "  +------------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""

    # Footer
    Write-Host "  ====================================================================" -ForegroundColor DarkGray
    Write-Host "  For help: Get-Help .\WindowsGameExport.ps1 -Full" -ForegroundColor DarkGray
    Write-Host "  GitHub: https://github.com/johnray/WindowsGameExport" -ForegroundColor DarkGray
    Write-Host "  ====================================================================" -ForegroundColor DarkGray
    Write-Host ""
}

# Check if script was run without meaningful parameters - show welcome screen
$hasAction = $OutputDirectory -or $DryRun -or $PSBoundParameters.ContainsKey('Drives')
if (-not $hasAction) {
    Show-WelcomeScreen
    exit 0
}

#endregion

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

function Read-GameList {
    <#
    .SYNOPSIS
        Read a list of game names from a text file
    .DESCRIPTION
        Reads a text file containing game names (one per line).
        Supports comments (lines starting with #) and wildcards (*).
        Empty lines are ignored.
    #>
    param(
        [string]$FilePath
    )

    if (-not $FilePath -or -not (Test-Path $FilePath)) {
        return @()
    }

    $patterns = @()
    try {
        $lines = Get-Content -Path $FilePath -ErrorAction Stop
        foreach ($line in $lines) {
            $line = $line.Trim()
            # Skip empty lines and comments
            if ($line -and -not $line.StartsWith('#')) {
                $patterns += $line
            }
        }
        Write-Verbose "Loaded $($patterns.Count) entries from $FilePath"
    } catch {
        Write-Warning "Could not read list file '$FilePath': $_"
    }

    return $patterns
}

function Test-GameMatchesList {
    <#
    .SYNOPSIS
        Check if a game name matches any pattern in a list
    .DESCRIPTION
        Compares game name against patterns. Supports wildcards (*).
        Matching is case-insensitive.
    #>
    param(
        [string]$GameName,
        [string[]]$Patterns
    )

    if (-not $Patterns -or $Patterns.Count -eq 0) {
        return $false
    }

    $nameLower = $GameName.ToLower()

    foreach ($pattern in $Patterns) {
        $patternLower = $pattern.ToLower()

        # Convert wildcard pattern to regex
        if ($pattern.Contains('*')) {
            $regexPattern = '^' + [regex]::Escape($patternLower).Replace('\*', '.*') + '$'
            if ($nameLower -match $regexPattern) {
                return $true
            }
        } else {
            # Exact match (case-insensitive)
            if ($nameLower -eq $patternLower) {
                return $true
            }
        }
    }

    return $false
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
                # Get display name and App ID from manifest
                $manifestPath = Join-Path $pkg.InstallLocation "AppxManifest.xml"
                $displayName = $null
                $appId = "App"  # Default fallback

                if (Test-Path $manifestPath) {
                    try {
                        [xml]$manifest = Get-Content $manifestPath -ErrorAction SilentlyContinue
                        $rawDisplayName = $manifest.Package.Properties.DisplayName
                        if ($rawDisplayName -and $rawDisplayName -notmatch '^ms-resource:') {
                            $displayName = $rawDisplayName
                        }
                        # Get the actual Application ID from the manifest
                        $appElement = $manifest.Package.Applications.Application
                        if ($appElement) {
                            # Handle both single app and array of apps
                            if ($appElement -is [array]) {
                                $appId = $appElement[0].Id
                            } else {
                                $appId = $appElement.Id
                            }
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
                    $launchCmd = "start `"`" shell:AppsFolder\$($pkg.PackageFamilyName)!$appId"
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
                        $appElement = $manifest.Package.Applications.Application
                        $appId = if ($appElement -is [array]) { $appElement[0].Id } else { $appElement.Id }

                        if ($displayName -and $displayName.Length -gt 2) {
                            # Look up the actual PackageFamilyName from Get-AppxPackage
                            # The publisher hash is cryptographically derived - we can't compute it
                            $installedPkg = Get-AppxPackage -Name $packageName -ErrorAction SilentlyContinue
                            if ($installedPkg) {
                                $launchCmd = "start `"`" shell:AppsFolder\$($installedPkg.PackageFamilyName)!$appId"
                                $games += Write-GameInfo -Name $displayName -Platform "Xbox" -Path $gameFolder.FullName -LaunchCommand $launchCmd
                                Write-Verbose "Found Xbox game (XboxGames folder): $displayName"
                            } else {
                                Write-Verbose "Could not find installed package for: $displayName"
                            }
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
        'wow_classic_era' = 'World of Warcraft Classic Era'
        'd3' = 'Diablo III'
        'd4' = 'Diablo IV'
        'd2r' = 'Diablo II Resurrected'
        'hs' = 'Hearthstone'
        'hero' = 'Heroes of the Storm'
        'pro' = 'Overwatch 2'
        's1' = 'StarCraft Remastered'
        's2' = 'StarCraft II'
        'w3' = 'Warcraft III Reforged'
        'wlby' = 'Crash Bandicoot 4'
        'viper' = 'Call of Duty Black Ops Cold War'
        'odin' = 'Call of Duty Modern Warfare'
        'lazr' = 'Call of Duty MW2 Campaign Remastered'
        'zeus' = 'Call of Duty Black Ops 4'
        'fore' = 'Call of Duty Vanguard'
        'auks' = 'Call of Duty Modern Warfare II'
        'spot' = 'Call of Duty Modern Warfare III'
        'cods' = 'Call of Duty Warzone'
        'rtro' = 'Blizzard Arcade Collection'
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
    # Search Wikipedia for an article about this item
    # Then fetch that article's intro and check if "game" appears in first 3 sentences
    param([string]$Name)

    $normalized = Get-NormalizedGameName -Name $Name
    $nameLower = $normalized.ToLower()

    # Helper to check if article intro describes this AS a video game
    # Returns $true if it's a game, $false if explicitly NOT a game, $null if inconclusive
    function Test-ArticleIsGame {
        param([string]$Title)

        try {
            $encodedTitle = [System.Web.HttpUtility]::UrlEncode($Title)
            # Get the first 5 sentences of the article
            $url = "https://en.wikipedia.org/w/api.php?action=query&titles=$encodedTitle&prop=extracts&exintro=1&explaintext=1&exsentences=5&format=json"
            $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 10 -ErrorAction Stop

            $pages = $response.query.pages
            $pageId = ($pages.PSObject.Properties | Select-Object -First 1).Name
            if ($pageId -eq '-1') { return $null }

            $extract = $pages.$pageId.extract
            if (-not $extract) { return $null }

            $extractLower = $extract.ToLower()

            # First check: Does "game" appear at all in the first 5 sentences?
            if ($extractLower -notmatch '\bgame\b') {
                # No mention of "game" - not a video game
                return $null
            }

            # NEGATIVE patterns - these are game-RELATED but NOT games themselves
            # Check these FIRST to avoid false positives
            if ($extractLower -match 'game console' -or
                $extractLower -match 'gaming brand' -or
                $extractLower -match 'gaming service' -or
                $extractLower -match 'gaming platform' -or
                $extractLower -match 'video gaming brand' -or
                $extractLower -match 'game streaming' -or
                $extractLower -match 'game controller' -or
                $extractLower -match 'game development' -or
                $extractLower -match 'game engine') {
                Write-Verbose "Wikipedia: '$Title' is game-related but NOT a game (console/brand/service)"
                return $false
            }

            # POSITIVE patterns - these describe something AS a video game
            if ($extractLower -match '\bis a[n]?\s+\d*\s*\w*\s*video game\b' -or    # "is a 2024 survival video game"
                $extractLower -match '\bis a[n]?\s+\w+\s+game\b' -or                 # "is a puzzle game"
                $extractLower -match 'video game developed' -or
                $extractLower -match 'video game published' -or
                $extractLower -match 'developed by .+ and published' -or
                $extractLower -match 'roguelike' -or
                $extractLower -match 'roguelite' -or
                $extractLower -match 'platformer' -or
                $extractLower -match 'first-person shooter' -or
                $extractLower -match 'third-person shooter' -or
                $extractLower -match 'action-adventure game' -or
                $extractLower -match 'role-playing game' -or
                $extractLower -match 'survival horror' -or
                $extractLower -match 'open world' -or
                $extractLower -match 'driving game' -or
                $extractLower -match 'simulation game' -or
                $extractLower -match 'indie game') {
                Write-Verbose "Wikipedia: '$Title' intro describes a video game"
                return $true
            }

            return $null
        } catch {
            return $null
        }
    }

    try {
        # Strategy 1: Search for just the name, find best matching article
        $encoded1 = [System.Web.HttpUtility]::UrlEncode($normalized)
        $url1 = "https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=$encoded1&srlimit=5&format=json"
        $response1 = Invoke-RestMethod -Uri $url1 -Method Get -TimeoutSec 10 -ErrorAction Stop

        if ($response1.query.search.Count -gt 0) {
            foreach ($result in $response1.query.search) {
                $title = $result.title
                $titleLower = $title.ToLower()

                # Get base title without disambiguation suffix like "(video game)"
                $baseTitle = ($title -replace '\s*\([^)]+\)\s*$', '').ToLower().Trim()

                # Title must closely match our search term
                # Either: title starts with our name, OR our name starts with title, OR exact match
                $isRelevant = $baseTitle -eq $nameLower -or
                              $baseTitle.StartsWith($nameLower) -or
                              $nameLower.StartsWith($baseTitle) -or
                              ($baseTitle.Split(' ')[0] -eq $nameLower.Split(' ')[0] -and $nameLower.Split(' ')[0].Length -ge 4)

                if (-not $isRelevant) { continue }

                # If title explicitly says "(video game)" - strong match
                if ($title -match '\(video game\)' -or $title -match '\(game\)') {
                    Write-Verbose "Wikipedia: '$title' has (video game) disambiguation"
                    return $true
                }

                # Fetch article and check intro
                $check = Test-ArticleIsGame -Title $title
                if ($null -ne $check) { return $check }
            }
        }

        # Strategy 2: Search with "video game" appended
        Start-Sleep -Milliseconds 200
        $encoded2 = [System.Web.HttpUtility]::UrlEncode("$normalized video game")
        $url2 = "https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=$encoded2&srlimit=3&format=json"
        $response2 = Invoke-RestMethod -Uri $url2 -Method Get -TimeoutSec 10 -ErrorAction Stop

        if ($response2.query.search.Count -gt 0) {
            foreach ($result in $response2.query.search) {
                $title = $result.title

                # Get base title without disambiguation suffix
                $baseTitle = ($title -replace '\s*\([^)]+\)\s*$', '').ToLower().Trim()

                # Title must closely match our search term
                $isRelevant = $baseTitle -eq $nameLower -or
                              $baseTitle.StartsWith($nameLower) -or
                              $nameLower.StartsWith($baseTitle) -or
                              ($baseTitle.Split(' ')[0] -eq $nameLower.Split(' ')[0] -and $nameLower.Split(' ')[0].Length -ge 4)

                if (-not $isRelevant) { continue }

                # If title explicitly says "(video game)" - strong match
                if ($title -match '\(video game\)' -or $title -match '\(game\)') {
                    Write-Verbose "Wikipedia: Found matching game article '$title'"
                    return $true
                }

                # Fetch article and check intro
                $check = Test-ArticleIsGame -Title $title
                if ($null -ne $check) { return $check }
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
                'is an? .*simulation game',
                'is an? .*survival game',
                'is an? .*horror game',
                'is an? .*racing game',
                'is an? .*puzzle game',
                'is an? .*roguelike',
                'is an? .*roguelite',
                'is an? .*sandbox',
                'is an? .*open world',
                'is an? .*indie game',
                'video game developed by',
                'video game published by',
                'game developed by',
                'developed and published.*game',
                'available on.*Steam',
                'available on.*PlayStation',
                'available on.*Xbox',
                'available on.*Nintendo'
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

function Test-IGNGame {
    # Check if game exists on IGN's game database
    # IGN only has pages in /games/ for actual video games
    [CmdletBinding()]
    param(
        [string]$GameName
    )

    $normalized = Get-NormalizedGameName -Name $GameName

    # Convert game name to URL slug (lowercase, replace spaces with hyphens, remove special chars)
    $slug = $normalized.ToLower() -replace "[^a-z0-9\s-]", "" -replace "\s+", "-"
    $url = "https://www.ign.com/games/$slug"

    try {
        # Use HttpWebRequest to check for redirects
        $request = [System.Net.HttpWebRequest]::Create($url)
        $request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        $request.AllowAutoRedirect = $false
        $request.Timeout = 10000

        $response = $request.GetResponse()
        $statusCode = [int]$response.StatusCode

        # If redirected, check if it's a close match (IGN sometimes adds publisher suffix)
        if ($statusCode -eq 301 -or $statusCode -eq 302) {
            $redirectUrl = $response.Headers["Location"]
            $response.Close()

            # Only follow redirect if the slug is nearly identical
            # Allow: "game" -> "game-1", "game-pc", "game-2024"
            # Reject: "bridge" -> "bridge-activision" (different game)
            if ($redirectUrl -and $redirectUrl -match "/games/([^/]+)") {
                $redirectSlug = $Matches[1]
                # Must be exact match, or only differ by short numeric/platform suffix
                $isCloseMatch = $redirectSlug -eq $slug -or
                                $redirectSlug -match "^$([regex]::Escape($slug))(-\d+|-pc|-ps\d*|-xbox.*|-switch|-wii.*)?$"
                if (-not $isCloseMatch) {
                    Write-Verbose "IGN: Redirect to different game ($redirectSlug) - skipping"
                    return $null
                }
                $url = "https://www.ign.com$redirectUrl"
            }
        } else {
            $response.Close()
        }

        # Now fetch the actual page content
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        $content = $webClient.DownloadString($url)

        # IGN game pages have og:type="Game" in their meta tags
        if ($content -match 'og:type.*content="Game"') {
            Write-Verbose "IGN: Found game page for '$GameName'"
            return $true
        }

        return $null
    } catch [System.Net.WebException] {
        # 404 means game not found on IGN
        return $null
    } catch {
        Write-Verbose "IGN error for '$GameName': $_"
        return $null
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

    # Detect garbled UWP package names (like "W eb Me di aE xt en si on s")
    # These have many 1-2 character "words" from mangled package names
    $words = $GameName -split '\s+'
    if ($words.Count -gt 3) {
        $shortWords = ($words | Where-Object { $_.Length -le 2 }).Count
        $ratio = $shortWords / $words.Count
        if ($ratio -gt 0.4) {
            Write-Verbose "Garbled package name detected (ratio=$ratio) - not a game"
            return $false
        }
    }

    # Detect codec/extension packages by name pattern
    # These are media extensions, not games
    $extensionPatterns = @(
        'Extension$',
        'Extensions$',
        'Video Extension',
        'Image Extension',
        'Codec$',
        'Video Codec',
        'Audio Codec',
        'Media Extension',
        'Web Extension',
        'VP9',
        'HEVC',
        'AV1',
        'HEIF',
        'MPEG',
        'AVC Encoder',
        'Webp Image',
        'Raw Image'
    )
    foreach ($pattern in $extensionPatterns) {
        if ($GameName -match $pattern) {
            Write-Verbose "Extension/codec pattern detected ($pattern) - not a game"
            return $false
        }
    }

    # Detect Microsoft/Windows service apps by pattern
    $servicePatterns = @(
        '^Bing',           # BingNews, BingWeather, BingSearch
        'Subsystem',       # Windows Subsystem for Linux
        'Cross Device',
        'Speech To Text',
        'Identity Provider',
        '^Zune'            # ZuneMusic, ZuneVideo
    )
    foreach ($pattern in $servicePatterns) {
        if ($GameName -match $pattern) {
            Write-Verbose "Windows service pattern detected ($pattern) - not a game"
            return $false
        }
    }

    # Windows built-in apps that are definitely NOT games
    # These are bundled with Windows and checking Wikipedia for them is pointless
    $windowsBuiltInApps = @(
        'Microsoft Edge',
        'Microsoft Teams',
        'Microsoft Store',
        'Microsoft Photos',
        'Microsoft Paint',
        'Microsoft 365 Copilot',
        'Microsoft Sticky Notes',
        'Windows Terminal',
        'Windows Photos',
        'Windows Camera',
        'Windows Calculator',
        'Windows Alarms',
        'Windows Notepad',
        'Windows Sound Recorder',
        'Windows Feedback Hub',
        'Windows Web Experience Pack',
        'Widgets Platform Runtime',
        'Xbox TCUI',
        'Xbox',
        'Game Bar',
        'Paint',
        'Photos',
        'Calculator',
        'Camera',
        'Notepad',
        'OneDrive',
        'Outlook for Windows',
        'iCloud',
        'Ubuntu',
        'NVIDIA Control Panel',
        'AMD Radeon Software',
        'Realtek Audio Control',
        'MSI Center',
        'Clipchamp',
        'Todos',
        'Get Help',
        'Snipping Tool',
        'Screen Sketch',
        'Your Phone',
        'Phone Link',
        'Drivers',
        'Driver',
        'Control Panel',
        'Settings',
        'Device Manager',
        'Keeper',
        'Power Automate',
        'Quick Assist',
        'Dev Home',
        'Ink.Handwriting',
        'Gaming Services',
        'Start Experiences',
        'Store Purchase',
        'Desktop App Installer',
        'Identity Provider'
    )
    $normalizedName = $GameName.ToLower().Trim()
    foreach ($app in $windowsBuiltInApps) {
        if ($normalizedName -eq $app.ToLower() -or $normalizedName -like "*$($app.ToLower())*") {
            Write-Verbose "Known Windows built-in app: $GameName - not a game"
            return $false
        }
    }

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

    # Try IGN game database
    $ignResult = Test-IGNGame -GameName $GameName
    Start-Sleep -Milliseconds 300

    if ($ignResult -eq $true) {
        return $true
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

    # Handle empty OutputDirectory in DryRun mode
    if (-not $OutputDirectory) {
        if ($DryRun) {
            $displayPath = if ($Game.Verified) { "<output>\" } else { "<output>\Unverified\" }
            Write-Host "Would create: $displayPath$fileName" -ForegroundColor Cyan
            return $fileName
        }
        throw "OutputDirectory is required when not in DryRun mode"
    }

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
    try {
        New-Item -Path $OutputDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Error "Failed to create output directory '$OutputDirectory': $_"
        exit 1
    }
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

# Load include/exclude lists
$includePatterns = Read-GameList -FilePath $IncludeList
$excludePatterns = Read-GameList -FilePath $ExcludeList

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
if ($includePatterns.Count -gt 0) {
    Write-Host "    Include List: $($includePatterns.Count) patterns from $IncludeList" -ForegroundColor Green
}
if ($excludePatterns.Count -gt 0) {
    Write-Host "    Exclude List: $($excludePatterns.Count) patterns from $ExcludeList" -ForegroundColor Yellow
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
    $countStr = if ($Count -gt 0) { "$Count potential" } else { "-" }
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

# Deduplicate games (same name from multiple sources)
$seenNames = @{}
$uniqueGames = @()
$duplicatesRemoved = 0
foreach ($game in $allGames) {
    $normalizedName = $game.Name.ToLower().Trim()
    if ($seenNames.ContainsKey($normalizedName)) {
        $duplicatesRemoved++
        Write-Verbose "Duplicate removed: $($game.Name) ($($game.Platform)) - already have from $($seenNames[$normalizedName])"
    } else {
        $seenNames[$normalizedName] = $game.Platform
        $uniqueGames += $game
    }
}
$allGames = $uniqueGames

# Apply exclude list - remove games matching exclude patterns
$excludedCount = 0
if ($excludePatterns.Count -gt 0) {
    $filteredGames = @()
    foreach ($game in $allGames) {
        if (Test-GameMatchesList -GameName $game.Name -Patterns $excludePatterns) {
            $excludedCount++
            Write-Verbose "Excluded by list: $($game.Name)"
        } else {
            $filteredGames += $game
        }
    }
    $allGames = $filteredGames
}

Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "    TOTAL" -ForegroundColor White -NoNewline
$totalMsg = "$($allGames.Count) potential games"
if ($duplicatesRemoved -gt 0 -or $excludedCount -gt 0) {
    $notes = @()
    if ($duplicatesRemoved -gt 0) { $notes += "$duplicatesRemoved duplicates" }
    if ($excludedCount -gt 0) { $notes += "$excludedCount excluded" }
    $totalMsg += " ($($notes -join ', ') removed)"
}
Write-Host "               $totalMsg" -ForegroundColor Cyan
Write-Host ""

# DryRun mode still runs verification to show what would be kept/filtered

# Verify games
if (-not $SkipVerification -and $allGames.Count -gt 0) {
    Write-Host "  Verifying games (Wikipedia/IGN/RAWG)..." -ForegroundColor Cyan
    Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
    $verified = 0
    $unverified = 0
    $currentIndex = 0
    $totalGames = $allGames.Count

    foreach ($game in $allGames) {
        $currentIndex++
        $includeListMatch = $false

        # Check include list first - games in include list are auto-verified
        if ($includePatterns.Count -gt 0 -and (Test-GameMatchesList -GameName $game.Name -Patterns $includePatterns)) {
            $isVerified = $true
            $includeListMatch = $true
            Write-Verbose "Include list match - auto-verified: $($game.Name)"
        }
        # Xbox games from XboxGames folder are trusted (Game Pass games)
        elseif ($game.Platform -eq 'Xbox' -and $game.Path -match '\\XboxGames\\') {
            $isVerified = $true
            Write-Verbose "Xbox Game Pass (XboxGames folder) - auto-verified"
        } else {
            $isVerified = Confirm-IsGame -GameName $game.Name -Platform $game.Platform -RawgApiKey $RawgApiKey -SkipVerification:$SkipVerification
        }
        $game.Verified = $isVerified

        # Show progress counter
        $progress = "[$currentIndex/$totalGames]".PadRight(10)

        if ($isVerified) {
            $verified++
            Write-Host "    $progress" -ForegroundColor DarkGray -NoNewline
            if ($includeListMatch) {
                Write-Host "[+L] " -ForegroundColor Cyan -NoNewline
            } else {
                Write-Host "[OK] " -ForegroundColor Green -NoNewline
            }
            Write-Host "$($game.Name)" -ForegroundColor White
        } else {
            $unverified++
            Write-Host "    $progress" -ForegroundColor DarkGray -NoNewline
            Write-Host "[??] " -ForegroundColor Yellow -NoNewline
            # Try strikethrough with ANSI escape code (may not work in all terminals)
            $esc = [char]27
            Write-Host "$esc[9m$($game.Name)$esc[0m" -ForegroundColor DarkGray
        }
    }

    Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "    Verified: $verified  |  Unverified: $unverified" -ForegroundColor Cyan
    Write-Host ""
} elseif ($SkipVerification -and $allGames.Count -gt 0) {
    # Mark all as verified if skipping verification
    Write-Host "  Verification skipped - all $($allGames.Count) games marked as verified" -ForegroundColor Yellow
    Write-Host ""
    foreach ($game in $allGames) {
        $game.Verified = $true
    }
} else {
    # No games to verify
    foreach ($game in $allGames) {
        $game.Verified = $true
    }
}

# Generate launchers
Write-Host "  Generating launcher files..." -ForegroundColor Cyan
Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
$results = Update-GameLaunchers -Games $allGames -OutputDirectory $OutputDirectory -State $state -DryRun:$DryRun -IgnoreUnverified:$IgnoreUnverified

# Save state
if (-not $DryRun -and $ConfigFile) {
    try {
        $state | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigFile -ErrorAction Stop
    } catch {
        Write-Warning "Failed to save state file: $_"
    }
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
if (-not $DryRun -and $OutputDirectory) {
    Write-Host "    Output: $OutputDirectory" -ForegroundColor White
    Write-Host ""
}

#endregion
