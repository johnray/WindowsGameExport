# WindowsGameExport

Automatically detect installed games across all major PC gaming platforms and generate launcher batch files using PowerShell.

## Features

- **9 Platform Detection Methods:**
  - Steam
  - Epic Games Store
  - GOG Galaxy
  - Xbox Game Pass / Microsoft Store
  - Amazon Games
  - EA App / Origin
  - Ubisoft Connect
  - Battle.net (Blizzard)
  - Filesystem Scan (standalone games with engine detection)

- **Online Game Verification:**
  - Wikipedia API (free, no signup required)
  - RAWG API (optional, free tier available)

- **Smart Change Detection:**
  - Only regenerates launchers for new or changed games
  - State tracking via JSON file

## Quick Start

```powershell
# Dry run - see what games would be found
.\WindowsGameExport.ps1 -DryRun

# Create launchers in a specific folder
.\WindowsGameExport.ps1 -OutputDirectory "C:\GameLaunchers"

# Include filesystem scan for standalone games
.\WindowsGameExport.ps1 -OutputDirectory "C:\GameLaunchers" -IncludeFilesystemScan

# Skip online verification (trust all detected games)
.\WindowsGameExport.ps1 -OutputDirectory "C:\GameLaunchers" -SkipVerification

# Scan specific drives only
.\WindowsGameExport.ps1 -Drives "D:", "E:" -OutputDirectory "D:\GameLaunchers"
```

## How It Works

1. **Platform Detection:** Scans registry keys, manifest files, and databases for each gaming platform
2. **Game Discovery:** Extracts game names, installation paths, and launch commands
3. **Verification:** Queries Wikipedia/RAWG to confirm detected items are actual games
4. **Launcher Creation:** Generates `.bat` files that launch games using platform-appropriate methods
5. **Change Tracking:** Maintains a state file to only update changed or new games

## Parameters

### `-Drives`
Array of drive letters to scan for games. Default: all fixed drives.

```powershell
.\WindowsGameExport.ps1 -Drives "C:", "D:", "E:"
```

### `-OutputDirectory`
Directory where `.bat` launcher files will be created. Will prompt if not specified.

```powershell
.\WindowsGameExport.ps1 -OutputDirectory "C:\GameLaunchers"
```

### `-RawgApiKey`
Optional RAWG API key for improved game verification accuracy. Get one free at https://rawg.io/apidocs

```powershell
.\WindowsGameExport.ps1 -RawgApiKey "your-api-key-here"
```

### `-IncludeFilesystemScan`
Enable filesystem scanning for standalone games not installed via launchers. This is slower but finds games installed outside of standard platforms.

```powershell
.\WindowsGameExport.ps1 -IncludeFilesystemScan
```

Detects games by identifying:
- Unity games (`UnityPlayer.dll`, `*_Data` folders)
- Unreal Engine games (`Engine` folder, `*-Win64-Shipping.exe`)
- Godot games (`*.pck` files)
- RPG Maker games (`Game.exe`, `RGSS*.dll`)
- Ren'Py games (`renpy` folder)
- Generic games (executables with supporting DLLs/data folders)

### `-Exclude`
Array of directory paths to exclude from filesystem scanning. Useful for skipping large non-game directories.

```powershell
.\WindowsGameExport.ps1 -IncludeFilesystemScan -Exclude "D:\Media", "D:\Documents", "E:\Backup"
```

### `-IncludeList`
Path to a text file containing game names to always include and auto-verify. Games matching patterns in this file bypass online verification. Supports wildcards (*).

```powershell
.\WindowsGameExport.ps1 -OutputDirectory "C:\GameLaunchers" -IncludeList "_include.txt"
```

### `-ExcludeList`
Path to a text file containing game names to always exclude. Games matching patterns in this file are skipped entirely. Supports wildcards (*).

```powershell
.\WindowsGameExport.ps1 -OutputDirectory "C:\GameLaunchers" -ExcludeList "_exclude.txt"
```

See `_include.example.txt` and `_exclude.example.txt` for file format examples.

### `-SkipVerification`
Skip online verification and trust all detected games. Faster but may include non-games.

```powershell
.\WindowsGameExport.ps1 -SkipVerification
```

### `-IgnoreUnverified`
Skip unverified games entirely instead of placing them in the `Unverified/` subfolder. Use this if you only want launchers for confirmed games.

```powershell
.\WindowsGameExport.ps1 -IgnoreUnverified
```

### `-DryRun`
Output detected games without creating any `.bat` files. Useful for previewing what will be found.

```powershell
.\WindowsGameExport.ps1 -DryRun
```

Example output:
```
=== Game Launcher Generator ===
Output: C:\GameLaunchers
Drives: C:, D:
Mode: DRY RUN (no files will be created)

Scanning for games...
  Steam: 45 games found
  Epic Games: 12 games found
  GOG: 8 games found
  Xbox/Microsoft Store: 3 games found
  Amazon Games: 2 games found
  EA/Origin: 5 games found
  Ubisoft Connect: 4 games found
  Battle.net: 6 games found

Total: 85 games detected

=== Detected Games ===
  [Battle.net] Diablo IV
    Path: C:\Program Files (x86)\Diablo IV
  [Epic] Hades
    Path: D:\Epic Games\Hades
  [Steam] Cyberpunk 2077
    Path: D:\SteamLibrary\steamapps\common\Cyberpunk 2077
  ...

Dry run complete. No files were created.
```

### `-ConfigFile`
Path to configuration/state JSON file. Default: `_state.json` in OutputDirectory.

```powershell
.\WindowsGameExport.ps1 -ConfigFile "D:\my_game_state.json"
```

### `-Verbose`
Show detailed progress output during scanning.

```powershell
.\WindowsGameExport.ps1 -Verbose
```

## Output Structure

The script creates a flat folder structure with platform identifiers in filenames:

```
C:\GameLaunchers\
├── _state.json                    # State tracking file
├── Cyberpunk 2077 (Steam).bat
├── Hades (Epic).bat
├── The Witcher 3 (GOG).bat
├── Forza Horizon 5 (Xbox).bat
├── Diablo IV (Battle.net).bat
├── Battlefield 2042 (EA).bat
├── Assassin's Creed Valhalla (Ubisoft).bat
├── Lost Ark (Amazon).bat
├── Hollow Knight (Standalone-Unity).bat
└── Unverified/
    ├── Some Unknown Game (Steam).bat
    └── My Custom Game (Standalone).bat
```

## Launcher File Format

Each `.bat` file contains:

```batch
@echo off
REM Game: Cyberpunk 2077
REM Platform: Steam
REM Path: D:\SteamLibrary\steamapps\common\Cyberpunk 2077
REM Verified: Yes
REM Generated: 2024-01-15 14:30:22
start "" "steam://rungameid/1091500"
```

## Platform-Specific Launch Methods

| Platform | Launch Method |
|----------|---------------|
| Steam | `steam://rungameid/<appid>` protocol |
| Epic Games | `com.epicgames.launcher://apps/<id>?action=launch&silent=true` protocol |
| GOG Galaxy | `GalaxyClient.exe /command=runGame /gameId=<id>` or direct executable |
| Xbox/Microsoft | `start "" shell:AppsFolder\<PackageFamilyName>!<AppId>` |
| Amazon Games | Direct executable launch |
| EA/Origin | Direct executable launch |
| Ubisoft Connect | Direct executable launch |
| Battle.net | `battlenet://<product_code>` protocol |
| Standalone | Direct executable launch |

## Platform Detection Details

### Steam
- **Registry:** `HKLM\SOFTWARE\Wow6432Node\Valve\Steam`
- **Library Folders:** `<Steam>\config\libraryfolders.vdf` (VDF format)
- **Game Manifests:** `steamapps\appmanifest_<appid>.acf` files

### Epic Games Store
- **Registry:** `HKLM\SOFTWARE\WOW6432Node\Epic Games\EpicGamesLauncher`
- **Manifests:** `C:\ProgramData\Epic\EpicGamesLauncher\Data\Manifests\*.item` (JSON)

### GOG Galaxy
- **Registry:** `HKLM\SOFTWARE\Wow6432Node\GOG.com\Games\<id>`
- **Alternative:** `goggame-*.info` files in game directories (JSON)

### Xbox Game Pass / Microsoft Store
- **Detection:** `Get-AppxPackage` PowerShell cmdlet
- **Filtering:** Known game publishers, XboxGames folder, gaming keywords

### Amazon Games
- **Database:** `%LOCALAPPDATA%\Amazon Games\Data\Games\Sql\GameInstallInfo.sqlite`

### EA App / Origin
- **Registry:** `HKLM\SOFTWARE\WOW6432Node\Origin Games\<id>`
- **Manifests:** `C:\ProgramData\Origin\LocalContent\*.mfst`

### Ubisoft Connect
- **Registry:** `HKLM\SOFTWARE\WOW6432Node\Ubisoft\Launcher\Installs\<id>`

### Battle.net
- **Database:** `C:\ProgramData\Battle.net\Agent\product.db` (SQLite)
- **Registry:** `HKLM\SOFTWARE\WOW6432Node\Blizzard Entertainment\<GameName>`
- **Config:** `%APPDATA%\Battle.net\Battle.net.config` (JSON)

## Game Verification

The script uses **dynamic verification** with no hardcoded exclusion lists. Items are verified in real-time using web APIs.

### Platform Trust
Games from dedicated gaming platforms are automatically trusted:
- **Steam, Epic, GOG, Battle.net, Amazon Games, EA, Ubisoft** - These platforms only distribute games
- **Xbox Game Pass** (XboxGames folder) - Trusted as Game Pass content

Items from general sources (WindowsApps, filesystem scan) require online verification.

### Wikipedia Search (Primary)
- Searches Wikipedia for the item name
- Simple check: Does the Wikipedia result mention "game"?
- If yes → it's a game. If no → it's not a game.
- Free, no API key required

### Wikipedia Page Lookup (Secondary)
- Directly fetches the Wikipedia page for the item
- Checks page categories for video game indicators
- Categories: "video games", "Windows games", "PC games", etc.
- Free, no API key required

### RAWG API (Optional)
- 500,000+ game database
- More accurate matching for less-known games
- Requires free API key signup at https://rawg.io/apidocs
- 20,000 requests/month on free tier

### Verification Logic
1. If from trusted gaming platform → auto-verified
2. Search Wikipedia - does the result mention "game"?
3. Lookup Wikipedia page categories
4. Query RAWG API (if key provided)
5. If all methods inconclusive → mark as unverified (placed in Unverified subfolder)

## Usage Examples

### Basic Usage
```powershell
# Scan all drives, prompt for output directory
.\WindowsGameExport.ps1
```

### Full Scan with Verification
```powershell
# Comprehensive scan with RAWG verification
.\WindowsGameExport.ps1 `
    -OutputDirectory "C:\GameLaunchers" `
    -IncludeFilesystemScan `
    -RawgApiKey "your-api-key"
```

### Fast Scan Without Verification
```powershell
# Quick scan, trust all detected games
.\WindowsGameExport.ps1 `
    -OutputDirectory "C:\GameLaunchers" `
    -SkipVerification
```

### Selective Drive Scan
```powershell
# Only scan game drives, exclude media folders
.\WindowsGameExport.ps1 `
    -Drives "D:", "E:" `
    -OutputDirectory "D:\GameLaunchers" `
    -IncludeFilesystemScan `
    -Exclude "D:\Videos", "D:\Music", "E:\Backup"
```

### Preview Mode
```powershell
# See what games are installed without creating files
.\WindowsGameExport.ps1 -DryRun -Verbose

# Preview with filesystem scan
.\WindowsGameExport.ps1 -DryRun -IncludeFilesystemScan
```

### Update Existing Launchers
```powershell
# Re-run to update - only changed/new games will be processed
.\WindowsGameExport.ps1 -OutputDirectory "C:\GameLaunchers"
```

### Custom Include/Exclude Lists
```powershell
# Use custom lists to control what gets included/excluded
.\WindowsGameExport.ps1 `
    -OutputDirectory "C:\GameLaunchers" `
    -IncludeList "my_games.txt" `
    -ExcludeList "skip_these.txt"
```

Example `my_games.txt`:
```
# Force-include these indie games that may not have Wikipedia entries
Herdling
My Custom Game
*Roguelike*
```

Example `skip_these.txt`:
```
# Skip these apps that keep being detected
Microsoft Edge
*Demo*
*Beta*
```

## Advanced Usage

### Combine with Other Tools
```powershell
# Run and capture output
$output = .\WindowsGameExport.ps1 -DryRun -Verbose 2>&1

# Parse for specific platforms
$steamGames = $output | Select-String "\[Steam\]"
```

### Scheduled Updates
Create a scheduled task to periodically update launchers:

```powershell
# Create scheduled task (run in elevated PowerShell)
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File `"C:\Scripts\WindowsGameExport.ps1`" -OutputDirectory `"C:\GameLaunchers`" -SkipVerification"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am

Register-ScheduledTask -TaskName "Update Game Launchers" `
    -Action $action -Trigger $trigger -Description "Weekly game launcher update"
```

### Integration with Launchers
The generated `.bat` files can be:
- Added to Steam as non-Steam games
- Imported into Playnite, LaunchBox, or other game launchers
- Used with Stream Deck or similar macro devices
- Pinned to Start Menu or Taskbar

## Requirements

- **PowerShell 5.1** or later (comes with Windows 10/11)
- **Windows 10/11** (for Xbox Game Pass detection via Get-AppxPackage)
- **Internet connection** (for game verification, unless using `-SkipVerification`)

### Optional
- **System.Data.SQLite** assembly (for Amazon Games and Battle.net database reading)
  - Script will skip these platforms gracefully if not available
- **RAWG API key** (for improved verification accuracy)

## Troubleshooting

### Execution Policy Error
If you get "cannot be loaded because running scripts is disabled":

**Option 1: Unblock the file**
1. Right-click `WindowsGameExport.ps1` in Windows Explorer
2. Select Properties
3. Check "Unblock" at the bottom of General tab
4. Click OK

**Option 2: Change execution policy**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Option 3: Bypass for single run**
```powershell
powershell -ExecutionPolicy Bypass -File ".\WindowsGameExport.ps1" -DryRun
```

### No Games Found for Platform
- Ensure the platform's launcher is installed
- Check that games are actually installed (not just in library)
- Run with `-Verbose` to see detailed scanning output
- Some platforms may store data in non-standard locations

### Amazon Games / Battle.net Not Detected
These platforms use SQLite databases. If the script can't read them:
- The `System.Data.SQLite` assembly may not be available
- Games from these platforms will be skipped
- Other platforms will still work normally

### Verification Fails for Known Games
- Game may have unusual name formatting
- Try with `-SkipVerification` to include all detected games
- Check Unverified folder for games that failed verification
- Consider using RAWG API key for better accuracy

### Filesystem Scan Finds Too Many Items
- Use `-Exclude` to skip large non-game directories
- Review Unverified folder and manually remove false positives
- Verification step should filter most non-games

### Slow Performance
- Online verification adds ~500ms per game
- Use `-SkipVerification` for faster scans
- Filesystem scan is inherently slower - only enable when needed
- Exclude large directories with `-Exclude`

## State File Format

The `_state.json` file tracks processed games:

```json
{
  "A1B2C3D4E5F6G7H8": {
    "Name": "Cyberpunk 2077",
    "Platform": "Steam",
    "Path": "D:\\SteamLibrary\\steamapps\\common\\Cyberpunk 2077",
    "Verified": true,
    "LastUpdated": "2024-01-15T14:30:22.1234567-05:00"
  },
  ...
}
```

The hash key is generated from `Name|Path|Platform` to detect changes.

## Known Limitations

1. **Xbox Game Pass:** Some games may not be detected if they don't follow standard UWP patterns
2. **Amazon Games / Battle.net:** Requires SQLite assembly for full functionality
3. **DRM-free standalone games:** May be missed without filesystem scan enabled
4. **Game name variations:** Verification may fail for games with very different store names vs. common names
5. **Launcher-required games:** Some games require their platform launcher to be running (handled automatically by protocol handlers)

## Contributing

Issues and pull requests welcome at: https://github.com/johnray/WindowsGameExport

## License

MIT License - See LICENSE file for details.

## Related Projects

- [RetroBatExport](https://github.com/johnray/RetroBatExport) - Export RetroBAT/EmulationStation game libraries
- [Playnite](https://playnite.link/) - Open source game library manager
- [LaunchBox](https://www.launchbox-app.com/) - Game launcher and organizer

## Acknowledgments

- [RAWG](https://rawg.io/) - Video game database API
- [Wikipedia API](https://www.mediawiki.org/wiki/API:Main_page) - Free knowledge base
- [Steam](https://store.steampowered.com/) - VDF format documentation
- [PCGamingWiki](https://www.pcgamingwiki.com/) - Game installation path references
