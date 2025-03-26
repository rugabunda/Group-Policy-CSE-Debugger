<#
.SYNOPSIS
    Group Policy CSE Debugger - Finds problematic CSEs causing pointer errors
.DESCRIPTION
    This script automates the debugging process for Group Policy errors by systematically
    removing CSE GUIDs from gpt.ini until the error disappears, identifying the problematic extension.
.PARAMETER BackupPath
    Optional. Path to an existing LGPO backup to use instead of creating a new one.
.PARAMETER Mode
    Optional. Debugging mode: 'Auto' or 'Manual'. Default is 'Auto'.
.EXAMPLE
    .\GPCseDebugger.ps1
    Runs the script in automatic mode with a new backup.
.EXAMPLE
    .\GPCseDebugger.ps1 -BackupPath "C:\Temp\{Backup}" -Mode "Manual"
    Runs the script in manual mode using an existing backup at the specified path.
.NOTES
    Requires LGPO.exe in the current directory
    Requires elevation/admin rights
#>

param (
    [string]$BackupPath = "",
    [ValidateSet("Auto", "Manual")]
    [string]$Mode = ""
)

# Set error action preference
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# Log file setup
$logFile = ".\GpoTest.log"
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$separatorLine = "=" * 80

# Create backup folder
$backupFolder = ".\GPT_Backups"
if (-not (Test-Path $backupFolder)) {
    New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
}

# Define shorthand script blocks for common log messages
$f1 = { Write-Log $separatorLine }
$f2 = { Write-Log "Running gpupdate /force..." }
$f3 = { Write-Log "Testing with gpresult /f /h test.html..." }
$f4 = { param($type, $name, $guid) Write-Log "Testing $type CSE: $name ($guid)..." }
$f5 = { Write-Log "Updated gpt.ini file with GUID pairs removed" }
$f6 = { Write-Log "Pointer error still exists." -Warning }
$f7 = { Write-Log "No pointer error detected!" -Success }

# Helper function to write to console and log file
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [switch]$Error,
        [switch]$Warning,
        [switch]$Success,
        [switch]$Diagnostic
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Determine console color
    if ($Error) {
        $color = "Red"
        $prefix = "[ERROR]"
    }
    elseif ($Warning) {
        $color = "Yellow"
        $prefix = "[WARNING]"
    }
    elseif ($Success) {
        $color = "Green"
        $prefix = "[SUCCESS]"
    }
    elseif ($Diagnostic) {
        $color = "Gray"
        $prefix = "[DEBUG]"
        # Skip writing debug messages to console unless $VerboseDebug is true
        if (-not $VerboseDebug) {
            # Still write to log file
            Add-Content -Path $logFile -Value "$timestamp $prefix $Message"
            return
        }
    }
    else {
        $color = "White"
        $prefix = "[INFO]"
    }
    
    # Write to console
    Write-Host "$prefix $Message" -ForegroundColor $color
    
    # Write to log file
    Add-Content -Path $logFile -Value "$timestamp $prefix $Message"
}

# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "This script requires administrator privileges. Please run as administrator." -Error
    exit 1
}

# Create or append log file
if (-not (Test-Path $logFile)) {
    New-Item -Path $logFile -ItemType File -Force | Out-Null
}

# Add a session separator to the log
$sessionStart = "=" * 30 + " NEW SESSION: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') " + "=" * 30
Add-Content -Path $logFile -Value $sessionStart

& $f1
Write-Log "Group Policy CSE Debugger - Starting at $timestamp"
& $f1

# Enable verbose debug logging if needed (set to $true for troubleshooting)
$VerboseDebug = $false

# Check if LGPO.exe exists
if (-not (Test-Path ".\LGPO.exe")) {
    Write-Log "LGPO.exe not found in the current directory. This tool is required for the debugging process." -Error
    Write-Log "Please download LGPO.exe from Microsoft Security Compliance Toolkit and place it in the current directory." -Error
    exit 1
}

Write-Log "LGPO.exe found in current directory." -Success

# Check for original backup and offer to restore
$gptInfPath = "C:\Windows\System32\GroupPolicy\gpt.ini"
$gptInfOriginal = "$backupFolder\gpt.ini.original"

if (Test-Path $gptInfOriginal) {
    Write-Host ""
    $restoreOriginal = Read-Host "Restore gpt.ini from original backup before proceeding? (Y/N)"
    if ($restoreOriginal -eq "Y") {
        Copy-Item $gptInfOriginal -Destination $gptInfPath -Force
        Write-Log "Restored original gpt.ini from first-run backup" -Success
    }
}

# Prompt for debugging mode if not specified via parameter
if ([string]::IsNullOrEmpty($Mode)) {
    Write-Host ""
    Write-Host "Select debugging mode:" -ForegroundColor Cyan
    Write-Host "1. Automatic Mode (runs all tests automatically)" -ForegroundColor Cyan
    Write-Host "2. Manual Mode (prompts after each test)" -ForegroundColor Cyan
    $modeChoice = Read-Host "Enter your choice (1 or 2)"
    
    if ($modeChoice -eq "1") {
        $Mode = "Auto"
    } elseif ($modeChoice -eq "2") {
        $Mode = "Manual"
    } else {
        Write-Log "Invalid choice. Defaulting to Automatic Mode." -Warning
        $Mode = "Auto"
    }
}

Write-Log "Selected debugging mode: $Mode"

# Test for Group Policy pointer error
Write-Log "Testing for Group Policy pointer errors..."
try {
    $gpresultOutput = gpresult /f /h test.html 2>&1
    $errorDetected = $gpresultOutput | Select-String -Pattern "ERROR: Invalid pointer" -Quiet
    
    if ($errorDetected) {
        Write-Log "Group Policy pointer error detected." -Warning
    } else {
        Write-Log "No Group Policy pointer errors detected. The system appears to be functioning correctly." -Success
        
        if ($Mode -eq "Manual") {
            Write-Host ""
            Write-Host "No errors were automatically detected. Would you like to continue anyway?" -ForegroundColor Yellow
            $continueAnyway = Read-Host "Continue with debugging? (Y/N)"
            
            if ($continueAnyway -ne "Y") {
                Write-Log "User chose to exit as no errors were detected."
                exit 0
            }
            
            Write-Log "User chose to continue debugging despite no errors being detected."
        } else {
            exit 0
        }
    }
} catch {
    Write-Log "Error running gpresult: $_" -Error
    exit 1
}

# Handle backup - either use specified path or create new backup
$backupGUID = ""
$fullBackupPath = ""

if ([string]::IsNullOrEmpty($BackupPath)) {
    # Backup current Group Policy
    Write-Log "Backing up current Group Policy settings..."
    $backupDir = (Get-Location).Path
    try {
        $lgpoBackup = & .\LGPO.exe /b $backupDir 2>&1
        Write-Log "Group Policy backup completed." -Success
    } catch {
        Write-Log "Error backing up Group Policy: $_" -Error
        exit 1
    }

    # Extract backup GUID folder name
    $backupMatch = $lgpoBackup | Select-String -Pattern "\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}" | Select-Object -First 1
    if (-not $backupMatch) {
        Write-Log "Could not find backup GUID in LGPO output." -Error
        exit 1
    }

    $backupGUID = $backupMatch.Matches.Value
    $fullBackupPath = Join-Path $backupDir $backupGUID
    Write-Log "Backup stored in folder: $backupGUID"
} else {
    # Use existing backup
    if (-not (Test-Path $BackupPath)) {
        Write-Log "Specified backup path does not exist: $BackupPath" -Error
        exit 1
    }
    
    # Check if the path is a GUID folder or contains one
    if ($BackupPath -match "\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$") {
        # Path ends with a GUID, use it directly
        $backupGUID = [regex]::Match($BackupPath, "\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}").Value
        $fullBackupPath = $BackupPath
    } else {
        # Try to find a GUID folder in the directory
        $guidFolders = Get-ChildItem -Path $BackupPath -Directory | Where-Object { $_.Name -match "\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}" }
        
        if ($guidFolders.Count -eq 0) {
            Write-Log "No valid GUID folders found in backup path: $BackupPath" -Error
            exit 1
        }
        
        # Use the first GUID folder found
        $backupGUID = $guidFolders[0].Name
        $fullBackupPath = Join-Path $BackupPath $backupGUID
    }
    
    Write-Log "Using existing backup at: $fullBackupPath" -Success
    Write-Log "Backup GUID: $backupGUID"
}

# Attempt to get CSE names and GUIDs by running LGPO restore
Write-Log "Analyzing CSE extensions..."
try {
    # Run LGPO with the full backup path
    $lgpoRestore = & .\LGPO.exe /g $fullBackupPath 2>&1
    
    # Create CSE mapping dictionary
    $cseMapping = @{}
    
    # Extract Machine CSEs
    $machineCses = $lgpoRestore | Select-String -Pattern "Registering Machine CSE: (.*), \{([0-9a-fA-F-]+)\}"
    
    foreach ($match in $machineCses) {
        $cseName = $match.Matches.Groups[1].Value
        $cseGuid = $match.Matches.Groups[2].Value.ToUpper() # Convert to uppercase for consistent matching
        $cseMapping[$cseGuid] = $cseName
        Write-Log "Found Machine CSE: $cseName with GUID: {$cseGuid}"
    }
    
    # Extract User CSEs
    $userCses = $lgpoRestore | Select-String -Pattern "Registering User CSE: (.*), \{([0-9a-fA-F-]+)\}"
    
    foreach ($match in $userCses) {
        $cseName = $match.Matches.Groups[1].Value
        $cseGuid = $match.Matches.Groups[2].Value.ToUpper() # Convert to uppercase for consistent matching
        $cseMapping[$cseGuid] = $cseName
        Write-Log "Found User CSE: $cseName with GUID: {$cseGuid}"
    }
} catch {
    Write-Log "Error analyzing CSE extensions: $_" -Error
    exit 1
}

# Backup the original gpt.ini file
$gptInfSession = "$backupFolder\gpt.ini.session"

# Create permanent original backup if it doesn't exist
if (-not (Test-Path $gptInfOriginal)) {
    try {
        Copy-Item -Path $gptInfPath -Destination $gptInfOriginal -Force
        Write-Log "Created permanent original gpt.ini backup to $gptInfOriginal" -Success
    } catch {
        Write-Log "Error creating original gpt.ini backup: $_" -Error
    }
}

if (-not (Test-Path $gptInfPath)) {
    Write-Log "Could not find gpt.ini file at $gptInfPath" -Error
    exit 1
}

# Create session backup for testing
try {
    Copy-Item -Path $gptInfPath -Destination $gptInfSession -Force
    Write-Log "Created session gpt.ini backup for testing" -Success
} catch {
    Write-Log "Error creating session gpt.ini backup: $_" -Error
    exit 1
}

# Read and parse the gpt.ini file
try {
    $gptInfContent = Get-Content -Path $gptInfPath -Raw
    $machineExtLine = $gptInfContent | Select-String -Pattern "gPCMachineExtensionNames=(.*)" | ForEach-Object { $_.Matches.Groups[1].Value }
    $userExtLine = $gptInfContent | Select-String -Pattern "gPCUserExtensionNames=(.*)" | ForEach-Object { $_.Matches.Groups[1].Value }
    
    Write-Log "Successfully parsed gpt.ini file" -Success
} catch {
    Write-Log "Error parsing gpt.ini file: $_" -Error
    exit 1
}

# Extract GUID pairs from the extension lines
function Extract-GuidPairs {
    param (
        [string]$ExtensionLine
    )
    
    $guidPairPattern = "\[(\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\})(\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\})\]"
    $matches = [regex]::Matches($ExtensionLine, $guidPairPattern)
    
    $guidPairs = @()
    foreach ($match in $matches) {
        $primaryGuid = $match.Groups[1].Value
        $secondaryGuid = $match.Groups[2].Value
        $fullPair = "[$primaryGuid$secondaryGuid]"
        
        # Extract GUID without braces for mapping lookup
        $primaryGuidNoBraces = $primaryGuid -replace '[{}]', ''
        
        $guidPairs += @{
            "FullPair" = $fullPair
            "PrimaryGuid" = $primaryGuid
            "PrimaryGuidNoBraces" = $primaryGuidNoBraces.ToUpper() # Store as uppercase for consistent matching
            "SecondaryGuid" = $secondaryGuid
        }
    }
    
    return $guidPairs
}

$machineGuidPairs = Extract-GuidPairs -ExtensionLine $machineExtLine
$userGuidPairs = Extract-GuidPairs -ExtensionLine $userExtLine

Write-Log "Found $($machineGuidPairs.Count) Machine CSE GUID pairs and $($userGuidPairs.Count) User CSE GUID pairs in gpt.ini"

# Function to update gpt.ini by removing specific GUID pairs
function Update-GptInf {
    param (
        [hashtable[]]$RemoveGuidPairs = @(),
        [string]$ExtensionType = "Machine"
    )
    
    # Create new extension string excluding the specified GUID pairs
    if ($ExtensionType -eq "Machine") {
        $newExtLine = $machineExtLine
        foreach ($pair in $RemoveGuidPairs) {
            $newExtLine = $newExtLine -replace [regex]::Escape($pair.FullPair), ""
        }
        $newContent = $gptInfContent -replace "gPCMachineExtensionNames=.*", "gPCMachineExtensionNames=$newExtLine"
    } else {
        $newExtLine = $userExtLine
        foreach ($pair in $RemoveGuidPairs) {
            $newExtLine = $newExtLine -replace [regex]::Escape($pair.FullPair), ""
        }
        $newContent = $gptInfContent -replace "gPCUserExtensionNames=.*", "gPCUserExtensionNames=$newExtLine"
    }
    
    # Write the new content to the file
    Set-Content -Path $gptInfPath -Value $newContent
    & $f5
}

# Function to test if GP pointer error still exists
function Test-GpPointerError {
    & $f2
    $gpupdateOutput = gpupdate /force 2>&1
    
    & $f3
    $gpresultOutput = gpresult /f /h test.html 2>&1
    $errorDetected = $gpresultOutput | Select-String -Pattern "ERROR: Invalid pointer" -Quiet
    
    if ($errorDetected) {
        & $f6
        return $true
    } else {
        & $f7
        return $false
    }
}

# Function to test a CSE pair and determine if it's problematic
function Test-CsePair {
    param (
        [hashtable]$Pair,
        [string]$Type = "Machine"
    )
    
    $primaryGuid = $Pair.PrimaryGuid
    $primaryGuidNoBraces = $Pair.PrimaryGuidNoBraces
    
    # Get CSE name
    $cseName = "Unknown CSE"
    if ($cseMapping.ContainsKey($primaryGuidNoBraces)) {
        $cseName = $cseMapping[$primaryGuidNoBraces]
    }
    
    & $f1
    & $f4 $Type $cseName $primaryGuid
    
    # Remove this GUID pair and test
    if ($Type -eq "Machine") {
        Update-GptInf -RemoveGuidPairs @($Pair) -ExtensionType "Machine"
    } else {
        Update-GptInf -RemoveGuidPairs @($Pair) -ExtensionType "User"
    }
    
    $hasError = Test-GpPointerError
    $continueTest = $true
    
    if ($Mode -eq "Manual") {
        Write-Host ""
        Write-Host "Testing completed for $cseName ($primaryGuid)" -ForegroundColor Cyan
        $userResponse = Read-Host "Did the error go away? (Y/N)"
        
        if ($userResponse -eq "Y") {
            $hasError = $false
            $continueTest = $false
        }
    }
    
    # Restore the original gpt.ini for the next test
    Copy-Item -Path $gptInfSession -Destination $gptInfPath -Force
    
    $result = @{
        "HasError" = $hasError
        "ContinueTest" = $continueTest
        "CSEName" = $cseName
        "Type" = $Type
        "GuidPair" = $Pair
    }
    
    return $result
}

# Begin systematic testing by removing each GUID pair one by one
& $f1
Write-Log "Beginning systematic testing of each CSE GUID pair..."
& $f1

$problematicGuidPairs = @()
$testedGuidPairs = @{}
$continueNextTest = $true

# First, test each Machine CSE GUID pair
foreach ($pair in $machineGuidPairs) {
    $result = Test-CsePair -Pair $pair -Type "Machine"
    
    if (-not $result.HasError) {
        Write-Log "Found problematic Machine CSE: $($result.CSEName) ($($pair.PrimaryGuid))" -Success
        $problematicGuidPairs += $result
        $testedGuidPairs[$pair.PrimaryGuid] = $false
        
        if ($Mode -eq "Auto" -or -not $result.ContinueTest) {
            break
        }
    } else {
        $testedGuidPairs[$pair.PrimaryGuid] = $true
    }
    
    if ($Mode -eq "Manual" -and $result.ContinueTest) {
        Write-Host ""
        $continueNextTest = Read-Host "Continue testing next CSE? (Y/N)"
        
        if ($continueNextTest -ne "Y") {
            Write-Log "User chose to stop testing."
            break
        }
    }
}

# If no problematic Machine CSE was found and we're continuing, test User CSEs
if ($problematicGuidPairs.Count -eq 0 -and ($Mode -eq "Auto" -or $continueNextTest -eq "Y")) {
    foreach ($pair in $userGuidPairs) {
        $result = Test-CsePair -Pair $pair -Type "User"
        
        if (-not $result.HasError) {
            Write-Log "Found problematic User CSE: $($result.CSEName) ($($pair.PrimaryGuid))" -Success
            $problematicGuidPairs += $result
            $testedGuidPairs[$pair.PrimaryGuid] = $false
            
            if ($Mode -eq "Auto" -or -not $result.ContinueTest) {
                break
            }
        } else {
            $testedGuidPairs[$pair.PrimaryGuid] = $true
        }
        
        if ($Mode -eq "Manual" -and $result.ContinueTest) {
            Write-Host ""
            $continueNextTest = Read-Host "Continue testing next CSE? (Y/N)"
            
            if ($continueNextTest -ne "Y") {
                Write-Log "User chose to stop testing."
                break
            }
        }
    }
}

# Summarize findings
& $f1
Write-Log "Summary of Findings:"
& $f1

if ($problematicGuidPairs.Count -gt 0) {
    foreach ($item in $problematicGuidPairs) {
        $primaryGuid = $item.GuidPair.PrimaryGuid
        Write-Log "Problematic CSE identified: $($item.CSEName) ($primaryGuid)" -Success
        Write-Log "Type: $($item.Type) CSE"
        
        # Offer advice based on the CSE
        switch -Wildcard ($item.CSEName) {
            "Registry Policy" {
                Write-Log "This CSE handles registry-based policy settings. Issues might be related to corrupted registry policies." -Warning
            }
            "Scripts" {
                Write-Log "This CSE handles startup/shutdown and logon/logoff scripts. Check for missing or problematic scripts." -Warning
            }
            "Security" {
                Write-Log "This CSE handles security settings. There might be conflicting or corrupted security policies." -Warning
            }
            "Software Installation" {
                Write-Log "This CSE handles software installation policies. Check for broken application deployment settings." -Warning
            }
            "Folder Redirection" {
                Write-Log "This CSE handles folder redirection. Check for invalid paths or permissions issues." -Warning
            }
            "Audit" {
                Write-Log "This CSE handles audit policy settings. There might be conflicting or corrupted audit policies." -Warning
            }
            default {
                Write-Log "This CSE might have corrupted settings or conflicts with other policies." -Warning
            }
        }
    }
    
    # Ask user for next steps
    Write-Host "[WARNING] Removing the problematic GUID may stop related errors but could disable associated Group Policy functionality. Keeping it might maintain functionality but risks continued errors. Ensure you understand the implications before proceeding." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "What would you like to do?" -ForegroundColor Cyan
    Write-Host "1. Rebuild gpt.ini preserving only valid GUIDs" -ForegroundColor Cyan
    Write-Host "2. Restore the original gpt.ini file" -ForegroundColor Cyan
    $choice = Read-Host "Enter your choice (1 or 2)"
    
    if ($choice -eq "1") {
        Write-Log "User chose to rebuild gpt.ini preserving only valid GUID pairs."
        
        # Rebuild gpt.ini with all GUID pairs except the problematic ones
        foreach ($item in $problematicGuidPairs) {
            if ($item.Type -eq "Machine") {
                Update-GptInf -RemoveGuidPairs @($item.GuidPair) -ExtensionType "Machine"
            } else {
                Update-GptInf -RemoveGuidPairs @($item.GuidPair) -ExtensionType "User"
            }
        }
        
        # Run GPUpdate to apply changes
        Write-Log "Running final gpupdate /force to apply changes..."
        $finalGpupdate = gpupdate /force 2>&1
        
        # Final test
        $finalGpresult = gpresult /f /h test.html 2>&1
        $finalErrorDetected = $finalGpresult | Select-String -Pattern "ERROR: Invalid pointer" -Quiet
        
        if ($finalErrorDetected) {
            Write-Log "Pointer error still exists after rebuilding gpt.ini. There might be additional issues." -Error
        } else {
            Write-Log "Group Policy is now working correctly after removing problematic CSEs!" -Success
        }
        
    } elseif ($choice -eq "2") {
        Write-Log "User chose to restore the original gpt.ini file."
        
        # Restore original gpt.ini
        Copy-Item -Path $gptInfSession -Destination $gptInfPath -Force
        
        # Run GPUpdate
        Write-Log "Running gpupdate /force with original settings..."
        $finalGpupdate = gpupdate /force 2>&1
        
        Write-Log "Original gpt.ini file has been restored. The error will likely still exist." -Warning
    } else {
        Write-Log "Invalid choice. Restoring original gpt.ini as a precaution." -Warning
        Copy-Item -Path $gptInfSession -Destination $gptInfPath -Force
    }
} else {
    Write-Log "No specific problematic CSE was identified." -Warning
    Write-Log "This could indicate a more complex issue or multiple conflicting CSEs." -Warning
    Write-Log "Consider checking for Group Policy corruption or consistency issues." -Warning
    
    # Restore original gpt.ini
    Copy-Item -Path $gptInfSession -Destination $gptInfPath -Force
}

& $f1
Write-Log "Group Policy CSE Debugging completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Log "Log file saved to: $((Get-Item $logFile).FullName)"
& $f1

Write-Host ""
Write-Host "Debugging process completed. See $logFile for detailed information." -ForegroundColor Green