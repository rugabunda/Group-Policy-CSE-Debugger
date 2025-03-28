<#
.SYNOPSIS
    Group Policy CSE Debugger - Finds problematic CSEs causing pointer errors
.DESCRIPTION
    This script helps automate the debugging process for Group Policy errors. 1. Pointer errors are tested by systematically
    removing CSE GUIDs from gpt.ini and testing one by one until the error disappears, identifying the problematic extension.
	2. Allowing users to disable extensions one by one until their problem goes away. 3. Enabling Advanced GPO logging.
.PARAMETER Mode
    Optional. Debugging mode: 'Auto' or 'Manual'. Default is 'Auto'.
.PARAMETER EnableLogging
    Optional. Enables enhanced Group Policy logging for detailed troubleshooting.
.PARAMETER DisableLogging
    Optional. Disables enhanced Group Policy logging and removes related files.
.EXAMPLE
    .\GPCseDebugger.ps1
    Runs the script in automatic mode.
.EXAMPLE
    .\GPCseDebugger.ps1 -Mode "Manual"
    Runs the script in manual mode.
.EXAMPLE
    .\GPCseDebugger.ps1 -EnableLogging
    Runs the script with enhanced Group Policy logging enabled.
.NOTES
    Requires elevation/admin rights
    
    Resources for additional troubleshooting:
    - https://learn.microsoft.com/en-us/archive/blogs/askds/a-treatise-on-group-policy-troubleshootingnow-with-gpsvc-log-analysis
    - https://learn.microsoft.com/en-us/answers/questions/120736/gpos-not-applied-ad-group-issue.html
    - http://www.sysprosoft.com/policyreporter.shtml
#>

param (
    [ValidateSet("Auto", "Manual")]
    [string]$Mode = "",
    [switch]$EnableLogging = $false,
    [switch]$DisableLogging = $false
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
$f4 = { param($type, $name, $guid) Write-Log "Testing $type CSE: $name $guid..." }
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

# Function to enable enhanced Group Policy logging
function Enable-GPLogging {
    Write-Log "Enabling enhanced Group Policy logging..."
    
    # Add registry key for detailed logging
    & reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" /v "GPSvcDebugLevel" /t REG_DWORD /d 0x00030002 /f | Out-Null
    
    # Create debug directory if it doesn't exist
    if (-not (Test-Path "$env:windir\debug\usermode")) {
        New-Item -Path "$env:windir\debug\usermode" -ItemType Directory -Force | Out-Null
    }
    
    Write-Log "Enhanced Group Policy logging enabled. Log will be created at $env:windir\debug\usermode\gpsvc.log" -Success
    Write-Log "Note: The log file will be created after running gpupdate /force" -Warning
    
    # Offer to open log viewer
    $openViewer = Read-Host "Would you like to open a log viewer window? (Y/N)"
    if ($openViewer -eq "Y") {
        Start-Process powershell -ArgumentList "-NoExit -Command `"Get-Content '$env:windir\debug\usermode\gpsvc.log' -Wait -Tail 50 | Where-Object {`$_ -ne ''}`"" -WindowStyle Normal
    }
}

# Function to disable enhanced Group Policy logging
function Disable-GPLogging {
    Write-Log "Disabling enhanced Group Policy logging..."
    
    # Remove registry key for detailed logging
    & reg delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" /v "GPSvcDebugLevel" /f | Out-Null
    
    $removeFolder = Read-Host "Do you want to remove the entire debug folder? ($env:windir\debug\usermode) (Y/N)"
    if ($removeFolder -eq "Y") {
        if (Test-Path "$env:windir\debug\usermode") {
            Remove-Item -Path "$env:windir\debug\usermode" -Recurse -Force
            Write-Log "Debug folder removed: $env:windir\debug\usermode" -Success
        } else {
            Write-Log "Debug folder not found: $env:windir\debug\usermode" -Warning
        }
    } else {
        Write-Log "Debug folder preserved. You can manually remove it later if needed." -Info
    }
    
    Write-Log "Enhanced Group Policy logging disabled." -Success
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

# Handle logging parameter requests first
if ($EnableLogging) {
    Enable-GPLogging
}

if ($DisableLogging) {
    Disable-GPLogging
    
    # Exit if only disabling logging was requested
    if (-not $Mode) {
        Write-Log "Logging disabled. Exiting as no other operations were requested."
        exit 0
    }
}

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
    Write-Host "3. Enable Enhanced GP Logging" -ForegroundColor Cyan
    Write-Host "4. Disable Enhanced GP Logging" -ForegroundColor Cyan
    $modeChoice = Read-Host "Enter your choice (1-4)"
    
    if ($modeChoice -eq "1") {
        $Mode = "Auto"
    } elseif ($modeChoice -eq "2") {
        $Mode = "Manual"
    } elseif ($modeChoice -eq "3") {
        Enable-GPLogging
        Write-Host ""
        $continueAfterLogging = Read-Host "Continue with debugging? (Y/N)"
        if ($continueAfterLogging -eq "Y") {
            $Mode = Read-Host "Select mode (Auto/Manual)"
        } else {
            exit 0
        }
    } elseif ($modeChoice -eq "4") {
        Disable-GPLogging
        Write-Host ""
        $continueAfterLogging = Read-Host "Continue with debugging? (Y/N)"
        if ($continueAfterLogging -eq "Y") {
            $Mode = Read-Host "Select mode (Auto/Manual)"
        } else {
            exit 0
        }
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

# Backup the gpt.ini file
Write-Log "Creating backup of current Group Policy settings..."
$timestampStr = Get-Date -Format "yyyyMMdd_HHmmss"
$gptInfBackup = "$backupFolder\gpt.ini_$timestampStr"
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

# Create timestamped backup
try {
    Copy-Item -Path $gptInfPath -Destination $gptInfBackup -Force
    Write-Log "Created timestamped backup of gpt.ini at: $gptInfBackup" -Success
} catch {
    Write-Log "Error creating backup: $_" -Error
    exit 1
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
    
    # If enhanced logging is enabled, check logs for specific error patterns
    if ($EnableLogging) {
        if (Test-Path "$env:windir\debug\usermode\gpsvc.log") {
            Write-Log "Analyzing GP debug logs for errors..." -Diagnostic
            # This could be expanded with specific patterns to look for in the logs
        }
    }
    
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

# Define hardcoded CSE mapping dictionary based on provided lists
$cseMapping = @{
    "B587E2B1-4D59-4E7E-AED9-22B9DF11D053" = "802.3 Group Policy"
    "C6DC5466-785A-11D2-84D0-00C04FB169F7" = "Application Management"
    "F3CCC681-B74C-4060-9F26-CD84525DCA2A" = "Audit Policy Configuration"
    "53D6AB1D-2488-11D1-A28C-00C04FB94F17" = "Certificates Run Restriction"
    "803E14A0-B4FB-11D0-A0D0-00A0C90F574B" = "Restricted Groups"
    "00000000-0000-0000-0000-000000000000" = "Core GPO Engine"
    "8A28E2C5-8D06-49A4-A08C-632DAA493E17" = "Deployed Printer Connections"
    "B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A" = "EFS Recovery"
    "FB2CA36D-0B40-4307-821B-A13B252DE56C" = "Enterprise QoS"
    "88E729D6-BDC1-11D1-BD2A-00C04FB9603F" = "Folder Redirection"
    "25537BA6-77A8-11D2-9B6C-0000F8080861" = "Folder Redirection"
    "F9C77450-3A41-477E-9310-9ACD617BD9E3" = "Group Policy Applications"
    "6232C319-91AC-4931-9385-E70C2B099F0E" = "Group Policy Folders"
    "CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D" = "Internet Explorer Machine Accelerators"
    "FC715823-C5FB-11D1-9EEF-00A0C90347FF" = "Internet Explorer Maintenance Extension protocol"
    "A2E30F80-D7DE-11D2-BBDE-00C04F86AE3B" = "Internet Explorer Maintenance policy processing"
    "7B849A69-220F-451E-B3FE-2CB811AF94AE" = "Internet Explorer User Accelerators"
    "4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3" = "Internet Explorer Zonemapping"
    "E437BC1C-AA7D-11D2-A382-00C04F991E27" = "IP Security"
    "9650FDBC-053A-4715-AD14-FC2DC65E8330" = "Hypervisor-Protected Code Integrity"
    "3610EDA5-77EF-11D2-8DC5-00C04FA31A66" = "Microsoft Disk Quota"
    "C631DF4C-088F-4156-B058-4375F0853CD8" = "Microsoft Offline Files"
    "F6E72D5A-6ED3-43D9-9710-4440455F6934" = "Policy Maker 2"
    "F27A6DA8-D22B-4179-A042-3D715F9E75B5" = "Policy Maker 3"
    "F17E8B5B-78F2-49A6-8933-7B767EDA5B41" = "Policy Maker 4"
    "F0DB2806-FD46-45B7-81BD-AA3744B32765" = "Policy Maker 5"
    "F581DAE7-8064-444A-AEB3-1875662A61CE" = "Policy Maker 6"
    "F648C781-42C9-4ED4-BB24-AEB8853701D0" = "Policy Maker 7"
    "FD2D917B-6519-4BF7-8403-456C0C64312F" = "Policy Maker 8"
    "FFC64763-70D2-45BC-8DEE-7ACAF1BA7F89" = "Policy Maker 9"
    "47BA4403-1AA0-47F6-BDC5-298F96D1C2E3" = "Policy Maker Print Policy"
    "728EE579-943C-4519-9EF7-AB56765798ED" = "Group Policy Data Sources"
    "1A6364EB-776B-4120-ADE1-B63A406A76B5" = "Group Policy Devices"
    "5794DAFD-BE60-433F-88A2-1A31939AC01F" = "Group Policy Drives"
    "0E28E245-9368-4853-AD84-6DA3BA35BB75" = "Group Policy Environment Variables"
    "7150F9BF-48AD-4DA4-A49C-29EF4A8369BA" = "Group Policy Files"
    "A3F3E39B-5D83-4940-B954-28315B82F0A8" = "Group Policy Folder Options"
    "74EE6C03-5363-4554-B161-627540339CAB" = "Group Policy Ini Files"
    "E47248BA-94CC-49C4-BBB5-9EB7F05183D0" = "Group Policy Internet Settings"
    "17D89FEC-5C44-4972-B12D-241CAEF74509" = "Group Policy Local Users and Groups"
    "3A0DBA37-F8B2-4356-83DE-3E90BD5C261F" = "Group Policy Network Options"
    "6A4C88C6-C502-4F74-8F60-2CB23EDC24E2" = "Group Policy Network Shares"
    "E62688F0-25FD-4C90-BFF5-F508B9D2E31F" = "Group Policy Power Options"
    "BC75B1ED-5833-4858-9BB8-CBF0B166DF9D" = "Group Policy Printers"
    "E5094040-C46C-4115-B030-04FB2E545B00" = "Group Policy Regional Options"
    "B087BE9D-ED37-454F-AF9C-04291E351182" = "Group Policy Registry"
    "AADCED64-746C-4633-A97C-D61349046527" = "Group Policy Scheduled Tasks"
    "91FBB303-0CD5-4055-BF42-E512A681B325" = "Group Policy Services"
    "C418DD9D-0D14-4EFB-8FBF-CFE535C8FAC7" = "Group Policy Shortcuts"
    "E4F48E54-F38D-4884-BFB9-D4D2E5729C18" = "Group Policy Start Menu"
    "1612B55C-243C-48DD-A449-FFC097B19776" = "User Group Policy Data Sources"
    "1B767E9A-7BE4-4D35-85C1-2E174A7BA951" = "User Group Policy Devices"
    "2EA1A81B-48E5-45E9-8BB7-A6E3AC170006" = "User Group Policy Drives"
    "35141B6B-498A-4CC7-AD59-CEF93D89B2CE" = "User Group Policy Environment Variables"
    "3BAE7E51-E3F4-41D0-853D-9BB9FD47605F" = "User Group Policy Files"
    "3BFAE46A-7F3A-467B-8CEA-6AA34DC71F53" = "User Group Policy Folder Options"
    "3EC4E9D3-714D-471F-88DC-4DD4471AAB47" = "User Group Policy Folders"
    "516FC620-5D34-4B08-8165-6A06B623EDEB" = "User Group Policy Ini Files"
    "5C935941-A954-4F7C-B507-885941ECE5C4" = "User Group Policy Internet Settings"
    "79F92669-4224-476C-9C5C-6EFB4D87DF4A" = "User Group Policy Local Users and Groups"
    "949FB894-E883-42C6-88C1-29169720E8CA" = "User Group Policy Network Options"
    "BFCBBEB0-9DF4-4C0C-A728-434EA66A0373" = "User Group Policy Network Shares"
    "9AD2BAFE-63B4-4883-A08C-C3C6196BCAFD" = "User Group Policy Power Options"
    "A8C42CEA-CDB8-4388-97F4-5831F933DA84" = "User Group Policy Printers"
    "B9CCA4DE-E2B9-4CBD-BF7D-11B6EBFBDDF7" = "User Group Policy Regional Options"
    "BEE07A6A-EC9F-4659-B8C9-0B1937907C83" = "User Group Policy Registry"
    "CAB54552-DEEA-4691-817E-ED4A4D1AFC72" = "User Group Policy Scheduled Tasks"
    "CC5746A9-9B74-4BE5-AE2E-64379C86E0E4" = "User Group Policy Services"
    "CEFFA6E2-E3BD-421B-852C-6F6A79A59BC1" = "User Group Policy Shortcuts"
    "CF848D48-888D-4F45-B530-6A201E62A605" = "User Group Policy Start Menu"
    "35378EAC-683F-11D2-A89A-00C04FBBCFA2" = "Registry"
    "3060E8CE-7020-11D2-842D-00C04FA372D4" = "Remote Installation Services"
    "40B66650-4972-11D1-A7CA-0000F87571E3" = "Scripts (Logon/Logoff) Run Restriction"
    "827D319E-6EAC-11D2-A4EA-00C04F79F83A" = "Security"
    "942A8E4F-A261-11D1-A760-00C04FB9603F" = "Software Installation"
    "BACF5C8A-A3C7-11D1-A760-00C04FB9603F" = "User Software Installation Run Restriction"
    "CDEAFC3D-948D-49DD-AB12-E578BA4AF7AA" = "TCPIP"
    "D02B1F72-3407-48AE-BA88-E8213C6761F1" = "Policy Settings"
    "0F6B957D-509E-11D1-A7CC-0000F87571E3" = "Policy Settings Run Restriction"
    "D02B1F73-3407-48AE-BA88-E8213C6761F1" = "User Policy Settings"
    "0F6B957E-509E-11D1-A7CC-0000F87571E3" = "User Policy Settings Run Restriction"
    "2BFCC077-22D2-48DE-BDE1-2F618D9B476D" = "AppV Policy"
    "0ACDD40C-75AC-47AB-BAA0-BF6DE7E7FE63" = "Wireless Group Policy"
    "169EBF44-942F-4C43-87CE-13C93996EBBE" = "UEV Policy"
    "16BE69FA-4209-4250-88CB-716CF41954E0" = "Central Access Policy Configuration"
    "2A8FDC61-2347-4C87-92F6-B05EB91A201A" = "MitigationOptions"
    "346193F5-F2FD-4DBD-860C-B88843475FD3" = "ConfigMgr User State Management Extension"
    "426031C0-0B47-4852-B0CA-AC3D37BFCB39" = "QoS Packet Scheduler"
    "42B5FAAE-6536-11D2-AE5A-0000F87571E3" = "Scripts"
    "4B7C3B0F-E993-4E06-A241-3FBE06943684" = "Per-process Mitigation Options"
    "4BCD6CDE-777B-48B6-9804-43568E23545D" = "Remote Desktop USB Redirection"
    "4D2F9B6F-1E52-4711-A382-6A8B1A003DE6" = "RemoteApp and Desktop Connections"
    "4D968B55-CAC2-4FF5-983F-0A54603781A3" = "Work Folders"
    "7909AD9E-09EE-4247-BAB9-7029D5F0A278" = "MDM Policy"
    "7933F41E-56F8-41D6-A31C-4148A711EE93" = "Windows Search Group Policy Extension"
    "BA649533-0AAC-4E04-B9BC-4DBAE0325B12" = "Windows To Go Startup Options"
    "C34B2751-1CF4-44F5-9262-C3FC39666591" = "Windows To Go Hibernate Options"
    "C50F9585-D8AD-46D4-8A81-940406C4D8A6" = "Application Manager"
    "CFF649BD-601D-4361-AD3D-0FC365DB4DB7" = "Delivery Optimization GP extension"
    "D76B9641-3288-4F75-942D-087DE603E3EA" = "AdmPwd (Administrator Password)"
    "F312195E-3D9D-447A-A3F5-08DFFA24735E" = "Virtualization Based Security (VBS)"
    "FBF687E6-F063-4D9F-9F4F-FD9A26ACDD5F" = "Connectivity Platform (PCPP)"
    "FC491EF1-C4AA-4CE1-B329-414B101DB823" = "Code Integrity (CI) policy"
    "9F02E2F5-5A41-4D1A-B473-4617E84BC957" = "Windows Protected Print Mode (WPP)"
    "B05566AC-FE9C-4368-BE01-7A4CBB6CBA11" = "WindowsFirewall"
    "53D6AB1B-2488-11D1-A28C-00C04FB94F17" = "EFS Policy"
    "0F3F3735-573D-9804-99E4-AB2A69BA5FD4" = "Computer Policy Setting"
    "40B6664F-4972-11D1-A7CA-0000F87571E3" = "Scripts (Startup/Shutdown)"
}

# Function to test a CSE pair and determine if it's problematic
function Test-CsePair {
    param (
        [hashtable]$Pair,
        [string]$Type = "Machine"
    )
    
    $primaryGuid = $Pair.PrimaryGuid
    $primaryGuidNoBraces = $Pair.PrimaryGuidNoBraces
    
    # Get CSE name from hardcoded mapping
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
        Write-Host "Testing completed for $cseName $primaryGuid" -ForegroundColor Cyan
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
Write-Log "Beginning systematic testing of CSE GUID pairs..."
& $f1

$problematicGuidPairs = @()
$testedGuidPairs = @{}

# Variable to track if user explicitly exited from the menu
$userExitedFromMenu = $false

# Handle testing based on selected mode
if ($Mode -eq "Auto") {
    # Automatic mode - test each GUID pair in sequence
    
    # First, test each Machine CSE GUID pair
    foreach ($pair in $machineGuidPairs) {
        $result = Test-CsePair -Pair $pair -Type "Machine"
        
        if (-not $result.HasError) {
            Write-Log "Found problematic Machine CSE: $($result.CSEName) $($pair.PrimaryGuid)" -Success
            $problematicGuidPairs += $result
            $testedGuidPairs[$pair.PrimaryGuid] = $false
            break
        } else {
            $testedGuidPairs[$pair.PrimaryGuid] = $true
        }
    }

    # If no problematic Machine CSE was found, test User CSEs
    if ($problematicGuidPairs.Count -eq 0) {
        foreach ($pair in $userGuidPairs) {
            $result = Test-CsePair -Pair $pair -Type "User"
            
            if (-not $result.HasError) {
                Write-Log "Found problematic User CSE: $($result.CSEName) $($pair.PrimaryGuid)" -Success
                $problematicGuidPairs += $result
                $testedGuidPairs[$pair.PrimaryGuid] = $false
                break
            } else {
                $testedGuidPairs[$pair.PrimaryGuid] = $true
            }
        }
    }
} else {
    # Manual mode - Create a list of all CSE pairs with proper identification
    $allCsePairs = @()
    
    # Add machine CSEs to the list
    foreach ($pair in $machineGuidPairs) {
        $primaryGuidNoBraces = $pair.PrimaryGuidNoBraces
        $cseName = "Unknown CSE"
        
        if ($cseMapping.ContainsKey($primaryGuidNoBraces)) {
            $cseName = $cseMapping[$primaryGuidNoBraces]
        }
        
        $allCsePairs += [PSCustomObject]@{
            Type = "Machine"
            CSEName = $cseName
            GuidPair = $pair
            PrimaryGuid = $pair.PrimaryGuid
            IsProblematic = $null
            Tested = $false
        }
    }
    
    # Add user CSEs to the list
    foreach ($pair in $userGuidPairs) {
        $primaryGuidNoBraces = $pair.PrimaryGuidNoBraces
        $cseName = "Unknown CSE"
        
        if ($cseMapping.ContainsKey($primaryGuidNoBraces)) {
            $cseName = $cseMapping[$primaryGuidNoBraces]
        }
        
        $allCsePairs += [PSCustomObject]@{
            Type = "User"
            CSEName = $cseName
            GuidPair = $pair
            PrimaryGuid = $pair.PrimaryGuid
            IsProblematic = $null
            Tested = $false
        }
    }
    
    # Loop until user chooses to exit
    $continueTests = $true
    while ($continueTests) {
        # Display menu with numbered list of all CSEs
        & $f1
        Write-Host "Select a CSE to test from the list below:" -ForegroundColor Cyan
        & $f1
        
        # Find the longest CSE name to determine column width
        $longestNameLength = 0
        foreach ($cse in $allCsePairs) {
            $nameLength = "$($cse.Type) CSE: $($cse.CSEName)".Length
            if ($nameLength -gt $longestNameLength) {
                $longestNameLength = $nameLength
            }
        }
        
        # Add padding for nice columns - ensure all GUIDs start from the same position
        $columnPadding = $longestNameLength + 5
        
        # Calculate the width needed for the item numbers
        $numberWidth = [math]::Max(2, [math]::Floor([math]::Log10($allCsePairs.Count)) + 1)
        
        for ($i = 0; $i -lt $allCsePairs.Count; $i++) {
            $statusMarker = " "
            $statusColor = "White"
            
            if ($allCsePairs[$i].Tested) {
                if ($allCsePairs[$i].IsProblematic) {
                    $statusMarker = "!"
                    $statusColor = "Red"
                } else {
                    $statusMarker = "√"
                    $statusColor = "Green"
                }
            }
            
            # Format the numbering with right alignment based on the max width
            $itemNumber = "$($i+1).".PadLeft($numberWidth + 1)
            
            # Format the CSE info
            $cseInfo = "$($allCsePairs[$i].Type) CSE: $($allCsePairs[$i].CSEName)"
            $paddedInfo = $cseInfo.PadRight($columnPadding)
            
            # Display with aligned columns
            Write-Host $itemNumber -NoNewline
            Write-Host " [$statusMarker]" -ForegroundColor $statusColor -NoNewline
            Write-Host " $paddedInfo" -NoNewline
            Write-Host "$($allCsePairs[$i].PrimaryGuid)"
        }
        
        Write-Host "0. Exit testing and proceed to summary" -ForegroundColor Yellow
        Write-Host "L. Enable/Configure enhanced GP logging" -ForegroundColor Cyan
        
        # Get user selection
        $selection = Read-Host "Enter the number of the CSE to test (0 to exit, L for logging)"
        
        # Check for logging option
        if ($selection -eq "L") {
            $loggingOption = Read-Host "Select logging option: (E)nable, (D)isable, or (V)iew current log"
            
            if ($loggingOption -eq "E") {
                Enable-GPLogging
            } elseif ($loggingOption -eq "D") {
                Disable-GPLogging
            } elseif ($loggingOption -eq "V" -and (Test-Path "$env:windir\debug\usermode\gpsvc.log")) {
                Start-Process powershell -ArgumentList "-NoExit -Command `"Get-Content '$env:windir\debug\usermode\gpsvc.log' -Wait -Tail 50 | Where-Object {`$_ -ne ''}`"" -WindowStyle Normal
            } else {
                Write-Log "Invalid logging option or log file not found." -Warning
            }
            continue
        }
        
        $selectionNum = 0
        
        # Validate input
        if ([int]::TryParse($selection, [ref]$selectionNum)) {
            if ($selectionNum -eq 0) {
                $continueTests = $false
                $userExitedFromMenu = $true  # Set this flag to indicate explicit exit
                Write-Log "User chose to stop testing and proceed to summary."
                continue
            } elseif ($selectionNum -gt 0 -and $selectionNum -le $allCsePairs.Count) {
                $selectedIndex = $selectionNum - 1
                $selectedCse = $allCsePairs[$selectedIndex]
                
                # Test the selected CSE
                $result = Test-CsePair -Pair $selectedCse.GuidPair -Type $selectedCse.Type
                
                # Update the testing status
                $allCsePairs[$selectedIndex].Tested = $true
                $allCsePairs[$selectedIndex].IsProblematic = -not $result.HasError
                
                # If problematic, add to the list
                if (-not $result.HasError) {
                    Write-Log "Found problematic $($selectedCse.Type) CSE: $($selectedCse.CSEName) $($selectedCse.PrimaryGuid)" -Success
                    $problematicGuidPairs += $result
                    $testedGuidPairs[$selectedCse.PrimaryGuid] = $false
                } else {
                    $testedGuidPairs[$selectedCse.PrimaryGuid] = $true
                }
                
                # Ask if user wants to test another CSE
                Write-Host ""
                Write-Host "Test completed for $($selectedCse.CSEName)" -ForegroundColor Cyan
                Write-Host "Select another CSE to test from the menu or enter 0 to proceed to summary." -ForegroundColor Cyan
            } else {
                Write-Log "Invalid selection. Please enter a number between 0 and $($allCsePairs.Count)." -Warning
            }
        } else {
            Write-Log "Invalid input. Please enter a number or 'L' for logging options." -Warning
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
        
        Write-Log "Problematic CSE identified: $($item.CSEName) $primaryGuid" -Success
        Write-Log "Type: $($item.Type) CSE"
        
        # Offer advice based on the CSE
        switch -Wildcard ($item.CSEName) {
            "Registry*" {
                Write-Log "This CSE handles registry-based policy settings. Issues might be related to corrupted registry policies." -Warning
            }
            "Scripts*" {
                Write-Log "This CSE handles startup/shutdown and logon/logoff scripts. Check for missing or problematic scripts." -Warning
            }
            "Security*" {
                Write-Log "This CSE handles security settings. There might be conflicting or corrupted security policies." -Warning
            }
            "Software Installation*" {
                Write-Log "This CSE handles software installation policies. Check for broken application deployment settings." -Warning
            }
            "Folder Redirection*" {
                Write-Log "This CSE handles folder redirection. Check for invalid paths or permissions issues." -Warning
            }
            "Audit Policy*" {
                Write-Log "This CSE handles audit policy settings. There might be conflicting or corrupted audit policies." -Warning
            }
            "RemoteApp*" {
                Write-Log "This CSE handles RemoteApp and Desktop Connections settings. There might be issues with RDS configurations." -Warning
            }
            "WindowsFirewall*" {
                Write-Log "This CSE handles Windows Firewall settings. There might be conflicts or corrupted firewall policies." -Warning
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
    Write-Host "3. Enable enhanced GP logging and try again" -ForegroundColor Cyan
    $choice = Read-Host "Enter your choice (1-3)"
    
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
    } elseif ($choice -eq "3") {
        Write-Log "User chose to enable enhanced logging and try again."
        
        # Enable enhanced logging
        Enable-GPLogging
        
        # Restore original gpt.ini
        Copy-Item -Path $gptInfSession -Destination $gptInfPath -Force
        
        # Suggest running the script again
        Write-Log "Enhanced logging has been enabled. Please run the script again to continue testing with detailed logging." -Success
    } else {
        Write-Log "Invalid choice. Restoring original gpt.ini as a precaution." -Warning
        Copy-Item -Path $gptInfSession -Destination $gptInfPath -Force
    }
} else {
    Write-Log "No specific problematic CSE was identified." -Warning
    Write-Log "This could indicate a more complex issue or multiple conflicting CSEs." -Warning
    Write-Log "Consider checking for Group Policy corruption or consistency issues." -Warning
    
    # Only offer enhanced logging if not exiting from manual mode
    if ($Mode -eq "Auto" -or ($Mode -eq "Manual" -and -not $userExitedFromMenu)) {
        # Offer to enable enhanced logging
        Write-Host "Would you like to enable enhanced Group Policy logging to further troubleshoot this issue?" -ForegroundColor Yellow
        $enableLoggingNow = Read-Host "Enable enhanced logging? (Y/N)"
        
        if ($enableLoggingNow -eq "Y") {
            Enable-GPLogging
        }
    }
    
    # Restore original gpt.ini
    Copy-Item -Path $gptInfSession -Destination $gptInfPath -Force
}

& $f1
Write-Log "Group Policy CSE Debugging completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Log "Log file saved to: $((Get-Item $logFile).FullName)"
& $f1

Write-Host ""
Write-Host "Debugging process completed. See $logFile for detailed information." -ForegroundColor Green
