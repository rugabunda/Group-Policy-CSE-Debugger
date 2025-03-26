# Group Policy CSE Debugger

## Description
This tool automatically diagnoses Group Policy errors by identifying problematic Client-Side Extensions (CSEs) that cause "Invalid pointer" errors. It systematically tests each CSE by temporarily removing it from gpt.ini and testing f the error disappears.

## Requirements
- Windows system with Group Policy functionality
- LGPO.exe from the Microsoft Security Compliance Toolkit (must be in the same directory as the script)
- Administrator privileges

## Installation
1. Download LGPO.exe from the Microsoft Security Compliance Toolkit
2. Place LGPO.exe in the same directory as the script
3. Run the script with administrator privileges

## Usage
```
.\
.\GPCseDebugger.ps1 [-BackupPath <path>] [-Mode <Auto|Manual>]
```

### Parameters
- **BackupPath**: (Optional) Path to an existing LGPO backup. If not specified, a new backup will be created.
- **Mode**: (Optional) Debugging mode - "Auto" or "Manual". Default is Auto.
  - **Auto**: Script runs all tests automatically and stops when it finds a problematic CSE
  - **Manual**: Script prompts after each test, allowing user to determine if error has been resolved

### Examples
```
# Run with default settings (Auto mode, new backup)
.\GPCseDebugger.ps1

# Run in Manual mode with existing backup
.\GPCseDebugger.ps1 -BackupPath "D:\Backups\{GUID-FOLDER}" -Mode "Manual"
```

## How It Works
1. Tests for Group Policy pointer errors
2. Creates or uses a specified Group Policy backup
3. Analyzes CSE extensions using LGPO.exe
4. Systematically removes each CSE GUID pair from gpt.ini
5. Tests after each removal to determine which CSE is causing the error
6. Provides specific advice based on the problematic CSE detected
7. Offers options to rebuild gpt.ini without the problematic CSE or restore original settings

## Log Files
The script maintains a detailed log file (GpoTest.log) that records all actions and findings. Each new session is appended to this log with a timestamp.
