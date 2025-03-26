# Group Policy CSE Debugger

## Description
This tool automatically diagnoses Group Policy errors by identifying problematic Client-Side Extensions (CSEs) that cause "Invalid pointer" and other errors. It systematically tests each CSE after temporarily removing it from gpt.ini.

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
.\GPCseDebugger.ps1 [-BackupPath <path>] [-Mode <Auto|Manual>]
```

### Parameters
- **BackupPath**: (Optional) Path to an existing LGPO backup. If not specified, a new backup will be created.
- **Mode**: (Optional) Debugging mode - "Auto" or "Manual". Default is Auto.
  - **Auto**: Script runs all tests automatically and stops when it finds a problematic CSE
  - **Manual**: Script prompts after each test, allowing user the time to test if a group policy error has been resolved after disabling a CSE

### Examples
```
# Run with default settings
.\GPCseDebugger.ps1

# Run in Manual mode with existing backup, example:
.\GPCseDebugger.ps1 -BackupPath "C:\Backups\{GUID}" -Mode "Manual"
```

## How It Works
1. Creates or uses a specified Group Policy backup
2. Analyzes CSE extensions using LGPO.exe
3. Creates first run permanent backup of original \windows\system32\GroupPolicy\gpt.ini to .\GPT_Backups\
3. Systematically removes each CSE GUID pair from \windows\system32\GroupPolicy\gpt.ini
4. Tests after each removal to determine which CSE is causing the error
5. Provides specific advice based on the problematic CSE detected
6. Offers options to rebuild gpt.ini without the problematic CSE or restore original settings (read disclaimer below)

## Log Files
The script maintains a detailed log file (GpoTest.log) that records all actions and findings. Each new session is appended to this log with a timestamp.

# DISCLAIMER: 

This tool is for diagnostic and debugging purposes to isolate the source of Group Policy errors. Removing problematic CSEs resolves pointer errors but disables related Group Policy functionality. This approach addresses symptoms rather than root causes, and policy settings controlled by removed CSEs will no longer apply. Consider this a temporary solution for diagnostic purposes only. For production environments, thoroughly document affected policies and consider rebuilding Group Policies through official management channels once the source of corruption is identified.
