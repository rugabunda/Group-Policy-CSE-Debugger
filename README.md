## Group Policy CSE Debugger

### Description
The GPCseDebugger streamlines the diagnosing of Microsoft Windows Group Policy errors by pinpointing problematic Client-Side Extensions (CSEs) responsible for issues such as "Invalid pointer" errors. This tool employs a systematic approach by sequentially removing CSE GUIDs from gpt.ini to isolate the faulty extension. Furthermore, it enables users to individually disable extensions to resolve issues and activates advanced Group Policy Object (GPO) logging for comprehensive troubleshooting and analysis.

### Usage
```powershell
.\GPCseDebugger.ps1 [-Mode <Auto|Manual>] [-EnableLogging] [-DisableLogging]
```

#### Parameters
- **Mode**: (Optional) Debugging mode - "Auto" or "Manual". Default is Auto.
  - **Auto**: Script runs all tests automatically and stops when it finds a problematic CSE
  - **Manual**: Script prompts after each test, allowing user the time to test if a group policy error has been resolved after disabling a CSE
- **EnableLogging**: (Optional) Enables enhanced Group Policy logging for detailed troubleshooting.
- **DisableLogging**: (Optional) Disables enhanced Group Policy logging and removes related files.

#### Examples
```powershell
# Run with default settings
.\GPCseDebugger.ps1

# Run in Manual mode
.\GPCseDebugger.ps1 -Mode "Manual"

# Run with enhanced Group Policy logging enabled
.\GPCseDebugger.ps1 -EnableLogging
```

### How It Works
1. Analyzes CSE extensions
2. Creates first run permanent backup of original \windows\system32\GroupPolicy\gpt.ini to .\GPT_Backups\
3. Systematically removes each CSE GUID pair from \windows\system32\GroupPolicy\gpt.ini
4. Tests after each removal to determine which CSE is causing the error
5. Provides specific advice based on the problematic CSE detected
6. Offers options to rebuild gpt.ini without the problematic CSE or restore original settings (read disclaimer below)

### Log Files
The script maintains a detailed log file (GpoTest.log) that records all actions and findings. Each new session is appended to this log with a timestamp.

### Screenshots
![Screenshot1](screenshots/1.jpg)
![Screenshot2](screenshots/2.jpg)

### DISCLAIMER

This tool is for diagnostic and debugging purposes to isolate the source of Group Policy errors. Removing problematic CSEs resolves pointer errors but disables related Group Policy functionality. Do not disable group policy functionality without first knowing the security implications.  This tool requires elevation/admin rights. 

Resources for additional troubleshooting:
- https://learn.microsoft.com/en-us/archive/blogs/askds/a-treatise-on-group-policy-troubleshootingnow-with-gpsvc-log-analysis
- https://learn.microsoft.com/en-us/answers/questions/120736/gpos-not-applied-ad-group-issue.html
- http://www.sysprosoft.com/policyreporter.shtml
