"""Helper: append Collections 3 and 4."""
chunk = r'''

MEMORY_FORENSICS = [
    {
        "title": "Volatility 3 Framework — Installation, Plugins, Profiles",
        "tags": ["volatility", "memory-forensics", "dfir", "incident-response"],
        "content": """# Volatility 3 Framework — Installation, Plugins, Profiles

## Installation

```bash
# Python 3.8+ required
pip install volatility3

# Or from source:
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip install -r requirements.txt
python vol.py -h

# Install additional dependencies for full plugin support:
pip install pycryptodome yara-python capstone
```

## Symbol Tables (replacing Profiles in Vol2)

Volatility 3 requires symbol tables (ISF files) for Windows/Linux/macOS.

```bash
# Windows symbols auto-downloaded from Microsoft Symbol Server
# First run against a Windows image: Volatility downloads needed symbols
# Cached in: ~/.cache/volatility3/symbols/

# For offline/air-gapped environments:
# Download pre-built symbol packs from:
# https://downloads.volatilityfoundation.org/volatility3/symbols/

# Extract to:
# volatility3/symbols/windows/
# volatility3/symbols/linux/
# volatility3/symbols/mac/
```

## Basic Usage

```bash
# All commands follow this pattern:
vol.py -f memory.raw <os_namespace>.<plugin_name> [args]

# Windows:
vol.py -f memory.raw windows.info                 # OS version, build
vol.py -f memory.raw windows.pslist               # Running processes
vol.py -f memory.raw windows.pstree               # Process tree
vol.py -f memory.raw windows.psscan               # Pool-tag scan (bypasses DKOM)
vol.py -f memory.raw windows.cmdline              # Command lines of each process
vol.py -f memory.raw windows.dlllist --pid 1234   # DLLs for specific process
vol.py -f memory.raw windows.handles --pid 1234   # Open handles
vol.py -f memory.raw windows.netscan              # Network connections

# Linux:
vol.py -f memory.raw linux.pslist
vol.py -f memory.raw linux.bash                   # Bash history from memory
vol.py -f memory.raw linux.netstat

# Mac:
vol.py -f memory.raw mac.pslist
vol.py -f memory.raw mac.bash
```

## Essential Plugin Reference

### Process Plugins

```bash
# pslist — active process list from EPROCESS linked list
vol.py -f memory.raw windows.pslist
# Fields: PID, PPID, ImageFileName, Offset, Threads, Handles, CreateTime, ExitTime

# psscan — pool-tag scan (finds DKOM-hidden processes)
vol.py -f memory.raw windows.psscan
# Cross-reference with pslist to find hidden processes:
# diff <(vol.py -f mem.raw windows.pslist) <(vol.py -f mem.raw windows.psscan)

# pstree — hierarchical view (reveals unusual parent-child)
vol.py -f memory.raw windows.pstree
# Legitimate: svchost.exe parent = services.exe
# Suspicious: svchost.exe parent = explorer.exe or cmd.exe

# cmdline — command lines (reveals PowerShell, encoded commands, etc.)
vol.py -f memory.raw windows.cmdline
# Look for: -EncodedCommand, -exec bypass, -WindowStyle Hidden
```

### Network Plugins

```bash
# netscan — active and recently closed connections
vol.py -f memory.raw windows.netscan
# Shows: Protocol, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner

# netstat (older Windows)
vol.py -f memory.raw windows.netstat
```

### Memory and Injection Plugins

```bash
# malfind — find injected code regions (RWX pages with PE headers)
vol.py -f memory.raw windows.malfind
vol.py -f memory.raw windows.malfind --pid 1234  # Filter by PID
# Output: memory regions with executable+writable protection + MZ header or shellcode

# vadinfo — Virtual Address Descriptor tree (normal memory layout)
vol.py -f memory.raw windows.vadinfo --pid 1234

# dumpfiles — dump file objects from memory cache
vol.py -f memory.raw windows.dumpfiles --pid 1234
vol.py -f memory.raw windows.dumpfiles --virtaddr 0xfffff800deadbeef

# memmap — physical/virtual address mapping
vol.py -f memory.raw windows.memmap --pid 1234 --dump
```

### Registry Plugins

```bash
vol.py -f memory.raw windows.registry.hivelist         # All loaded registry hives
vol.py -f memory.raw windows.registry.printkey \
    --key "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"  # Dump specific key

vol.py -f memory.raw windows.registry.userassist       # UserAssist (recently run programs)
vol.py -f memory.raw windows.registry.shimcache        # Application Compatibility Cache
```

### Driver and Kernel Plugins

```bash
vol.py -f memory.raw windows.driverscan               # All drivers (including hidden)
vol.py -f memory.raw windows.driverirp                # IRP handler addresses
vol.py -f memory.raw windows.ssdt                     # SSDT entries
vol.py -f memory.raw windows.modules                  # Loaded kernel modules
```

## Output Formats

```bash
# Default: table output
vol.py -f memory.raw windows.pslist

# JSON output (for scripting/SIEM ingestion):
vol.py -f memory.raw windows.pslist --output json > pslist.json

# Pipe to grep for quick filtering:
vol.py -f memory.raw windows.netscan | grep "ESTABLISHED"
vol.py -f memory.raw windows.cmdline | grep -i "encoded\|bypass\|hidden"
```

## Automating Analysis

```bash
# Quick triage script — run all key plugins:
for plugin in pslist psscan pstree cmdline netscan malfind dlllist; do
    echo "=== $plugin ===" >> report.txt
    vol.py -f memory.raw windows.$plugin >> report.txt 2>&1
done

# Compare pslist vs psscan for DKOM-hidden processes:
vol.py -f memory.raw windows.pslist  --output json | python3 -c "
import json,sys
pslist = {p['PID'] for p in json.load(sys.stdin)}
"
vol.py -f memory.raw windows.psscan --output json | python3 -c "
import json,sys
psscan = {p['PID'] for p in json.load(sys.stdin)}
# PIDs in psscan but not pslist = hidden
"
```
""",
    },
    {
        "title": "Process Analysis — pslist, pstree, Process Hollowing Detection",
        "tags": ["volatility", "process-analysis", "process-hollowing", "memory-forensics", "dfir"],
        "content": """# Process Analysis — pslist, pstree, Process Hollowing Detection

## Process Data Structures

### EPROCESS in Windows

The `EPROCESS` kernel structure represents each process. Key offsets:

```
UniqueProcessId       — PID
InheritedFromUniqueProcessId — PPID
ImageFileName[15]     — Process name (truncated to 15 chars)
ActiveProcessLinks    — Doubly-linked list (DKOM manipulates this)
VadRoot               — Virtual Address Descriptor tree root
Token                 — Access token (privileges)
CreateTime/ExitTime   — Process lifetime
Peb                   — Pointer to user-mode PEB
```

## Process Listing Analysis

```bash
# pslist (EPROCESS ActiveProcessLinks traversal):
vol.py -f memory.raw windows.pslist
# Output columns: PID, PPID, ImageFileName, Offset(V), Threads, Handles, Session, Wow64, CreateTime

# psscan (pool tag scan — bypasses DKOM):
vol.py -f memory.raw windows.psscan

# Find hidden processes (in psscan but not pslist):
comm -23 \
  <(vol.py -f mem.raw windows.psscan  | awk '{print $1}' | sort) \
  <(vol.py -f mem.raw windows.pslist  | awk '{print $1}' | sort)
```

## Suspicious Process Indicators

### Unusual Parent-Child Relationships

```
LEGITIMATE:
  System (4) → smss.exe (child)
  smss.exe → wininit.exe, winlogon.exe, csrss.exe
  wininit.exe → services.exe, lsass.exe
  services.exe → svchost.exe (multiple)
  explorer.exe → user applications

SUSPICIOUS:
  svchost.exe spawned by explorer.exe or cmd.exe
  lsass.exe spawned by anything other than wininit.exe
  powershell.exe spawned by Word, Excel, Acrobat
  cmd.exe spawned by svchost.exe with no obvious service
  mshta.exe, wscript.exe, cscript.exe spawned by Office
```

```bash
# Inspect parent-child with pstree:
vol.py -f memory.raw windows.pstree
# Look for: lateral branches that shouldn't exist
# cmd.exe child of svchost.exe
# powershell.exe child of WINWORD.EXE
```

### Masquerading (Name Spoofing)

```bash
# Malware names itself like legitimate processes:
# svchost32.exe, svch0st.exe, lsass_.exe, csrss_.exe, explorer_.exe

# Check via cmdline for full path:
vol.py -f memory.raw windows.cmdline | grep -i "svchost\|lsass\|csrss"
# Legitimate: C:\Windows\System32\svchost.exe
# Suspicious: C:\Users\user\AppData\Temp\svchost.exe

# Also check process path against expected locations:
vol.py -f memory.raw windows.dlllist | grep ImageFileName
# WINWORD.EXE should be in C:\Program Files\Microsoft Office\
# Anything in %TEMP%, %APPDATA%, C:\ProgramData\ is suspicious
```

## Process Hollowing Detection

Process hollowing: legitimate process started suspended, original code unmapped, malicious code written and resumed.

### Indicators

```bash
# 1. malfind — finds executable memory regions that look injected:
vol.py -f memory.raw windows.malfind
# Shows: Pid, Process, Protection, VadTag, Hexdump, Disassembly
# Key: regions with 'PAGE_EXECUTE_READWRITE' or containing MZ header

# 2. VAD analysis — hollowed process has unusual VAD entries:
vol.py -f memory.raw windows.vadinfo --pid <suspicious_pid>
# Legitimate svchost: .exe and .dll mapped files with read-exec protection
# Hollowed: private allocations (VadS tag, no filename) that are executable

# 3. Dump and compare:
vol.py -f memory.raw windows.procdump --pid <pid>
# Then: file, strings, YARA scan on dumped .exe
```

### VAD Tag Reference

| Tag | Meaning |
|---|---|
| Vad | Standard VAD node |
| VadS | Short VAD — private allocation (no mapped file) |
| VadF | Long VAD with mapped file |
| VadL | Not used in recent Windows |

```bash
# VadS (private allocation) that is executable = classic injection indicator
vol.py -f memory.raw windows.vadinfo --pid 1234 | grep -A3 "VadS"
# If protection = EXECUTE_READWRITE and size is large → dump it

# Dump specific VAD region:
vol.py -f memory.raw windows.dumpfiles --virtaddr <vad_start>
```

## Detecting Specific Injection Techniques

### Classic DLL Injection (CreateRemoteThread + LoadLibrary)

```bash
# Evidence:
# - Source process has handles to target process (OpenProcess)
# - Target process has unexpected DLL in its module list

vol.py -f memory.raw windows.handles --pid <injecting_pid> | grep Process
# Shows open process handles

vol.py -f memory.raw windows.dlllist --pid <target_pid>
# Look for DLLs in unusual paths (TEMP, APPDATA) or unsigned DLLs
```

### Process Doppelganging

A newer technique using Windows TxF (transactional NTFS) to load malware.

```bash
# malfind won't always catch it
# Look for: discrepancy between ImageFileName and actual loaded code
# Use dumpfiles to extract the mapped image and compare hash to expected

vol.py -f memory.raw windows.dumpfiles --pid <pid> --dump
sha256sum file.*.exe
# Compare to known-good hash of svchost.exe
```

### Reflective DLL Injection

```bash
# Reflective DLL has its own loader; never appears in module list
# malfind catches it as a private RWX region with MZ header:
vol.py -f memory.raw windows.malfind
# Hexdump shows: 4d 5a (MZ) in a private allocation
# Dump and analyze as PE
```

## Process Memory Dump and Analysis

```bash
# Dump entire process virtual address space:
vol.py -f memory.raw windows.memmap --pid 1234 --dump
# Creates pid.1234.dmp

# Dump just the .exe:
vol.py -f memory.raw windows.procdump --pid 1234

# Dump all loaded DLLs:
vol.py -f memory.raw windows.dlllist --pid 1234 --dump

# Then analyze dumps:
file pid.1234.dmp
strings pid.1234.dmp | grep -E "http|https|cmd|powershell"
yara -r rules/ pid.1234.dmp
```
""",
    },
    {
        "title": "Detecting Code Injection — malfind, VAD Analysis, Hollowed Processes",
        "tags": ["code-injection", "malfind", "vad", "memory-forensics", "volatility", "dfir"],
        "content": """# Detecting Code Injection — malfind, VAD Analysis, Hollowed Processes

## Code Injection Overview

Code injection is the act of writing executable code into another process's memory. It is used for privilege escalation, AV evasion, and persistence. Common techniques:

| Technique | API Used | Detection |
|---|---|---|
| Classic DLL injection | CreateRemoteThread + LoadLibrary | Unexpected DLL in dlllist |
| Shellcode injection | VirtualAllocEx + WriteProcessMemory + CreateRemoteThread | RWX VAD with no file |
| Process hollowing | CreateProcess(SUSPENDED) + ZwUnmapViewOfSection + WriteProcessMemory | VAD mismatch |
| Atom bombing | GlobalAddAtom + NtQueueApcThread | APC queue artifacts |
| Process doppelganging | TxF transaction + NtCreateProcessEx | Executable mapped from phantom file |

## malfind Plugin

`malfind` scans all processes for VAD regions that:
1. Have execute permission
2. Are private allocations (not mapped to a file)
3. Contain MZ header OR suspicious disassembly

```bash
# Scan all processes:
vol.py -f memory.raw windows.malfind

# Filter to specific process:
vol.py -f memory.raw windows.malfind --pid 1234

# Dump suspicious regions:
vol.py -f memory.raw windows.malfind --dump
# Creates files: pid.1234.vad.0xVADSTART-0xVADEND.dmp

# Sample output:
# PID: 1234, Process: svchost.exe
# Start VPN: 0x3c0000  End VPN: 0x3fffff
# Tag: VadS  Protection: PAGE_EXECUTE_READWRITE
# Hexdump: 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff ...
# Disassembly: PUSH EBP; MOV EBP, ESP; ...
```

### Interpreting malfind Results

```
MZ header at start of VadS region:
  → Injected PE (DLL or EXE)
  → Dump and analyze as PE file

Shellcode-like bytes (no MZ, but executable code):
  → Shellcode or position-independent code
  → Disassemble, look for GetProcAddress-equivalent

PAGE_EXECUTE_READ_WRITE without suspicious code:
  → May be legitimate (JIT compilers, .NET, etc.)
  → Filter by correlating with process type

False positives:
  → Browser processes (Chrome, Firefox use RWX for JIT)
  → .NET CLR creates RWX regions for JIT-compiled code
  → Exclude known PID of browsers if not under investigation
```

## VAD Tree Analysis

The Virtual Address Descriptor (VAD) tree describes the virtual memory layout of a process.

```bash
# Dump VAD tree for process:
vol.py -f memory.raw windows.vadinfo --pid 1234

# Output fields:
# VAD:      Node address in kernel
# Start:    Region start VA
# End:      Region end VA
# Tag:      VAD type (VadS = private, VadF = file-mapped)
# Protection: Memory protection flags
# CommitCharge: Pages committed
# PrivateMemory: 1 = not file-backed
# File:     Mapped file path (if any)
```

### Suspicious VAD Entries

```bash
# Find VadS regions with execute permission:
vol.py -f memory.raw windows.vadinfo --pid 1234 | \
  python3 -c "
import sys
for line in sys.stdin:
    if 'VadS' in line and ('EXECUTE' in line or 'Execute' in line):
        print(line, end='')
"

# Cross-check: process named svchost.exe should have these VadF entries:
# C:\Windows\System32\svchost.exe
# C:\Windows\System32\ntdll.dll
# C:\Windows\System32\kernel32.dll
# etc.
# Any private executable regions (VadS) in svchost = injection indicator
```

## Process Hollowing — Detailed Detection

### Technique Steps

```
1. CreateProcess("svchost.exe", CREATE_SUSPENDED)
2. ZwQueryProcessInformation to get image base
3. ZwUnmapViewOfSection to remove original executable
4. VirtualAllocEx at original base address
5. WriteProcessMemory to write malicious PE
6. SetThreadContext to update EIP to new entrypoint
7. ResumeThread
```

### Detection Method

```bash
# Step 1: Find process with suspicious name (masquerading)
vol.py -f memory.raw windows.cmdline
# Legitimate svchost: "C:\Windows\System32\svchost.exe -k NetworkService"
# Hollowed:           no args, or wrong path

# Step 2: Dump the process executable image from memory
vol.py -f memory.raw windows.procdump --pid 1234

# Step 3: Compare dump hash vs. known-good
Get-FileHash procdump_1234.exe  # or sha256sum
# Known-good svchost.exe SHA256 from a clean system

# Step 4: Check PE header vs. expected
python3 -c "
import pefile
pe = pefile.PE('procdump_1234.exe')
print(pe.dump_info()[:2000])
"
# Hollowed process will have different compile time, imports, sections

# Step 5: malfind on the specific PID
vol.py -f memory.raw windows.malfind --pid 1234
# May show RWX private allocation at image base address
```

## Detecting Specific Malware Families

### Cobalt Strike Beacon in Memory

```bash
# CS beacon leaves footprint in svchost or rundll32 memory
vol.py -f memory.raw windows.malfind --pid <pid_of_host> --dump

# YARA scan dumped regions:
yara cs_beacon.yar dump/pid.*.dmp

# cs_beacon.yar:
rule CobaltStrike_Beacon {
    strings:
        $s1 = { 69 68 69 68 }      // Watermark area
        $s2 = { FC E8 [4-8] 60 89 E5 }  // Shellcode stub
        $p1 = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        $cfg = { 00 01 00 01 00 02 }
    condition:
        ($s2 or $cfg) and filesize < 500KB
}

# Extract CS config from beacon:
# Use BeaconEye, CobaltStrikeParser, or cs-decrypt-beacon python tools
python cs-decrypt-beacon.py dump/pid.1234.vad.0x1000-0x2000.dmp
```

### Metasploit Meterpreter

```bash
# Meterpreter stages are reflectively loaded DLLs in target process
vol.py -f memory.raw windows.malfind | grep -i "metsrv\|meterpreter"

# Check for metsrv.dll or stage2 shellcode:
vol.py -f memory.raw windows.malfind --dump
strings dump/*.dmp | grep -i "metsrv\|mettle\|meterpreter"

# Check network connection from injected process:
vol.py -f memory.raw windows.netscan | grep <pid_of_injected>
# Shows ESTABLISHED connection to attacker IP on port 4444 or 443
```

## Reporting Injection Findings

```
Finding: Code Injection in svchost.exe (PID 1848)

Evidence:
1. malfind: VAD region 0x3c0000-0x43ffff
   - Tag: VadS (private, not file-backed)
   - Protection: PAGE_EXECUTE_READWRITE
   - First bytes: 4d 5a (MZ header = embedded PE)

2. procdump comparison:
   - Dumped hash: abc123...
   - Expected svchost.exe hash: def456...
   - MISMATCH confirmed

3. netscan: PID 1848 has ESTABLISHED connection to 185.220.x.x:443

4. Dumped PE analysis:
   - Imports: HttpOpenRequest, HttpSendRequest, InternetConnect
   - Strings: gate.php, Mozilla/5.0 (compatible; MSIE 9.0)
   - YARA match: CobaltStrike_Beacon

Conclusion: Process hollowing with Cobalt Strike beacon injected into svchost.exe
```
""",
    },
    {
        "title": "Extracting Credentials from Memory — LSASS Analysis, Mimikatz Artifacts",
        "tags": ["credentials", "lsass", "mimikatz", "memory-forensics", "volatility", "dfir"],
        "content": """# Extracting Credentials from Memory — LSASS Analysis, Mimikatz Artifacts

## Why LSASS Matters

`lsass.exe` (Local Security Authority Subsystem Service) manages authentication, storing credentials in memory. NT hashes, Kerberos tickets, WDigest plaintext passwords, and DPAPI master keys all reside here during a user's session.

## LSASS Process Characteristics

```bash
# Legitimate lsass.exe:
# - Single instance
# - Parent: wininit.exe
# - Path: C:\Windows\System32\lsass.exe
# - User: SYSTEM
# - No network connections (usually)

vol.py -f memory.raw windows.pstree | grep -i "wininit\|lsass"
# Should show: wininit.exe -> lsass.exe

vol.py -f memory.raw windows.cmdline | grep lsass
# Legitimate: "C:\Windows\system32\lsass.exe"
# Suspicious: additional arguments or different path
```

## Volatility Credential Extraction Plugins

```bash
# Windows NT/NTLM hashes and other cached credentials:
vol.py -f memory.raw windows.lsadump

# Cached domain credentials (DCC2 hashes):
vol.py -f memory.raw windows.cachedump

# Local SAM hashes:
vol.py -f memory.raw windows.hashdump
# Output: username:RID:LM_hash:NT_hash:::

# WDigest (plaintext on Windows <8.1 or when WDigest enabled):
# (vol3 doesn't have direct wdigest plugin — use pypykatz instead)
```

## pypykatz — Pure Python Mimikatz

```bash
pip install pypykatz

# Analyze LSASS minidump:
pypykatz lsa minidump lsass.dmp

# Analyze full memory image:
pypykatz lsa live  # (run on live system)

# With Volatility output:
# First dump LSASS process:
vol.py -f memory.raw windows.memmap --pid $(vol.py -f memory.raw windows.pslist | grep lsass | awk '{print $1}') --dump

# Then analyze with pypykatz:
pypykatz lsa minidump lsass_pid.dmp

# Output sections:
# MSV (NTLM hashes)
# WDigest (plaintext if enabled)
# Kerberos (tickets)
# DPAPI (master keys)
# SSP (Security Support Provider creds)
# LiveSSP
# Credman (Windows Credential Manager entries)
```

## Mimikatz Artifacts in Memory

When an attacker ran mimikatz on the compromised system:

```bash
# 1. Search for mimikatz strings in process dumps:
vol.py -f memory.raw windows.cmdline | grep -i "sekurlsa\|lsadump\|kerberos::list"

# 2. YARA scan for mimikatz signatures:
yara mimikatz_rules.yar memory.raw

# 3. Check for privilege escalation artifact:
# mimikatz runs "privilege::debug" before credential extraction
# This opens a handle to LSASS with PROCESS_VM_READ

vol.py -f memory.raw windows.handles | grep -i lsass
# If a non-system process has read access to LSASS = credential theft occurred
```

## LSASS Dump Artifacts

Attackers dump LSASS to extract offline:

```bash
# Common dumping methods and their artifacts:

# 1. Task Manager (Interactive):
# Creates lsass.dmp in %USERPROFILE%\AppData\Local\Temp\

# 2. ProcDump (Sysinternals):
# procdump.exe -ma lsass.exe lsass.dmp
# Command line in cmdline/event logs

# 3. comsvcs.dll (LOLBin):
# rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass_pid> lsass.dmp full
# Look for: Windows.cmdline with rundll32 + comsvcs.dll + MiniDump + lsass pid

# 4. Direct NTFS read of lsass.exe image:
# Some tools read via raw disk access to avoid process monitoring

vol.py -f memory.raw windows.cmdline | grep -iE "procdump|comsvcs|minidump|lsass"
```

## Kerberos Ticket Analysis

```bash
# Dump Kerberos tickets from memory:
vol.py -f memory.raw windows.kerberos

# Or via pypykatz:
pypykatz lsa minidump lsass.dmp | grep -A20 "Kerberos"

# Look for:
# ServiceName: krbtgt — Golden Ticket (TGT, valid for 10 years = attacker-forged)
# ServiceName: CIFS/DC01 — Silver Ticket (service ticket, no domain auth)

# Kerberoasting artifacts:
# SPN tickets for service accounts (attacker requested for offline cracking)
# Multiple TGS tickets for service accounts = Kerberoasting indicator
```

## DPAPI Master Key Recovery

```bash
# DPAPI (Data Protection API) protects stored credentials, browser passwords, etc.
# Master keys stored in memory while user logged in

# Extract DPAPI masterkeys from memory:
vol.py -f memory.raw windows.dpapi.mastekey
pypykatz dpapi prefilter memory lsass.dmp

# Use masterkey to decrypt browser passwords, WiFi credentials:
pypykatz dpapi chrome --masterkey <masterkey_guid> <chrome_login_data_path>
```

## Detecting Credential Theft in Practice

```bash
# Full workflow:
# 1. Get LSASS PID
LSASS_PID=$(vol.py -f memory.raw windows.pslist | awk '/lsass/{print $1}')

# 2. Check LSASS parent (should be wininit.exe):
vol.py -f memory.raw windows.pstree | grep -A2 "wininit"

# 3. Check handles TO lsass (who opened it?):
vol.py -f memory.raw windows.handles | grep $LSASS_PID

# 4. Dump LSASS memory:
vol.py -f memory.raw windows.memmap --pid $LSASS_PID --dump

# 5. Run pypykatz:
pypykatz lsa minidump pid.$LSASS_PID.dmp > credentials.txt

# 6. YARA for mimikatz:
yara -r /opt/yara-rules/mimikatz.yar memory.raw

# 7. Check for credential-related registry keys:
vol.py -f memory.raw windows.registry.printkey \
    --key "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"
# UseLogonCredential = 1 means plaintext passwords enabled (attacker may have set this)
```
""",
    },
    {
        "title": "Rootkit Detection — SSDT Hooks, DKOM, Hidden Processes",
        "tags": ["rootkit", "ssdt", "dkom", "hidden-processes", "memory-forensics", "volatility"],
        "content": """# Rootkit Detection — SSDT Hooks, DKOM, Hidden Processes

## Rootkit Types Overview

| Type | Privilege | Persistence Method |
|---|---|---|
| User-mode | Ring 3 | DLL injection, API hooking via IAT/EAT |
| Kernel-mode | Ring 0 | Driver load, SSDT hook, DKOM |
| Bootkit | Boot phase | MBR/VBR infection |
| UEFI | Firmware | SPI flash modification |

## DKOM — Direct Kernel Object Manipulation

DKOM hides processes by unlinking their `EPROCESS` from the `ActiveProcessLinks` doubly-linked list. The kernel uses this list for `NtQuerySystemInformation` (which Task Manager calls), so hidden processes are invisible.

### Detection

```bash
# pslist traverses ActiveProcessLinks — manipulable by DKOM
vol.py -f memory.raw windows.pslist

# psscan scans physical memory for EPROCESS pool tags — bypasses DKOM
vol.py -f memory.raw windows.psscan

# Compare: processes in psscan but not pslist = DKOM hidden
python3 << 'EOF'
import subprocess, json

def get_pids(plugin):
    result = subprocess.run(
        ["vol.py", "-f", "memory.raw", f"windows.{plugin}", "--output", "json"],
        capture_output=True, text=True
    )
    return {int(p.get("PID", p.get("Offset(V)",0))) for p in json.loads(result.stdout).get("rows",[])}

pslist = get_pids("pslist")
psscan = get_pids("psscan")

hidden = psscan - pslist
if hidden:
    print(f"DKOM HIDDEN PROCESSES: {hidden}")
else:
    print("No hidden processes detected")
EOF
```

## SSDT Hook Detection

The System Service Descriptor Table (SSDT) maps syscall numbers to kernel functions. Rootkits overwrite SSDT entries to intercept and manipulate system calls.

```bash
# Volatility SSDT plugin:
vol.py -f memory.raw windows.ssdt

# Output: for each syscall entry, shows:
# Index, Address, Module, Symbol
# Legitimate: Address falls within ntoskrnl.exe or win32k.sys range
# Hooked:     Address outside both modules = rootkit hook

# Example suspicious output:
# Index 0x0012 (NtCreateFile)
# Address 0xfffffa800a123456  <-- not in ntoskrnl!
# Module: UNKNOWN
```

### Manual SSDT Analysis

```windbg
# WinDbg commands to check SSDT:
dq nt!KiServiceTable L?0x200  # Dump all SSDT entries

# Get ntoskrnl address range:
lm m ntoskrnl
# Note: fffff80000000000 - fffff80001234567

# Any SSDT entry outside this range = hooked
.foreach (addr {dq nt!KiServiceTable L?0x200}) {
    .if (addr < 0xfffff80000000000 | addr > 0xfffff80001234567) {
        .echo SSDT HOOK at: addr
        ln addr     # Symbol name of hook
    }
}
```

## IRP Hook Detection

Input/Output Request Packet (IRP) handler hooks intercept driver communications.

```bash
# driverirp — show all IRP handler addresses:
vol.py -f memory.raw windows.driverirp

# Each driver has 28 IRP major function handlers
# Legitimate: all handlers point within the driver's own address range
# Hooked: handler points to a different module

# Example:
# Driver \Driver\Disk
# IRP_MJ_READ: 0xfffff80012345678 [Disk.sys]  <- Legitimate
# IRP_MJ_WRITE: 0xfffffa800abcdef0 [UNKNOWN]  <- HOOK!
```

## DKOM Objects Beyond Processes

Rootkits also manipulate other kernel objects:

```bash
# Hidden drivers (not in loaded module list):
vol.py -f memory.raw windows.driverscan     # Pool scan for DRIVER_OBJECT
vol.py -f memory.raw windows.modules        # ActiveDriverLinks traversal
# Drivers in driverscan but not modules = hidden

# Hidden device objects:
vol.py -f memory.raw windows.devicetree     # Device stack visualization

# Network connection hiding (hidden sockets):
vol.py -f memory.raw windows.netscan        # Pool tag scan for TCP/UDP endpoints
# Compare with netstat output from live system for discrepancies
```

## Detecting Kernel Hooks with Memory Analysis

```bash
# Check if ntoskrnl.exe in memory matches on-disk version:
# 1. Extract ntoskrnl from memory:
vol.py -f memory.raw windows.modules | grep ntoskrnl
vol.py -f memory.raw windows.dumpfiles --virtaddr <ntoskrnl_base>

# 2. Compare to clean copy from matching patch Tuesday:
vbindiff ntoskrnl_from_memory.exe C:/Windows/System32/ntoskrnl.exe

# Inline hooks: first bytes of kernel function replaced with JMP to hook
# SSDT hooks: function pointer redirected
# Both visible in memory comparison
```

## Bootkit Detection

Bootkits infect the MBR, VBR, or Windows Boot Manager.

```bash
# Extract and analyze MBR (sector 0):
python3 -c "
import struct
# If we have a raw disk image:
with open('disk.img', 'rb') as f:
    mbr = f.read(512)
# Check MBR signature: last 2 bytes should be 0x55 0xAA
print(f'MBR signature: {mbr[510:512].hex()}')  # Should be '55aa'
# Check bootstrap code: first 446 bytes
# Known clean MBR starts with: 33 C0 8E D0 (XOR AX,AX; MOV SS,AX; ...)
print(f'First bytes: {mbr[:8].hex()}')
"

# Volatility bootkit detection (Vol2 era — use similar concepts in Vol3):
# Compare MBR from memory vs. disk
# Look for INT 13h hooks (disk access interception)

# Detection tools:
# Gmer — real-time MBR check vs. disk copy
# Kaspersky TDSSKiller — TDL4/Alureon bootkit removal
```

## UEFI Rootkit Analysis

```bash
# Extract UEFI firmware from SPI flash:
# Use ch341a programmer or Intel FPT tool

# Chipsec UEFI analysis:
pip install chipsec
python chipsec_main.py -m tools.uefi.scan_image -a bios.bin

# UEFITool — parse and visualize UEFI firmware:
# https://github.com/LongSoft/UEFITool

# Indicators of UEFI rootkit (CosmicStrand, MosaicAggressor, LoJax):
# Extra modules in DXE phase with no legitimate source
# Modified EFI modules (compare checksum vs. vendor reference)
# Modules loading from unusual GUIDs
# SmmCore patching or SMM handler additions

# Verification via capsule update comparison:
# Download vendor firmware update
# Compare all DXE/PEI modules byte-by-byte with device firmware
```
""",
    },
    {
        "title": "Memory Acquisition — WinPmem, LiME, DumpIt",
        "tags": ["memory-acquisition", "winpmem", "lime", "dumpit", "dfir", "incident-response"],
        "content": """# Memory Acquisition — WinPmem, LiME, DumpIt

## Why Memory Acquisition Matters

Physical memory contains live forensic evidence unavailable on disk: running processes, network connections, decrypted payloads, credentials, and volatile malware that leaves no disk artifacts. Acquisition must be performed before system shutdown.

## Windows Memory Acquisition

### WinPmem

```
Source: https://github.com/Velocidex/WinPmem
License: Apache 2.0 — approved for incident response

# Basic acquisition:
winpmem_mini_x64_rc2.exe memory.raw

# With compression:
winpmem_mini_x64_rc2.exe --compress memory.raw.gz

# Output formats: raw, crashdump, elf coredump
winpmem_mini_x64_rc2.exe --format raw memory.raw
winpmem_mini_x64_rc2.exe --format crashdump memory.dmp   # Opens in WinDbg

# Acquire to network share (avoid writing to local disk):
winpmem_mini_x64_rc2.exe \\192.168.1.100\share\memory.raw

# Verify hash (chain of custody):
winpmem_mini_x64_rc2.exe --hash memory.raw
```

### DumpIt (Magnet Forensics)

```
# Simple double-click executable — minimal footprint
DumpIt.exe                         # Interactive prompts
DumpIt.exe /OUTPUT C:\memory.raw   # Non-interactive
DumpIt.exe /OUTPUT \\server\share\memory.raw

# DumpIt creates a SHA256 hash automatically
# Supports AVML format (Azure/cloud forensics compatible)
```

### Magnet RAM Capture

```
# Free tool from Magnet Forensics
# GUI-based, creates .mem file with hash log
# Suitable for non-technical first responders
```

### FTK Imager (Memory Acquisition)

```
AccessData FTK Imager > File > Capture Memory
Choose destination path (prefer network share or clean external drive)
Include pagefile.sys: Yes (additional volatile data)
Creates: memdump.mem + pagefile.sys + AD1 case file
```

### PowerShell via Velociraptor (Remote Acquisition)

```yaml
# VQL artifact to acquire memory remotely:
name: Windows.Memory.Acquisition
sources:
  - query: |
      LET result = execve(argv=[
          "winpmem.exe", "--format", "raw",
          "--output", "C:\\Temp\\memory.raw"
      ])
      SELECT * FROM result
```

## Linux Memory Acquisition

### LiME (Linux Memory Extractor)

```bash
# LiME is a kernel module (loadable kernel module / LKM)
# Must compile for target kernel version

# On compatible system:
apt install linux-headers-$(uname -r) build-essential
git clone https://github.com/504ensicslabs/lime.git
cd lime/src && make

# Acquire to file:
insmod lime-$(uname -r).ko "path=/tmp/memory.lime format=lime"
# output: /tmp/memory.lime (LiME format)

# Acquire to network (netcat on port 4444):
insmod lime.ko "path=tcp:4444 format=lime"
# On analysis workstation:
nc <target_ip> 4444 > memory.lime

# Formats:
# lime — LiME raw format with segment headers
# raw  — contiguous raw dump
# padded — gaps zero-padded for flat address space
```

### /proc/kcore

```bash
# Virtual file representing physical memory (requires root)
# Not reliable on all kernels — better to use LiME

# Quick extraction:
dd if=/proc/kcore of=memory.raw bs=1M
# Note: size reported may exceed physical RAM (virtual addresses included)
```

### avml (Azure/Cloud)

```bash
# Microsoft AVML — designed for cloud VMs (Azure, AWS, GCP)
# Rust-based, supports live acquisition from running VMs

wget https://github.com/microsoft/avml/releases/latest/download/avml
chmod +x avml
./avml memory.lime

# Supported formats: lime, raw
# Can upload directly to Azure Blob Storage or AWS S3:
./avml --output s3://bucket/memory.lime
```

## macOS Memory Acquisition

```bash
# osxpmem (requires SIP disabled or kernel extension signing):
sudo osxpmem memory.aff4

# Alternatively: create VMware snapshot (VMware Fusion/Parallels)
# .vmem file = RAM contents

# Note: macOS memory forensics is complex due to:
# - System Integrity Protection (SIP)
# - T2 chip encryption on newer Macs
# - Apple Silicon virtualization restrictions
```

## Chain of Custody

```
MEMORY ACQUISITION DOCUMENTATION TEMPLATE:

Case Number: IR-2025-0042
Evidence Item: Memory image of WORKSTATION-01
Acquisition Date/Time: 2025-03-15 14:32:07 UTC
Acquired By: John Smith (IR analyst)

System Information:
  Hostname: WORKSTATION-01
  OS: Windows 10 22H2 (Build 19045)
  RAM: 16 GB
  Uptime at acquisition: 3d 4h 12m

Acquisition Tool: WinPmem v4.0.rc1 (winpmem_mini_x64_rc2.exe)
Tool Hash (SHA256): [tool hash - verify before use]

Acquisition Details:
  Command: winpmem_mini_x64_rc2.exe --format raw memory.raw
  Output file: WORKSTATION-01_20250315-143207.raw
  File size: 17,179,869,184 bytes (16 GB)
  SHA256: abc123...def456

Storage: Copied to evidence drive (Seagate 1TB, S/N: XXXXXXXX)
Duplicate: Copied to network share: \\evidence-server\IR-2025-0042\

Notes:
  System was active during acquisition
  No shutdown performed (volatile data preserved)
  Malware suspected in svchost.exe (PID 1848)
```

## Volatility 3 — Opening Acquired Images

```bash
# Raw format (from WinPmem, DumpIt):
vol.py -f WORKSTATION-01.raw windows.info

# Crash dump format (from DumpIt /crashdump):
vol.py -f memory.dmp windows.info

# LiME format (Linux):
vol.py -f memory.lime linux.info

# ELF coredump:
vol.py -f memory.elf windows.info  # if Windows memory acquired as ELF

# Auto-detect format (Vol3 tries multiple):
vol.py -f memory.raw windows.info
# If no symbol match: try adding --isf /path/to/custom.json
```

## Cloud/VM Memory Acquisition

```bash
# VMware ESXi — snapshot creates .vmem file (raw memory)
# Via ESXi CLI:
vim-cmd vmsvc/snapshot.create <vmid> "ForensicSnap" "" true true
# .vmem file in VM directory

# AWS EC2 — kernel live dump via SSM:
aws ssm send-command \
  --document-name "AWS-RunPowerShellScript" \
  --targets Key=instanceids,Values=i-1234567890 \
  --parameters commands=["winpmem.exe C:\\memory.raw"]

# Azure — disk snapshot approach:
az vm run-command invoke --resource-group rg --name vm \
  --command-id RunPowerShellScript \
  --scripts "winpmem.exe C:\memory.raw"
# Then attach disk snapshot and copy .raw to analysis system
```
""",
    },
    {
        "title": "Volatility Registry Analysis and Network Connection Forensics",
        "tags": ["volatility", "registry", "network-forensics", "memory-forensics", "dfir"],
        "content": """# Volatility Registry Analysis and Network Connection Forensics

## Registry Analysis from Memory

Windows registry hives are loaded into memory, allowing extraction of persistence mechanisms, configuration data, and user activity without parsing disk files.

### Registry Hive Listing

```bash
# List all loaded registry hives:
vol.py -f memory.raw windows.registry.hivelist

# Output example:
# Virtual     Physical    Name
# 0x9f...     0x3a...     \\REGISTRY\\MACHINE\\SYSTEM
# 0x9e...     0x2f...     \\REGISTRY\\MACHINE\\SOFTWARE
# 0x9d...     0x1c...     \\REGISTRY\\USER\\S-1-5-21-...\\NTUSER.DAT
# 0x9c...     0x4d...     \\REGISTRY\\USER\\S-1-5-21-...\\UsrClass.dat
```

### Extracting Registry Keys

```bash
# Print specific key and all values:
vol.py -f memory.raw windows.registry.printkey \
    --key "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

vol.py -f memory.raw windows.registry.printkey \
    --key "SYSTEM\\CurrentControlSet\\Services"

# Specify hive by offset (from hivelist) for performance:
vol.py -f memory.raw windows.registry.printkey \
    --offset 0x9e... \
    --key "Microsoft\\Windows NT\\CurrentVersion"
```

### Key Forensic Registry Locations

```bash
# Persistence:
--key "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
--key "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
--key "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
# Shell value should be "explorer.exe"
# Userinit should be "C:\\Windows\\system32\\userinit.exe,"

# Services (common persistence and privilege escalation):
--key "SYSTEM\\CurrentControlSet\\Services"

# WDigest credential caching:
--key "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"
# UseLogonCredential: 0 = no plaintext; 1 = plaintext stored (attacker may set this)

# LSA security packages (DLL injection into lsass):
--key "SYSTEM\\CurrentControlSet\\Control\\Lsa"
# SecurityPackages value — unexpected entries = malicious SSP

# Application compatibility (ShimCache):
--key "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache"

# Recent execution (Amcache equivalent from memory):
vol.py -f memory.raw windows.registry.shimcache
```

### UserAssist (Recently Executed Programs)

```bash
vol.py -f memory.raw windows.registry.userassist

# Output: ROT13-encoded program paths, run count, last run time
# Decode ROT13 automatically in output
# Reveals what programs were recently launched interactively
```

## Network Connection Forensics from Memory

### netscan — Primary Network Plugin

```bash
vol.py -f memory.raw windows.netscan

# Output columns:
# Offset    Proto  LocalAddr   LocalPort  ForeignAddr    ForeignPort  State      PID  Owner     Created

# Filter for established connections:
vol.py -f memory.raw windows.netscan | grep ESTABLISHED

# Filter by suspicious ports (common C2 ports):
vol.py -f memory.raw windows.netscan | awk '{print $6}' | sort -u
# Check for: 4444, 1337, 31337, 8080, 8443, non-standard high ports
```

### Correlating Connections to Processes

```bash
# Get all connections with owning process:
vol.py -f memory.raw windows.netscan | awk '{print $9, $5, $4, $6, $7}'
# PID ForeignAddr LocalAddr ForeignPort State

# Find connection owner process:
SUSPICIOUS_PID=1848
vol.py -f memory.raw windows.netscan | grep $SUSPICIOUS_PID
vol.py -f memory.raw windows.pstree | grep $SUSPICIOUS_PID
vol.py -f memory.raw windows.cmdline | grep $SUSPICIOUS_PID
vol.py -f memory.raw windows.dlllist --pid $SUSPICIOUS_PID
```

### Socket and Connection Artifacts

```bash
# Even closed connections leave socket objects in memory:
# netscan scans pool for SOCKET/TCP_ENDPOINT/UDP_ENDPOINT objects

# Example findings:
# Active ESTABLISHED:
# TCP 10.0.0.50:49612 → 185.220.101.45:443 ESTABLISHED svchost.exe (1848)

# Recently closed (CLOSE_WAIT, TIME_WAIT):
# TCP 10.0.0.50:49601 → 185.220.101.45:80 CLOSE_WAIT powershell.exe (2340)

# Listening ports:
# TCP 0.0.0.0:4444 → 0.0.0.0:0 LISTENING nc.exe (4444)  ← backdoor!
```

### DNS Cache from Memory

```bash
# Windows DNS client caches responses in a service process
# Extract from svchost.exe running dnscache service

# Find the dnscache process:
vol.py -f memory.raw windows.cmdline | grep -i dnscache
# Or: vol.py -f memory.raw windows.pstree | grep svchost (multiple results)

# Dump the svchost running dnscache:
DNSCACHE_PID=$(vol.py -f memory.raw windows.services 2>/dev/null | awk '/dnscache/{print $1}')
vol.py -f memory.raw windows.memmap --pid $DNSCACHE_PID --dump

# Search for DNS records:
strings pid.$DNSCACHE_PID.dmp | grep -E "[a-z0-9.-]{4,}\.[a-z]{2,6}" | \
  grep -v "microsoft\|windows\|adobe\|google" | sort -u
```

## Comprehensive Memory Analysis Report

```
MEMORY FORENSICS REPORT
Case: IR-2025-0042
Analyst: SOC Team
Image: WORKSTATION-01_20250315.raw

EXECUTIVE SUMMARY:
Evidence of Cobalt Strike beacon injection into svchost.exe (PID 1848),
credential theft via LSASS dump, and active C2 communication to 185.220.101.45.

TIMELINE:
14:02 UTC — Malicious macro executed (WINWORD.EXE spawned powershell.exe)
14:03 UTC — PowerShell downloaded shellcode from pastebin.com
14:04 UTC — Shellcode injected into svchost.exe (PID 1848)
14:05 UTC — LSASS opened with PROCESS_VM_READ by PID 1848
14:06 UTC — C2 beacon established: 185.220.101.45:443 ESTABLISHED

FINDINGS:

1. PROCESS INJECTION (svchost.exe PID 1848)
   - malfind: RWX VAD region 0x3c0000–0x43ffff with MZ header
   - Injected PE: YARA match CobaltStrike_Beacon
   - ESTABLISHED connection to 185.220.101.45:443

2. CREDENTIAL THEFT
   - Handle to lsass.exe with PROCESS_VM_READ from PID 1848
   - pypykatz output shows NT hashes for 3 domain accounts

3. PERSISTENCE
   - Registry Run key: HKCU\\...\\Run\\Updater = C:\\Users\\user\\AppData\\svchost32.exe

4. DROPPED FILES
   - C:\\Users\\user\\AppData\\Roaming\\svchost32.exe (stage 2)
   - C:\\ProgramData\\update.bat

RECOMMENDED ACTIONS:
1. Isolate WORKSTATION-01 immediately
2. Reset passwords for all 3 compromised accounts
3. Block 185.220.101.45 on perimeter firewall
4. Search for lateral movement from this workstation
5. Preserve memory image as evidence
```
""",
    },
    {
        "title": "Windows Kernel Forensics — Pool Tags, Object Headers, Driver Analysis",
        "tags": ["kernel-forensics", "pool-tags", "drivers", "windbg", "memory-forensics", "dfir"],
        "content": """# Windows Kernel Forensics — Pool Tags, Object Headers, Driver Analysis

## Windows Pool Memory

The Windows kernel uses pool memory for dynamic allocation. Each allocation has a pool header containing a 4-byte tag identifying the allocation type.

### Pool Header Structure

```c
typedef struct _POOL_HEADER {
    union {
        struct {
            ULONG PreviousSize : 8;    // previous block size
            ULONG PoolIndex    : 8;    // pool descriptor index
            ULONG BlockSize    : 8;    // this block size (in 8-byte units)
            ULONG PoolType     : 8;    // 0=NonPaged, 1=Paged
        };
        ULONG Ulong1;
    };
    ULONG PoolTag;    // 4-char tag identifying allocation type
    // Object body follows
} POOL_HEADER;
```

### Common Pool Tags

| Tag | Object Type | Forensic Value |
|---|---|---|
| `Proc` (0x636F7250) | EPROCESS | Active/hidden processes |
| `Thre` | ETHREAD | Threads |
| `File` | FILE_OBJECT | Open file handles |
| `Driv` | DRIVER_OBJECT | Loaded drivers |
| `Mutant` | KMUTANT | Mutex objects |
| `Even` | EVENT | Event objects |
| `TcpE` | TCP_ENDPOINT | TCP connections |
| `UdpA` | UDP_ENDPOINT | UDP sockets |
| `FMfn` | FILE_NAME | File name strings |

### Pool Scanning with Volatility

```bash
# Scan for all EPROCESS objects (bypasses DKOM hidden process manipulation):
vol.py -f memory.raw windows.psscan
# Internally searches for: POOL_TAG = 0x636F7250 ('Proc')

# Scan for DRIVER_OBJECT (finds hidden drivers):
vol.py -f memory.raw windows.driverscan
# Pool tag: 'Driv' = 0x76697244

# Scan for FILE_OBJECT:
vol.py -f memory.raw windows.filescan
# Shows all cached file objects — reveals opened files even if closed

# Scan for KMUTANT (mutex objects — C2 check-in mutexes):
vol.py -f memory.raw windows.mutantscan
# C2 tools use mutexes to prevent re-infection
# Look for: "Global\\<random_string>", known mutex names
```

## Object Headers and Type Objects

Every kernel object has an object header preceding the body:

```c
typedef struct _OBJECT_HEADER {
    LONG_PTR PointerCount;
    union {
        LONG_PTR HandleCount;
        PVOID NextToFree;
    };
    EX_PUSH_LOCK Lock;
    UCHAR TypeIndex;    // Index into ObpObjectTypes[] array
    UCHAR TraceFlags;
    UCHAR InfoMask;
    UCHAR Flags;
    union {
        POBJECT_CREATE_INFORMATION ObjectCreateInfo;
        PVOID QuotaBlockCharged;
    };
    PVOID SecurityDescriptor;
    QUAD Body;    // Object body follows here
} OBJECT_HEADER;

// Object body is at: OBJECT_HEADER + sizeof(OBJECT_HEADER)
// Or: OBJECT_HEADER address + offsetof(OBJECT_HEADER, Body)
```

```windbg
# WinDbg: examine an object
!object \Device\HarddiskVolume1
# Shows type, name, reference count, security descriptor

# Display object header of a specific address:
!object poi(fffff8001234abcd)   # Dereference pointer to object
dt _OBJECT_HEADER fffff8001234a000   # Raw structure dump
```

## Driver Analysis

### Driver Object Structure

```windbg
# Examine a specific driver object:
!drvobj \Driver\suspect_driver full

# Output includes:
# Driver object at 0xffff...
# DriverName:  \Driver\suspect_driver
# DriverStart: 0xfffff800...  (base address)
# DriverSize:  0x...
# DriverEntry: 0xfffff800...  (entrypoint)
# IRP handlers: MajorFunction[0..27]
```

### Finding Suspicious Drivers

```bash
# List all drivers with Volatility:
vol.py -f memory.raw windows.driverscan
# Shows: Offset, Start, Size, ServiceKey, Name, Driver

# Unsigned drivers (verify loaded drivers against known-good):
driverquery /si | findstr "FALSE"  # Windows command

# Check for drivers loaded from unusual paths:
vol.py -f memory.raw windows.modules | grep -iv "\\windows\\system32\\drivers"
# Legitimate drivers: C:\Windows\System32\drivers\*.sys
# Suspicious: any other path (TEMP, APPDATA, ProgramData)
```

### IRP Handler Verification

```bash
vol.py -f memory.raw windows.driverirp

# Legitimate: all IRP handlers point within the driver's own module
# Hooking rootkit: IRP_MJ_READ or IRP_MJ_WRITE handler points to different module

# Example of hook detection:
# Driver: \Driver\Disk
# IRP_MJ_READ [0]: 0xfffff800`1a123456  -> disk.sys  [LEGITIMATE]
# IRP_MJ_WRITE[1]: 0xfffffa80`0abcdef0  -> ???       [SUSPICIOUS - HOOK]

# Identify unknown module:
vol.py -f memory.raw windows.modules | grep "0xfffffa80"
```

## Analyzing the SSDT

The System Service Descriptor Table maps syscall numbers to handler functions.

```bash
vol.py -f memory.raw windows.ssdt

# Normal output:
# Index  Address              Module          Symbol
# 0x0000 0xfffff80012345678   ntoskrnl.exe   NtMapUserPhysicalPages

# Hooked output:
# Index  Address              Module          Symbol
# 0x0025 0xfffffa800abcdef0   UNKNOWN         ---
# ^^^ address not in ntoskrnl = SSDT hook
```

### Bypassing SSDT Hooks for Analysis

```windbg
# When SSDT is hooked, kernel APIs return manipulated data
# To see true process list despite hooks:
# 1. Use physical memory scanner (Volatility psscan)
# 2. Use WinDbg kernel debugger (bypasses hooks via direct memory access)

# In WinDbg: direct EPROCESS list traversal
.process /p /r
!process 0 0  # Uses kernel interface — may be hooked
# vs.
# Manually walk EPROCESS list:
dt _EPROCESS fffffa800abcde00  # Direct struct access, bypasses hooks
```

## Detecting Kernel Rootkits in Practice

```bash
# Full kernel rootkit detection workflow:

# Step 1: Compare pslist vs psscan
vol.py -f memory.raw windows.pslist > pslist.txt
vol.py -f memory.raw windows.psscan > psscan.txt
diff pslist.txt psscan.txt  # Hidden processes show up here

# Step 2: Check SSDT
vol.py -f memory.raw windows.ssdt | grep UNKNOWN

# Step 3: Check all drivers
vol.py -f memory.raw windows.driverscan > driverscan.txt
vol.py -f memory.raw windows.modules > modules.txt
diff modules.txt driverscan.txt  # Hidden drivers

# Step 4: Check IRP hooks
vol.py -f memory.raw windows.driverirp | grep -v "\\\\Windows\\\\System32"

# Step 5: Network connections for hidden sockets
vol.py -f memory.raw windows.netscan

# Step 6: Dump suspicious driver for analysis
vol.py -f memory.raw windows.dumpfiles --virtaddr <driver_base_address>
# Analyze dumped .sys file with Ghidra/IDA
```
""",
    },
]
'''

with open("C:/Users/Tomo/ixion/src/ion/data/kb_forensics_advanced.py", "a", encoding="utf-8") as f:
    f.write(chunk)
print("Collection 3 done. Lines:", open("C:/Users/Tomo/ixion/src/ion/data/kb_forensics_advanced.py", encoding="utf-8").read().count("\n"))
